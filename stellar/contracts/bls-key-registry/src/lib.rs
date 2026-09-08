//! BLSKeyRegistry v2 — maps a 32-byte account id to up to five BLS key slots.
//! State changes are authenticated by the owner's wallet sig + BLS
//! proof-of-possession, never by the invoker (relayable). `register` / `revoke`
//! consume the per-account nonce; `set_valid_until` is shorten-only and
//! nonce-free so a pre-signed retirement never expires (design 03 §3.4, 05 §5.6).

#![no_std]

mod errors;
mod events;
mod storage;

use soroban_sdk::{
    bytesn, contract, contractclient, contractimpl, contracttype,
    crypto::bls12_381::{Bls12381G1Affine as G1Affine, Bls12381G2Affine as G2Affine},
    vec, Address, Bytes, BytesN, Env, Vec,
};

use errors::RegistryError;
use proofbridge_core::eip712::{address_to_bytes32, contract_address_to_bytes32};
pub use storage::KeySlot;

/// RFC 9380 / IETF BLS proof-of-possession DST.
pub const DST_POP: &str = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// keccak256("ProofBridge.BLSKeyRegistry.Register.v1")
const REG_TAG: [u8; 32] = [
    0x6c, 0xd2, 0xef, 0x15, 0x5a, 0x7c, 0x76, 0x75, 0xfe, 0x1d, 0x69, 0xad, 0xb5, 0x3f, 0xf8, 0x6e,
    0x72, 0x00, 0x54, 0xdf, 0xea, 0x3b, 0xb2, 0x28, 0x70, 0x8b, 0x27, 0x29, 0x60, 0x3a, 0x9b, 0xa8,
];
/// keccak256("ProofBridge.BLSKeyRegistry.Revoke.v1")
const REVOKE_TAG: [u8; 32] = [
    0xde, 0x96, 0x30, 0x9c, 0xde, 0xa1, 0x14, 0xde, 0xe7, 0x2c, 0x42, 0x59, 0x5e, 0x02, 0xd3, 0x0a,
    0xe8, 0x19, 0x03, 0xef, 0x82, 0x7b, 0xc2, 0x05, 0x3a, 0x40, 0xcb, 0x90, 0x3f, 0xbc, 0xe2, 0xd3,
];
/// keccak256("ProofBridge.BLSKeyRegistry.PoP.v1")
const POP_TAG: [u8; 32] = [
    0x28, 0xcc, 0x1b, 0x6c, 0x54, 0xf4, 0x22, 0xc0, 0x34, 0x57, 0x07, 0x7b, 0xa8, 0x81, 0x47, 0x10,
    0xc3, 0xdd, 0xb0, 0x7e, 0xe5, 0xb4, 0xa0, 0x68, 0xe9, 0x90, 0xbb, 0x90, 0xc5, 0x62, 0x20, 0x07,
];

/// keccak256("ProofBridge.BLSKeyRegistry.SetValidUntil.v1")
const SET_VALID_UNTIL_TAG: [u8; 32] = [
    0xd0, 0xc0, 0x00, 0x29, 0xb6, 0x14, 0x56, 0xf2, 0x61, 0xfd, 0xd3, 0xfc, 0x50, 0x14, 0xb3, 0x12,
    0x5f, 0x02, 0x02, 0x5a, 0xee, 0x7f, 0x21, 0xf0, 0x82, 0x2b, 0x50, 0x38, 0x29, 0x22, 0x83, 0x5a,
];

pub const MAX_ACTIVE_SLOTS: u32 = 5;
/// Seconds past valid_until before a slot may be pruned.
pub const GRACE_PERIOD: u64 = 30 * 24 * 60 * 60;

const ETH_SIGN_PREFIX: &[u8; 28] = b"\x19Ethereum Signed Message:\n32";

/// How the account owner authorized this state change.
#[contracttype]
#[derive(Clone)]
pub enum OwnerAuth {
    /// `require_auth`; the address must resolve to `account`.
    Stellar(Address),
    /// `r || s || v` secp256k1 personal_sign; recovered address must match `account`.
    Evm(BytesN<65>),
}

/// Escrow-side seam so revoke can refuse while the account has open positions.
#[contractclient(name = "PositionGuardClient")]
pub trait PositionGuard {
    fn has_open_positions(env: Env, account: BytesN<32>) -> bool;
}

#[contract]
pub struct BlsKeyRegistry;

#[contractimpl]
impl BlsKeyRegistry {
    pub fn initialize(env: Env, admin: Address, chain_id: u128) -> Result<(), RegistryError> {
        if storage::is_initialized(&env) {
            return Err(RegistryError::AlreadyInitialized);
        }
        storage::set_initialized(&env);
        storage::set_admin(&env, &admin);
        storage::set_chain_id(&env, chain_id);
        events::Initialized { admin, chain_id }.publish(&env);
        Ok(())
    }

    pub fn pause(env: Env) -> Result<(), RegistryError> {
        let admin = storage::get_admin(&env);
        admin.require_auth();
        storage::set_paused(&env, true);
        events::Paused { admin }.publish(&env);
        Ok(())
    }

    pub fn unpause(env: Env) -> Result<(), RegistryError> {
        let admin = storage::get_admin(&env);
        admin.require_auth();
        storage::set_paused(&env, false);
        events::Unpaused { admin }.publish(&env);
        Ok(())
    }

    pub fn transfer_admin(env: Env, to: Address) -> Result<(), RegistryError> {
        let admin = storage::get_admin(&env);
        admin.require_auth();
        storage::set_pending_admin(&env, &to);
        events::AdminTransferStarted { from: admin, to }.publish(&env);
        Ok(())
    }

    pub fn accept_admin(env: Env) -> Result<(), RegistryError> {
        let pending = storage::get_pending_admin(&env).ok_or(RegistryError::NotPendingAdmin)?;
        pending.require_auth();
        let old = storage::get_admin(&env);
        storage::set_admin(&env, &pending);
        storage::clear_pending_admin(&env);
        events::AdminTransferred {
            from: old,
            to: pending,
        }
        .publish(&env);
        Ok(())
    }

    pub fn set_position_guards(env: Env, guards: Vec<Address>) -> Result<(), RegistryError> {
        if !storage::is_initialized(&env) {
            return Err(RegistryError::NotInitialized);
        }
        storage::get_admin(&env).require_auth();
        storage::set_guards(&env, &guards);
        events::PositionGuardsSet { guards }.publish(&env);
        Ok(())
    }

    /// Adds a slot; never guarded (additive, design 03 §3.3). Returns the slot id.
    pub fn register(
        env: Env,
        account: BytesN<32>,
        owner: OwnerAuth,
        bls_pub_key: BytesN<96>,
        pop: BytesN<192>,
        nonce: u64,
    ) -> Result<u32, RegistryError> {
        if !storage::is_initialized(&env) {
            return Err(RegistryError::NotInitialized);
        }
        if storage::is_paused(&env) {
            return Err(RegistryError::ContractPaused);
        }
        if nonce != storage::get_nonce(&env, &account) {
            return Err(RegistryError::BadNonce);
        }
        if bls_pub_key == g1_identity(&env) {
            return Err(RegistryError::IdentityKey);
        }
        if !verify_pop(&env, &account, &bls_pub_key, &pop, nonce) {
            return Err(RegistryError::InvalidPop);
        }
        check_owner(&env, &account, owner, || {
            reg_digest(&env, &account, &bls_pub_key, nonce)
        })?;

        let commitment: BytesN<32> = env
            .crypto()
            .keccak256(&Bytes::from_slice(&env, &bls_pub_key.to_array()))
            .to_bytes();
        let slot_id = add_slot(&env, &account, &commitment)?;
        storage::set_nonce(&env, &account, nonce + 1);
        events::KeyRegistered {
            account,
            slot_id,
            bls_pub_key,
            nonce,
        }
        .publish(&env);
        Ok(slot_id)
    }

    /// Shorten-only, nonce-free, never guarded, and not pausable: the retirement lever
    /// (D6/D9) only ever reduces authority, so a registry pause must not block it.
    pub fn set_valid_until(
        env: Env,
        account: BytesN<32>,
        owner: OwnerAuth,
        slot_id: u32,
        valid_until: u64,
    ) -> Result<(), RegistryError> {
        if !storage::is_initialized(&env) {
            return Err(RegistryError::NotInitialized);
        }
        let mut slot =
            storage::get_slot(&env, &account, slot_id).ok_or(RegistryError::NoSuchSlot)?;
        if valid_until == 0 || (slot.valid_until != 0 && valid_until >= slot.valid_until) {
            return Err(RegistryError::BadValidUntil);
        }
        check_owner(&env, &account, owner, || {
            set_valid_until_digest(&env, &account, slot_id, valid_until)
        })?;

        slot.valid_until = valid_until;
        storage::set_slot(&env, &account, slot_id, &slot);
        events::SlotValidUntilSet {
            account,
            slot_id,
            valid_until,
        }
        .publish(&env);
        Ok(())
    }

    /// Leaves the protocol: drops every slot. Still guarded (t1-design §1.8).
    pub fn revoke(
        env: Env,
        account: BytesN<32>,
        owner: OwnerAuth,
        nonce: u64,
    ) -> Result<(), RegistryError> {
        if !storage::is_initialized(&env) {
            return Err(RegistryError::NotInitialized);
        }
        if storage::is_paused(&env) {
            return Err(RegistryError::ContractPaused);
        }
        let mut entry = storage::get_entry(&env, &account);
        if entry.live.is_empty() {
            return Err(RegistryError::NotRegistered);
        }
        if nonce != storage::get_nonce(&env, &account) {
            return Err(RegistryError::BadNonce);
        }
        require_no_open_positions(&env, &account)?;
        check_owner(&env, &account, owner, || {
            revoke_digest(&env, &account, nonce)
        })?;

        for slot_id in entry.live.iter() {
            storage::remove_slot(&env, &account, slot_id);
        }
        entry.live = Vec::new(&env);
        storage::set_entry(&env, &account, &entry);
        storage::set_nonce(&env, &account, nonce + 1);
        events::KeyRevoked { account, nonce }.publish(&env);
        Ok(())
    }

    // ---- views ----

    /// The verifier's one call: the commitment iff the slot exists and is usable now.
    pub fn commitment_at(
        env: Env,
        account: BytesN<32>,
        slot_id: u32,
    ) -> Result<BytesN<32>, RegistryError> {
        let slot = storage::get_slot(&env, &account, slot_id).ok_or(RegistryError::NoSuchSlot)?;
        if slot.valid_until != 0 && env.ledger().timestamp() >= slot.valid_until {
            return Err(RegistryError::SlotExpired);
        }
        storage::touch(&env, &account, slot_id);
        Ok(slot.commitment)
    }

    /// True iff at least one live slot is usable now (the "is registered" check for 2.3c).
    pub fn has_usable_slot(env: Env, account: BytesN<32>) -> bool {
        let now = env.ledger().timestamp();
        storage::get_entry(&env, &account)
            .live
            .iter()
            .any(|slot_id| {
                matches!(storage::get_slot(&env, &account, slot_id),
                Some(s) if s.valid_until == 0 || now < s.valid_until)
            })
    }

    pub fn lookup(env: Env, account: BytesN<32>, slot_id: u32) -> Option<KeySlot> {
        storage::get_slot(&env, &account, slot_id)
    }

    pub fn live_slots(env: Env, account: BytesN<32>) -> Vec<u32> {
        storage::get_entry(&env, &account).live
    }

    pub fn next_slot_id(env: Env, account: BytesN<32>) -> u32 {
        storage::get_entry(&env, &account).next_slot_id
    }

    pub fn is_used(env: Env, account: BytesN<32>, commitment: BytesN<32>) -> bool {
        storage::is_used(&env, &account, &commitment)
    }

    pub fn nonce_of(env: Env, account: BytesN<32>) -> u64 {
        storage::get_nonce(&env, &account)
    }

    pub fn chain_id(env: Env) -> u128 {
        storage::get_chain_id(&env)
    }

    pub fn admin(env: Env) -> Address {
        storage::get_admin(&env)
    }
}

// =============================================================================
// Message building
// =============================================================================

fn chain_id_be32(chain_id: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&chain_id.to_be_bytes());
    out
}

fn nonce_be32(nonce: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&nonce.to_be_bytes());
    out
}

/// pop_msg = POP_TAG || chainId(32) || registryId(32) || account(32) || pk(96) || nonce(32)
fn pop_msg(env: &Env, account: &BytesN<32>, bls_pub_key: &BytesN<96>, nonce: u64) -> Bytes {
    let mut msg = Bytes::from_slice(env, &POP_TAG);
    msg.extend_from_slice(&chain_id_be32(storage::get_chain_id(env)));
    msg.extend_from_slice(&contract_address_to_bytes32(env).to_array());
    msg.extend_from_slice(&account.to_array());
    msg.extend_from_slice(&bls_pub_key.to_array());
    msg.extend_from_slice(&nonce_be32(nonce));
    msg
}

/// reg_digest = keccak256(REG_TAG || chainId || registryId || account || keccak256(pk) || nonce)
fn reg_digest(env: &Env, account: &BytesN<32>, bls_pub_key: &BytesN<96>, nonce: u64) -> BytesN<32> {
    let pk_hash = env
        .crypto()
        .keccak256(&Bytes::from_slice(env, &bls_pub_key.to_array()));
    let mut msg = Bytes::from_slice(env, &REG_TAG);
    msg.extend_from_slice(&chain_id_be32(storage::get_chain_id(env)));
    msg.extend_from_slice(&contract_address_to_bytes32(env).to_array());
    msg.extend_from_slice(&account.to_array());
    msg.extend_from_slice(&pk_hash.to_array());
    msg.extend_from_slice(&nonce_be32(nonce));
    env.crypto().keccak256(&msg).to_bytes()
}

/// revoke_digest = keccak256(REVOKE_TAG || chainId || registryId || account || nonce)
fn revoke_digest(env: &Env, account: &BytesN<32>, nonce: u64) -> BytesN<32> {
    let mut msg = Bytes::from_slice(env, &REVOKE_TAG);
    msg.extend_from_slice(&chain_id_be32(storage::get_chain_id(env)));
    msg.extend_from_slice(&contract_address_to_bytes32(env).to_array());
    msg.extend_from_slice(&account.to_array());
    msg.extend_from_slice(&nonce_be32(nonce));
    env.crypto().keccak256(&msg).to_bytes()
}

/// set_valid_until_digest = keccak256(SET_VALID_UNTIL_TAG || chainId || registryId || account || slotId(32) || validUntil(32))
fn set_valid_until_digest(
    env: &Env,
    account: &BytesN<32>,
    slot_id: u32,
    valid_until: u64,
) -> BytesN<32> {
    let mut msg = Bytes::from_slice(env, &SET_VALID_UNTIL_TAG);
    msg.extend_from_slice(&chain_id_be32(storage::get_chain_id(env)));
    msg.extend_from_slice(&contract_address_to_bytes32(env).to_array());
    msg.extend_from_slice(&account.to_array());
    msg.extend_from_slice(&nonce_be32(slot_id as u64));
    msg.extend_from_slice(&nonce_be32(valid_until));
    env.crypto().keccak256(&msg).to_bytes()
}

// =============================================================================
// Verification
// =============================================================================

/// Uncompressed G1 identity encoding (infinity bit set, all else zero).
fn g1_identity(env: &Env) -> BytesN<96> {
    let mut buf = [0u8; 96];
    buf[0] = 0x40;
    BytesN::from_array(env, &buf)
}

/// e(pk, H(pop_msg)) == e(G1, pop) ⇔ pairing_check([pk, -G1], [H(pop_msg), pop]).
/// The host subgroup-checks both points as pairing inputs.
/// Slot insertion shared by `register` and the (2.1b) proof-accepting path.
fn add_slot(
    env: &Env,
    account: &BytesN<32>,
    commitment: &BytesN<32>,
) -> Result<u32, RegistryError> {
    if storage::is_used(env, account, commitment) {
        return Err(RegistryError::KeyPreviouslyUsed);
    }
    let mut entry = storage::get_entry(env, account);
    if entry.live.len() >= MAX_ACTIVE_SLOTS {
        prune(env, account, &mut entry);
        if entry.live.len() >= MAX_ACTIVE_SLOTS {
            return Err(RegistryError::RegistryFull);
        }
    }
    let slot_id = entry.next_slot_id;
    entry.next_slot_id += 1;
    entry.live.push_back(slot_id);
    storage::set_slot(
        env,
        account,
        slot_id,
        &KeySlot {
            commitment: commitment.clone(),
            valid_until: 0,
            registered_at: env.ledger().timestamp(),
        },
    );
    storage::set_entry(env, account, &entry);
    storage::set_used(env, account, commitment);
    Ok(slot_id)
}

/// Drops every slot past valid_until + GRACE_PERIOD (order of `live` is not meaningful).
fn prune(env: &Env, account: &BytesN<32>, entry: &mut storage::RegistryEntry) {
    let now = env.ledger().timestamp();
    let mut kept = Vec::new(env);
    for slot_id in entry.live.iter() {
        let prunable = match storage::get_slot(env, account, slot_id) {
            Some(s) => s.valid_until != 0 && now > s.valid_until.saturating_add(GRACE_PERIOD),
            None => true,
        };
        if prunable {
            storage::remove_slot(env, account, slot_id);
            events::SlotPruned {
                account: account.clone(),
                slot_id,
            }
            .publish(env);
        } else {
            kept.push_back(slot_id);
        }
    }
    entry.live = kept;
}

/// Scheme dispatch; a new scheme is one more arm (design 03 §3.5). The digest is
/// only built for the signature schemes (`require_auth` needs none).
fn check_owner(
    env: &Env,
    account: &BytesN<32>,
    owner: OwnerAuth,
    digest: impl FnOnce() -> BytesN<32>,
) -> Result<(), RegistryError> {
    match owner {
        OwnerAuth::Stellar(addr) => {
            addr.require_auth();
            if address_to_bytes32(env, &addr) != *account {
                return Err(RegistryError::OwnerMismatch);
            }
            Ok(())
        }
        OwnerAuth::Evm(sig) => check_evm_owner(env, account, &digest(), &sig),
    }
}

fn require_no_open_positions(env: &Env, account: &BytesN<32>) -> Result<(), RegistryError> {
    if let Some(guards) = storage::get_guards(env) {
        for guard in guards.iter() {
            if PositionGuardClient::new(env, &guard).has_open_positions(account) {
                return Err(RegistryError::AccountInFlight);
            }
        }
    }
    Ok(())
}

fn verify_pop(
    env: &Env,
    account: &BytesN<32>,
    bls_pub_key: &BytesN<96>,
    pop: &BytesN<192>,
    nonce: u64,
) -> bool {
    let bls = env.crypto().bls12_381();

    // Negative G1 generator, hardcoded to save a host negation per verify.
    let neg_g1 = G1Affine::from_bytes(bytesn!(
        env,
        0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca
    ));

    let pk = G1Affine::from_bytes(bls_pub_key.clone());
    let sig = G2Affine::from_bytes(pop.clone());
    let dst = Bytes::from_slice(env, DST_POP.as_bytes());
    let msg_g2 = bls.hash_to_g2(&pop_msg(env, account, bls_pub_key, nonce), &dst);

    bls.pairing_check(vec![env, pk, neg_g1], vec![env, msg_g2, sig])
}

/// `account` must be 12 zero bytes || the recovered personal_sign eth address.
fn check_evm_owner(
    env: &Env,
    account: &BytesN<32>,
    digest: &BytesN<32>,
    sig: &BytesN<65>,
) -> Result<(), RegistryError> {
    let acct = account.to_array();
    if acct[..12].iter().any(|b| *b != 0) {
        return Err(RegistryError::OwnerMismatch);
    }

    let mut prefixed = Bytes::from_slice(env, ETH_SIGN_PREFIX);
    prefixed.extend_from_slice(&digest.to_array());
    let eth_digest = env.crypto().keccak256(&prefixed);

    let sig_arr = sig.to_array();
    let mut rs = [0u8; 64];
    rs.copy_from_slice(&sig_arr[..64]);
    let addr = proofbridge_core::secp::recover_evm_address(
        env,
        &eth_digest,
        &BytesN::from_array(env, &rs),
        sig_arr[64] as u32,
    )
    .ok_or(RegistryError::OwnerMismatch)?;

    if addr[..] != acct[12..] {
        return Err(RegistryError::OwnerMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod test;
