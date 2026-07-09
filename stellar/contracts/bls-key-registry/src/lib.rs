//! BLSKeyRegistry — maps a 32-byte account id to its one BLS key.
//! State changes are authenticated by the owner's wallet sig + BLS
//! proof-of-possession + per-account nonce, never by the invoker (relayable).

#![no_std]

mod errors;
mod events;
mod storage;

use soroban_sdk::{
    bytesn, contract, contractclient, contractimpl, contracttype,
    crypto::bls12_381::{G1Affine, G2Affine},
    vec, Address, Bytes, BytesN, Env, Vec,
};

use errors::RegistryError;
use proofbridge_core::eip712::{address_to_bytes32, contract_address_to_bytes32};

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

    pub fn register(
        env: Env,
        account: BytesN<32>,
        owner: OwnerAuth,
        bls_pub_key: BytesN<96>,
        pop: BytesN<192>,
        nonce: u64,
    ) -> Result<(), RegistryError> {
        if !storage::is_initialized(&env) {
            return Err(RegistryError::NotInitialized);
        }
        if storage::is_paused(&env) {
            return Err(RegistryError::ContractPaused);
        }
        if nonce != storage::get_nonce(&env, &account) {
            return Err(RegistryError::BadNonce);
        }
        // rotation (overwrite) is a key change like revoke: blocked while in flight
        if storage::get_commitment(&env, &account).is_some() {
            require_no_open_positions(&env, &account)?;
        }
        if bls_pub_key == g1_identity(&env) {
            return Err(RegistryError::IdentityKey);
        }
        if !verify_pop(&env, &account, &bls_pub_key, &pop, nonce) {
            return Err(RegistryError::InvalidPop);
        }
        match owner {
            OwnerAuth::Stellar(addr) => {
                addr.require_auth();
                if address_to_bytes32(&env, &addr) != account {
                    return Err(RegistryError::OwnerMismatch);
                }
            }
            OwnerAuth::Evm(sig) => {
                let digest = reg_digest(&env, &account, &bls_pub_key, nonce);
                check_evm_owner(&env, &account, &digest, &sig)?;
            }
        }

        let commitment: BytesN<32> = env
            .crypto()
            .keccak256(&Bytes::from_slice(&env, &bls_pub_key.to_array()))
            .to_bytes();
        storage::set_commitment(&env, &account, &commitment);
        storage::set_nonce(&env, &account, nonce + 1);
        events::KeyRegistered {
            account,
            bls_pub_key,
            nonce,
        }
        .publish(&env);
        Ok(())
    }

    /// Returns `keccak256(bls_pub_key)` — the full key travels in unlock metadata.
    pub fn key_of(env: Env, account: BytesN<32>) -> Result<BytesN<32>, RegistryError> {
        storage::get_commitment(&env, &account).ok_or(RegistryError::NotRegistered)
    }

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
        if storage::get_commitment(&env, &account).is_none() {
            return Err(RegistryError::NotRegistered);
        }
        if nonce != storage::get_nonce(&env, &account) {
            return Err(RegistryError::BadNonce);
        }
        require_no_open_positions(&env, &account)?;
        match owner {
            OwnerAuth::Stellar(addr) => {
                addr.require_auth();
                if address_to_bytes32(&env, &addr) != account {
                    return Err(RegistryError::OwnerMismatch);
                }
            }
            OwnerAuth::Evm(sig) => {
                let digest = revoke_digest(&env, &account, nonce);
                check_evm_owner(&env, &account, &digest, &sig)?;
            }
        }

        storage::remove_commitment(&env, &account);
        storage::set_nonce(&env, &account, nonce + 1);
        events::KeyRevoked { account, nonce }.publish(&env);
        Ok(())
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
    let v = sig_arr[64];
    let recovery_id = if v >= 27 { v - 27 } else { v } as u32;

    let pubkey =
        env.crypto()
            .secp256k1_recover(&eth_digest, &BytesN::from_array(env, &rs), recovery_id);
    let pk_arr = pubkey.to_array();
    let addr_hash = env
        .crypto()
        .keccak256(&Bytes::from_slice(env, &pk_arr[1..]))
        .to_array();

    if addr_hash[12..] != acct[12..] {
        return Err(RegistryError::OwnerMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod test;
