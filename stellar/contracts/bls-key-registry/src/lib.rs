//! BLSKeyRegistry v2 — maps a 32-byte account id to up to five BLS key slots.
//! State changes are authenticated by the owner's wallet sig + BLS
//! proof-of-possession, never by the invoker (relayable). `register` / `revoke`
//! consume the per-account nonce; `set_valid_until` is shorten-only and
//! nonce-free so a pre-signed retirement never expires (design 03 §3.4, 05 §5.6).
//! The owner signature is the one both registries accept (2.6 plan 13, `owner`).

#![no_std]

mod errors;
mod events;
mod owner;
mod storage;

use soroban_sdk::{
    bytesn, contract, contractclient, contractimpl,
    crypto::bls12_381::{Bls12381G1Affine as G1Affine, Bls12381G2Affine as G2Affine},
    vec, Address, Bytes, BytesN, ContractExecutable, Env, String, Vec,
};

use errors::RegistryError;
use owner::{check_owner, key_fingerprint, keys_domain_separator, KeyMessage, MAX_REGISTER_TTL};
pub use owner::{KeyLeg, OwnerAuth, OwnerSig, SignedOwner};
use proofbridge_core::cross_contract::{self, VerifierClient, LEAF_DOMAIN_REGISTERED};
use proofbridge_core::eip712::contract_address_to_bytes32;
pub use storage::KeySlot;

/// RFC 9380 / IETF BLS proof-of-possession DST.
pub const DST_POP: &str = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// keccak256("ProofBridge.BLSKeyRegistry.PoP.v1")
const POP_TAG: [u8; 32] = [
    0x28, 0xcc, 0x1b, 0x6c, 0x54, 0xf4, 0x22, 0xc0, 0x34, 0x57, 0x07, 0x7b, 0xa8, 0x81, 0x47, 0x10,
    0xc3, 0xdd, 0xb0, 0x7e, 0xe5, 0xb4, 0xa0, 0x68, 0xe9, 0x90, 0xbb, 0x90, 0xc5, 0x62, 0x20, 0x07,
];

pub const MAX_ACTIVE_SLOTS: u32 = 5;
/// Seconds past valid_until before a slot may be pruned.
pub const GRACE_PERIOD: u64 = 30 * 24 * 60 * 60;

/// Escrow-side seam so revoke can refuse while the account has open positions.
#[contractclient(name = "PositionGuardClient")]
pub trait PositionGuard {
    fn has_open_positions(env: Env, account: BytesN<32>) -> bool;
}

#[contract]
pub struct BlsKeyRegistry;

#[contractimpl]
impl BlsKeyRegistry {
    /// `deploy_env` (local / testnet / mainnet) salts the key messages' domain and names the
    /// Network line (2.6 review D3): a signature for one environment never applies in another.
    pub fn initialize(
        env: Env,
        admin: Address,
        chain_id: u128,
        deploy_env: String,
    ) -> Result<(), RegistryError> {
        if storage::is_initialized(&env) {
            return Err(RegistryError::AlreadyInitialized);
        }
        let domain = keys_domain_separator(&env, &deploy_env)?;
        storage::set_initialized(&env);
        storage::set_admin(&env, &admin);
        storage::set_chain_id(&env, chain_id);
        storage::set_keys_env(&env, &deploy_env, &domain);
        proofbridge_core::ttl::extend_instance(&env);
        events::Initialized {
            admin,
            chain_id,
            deploy_env,
        }
        .publish(&env);
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

    /// Swap the contract's code behind the two-step admin (#404 D5): the next gap of this
    /// class is a code swap, not a migration. Storage and the pause flag are untouched.
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) -> Result<(), RegistryError> {
        let admin = storage::get_admin(&env);
        admin.require_auth();
        env.deployer()
            .update_current_contract(ContractExecutable::Wasm(new_wasm_hash.clone()));
        events::Upgraded {
            admin,
            wasm_hash: new_wasm_hash,
        }
        .publish(&env);
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

    /// 2.1b: wire (or unwire) proof-carried registration — the anchor, the verifier and the home
    /// chains a leaf may come from. Enabling requires at least one source; the flip is a
    /// configuration change, never a redeploy (D3). This chain is never a source: its own leaves
    /// belong to another registry.
    pub fn set_proof_registration(
        env: Env,
        anchor: Address,
        verifier: Address,
        sources: Vec<u128>,
        enabled: bool,
    ) -> Result<(), RegistryError> {
        if !storage::is_initialized(&env) {
            return Err(RegistryError::NotInitialized);
        }
        storage::get_admin(&env).require_auth();
        if enabled && sources.is_empty() {
            return Err(RegistryError::ProofRegistrationRefsUnset);
        }
        if sources.contains(storage::get_chain_id(&env)) {
            return Err(RegistryError::SourceNotAllowed);
        }
        storage::set_proof_registration(
            &env,
            &storage::ProofRegistration {
                anchor: anchor.clone(),
                verifier: verifier.clone(),
                sources: sources.clone(),
                enabled,
            },
        );
        events::ProofRegistrationSet {
            anchor,
            verifier,
            sources,
            enabled,
        }
        .publish(&env);
        Ok(())
    }

    pub fn register(
        env: Env,
        account: BytesN<32>,
        owner: OwnerAuth,
        bls_pub_key: BytesN<96>,
        pop: BytesN<192>,
        nonce: u64,
        deadline: u64,
    ) -> Result<u32, RegistryError> {
        if !storage::is_initialized(&env) {
            return Err(RegistryError::NotInitialized);
        }
        if storage::is_paused(&env) {
            return Err(RegistryError::ContractPaused);
        }
        // D2: refused past the deadline, and when the deadline sits more than 7 days out.
        let now = env.ledger().timestamp();
        if now > deadline {
            return Err(RegistryError::DeadlineExpired);
        }
        if deadline - now > MAX_REGISTER_TTL {
            return Err(RegistryError::DeadlineTooFar);
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
        let fingerprint = key_fingerprint(&env, &bls_pub_key);
        check_owner(
            &env,
            &account,
            owner,
            KeyMessage::Register {
                fingerprint: fingerprint.clone(),
                nonce,
                deadline,
            },
        )?;

        let commitment: BytesN<32> = env
            .crypto()
            .keccak256(&Bytes::from_slice(&env, &bls_pub_key.to_array()))
            .to_bytes();
        let slot_id = add_slot(&env, &account, &commitment, &fingerprint)?;
        storage::set_nonce(&env, &account, nonce + 1);
        proofbridge_core::ttl::extend_instance(&env);
        events::KeyRegistered {
            account,
            slot_id,
            bls_pub_key,
            nonce,
        }
        .publish(&env);
        Ok(slot_id)
    }

    /// Adds a slot on an inclusion proof of the account's home-chain `REGISTERED` leaf against an
    /// anchored root, instead of an owner signature (2.1b, design 03 §3.6). Flagged off in T2.
    ///
    /// Cheap rejections first: flag, identity, the replay guard, the source allow-list and the
    /// anchor lookup all run before the pairing and the proof verify. No nonce: `is_used` is the
    /// replay guard, so a leaf registers its key at most once, and the account nonce is untouched.
    /// The POP binds `epoch` where `register` binds the nonce (D2, D7). The subject is rebuilt from
    /// this chain and registry (`registration_subject`), so a leaf is good for exactly one registry.
    pub fn register_by_proof(
        env: Env,
        account: BytesN<32>,
        bls_pub_key: BytesN<96>,
        pop: BytesN<192>,
        epoch: u64,
        source_chain_id: u128,
        target_root: BytesN<32>,
        proof: Bytes,
    ) -> Result<u32, RegistryError> {
        if !storage::is_initialized(&env) {
            return Err(RegistryError::NotInitialized);
        }
        if storage::is_paused(&env) {
            return Err(RegistryError::ContractPaused);
        }
        let cfg = storage::get_proof_registration(&env)
            .filter(|c| c.enabled)
            .ok_or(RegistryError::ProofRegistrationDisabled)?;
        if bls_pub_key == g1_identity(&env) {
            return Err(RegistryError::IdentityKey);
        }
        let commitment: BytesN<32> = env
            .crypto()
            .keccak256(&Bytes::from_slice(&env, &bls_pub_key.to_array()))
            .to_bytes();
        if storage::is_used(&env, &account, &commitment) {
            return Err(RegistryError::KeyPreviouslyUsed);
        }
        if !cfg.sources.contains(source_chain_id) {
            return Err(RegistryError::SourceNotAllowed);
        }
        if !cross_contract::is_anchored(&env, &cfg.anchor, source_chain_id, &target_root) {
            return Err(RegistryError::RootNotAnchored);
        }
        if !verify_pop(&env, &account, &bls_pub_key, &pop, epoch) {
            return Err(RegistryError::InvalidPop);
        }

        let subject = cross_contract::registration_subject(
            &env,
            storage::get_chain_id(&env),
            &contract_address_to_bytes32(&env),
            &account,
            &commitment,
            epoch,
        );
        let inputs = cross_contract::build_event_public_inputs(
            &env,
            &target_root,
            &subject,
            LEAF_DOMAIN_REGISTERED,
        );
        match VerifierClient::new(&env, &cfg.verifier).try_verify_proof(&inputs, &proof) {
            Ok(Ok(())) => {}
            _ => return Err(RegistryError::InvalidLeafProof),
        }

        let slot_id = add_slot(
            &env,
            &account,
            &commitment,
            &key_fingerprint(&env, &bls_pub_key),
        )?;
        proofbridge_core::ttl::extend_instance(&env);
        events::KeyRegisteredByProof {
            account,
            slot_id,
            bls_pub_key,
            epoch,
            source_chain_id,
        }
        .publish(&env);
        Ok(slot_id)
    }

    /// Shorten-only, nonce-free, never guarded, and not pausable: the retirement lever
    /// (D6/D9) only ever reduces authority, so a registry pause must not block it. Names the key
    /// by its fingerprint (keccak of the EIP-2537 form), so one pre-signed `RetireKey` serves
    /// every registry; the slot is found through the map written at registration.
    pub fn set_valid_until(
        env: Env,
        account: BytesN<32>,
        owner: OwnerAuth,
        key_commitment: BytesN<32>,
        valid_until: u64,
    ) -> Result<(), RegistryError> {
        if !storage::is_initialized(&env) {
            return Err(RegistryError::NotInitialized);
        }
        let slot_id = storage::get_key_slot(&env, &account, &key_commitment)
            .ok_or(RegistryError::NoSuchSlot)?;
        let mut slot =
            storage::get_slot(&env, &account, slot_id).ok_or(RegistryError::NoSuchSlot)?;
        if valid_until == 0 || (slot.valid_until != 0 && valid_until >= slot.valid_until) {
            return Err(RegistryError::BadValidUntil);
        }
        check_owner(
            &env,
            &account,
            owner,
            KeyMessage::Retire {
                fingerprint: key_commitment,
                valid_until,
            },
        )?;

        slot.valid_until = valid_until;
        storage::set_slot(&env, &account, slot_id, &slot);
        // D14/D14b: the slot stops at the later of the named date and now, and a later shorten can
        // only move that earlier.
        let eff = valid_until.max(env.ledger().timestamp());
        let prev = storage::get_expired_at(&env, &account, slot_id);
        let at = if prev == 0 { eff } else { prev.min(eff) };
        storage::set_expired_at(&env, &account, slot_id, at);
        proofbridge_core::ttl::extend_instance(&env);
        events::SlotValidUntilSet {
            account,
            slot_id,
            valid_until,
        }
        .publish(&env);
        Ok(())
    }

    /// Leaves the protocol: drops every slot, guarded (t1-design §1.8). With no slots here it only
    /// bumps the nonce, killing every outstanding signature at this registry (2.6 review D2).
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
        if nonce != storage::get_nonce(&env, &account) {
            return Err(RegistryError::BadNonce);
        }
        if !entry.live.is_empty() {
            require_no_open_positions(&env, &account)?;
        }
        check_owner(&env, &account, owner, KeyMessage::Revoke { nonce })?;

        for slot_id in entry.live.iter() {
            storage::remove_slot(&env, &account, slot_id);
        }
        entry.live = Vec::new(&env);
        storage::set_entry(&env, &account, &entry);
        storage::set_nonce(&env, &account, nonce + 1);
        proofbridge_core::ttl::extend_instance(&env);
        events::KeyRevoked { account, nonce }.publish(&env);
        Ok(())
    }

    /// Kills every outstanding signature naming `nonce` here (a pending registration) by consuming
    /// the nonce; no slot changes, so live keys stay and no guard is asked (review D2).
    pub fn cancel_pending(
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
        if nonce != storage::get_nonce(&env, &account) {
            return Err(RegistryError::BadNonce);
        }
        check_owner(&env, &account, owner, KeyMessage::Cancel { nonce })?;
        storage::set_nonce(&env, &account, nonce + 1);
        proofbridge_core::ttl::extend_instance(&env);
        events::RegistrationCancelled { account, nonce }.publish(&env);
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
        storage::touch(&env, &account, slot_id, &slot.fingerprint);
        // C-13: the verifier reads this on every unlock; an idle registry must not archive.
        proofbridge_core::ttl::extend_instance(&env);
        Ok(slot.commitment)
    }

    /// Did any of `account`'s slots expire in `[from, to]` (#422 D12/D14/D14b). The escrows' cancel
    /// grace asks it over the order's life as a payout, `[locked_at, cutoff]` (D16): a slot the order
    /// may have been co-signed under died while the payout could still land. A slot expires at the
    /// later of the date its shorten named and the moment of the shorten (a kill names `1`), and a
    /// later shorten can only move that earlier, so a kill, a near-future shorten, a pre-lock shorten
    /// naming a date inside the window and a re-kill after it all count; a rotation whose old slot
    /// outlives the cutoff does not. A dead slot is forgotten once the account has no open positions,
    /// or 30 days on.
    pub fn any_slot_expired_within(env: Env, account: BytesN<32>, from: u64, to: u64) -> bool {
        proofbridge_core::ttl::extend_instance(&env);
        storage::get_entry(&env, &account)
            .live
            .iter()
            .any(|slot_id| {
                let vu = expired_at(&env, &account, slot_id);
                vu != 0 && vu >= from && vu <= to
            })
    }

    /// True iff at least one live slot is usable now (the "is registered" check for 2.3c).
    pub fn has_usable_slot(env: Env, account: BytesN<32>) -> bool {
        proofbridge_core::ttl::extend_instance(&env);
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
        proofbridge_core::ttl::extend_instance(&env);
        storage::get_slot(&env, &account, slot_id)
    }

    pub fn live_slots(env: Env, account: BytesN<32>) -> Vec<u32> {
        storage::get_entry(&env, &account).live
    }

    pub fn next_slot_id(env: Env, account: BytesN<32>) -> u32 {
        storage::get_entry(&env, &account).next_slot_id
    }

    /// The slot a key fingerprint occupies (the one `set_valid_until` acts on), while it exists.
    pub fn slot_of_key(env: Env, account: BytesN<32>, key_commitment: BytesN<32>) -> Option<u32> {
        storage::get_key_slot(&env, &account, &key_commitment)
            .filter(|id| storage::get_slot(&env, &account, *id).is_some())
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

    /// The environment the registry was initialized for (D3).
    pub fn keys_env(env: Env) -> String {
        storage::get_keys_env(&env)
    }

    /// The key messages' EIP-712 domain separator, salted with the environment (D3).
    pub fn domain_separator(env: Env) -> BytesN<32> {
        storage::get_domain(&env)
    }

    pub fn admin(env: Env) -> Address {
        storage::get_admin(&env)
    }

    /// The revoke guards `set_position_guards` installed, empty before any. The deploy CLI reads
    /// this so a redeploy sends `set_position_guards` only when it would change something (#424).
    pub fn position_guards(env: Env) -> Vec<Address> {
        storage::get_guards(&env).unwrap_or_else(|| Vec::new(&env))
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
    fingerprint: &BytesN<32>,
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
            fingerprint: fingerprint.clone(),
        },
    );
    storage::set_entry(env, account, &entry);
    storage::set_used(env, account, commitment);
    storage::set_key_slot(env, account, fingerprint, slot_id);
    Ok(slot_id)
}

/// When the slot stopped being usable: `0` while unbounded, else the recorded expiry (#422 D14/D14b).
fn expired_at(env: &Env, account: &BytesN<32>, slot_id: u32) -> u64 {
    match storage::get_slot(env, account, slot_id) {
        Some(s) if s.valid_until != 0 => match storage::get_expired_at(env, account, slot_id) {
            0 => s.valid_until,
            at => at,
        },
        _ => 0,
    }
}

/// Drops every dead slot the escrows can no longer need: past its expiry + GRACE_PERIOD, or at once
/// when the guards are wired and none reports open positions for the account (#422 D17 — no order's
/// cancel can still ask about its history; D17b — with no guard to ask, never at once). Not in the
/// expiry's own second (D17a): a lock in that second still counts the kill. Order of `live` is not
/// meaningful.
fn prune(env: &Env, account: &BytesN<32>, entry: &mut storage::RegistryEntry) {
    let now = env.ledger().timestamp();
    let wired = storage::get_guards(env).map_or(false, |g| !g.is_empty());
    let free = wired && !has_open_positions(env, account);
    let mut kept = Vec::new(env);
    for slot_id in entry.live.iter() {
        let prunable = match storage::get_slot(env, account, slot_id) {
            Some(_) => {
                let vu = expired_at(env, account, slot_id);
                vu != 0 && (now > vu.saturating_add(GRACE_PERIOD) || (free && now > vu))
            }
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

fn require_no_open_positions(env: &Env, account: &BytesN<32>) -> Result<(), RegistryError> {
    if has_open_positions(env, account) {
        return Err(RegistryError::AccountInFlight);
    }
    Ok(())
}

fn has_open_positions(env: &Env, account: &BytesN<32>) -> bool {
    match storage::get_guards(env) {
        Some(guards) => guards
            .iter()
            .any(|guard| PositionGuardClient::new(env, &guard).has_open_positions(account)),
        None => false,
    }
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

#[cfg(test)]
mod test;
