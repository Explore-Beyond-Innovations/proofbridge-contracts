//! Storage keys and helpers for the RootAnchor contract.
//!
//! Per-chain configuration (delay, latest sequence) and the signer set live in **instance** storage,
//! bumped on every entry point including the consumer read, so a quiet route never archives the
//! values a refund needs. Per-root records and approvals are persistent, bumped on write and on read.

use soroban_sdk::{contracttype, symbol_short, Address, BytesN, Env, Symbol, Vec};

use proofbridge_core::ttl;

// Instance storage (contract-level).
const KEY_INIT: Symbol = symbol_short!("init");
const KEY_ADMIN: Symbol = symbol_short!("admin");
/// Pending admin for the two-step handover.
const KEY_PENDADM: Symbol = symbol_short!("pendadm");
/// Pause flag; gates `anchor` only, never `is_anchored`.
const KEY_PAUSED: Symbol = symbol_short!("paused");
/// The notary set — every ladder rung is a `set_signers`.
const KEY_SIGNERS: Symbol = symbol_short!("signers");
const KEY_THRESH: Symbol = symbol_short!("thresh");
/// Bumped on every `set_signers`; approvals from an earlier epoch do not count.
const KEY_SETEPOCH: Symbol = symbol_short!("setepoch");
/// When true, a new root's ledger sequence must exceed the chain's latest.
const KEY_MONO: Symbol = symbol_short!("mono");
/// (KEY_DELAY, chain_id) -> u64 seconds an anchor must age before it is usable
const KEY_DELAY: Symbol = symbol_short!("delay");
/// (KEY_LATEST, chain_id) -> u64 highest ledger sequence anchored
const KEY_LATEST: Symbol = symbol_short!("latest");

// Persistent storage.
/// (KEY_ANCHOR, chain_id, root) -> AnchorRec
const KEY_ANCHOR: Symbol = symbol_short!("anchor");
/// (KEY_APPRV, chain_id, root, signer) -> u64 stamp `(set_epoch << 32) | gen` at approval time
const KEY_APPRV: Symbol = symbol_short!("apprv");

/// One notarized root of one source chain.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorRec {
    /// The highest source-chain ledger any approval named; the monotonic check runs against it
    pub ledger_seq: u64,
    /// Whether the threshold has been reached. An explicit flag rather than `anchored_at != 0`:
    /// a test ledger starts at timestamp 0, and a real one may not be assumed non-zero either.
    pub anchored: bool,
    /// The ledger timestamp when the threshold was reached; the delay counts from here
    pub anchored_at: u64,
    /// Distinct signers who approved under (`set_epoch`, `gen`)
    pub approvals: u32,
    /// The signer-set epoch the approvals belong to; a rotation resets the count
    pub set_epoch: u32,
    /// Bumped by `revoke_anchor`, so every earlier approval stamp stops matching
    pub gen: u32,
}

pub fn is_initialized(env: &Env) -> bool {
    env.storage().instance().has(&KEY_INIT)
}

pub fn set_initialized(env: &Env) {
    env.storage().instance().set(&KEY_INIT, &true);
}

pub fn set_admin(env: &Env, admin: &Address) {
    env.storage().instance().set(&KEY_ADMIN, admin);
}

pub fn get_admin(env: &Env) -> Address {
    env.storage().instance().get(&KEY_ADMIN).unwrap()
}

pub fn get_pending_admin(env: &Env) -> Option<Address> {
    env.storage().instance().get(&KEY_PENDADM)
}

pub fn set_pending_admin(env: &Env, admin: &Address) {
    env.storage().instance().set(&KEY_PENDADM, admin);
}

pub fn clear_pending_admin(env: &Env) {
    env.storage().instance().remove(&KEY_PENDADM);
}

pub fn is_paused(env: &Env) -> bool {
    env.storage().instance().get(&KEY_PAUSED).unwrap_or(false)
}

pub fn set_paused(env: &Env, paused: bool) {
    env.storage().instance().set(&KEY_PAUSED, &paused);
}

pub fn get_signers(env: &Env) -> Vec<Address> {
    env.storage()
        .instance()
        .get(&KEY_SIGNERS)
        .unwrap_or_else(|| Vec::new(env))
}

pub fn set_signers(env: &Env, signers: &Vec<Address>) {
    env.storage().instance().set(&KEY_SIGNERS, signers);
}

pub fn get_threshold(env: &Env) -> u32 {
    env.storage().instance().get(&KEY_THRESH).unwrap_or(0)
}

pub fn set_threshold(env: &Env, threshold: u32) {
    env.storage().instance().set(&KEY_THRESH, &threshold);
}

pub fn get_set_epoch(env: &Env) -> u32 {
    env.storage().instance().get(&KEY_SETEPOCH).unwrap_or(0)
}

pub fn bump_set_epoch(env: &Env) -> u32 {
    let next = get_set_epoch(env) + 1;
    env.storage().instance().set(&KEY_SETEPOCH, &next);
    next
}

pub fn get_monotonic(env: &Env) -> bool {
    env.storage().instance().get(&KEY_MONO).unwrap_or(true)
}

pub fn set_monotonic(env: &Env, monotonic: bool) {
    env.storage().instance().set(&KEY_MONO, &monotonic);
}

pub fn get_delay(env: &Env, chain_id: u128) -> u64 {
    env.storage()
        .instance()
        .get(&(KEY_DELAY, chain_id))
        .unwrap_or(0)
}

pub fn set_delay(env: &Env, chain_id: u128, delay: u64) {
    env.storage().instance().set(&(KEY_DELAY, chain_id), &delay);
}

pub fn get_latest_seq(env: &Env, chain_id: u128) -> u64 {
    env.storage()
        .instance()
        .get(&(KEY_LATEST, chain_id))
        .unwrap_or(0)
}

pub fn set_latest_seq(env: &Env, chain_id: u128, seq: u64) {
    env.storage().instance().set(&(KEY_LATEST, chain_id), &seq);
}

pub fn get_anchor(env: &Env, chain_id: u128, root: &BytesN<32>) -> Option<AnchorRec> {
    let key = (KEY_ANCHOR, chain_id, root.clone());
    let rec: Option<AnchorRec> = env.storage().persistent().get(&key);
    if rec.is_some() {
        ttl::extend_persistent(env, &key);
    }
    rec
}

pub fn set_anchor(env: &Env, chain_id: u128, root: &BytesN<32>, rec: &AnchorRec) {
    let key = (KEY_ANCHOR, chain_id, root.clone());
    env.storage().persistent().set(&key, rec);
    ttl::extend_persistent(env, &key);
}

pub fn get_approval_stamp(
    env: &Env,
    chain_id: u128,
    root: &BytesN<32>,
    signer: &Address,
) -> Option<u64> {
    env.storage()
        .persistent()
        .get(&(KEY_APPRV, chain_id, root.clone(), signer.clone()))
}

pub fn set_approval_stamp(
    env: &Env,
    chain_id: u128,
    root: &BytesN<32>,
    signer: &Address,
    stamp: u64,
) {
    let key = (KEY_APPRV, chain_id, root.clone(), signer.clone());
    env.storage().persistent().set(&key, &stamp);
    ttl::extend_persistent(env, &key);
}
