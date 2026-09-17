//! Storage for the DisputeManager.
//!
//! Its own keys: this contract is not an escrow, so it shares nothing with `escrow_storage`. TTL is
//! extended on every fund-bearing write, because a bond whose entry archives is a bond nobody can
//! route.

use proofbridge_core::ttl;
use proofbridge_core::types::{DisputeParams, DisputeRecord};
use soroban_sdk::{symbol_short, Address, BytesN, Env, Symbol};

const KEY_CONFIG: Symbol = symbol_short!("config");
const KEY_PENDADM: Symbol = symbol_short!("pendadm");
const KEY_ARBITER: Symbol = symbol_short!("arbiter");
const KEY_FEEPOOL: Symbol = symbol_short!("feepool");
const KEY_PAUSSEC: Symbol = symbol_short!("pausesec");
const KEY_WNATIVE: Symbol = symbol_short!("wnative");
/// Escrows this module serves: `(escrows, address) -> bool`.
const KEY_ESCROWS: Symbol = symbol_short!("escrows");
/// Per-route parameters: `(dparams, chain_id) -> DisputeParams`.
const KEY_DPARAMS: Symbol = symbol_short!("dparams");
/// Disputes: `(disputes, order_hash) -> DisputeRecord`.
const KEY_DISPUTE: Symbol = symbol_short!("disputes");
/// Credited payouts: `(claims, recipient) -> u128`.
const KEY_CLAIMS: Symbol = symbol_short!("claims");

// ── admin ────────────────────────────────────────────────────────────────

pub fn get_admin(env: &Env) -> Option<Address> {
    env.storage().instance().get(&KEY_CONFIG)
}

pub fn set_admin(env: &Env, admin: &Address) {
    env.storage().instance().set(&KEY_CONFIG, admin);
}

pub fn get_pending_admin(env: &Env) -> Option<Address> {
    env.storage().instance().get(&KEY_PENDADM)
}

pub fn set_pending_admin(env: &Env, to: &Address) {
    env.storage().instance().set(&KEY_PENDADM, to);
}

pub fn clear_pending_admin(env: &Env) {
    env.storage().instance().remove(&KEY_PENDADM);
}

pub fn get_arbiter(env: &Env) -> Option<Address> {
    env.storage().instance().get(&KEY_ARBITER)
}

pub fn set_arbiter(env: &Env, a: &Address) {
    env.storage().instance().set(&KEY_ARBITER, a);
}

pub fn get_fee_pool(env: &Env) -> Option<Address> {
    env.storage().instance().get(&KEY_FEEPOOL)
}

pub fn set_fee_pool(env: &Env, a: &Address) {
    env.storage().instance().set(&KEY_FEEPOOL, a);
}

pub fn get_w_native(env: &Env) -> Option<Address> {
    env.storage().instance().get(&KEY_WNATIVE)
}

pub fn set_w_native(env: &Env, a: &Address) {
    env.storage().instance().set(&KEY_WNATIVE, a);
}

pub fn get_paused_seconds(env: &Env) -> u64 {
    env.storage().instance().get(&KEY_PAUSSEC).unwrap_or(0)
}

// ── escrows ──────────────────────────────────────────────────────────────

pub fn is_escrow(env: &Env, who: &Address) -> bool {
    let key = (KEY_ESCROWS, who.clone());
    env.storage().persistent().get(&key).unwrap_or(false)
}

pub fn set_escrow(env: &Env, who: &Address, allowed: bool) {
    let key = (KEY_ESCROWS, who.clone());
    env.storage().persistent().set(&key, &allowed);
    ttl::extend_persistent(env, &key);
}

// ── parameters ───────────────────────────────────────────────────────────

pub fn get_params(env: &Env, chain_id: u128) -> Option<DisputeParams> {
    let key = (KEY_DPARAMS, chain_id);
    env.storage().persistent().get(&key)
}

pub fn set_params(env: &Env, chain_id: u128, p: &DisputeParams) {
    let key = (KEY_DPARAMS, chain_id);
    env.storage().persistent().set(&key, p);
    ttl::extend_persistent(env, &key);
}

// ── disputes ─────────────────────────────────────────────────────────────

pub fn get_dispute(env: &Env, order_hash: &BytesN<32>) -> Option<DisputeRecord> {
    let key = (KEY_DISPUTE, order_hash.clone());
    env.storage().persistent().get(&key)
}

pub fn set_dispute(env: &Env, order_hash: &BytesN<32>, d: &DisputeRecord) {
    let key = (KEY_DISPUTE, order_hash.clone());
    env.storage().persistent().set(&key, d);
    ttl::extend_persistent(env, &key);
}

pub fn remove_dispute(env: &Env, order_hash: &BytesN<32>) {
    let key = (KEY_DISPUTE, order_hash.clone());
    env.storage().persistent().remove(&key);
}

// ── credited payouts ─────────────────────────────────────────────────────

pub fn get_claimable(env: &Env, who: &Address) -> u128 {
    let key = (KEY_CLAIMS, who.clone());
    env.storage().persistent().get(&key).unwrap_or(0)
}

pub fn set_claimable(env: &Env, who: &Address, amount: u128) {
    let key = (KEY_CLAIMS, who.clone());
    env.storage().persistent().set(&key, &amount);
    ttl::extend_persistent(env, &key);
}

pub fn extend_instance_ttl(env: &Env) {
    ttl::extend_instance(env);
}
