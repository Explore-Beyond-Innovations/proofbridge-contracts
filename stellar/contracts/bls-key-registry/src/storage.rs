//! Storage helpers for the BLSKeyRegistry contract.

use soroban_sdk::{symbol_short, Address, BytesN, Env, Symbol};

const KEY_INIT: Symbol = symbol_short!("init");
const KEY_ADMIN: Symbol = symbol_short!("admin");
const KEY_CHAIN: Symbol = symbol_short!("chain");
const KEY_GUARD: Symbol = symbol_short!("guard");
/// Pause flag for register/revoke.
const KEY_PAUSED: Symbol = symbol_short!("paused");
/// Pending admin for the two-step handover.
const KEY_PENDADM: Symbol = symbol_short!("pendadm");

/// Prefix for key commitments: (KEY_COMMIT, account) -> keccak256(bls_pub_key)
const KEY_COMMIT: Symbol = symbol_short!("commit");
/// Prefix for per-account nonces: (KEY_NONCE, account) -> u64
const KEY_NONCE: Symbol = symbol_short!("nonce");

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

pub fn set_chain_id(env: &Env, chain_id: u128) {
    env.storage().instance().set(&KEY_CHAIN, &chain_id);
}

pub fn get_chain_id(env: &Env) -> u128 {
    env.storage().instance().get(&KEY_CHAIN).unwrap()
}

pub fn set_guard(env: &Env, guard: &Address) {
    env.storage().instance().set(&KEY_GUARD, guard);
}

pub fn get_guard(env: &Env) -> Option<Address> {
    env.storage().instance().get(&KEY_GUARD)
}

pub fn set_commitment(env: &Env, account: &BytesN<32>, commitment: &BytesN<32>) {
    env.storage()
        .persistent()
        .set(&(KEY_COMMIT, account.clone()), commitment);
}

pub fn get_commitment(env: &Env, account: &BytesN<32>) -> Option<BytesN<32>> {
    env.storage()
        .persistent()
        .get(&(KEY_COMMIT, account.clone()))
}

pub fn remove_commitment(env: &Env, account: &BytesN<32>) {
    env.storage()
        .persistent()
        .remove(&(KEY_COMMIT, account.clone()));
}

/// Nonce starts at 0 for a never-seen account and bumps on every state change.
pub fn get_nonce(env: &Env, account: &BytesN<32>) -> u64 {
    env.storage()
        .persistent()
        .get(&(KEY_NONCE, account.clone()))
        .unwrap_or(0)
}

pub fn set_nonce(env: &Env, account: &BytesN<32>, nonce: u64) {
    env.storage()
        .persistent()
        .set(&(KEY_NONCE, account.clone()), &nonce);
}

pub fn is_paused(env: &Env) -> bool {
    env.storage().instance().get(&KEY_PAUSED).unwrap_or(false)
}

pub fn set_paused(env: &Env, paused: bool) {
    env.storage().instance().set(&KEY_PAUSED, &paused);
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
