//! The storage both escrows share.
//!
//! The ad-manager and the order-portal keep the same ledger shape for everything that is not an ad or an order
//! record: the config, the pause clock, the two-step admin, orders, claims, settled flags, route timing, the anchor,
//! nullifiers, in-flight counts and the claimable ledger. This module owns that half once.
//!
//! **Every `symbol_short!` literal here is the one the escrows already wrote**, and every key keeps its tuple arity
//! and element order. A ledger key is the symbol string, not the Rust name, so this move is byte-for-byte
//! layout-preserving: no migration, no orphaned entry. Anything whose *value* type differs between the two escrows
//! (the chain record, ads) stays in the contract crate.

use soroban_sdk::{symbol_short, Address, BytesN, Env, Symbol};

use crate::ttl::extend_persistent;
use crate::types::{ClaimRecord, ContractConfig, OrderRecord, RouteTiming, Status};

// Instance
const KEY_CONFIG: Symbol = symbol_short!("config");
const KEY_PAUSED: Symbol = symbol_short!("paused");
const KEY_PENDADM: Symbol = symbol_short!("pendadm");
const KEY_INITIALIZED: Symbol = symbol_short!("init");
const KEY_ANCHOR: Symbol = symbol_short!("anchor");
/// The dispute module the escrow reads (2.3g). Unset means disputes are unavailable here, which
/// is a safe default rather than a broken one.
const KEY_DSPMGR: Symbol = symbol_short!("dspmgr");
const KEY_PAUSED_AT: Symbol = symbol_short!("pausedat");
const KEY_PAUSEDSEC: Symbol = symbol_short!("pausedsec");

// Persistent
const KEY_ROUTES: Symbol = symbol_short!("routes");
const KEY_ORDERS: Symbol = symbol_short!("orders");
const KEY_NULLIFIERS: Symbol = symbol_short!("nulls");
const KEY_RVERIF: Symbol = symbol_short!("rverif");
const KEY_INFLT: Symbol = symbol_short!("inflt");
const KEY_CLAIM: Symbol = symbol_short!("claim");
const KEY_TIMING: Symbol = symbol_short!("timing");
const KEY_CLAIMS: Symbol = symbol_short!("claims");
const KEY_SETTLED: Symbol = symbol_short!("settled");

// ── initialization and config ────────────────────────────────────────────

pub fn is_initialized(env: &Env) -> bool {
    env.storage().instance().has(&KEY_INITIALIZED)
}

pub fn set_initialized(env: &Env) {
    env.storage().instance().set(&KEY_INITIALIZED, &true);
}

/// The config, or `None` before `initialize`. Each escrow maps the `None` to its own error.
pub fn get_config(env: &Env) -> Option<ContractConfig> {
    env.storage().instance().get(&KEY_CONFIG)
}

pub fn set_config(env: &Env, config: &ContractConfig) {
    env.storage().instance().set(&KEY_CONFIG, config);
}

// ── token routes: (token, peer_chain_id) -> peer token ───────────────────

pub fn get_token_route(env: &Env, token: &BytesN<32>, peer_chain_id: u128) -> Option<BytesN<32>> {
    let key = (KEY_ROUTES, token.clone(), peer_chain_id);
    env.storage().persistent().get(&key)
}

pub fn set_token_route(
    env: &Env,
    token: &BytesN<32>,
    peer_chain_id: u128,
    peer_token: &BytesN<32>,
) {
    let key = (KEY_ROUTES, token.clone(), peer_chain_id);
    env.storage().persistent().set(&key, peer_token);
}

pub fn remove_token_route(env: &Env, token: &BytesN<32>, peer_chain_id: u128) {
    let key = (KEY_ROUTES, token.clone(), peer_chain_id);
    env.storage().persistent().remove(&key);
}

// ── orders ───────────────────────────────────────────────────────────────

pub fn get_order(env: &Env, order_hash: &BytesN<32>) -> OrderRecord {
    env.storage()
        .persistent()
        .get(&(KEY_ORDERS, order_hash.clone()))
        .unwrap_or(OrderRecord {
            status: Status::None,
            paused_at_open: 0,
        })
}

pub fn get_order_status(env: &Env, order_hash: &BytesN<32>) -> Status {
    get_order(env, order_hash).status
}

/// `None → Open`, stamping the pause counter the leg's window is measured from.
pub fn open_order(env: &Env, order_hash: &BytesN<32>) {
    set_order(
        env,
        order_hash,
        &OrderRecord {
            status: Status::Open,
            paused_at_open: get_paused_seconds(env),
        },
    );
}

/// Flip the status, keeping the leg's pause snapshot; every flip re-extends the record (2.3h's TTL
/// runbook lists this write).
pub fn set_order_status(env: &Env, order_hash: &BytesN<32>, status: Status) {
    let mut rec = get_order(env, order_hash);
    rec.status = status;
    set_order(env, order_hash, &rec);
}

fn set_order(env: &Env, order_hash: &BytesN<32>, rec: &OrderRecord) {
    let key = (KEY_ORDERS, order_hash.clone());
    env.storage().persistent().set(&key, rec);
    extend_persistent(env, &key);
}

// ── termination (2.3e) ───────────────────────────────────────────────────

pub fn get_route_timing(env: &Env, chain_id: u128) -> Option<RouteTiming> {
    env.storage().persistent().get(&(KEY_TIMING, chain_id))
}

pub fn set_route_timing(env: &Env, chain_id: u128, timing: &RouteTiming) {
    let key = (KEY_TIMING, chain_id);
    env.storage().persistent().set(&key, timing);
    extend_persistent(env, &key);
}

pub fn get_root_anchor(env: &Env) -> Option<Address> {
    env.storage().instance().get(&KEY_ANCHOR)
}

pub fn set_root_anchor(env: &Env, anchor: &Address) {
    env.storage().instance().set(&KEY_ANCHOR, anchor);
}

pub fn get_dispute_manager(env: &Env) -> Option<Address> {
    env.storage().instance().get(&KEY_DSPMGR)
}

pub fn set_dispute_manager(env: &Env, manager: &Address) {
    env.storage().instance().set(&KEY_DSPMGR, manager);
}

pub fn get_claim(env: &Env, order_hash: &BytesN<32>) -> Option<ClaimRecord> {
    env.storage()
        .persistent()
        .get(&(KEY_CLAIMS, order_hash.clone()))
}

pub fn set_claim(env: &Env, order_hash: &BytesN<32>, claim: &ClaimRecord) {
    let key = (KEY_CLAIMS, order_hash.clone());
    env.storage().persistent().set(&key, claim);
    extend_persistent(env, &key);
}

pub fn remove_claim(env: &Env, order_hash: &BytesN<32>) {
    env.storage()
        .persistent()
        .remove(&(KEY_CLAIMS, order_hash.clone()));
}

pub fn is_settled_recorded(env: &Env, order_hash: &BytesN<32>) -> bool {
    env.storage()
        .persistent()
        .get(&(KEY_SETTLED, order_hash.clone()))
        .unwrap_or(false)
}

pub fn set_settled_recorded(env: &Env, order_hash: &BytesN<32>) {
    let key = (KEY_SETTLED, order_hash.clone());
    env.storage().persistent().set(&key, &true);
    extend_persistent(env, &key);
}

// ── nullifiers ───────────────────────────────────────────────────────────

pub fn is_nullifier_used(env: &Env, nullifier_hash: &BytesN<32>) -> bool {
    let key = (KEY_NULLIFIERS, nullifier_hash.clone());
    env.storage().persistent().get(&key).unwrap_or(false)
}

pub fn set_nullifier_used(env: &Env, nullifier_hash: &BytesN<32>) {
    let key = (KEY_NULLIFIERS, nullifier_hash.clone());
    env.storage().persistent().set(&key, &true);
}

// ── root verifiers ───────────────────────────────────────────────────────

pub fn set_root_verifier(env: &Env, chain_id: u128, module: &Address) {
    env.storage()
        .persistent()
        .set(&(KEY_RVERIF, chain_id), module);
}

pub fn get_root_verifier(env: &Env, chain_id: u128) -> Option<Address> {
    env.storage().persistent().get(&(KEY_RVERIF, chain_id))
}

// ── in-flight positions ──────────────────────────────────────────────────

pub fn get_in_flight(env: &Env, account: &BytesN<32>) -> u64 {
    env.storage()
        .persistent()
        .get(&(KEY_INFLT, account.clone()))
        .unwrap_or(0)
}

pub fn set_in_flight(env: &Env, account: &BytesN<32>, count: u64) {
    env.storage()
        .persistent()
        .set(&(KEY_INFLT, account.clone()), &count);
}

// ── pause clock and two-step admin ───────────────────────────────────────

pub fn is_paused(env: &Env) -> bool {
    env.storage().instance().get(&KEY_PAUSED).unwrap_or(false)
}

pub fn set_paused(env: &Env, paused: bool) {
    env.storage().instance().set(&KEY_PAUSED, &paused);
}

pub fn get_last_paused_at(env: &Env) -> u64 {
    env.storage().instance().get(&KEY_PAUSED_AT).unwrap_or(0)
}

pub fn set_last_paused_at(env: &Env, at: u64) {
    env.storage().instance().set(&KEY_PAUSED_AT, &at);
}

pub fn get_paused_seconds(env: &Env) -> u64 {
    env.storage().instance().get(&KEY_PAUSEDSEC).unwrap_or(0)
}

pub fn set_paused_seconds(env: &Env, secs: u64) {
    env.storage().instance().set(&KEY_PAUSEDSEC, &secs);
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

// ── the claimable ledger ─────────────────────────────────────────────────

pub fn get_claimable(env: &Env, recipient: &BytesN<32>, token: &BytesN<32>) -> u128 {
    env.storage()
        .persistent()
        .get(&(KEY_CLAIM, recipient.clone(), token.clone()))
        .unwrap_or(0)
}

/// A credited balance owed to `recipient`. Fund-bearing, so its TTL is extended on every write
/// (2.3h D2): an archived credit is money the owner cannot reach until somebody pays to restore the
/// entry. The dispute module has done this since it was written; these older escrow writes did not.
pub fn set_claimable(env: &Env, recipient: &BytesN<32>, token: &BytesN<32>, amount: u128) {
    let key = (KEY_CLAIM, recipient.clone(), token.clone());
    env.storage().persistent().set(&key, &amount);
    crate::ttl::extend_persistent(env, &key);
}
