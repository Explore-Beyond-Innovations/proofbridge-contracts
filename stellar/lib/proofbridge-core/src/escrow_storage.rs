//! The storage both escrows share.
//!
//! The ad-manager and the order-portal keep the same ledger shape for everything that is not an ad or an order
//! record: the config, the pause flag, the two-step admin, orders, claims, settled flags, route timing, the anchor,
//! nullifiers, in-flight counts and the claimable ledger. This module owns that half once.
//!
//! **Every `symbol_short!` literal here is the one the escrows already wrote**, and every key keeps its tuple arity
//! and element order. A ledger key is the symbol string, not the Rust name, so this move is byte-for-byte
//! layout-preserving: no migration, no orphaned entry. Anything whose *value* type differs between the two escrows
//! (the chain record, ads) stays in the contract crate.

use soroban_sdk::{symbol_short, Address, BytesN, Env, Symbol, Vec};

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

// Persistent
const KEY_ROUTES: Symbol = symbol_short!("routes");
const KEY_ORDERS: Symbol = symbol_short!("orders");
const KEY_NULLIFIERS: Symbol = symbol_short!("nulls");
const KEY_RVERIF: Symbol = symbol_short!("rverif");
/// (KEY_RVCHG, chain_id) -> u64: when the route's verifier last changed (set or repointed).
const KEY_RVCHG: Symbol = symbol_short!("rvchg");
const KEY_WIRED: Symbol = symbol_short!("wired");
const KEY_INFLT: Symbol = symbol_short!("inflt");
const KEY_CLAIM: Symbol = symbol_short!("claim");
/// `(timing, chain_id, version) -> RouteTiming`; versions are never edited in place.
const KEY_TIMING: Symbol = symbol_short!("timing");
/// `(timingv, chain_id) -> u32`: the route's current timing version (0 = unset).
const KEY_TIMINGV: Symbol = symbol_short!("timingv");
const KEY_CLAIMS: Symbol = symbol_short!("claims");
const KEY_SETTLED: Symbol = symbol_short!("settled");
/// C-11: the dispute module an order was filed with: `(dspord, order_hash) -> Address`.
const KEY_DSPORD: Symbol = symbol_short!("dspord");

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
    // Not fund-bearing, but settlement-bearing: a route that ages out makes every order on that
    // pair unsettleable until someone restores it. Routes are set once and then only read.
    extend_persistent(env, &key);
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
            locked_at: 0,
            registry_epoch: 0,
            timing_version: 0,
            anchor_delay: 0,
            pinned_slot: 0,
            repinned: false,
            lp_fee_bps: 0,
            protocol_fee_bps: 0,
        })
}

pub fn get_order_status(env: &Env, order_hash: &BytesN<32>) -> Status {
    get_order(env, order_hash).status
}

/// `None → Open`, stamping the route-timing version every window reads and, on the ad chain, the
/// key-registry epoch (#465) and the anchor-delay snapshot (the order portal passes 0 for both).
pub fn open_order(
    env: &Env,
    order_hash: &BytesN<32>,
    timing_version: u32,
    registry_epoch: u32,
    anchor_delay: u32,
    pinned_slot: u32,
    fee_bps: (u32, u32),
) {
    set_order(
        env,
        order_hash,
        &OrderRecord {
            status: Status::Open,
            locked_at: env.ledger().timestamp(),
            registry_epoch,
            timing_version,
            anchor_delay,
            pinned_slot,
            repinned: false,
            lp_fee_bps: fee_bps.0,
            protocol_fee_bps: fee_bps.1,
        },
    );
}

/// Flip the status, keeping the rest of the record; every flip re-extends the record (2.3h's TTL
/// runbook lists this write).
pub fn set_order_status(env: &Env, order_hash: &BytesN<32>, status: Status) {
    let mut rec = get_order(env, order_hash);
    rec.status = status;
    set_order(env, order_hash, &rec);
}

/// Move an open order's co-signing pin (the ad-manager's `repin_order`, plan 12 D12) and stamp the
/// order re-pinned: the denial rule counts a re-pin for the rest of the order's life.
pub fn set_pinned_slot(env: &Env, order_hash: &BytesN<32>, slot: u32) {
    let mut rec = get_order(env, order_hash);
    rec.pinned_slot = slot;
    rec.repinned = true;
    set_order(env, order_hash, &rec);
}

fn set_order(env: &Env, order_hash: &BytesN<32>, rec: &OrderRecord) {
    let key = (KEY_ORDERS, order_hash.clone());
    env.storage().persistent().set(&key, rec);
    extend_persistent(env, &key);
}

// ── termination (2.3e) ───────────────────────────────────────────────────

pub fn get_timing_version(env: &Env, chain_id: u128) -> u32 {
    env.storage()
        .persistent()
        .get(&(KEY_TIMINGV, chain_id))
        .unwrap_or(0)
}

pub fn get_route_timing_at(env: &Env, chain_id: u128, version: u32) -> Option<RouteTiming> {
    env.storage()
        .persistent()
        .get(&(KEY_TIMING, chain_id, version))
}

/// Write `timing` as the route's next version and return it; earlier versions stay readable.
pub fn push_route_timing(env: &Env, chain_id: u128, timing: &RouteTiming) -> u32 {
    let version = get_timing_version(env, chain_id) + 1;
    let key = (KEY_TIMING, chain_id, version);
    env.storage().persistent().set(&key, timing);
    extend_persistent(env, &key);
    let vkey = (KEY_TIMINGV, chain_id);
    env.storage().persistent().set(&vkey, &version);
    extend_persistent(env, &vkey);
    version
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

/// The module this order's dispute was filed with; `None` if it never was (C-11).
pub fn get_order_dispute_manager(env: &Env, order_hash: &BytesN<32>) -> Option<Address> {
    env.storage()
        .persistent()
        .get(&(KEY_DSPORD, order_hash.clone()))
}

/// Snapshotted at filing so a later module swap only affects new filings (D5).
pub fn set_order_dispute_manager(env: &Env, order_hash: &BytesN<32>, manager: &Address) {
    let key = (KEY_DSPORD, order_hash.clone());
    env.storage().persistent().set(&key, manager);
    extend_persistent(env, &key);
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

/// The replay guard. Extended for the opposite reason to a credit: an archived nullifier reads as
/// absent, which reads as *unused*, so an aged-out entry does not park money — it reopens a spent
/// proof.
pub fn set_nullifier_used(env: &Env, nullifier_hash: &BytesN<32>) {
    let key = (KEY_NULLIFIERS, nullifier_hash.clone());
    env.storage().persistent().set(&key, &true);
    extend_persistent(env, &key);
}

// ── root verifiers ───────────────────────────────────────────────────────

/// Set once per peer chain and then only read, so nothing else would ever bump it — and an unlock
/// cannot be root-verified without it. Every set stamps the change: the ad-manager's denial rule
/// counts a verifier changed after an order's lock as a gap in the co-signed path.
pub fn set_root_verifier(env: &Env, chain_id: u128, module: &Address) {
    let key = (KEY_RVERIF, chain_id);
    env.storage().persistent().set(&key, module);
    extend_persistent(env, &key);
    let stamp = (KEY_RVCHG, chain_id);
    env.storage()
        .persistent()
        .set(&stamp, &env.ledger().timestamp());
    extend_persistent(env, &stamp);
}

/// When the route's verifier last changed; 0 while never set.
pub fn get_root_verifier_changed_at(env: &Env, chain_id: u128) -> u64 {
    env.storage()
        .persistent()
        .get(&(KEY_RVCHG, chain_id))
        .unwrap_or(0)
}

pub fn get_root_verifier(env: &Env, chain_id: u128) -> Option<Address> {
    env.storage().persistent().get(&(KEY_RVERIF, chain_id))
}

/// #466: every chain a root verifier was ever set for, once each, in first-wired order.
pub fn add_wired_chain(env: &Env, chain_id: u128) {
    let mut chains = get_wired_chains(env);
    if !chains.contains(chain_id) {
        chains.push_back(chain_id);
        env.storage().persistent().set(&KEY_WIRED, &chains);
    }
    if env.storage().persistent().has(&KEY_WIRED) {
        extend_persistent(env, &KEY_WIRED);
    }
}

pub fn get_wired_chains(env: &Env) -> Vec<u128> {
    env.storage()
        .persistent()
        .get(&KEY_WIRED)
        .unwrap_or_else(|| Vec::new(env))
}

// ── in-flight positions ──────────────────────────────────────────────────

pub fn get_in_flight(env: &Env, account: &BytesN<32>) -> u64 {
    env.storage()
        .persistent()
        .get(&(KEY_INFLT, account.clone()))
        .unwrap_or(0)
}

/// An account's open-position count. Extended for the fail-open reason again: `get_in_flight` reads
/// a missing key as 0, so an archived row does not park anything — it silently clears the account's
/// position cap. A zero count is written as a removal instead, since a zero row owes nothing and
/// reads identically.
pub fn set_in_flight(env: &Env, account: &BytesN<32>, count: u64) {
    let key = (KEY_INFLT, account.clone());
    if count == 0 {
        env.storage().persistent().remove(&key);
        return;
    }
    env.storage().persistent().set(&key, &count);
    extend_persistent(env, &key);
}

// ── pause flag and two-step admin ───────────────────────────────────────

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
    if amount == 0 {
        // A drained credit owes nothing. Removing it refunds the rent and keeps the ledger from
        // accumulating zero rows that would each be paid to keep alive; `get_claimable` reads a
        // missing key as 0, so the two are the same value.
        env.storage().persistent().remove(&key);
        return;
    }
    env.storage().persistent().set(&key, &amount);
    extend_persistent(env, &key);
}
