//! Storage helpers for the OrderPortal contract

use soroban_sdk::{symbol_short, Address, BytesN, Env, Symbol};

use crate::types::{ChainInfo, ClaimRecord, ContractConfig, RouteTiming, Status};

// =============================================================================
// Storage Keys
// =============================================================================

/// Key for contract configuration
const KEY_CONFIG: Symbol = symbol_short!("config");
/// Pause flag for every state-changing entry point.
const KEY_PAUSED: Symbol = symbol_short!("paused");
/// Pending admin for the two-step handover.
const KEY_PENDADM: Symbol = symbol_short!("pendadm");
/// Key for initialization flag
const KEY_INIT: Symbol = symbol_short!("init");

/// Prefix for chain configurations
const KEY_CHAINS: Symbol = symbol_short!("chains");
/// Prefix for token routes
const KEY_ROUTES: Symbol = symbol_short!("routes");
/// Prefix for order statuses
const KEY_ORDERS: Symbol = symbol_short!("orders");
/// Prefix for nullifier tracking
const KEY_NULLS: Symbol = symbol_short!("nulls");
/// Prefix for root-verifier modules: (KEY_RVERIF, chain_id) -> Address
const KEY_RVERIF: Symbol = symbol_short!("rverif");
/// Prefix for in-flight order counts: (KEY_INFLT, account) -> u64
const KEY_INFLT: Symbol = symbol_short!("inflt");
/// Prefix for unclaimed payouts: (KEY_CLAIM, recipient, token) -> u128
const KEY_CLAIM: Symbol = symbol_short!("claim");
/// Prefix for route timing (2.3e D6): (KEY_TIMING, chain_id) -> RouteTiming
const KEY_TIMING: Symbol = symbol_short!("timing");
/// The notary the evidence paths read (2.3e D7), instance storage.
const KEY_ANCHOR: Symbol = symbol_short!("anchor");
/// Prefix for open presentation windows: (KEY_CLAIMS, order_hash) -> ClaimRecord
const KEY_CLAIMS: Symbol = symbol_short!("claims");
/// Prefix for recorded settled leaves: (KEY_SETTLED, order_hash) -> bool
const KEY_SETTLED: Symbol = symbol_short!("settled");
/// The pause clock (instance): when the escrow was last paused / unpaused, and the seconds it has
/// spent paused in total. A window's real end moves by the pause time that fell inside it.
const KEY_PAUSED_AT: Symbol = symbol_short!("pausedat");
const KEY_UNPAUSED: Symbol = symbol_short!("unpaused");
const KEY_PAUSEDSEC: Symbol = symbol_short!("pausedsec");

// =============================================================================
// Instance Storage (Contract-level state)
// =============================================================================

/// Check if the contract is initialized
pub fn is_initialized(env: &Env) -> bool {
    env.storage().instance().has(&KEY_INIT)
}

/// Mark the contract as initialized
pub fn set_initialized(env: &Env) {
    env.storage().instance().set(&KEY_INIT, &true);
}

/// Get the contract configuration
pub fn get_config(env: &Env) -> Result<ContractConfig, crate::errors::OrderPortalError> {
    env.storage()
        .instance()
        .get(&KEY_CONFIG)
        .ok_or(crate::errors::OrderPortalError::NotInitialized)
}

/// Set the contract configuration
pub fn set_config(env: &Env, config: &ContractConfig) {
    env.storage().instance().set(&KEY_CONFIG, config);
}

// =============================================================================
// Persistent Storage - Chains
// =============================================================================

/// Get chain configuration
pub fn get_chain(env: &Env, chain_id: u128) -> Option<ChainInfo> {
    env.storage().persistent().get(&(KEY_CHAINS, chain_id))
}

/// Set chain configuration
pub fn set_chain(env: &Env, chain_id: u128, info: &ChainInfo) {
    env.storage()
        .persistent()
        .set(&(KEY_CHAINS, chain_id), info);
}

/// Remove chain configuration
pub fn remove_chain(env: &Env, chain_id: u128) {
    env.storage().persistent().remove(&(KEY_CHAINS, chain_id));
}

// =============================================================================
// Persistent Storage - Token Routes
// =============================================================================

/// Get token route: order_token -> (ad_chain_id) -> ad_token
pub fn get_token_route(
    env: &Env,
    order_token: &BytesN<32>,
    ad_chain_id: u128,
) -> Option<BytesN<32>> {
    env.storage()
        .persistent()
        .get(&(KEY_ROUTES, order_token.clone(), ad_chain_id))
}

/// Set token route
pub fn set_token_route(
    env: &Env,
    order_token: &BytesN<32>,
    ad_chain_id: u128,
    ad_token: &BytesN<32>,
) {
    env.storage()
        .persistent()
        .set(&(KEY_ROUTES, order_token.clone(), ad_chain_id), ad_token);
}

/// Remove token route
pub fn remove_token_route(env: &Env, order_token: &BytesN<32>, ad_chain_id: u128) {
    env.storage()
        .persistent()
        .remove(&(KEY_ROUTES, order_token.clone(), ad_chain_id));
}

// =============================================================================
// Persistent Storage - Orders
// =============================================================================

/// Get order status
pub fn get_order_status(env: &Env, order_hash: &BytesN<32>) -> Status {
    env.storage()
        .persistent()
        .get(&(KEY_ORDERS, order_hash.clone()))
        .unwrap_or(Status::None)
}

/// Set order status; every flip re-extends the record (2.3h's TTL runbook lists this write).
pub fn set_order_status(env: &Env, order_hash: &BytesN<32>, status: Status) {
    let key = (KEY_ORDERS, order_hash.clone());
    env.storage().persistent().set(&key, &status);
    proofbridge_core::ttl::extend_persistent(env, &key);
}

// =============================================================================
// Termination (2.3e)
// =============================================================================

pub fn get_route_timing(env: &Env, chain_id: u128) -> Option<RouteTiming> {
    env.storage().persistent().get(&(KEY_TIMING, chain_id))
}

pub fn set_route_timing(env: &Env, chain_id: u128, timing: &RouteTiming) {
    let key = (KEY_TIMING, chain_id);
    env.storage().persistent().set(&key, timing);
    proofbridge_core::ttl::extend_persistent(env, &key);
}

pub fn get_root_anchor(env: &Env) -> Option<Address> {
    env.storage().instance().get(&KEY_ANCHOR)
}

pub fn set_root_anchor(env: &Env, anchor: &Address) {
    env.storage().instance().set(&KEY_ANCHOR, anchor);
}

pub fn get_claim(env: &Env, order_hash: &BytesN<32>) -> Option<ClaimRecord> {
    env.storage()
        .persistent()
        .get(&(KEY_CLAIMS, order_hash.clone()))
}

pub fn set_claim(env: &Env, order_hash: &BytesN<32>, claim: &ClaimRecord) {
    let key = (KEY_CLAIMS, order_hash.clone());
    env.storage().persistent().set(&key, claim);
    proofbridge_core::ttl::extend_persistent(env, &key);
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
    proofbridge_core::ttl::extend_persistent(env, &key);
}

pub fn remove_claim(env: &Env, order_hash: &BytesN<32>) {
    env.storage()
        .persistent()
        .remove(&(KEY_CLAIMS, order_hash.clone()));
}

// =============================================================================
// Persistent Storage - Nullifiers
// =============================================================================

/// Check if nullifier is used
pub fn is_nullifier_used(env: &Env, nullifier_hash: &BytesN<32>) -> bool {
    env.storage()
        .persistent()
        .get(&(KEY_NULLS, nullifier_hash.clone()))
        .unwrap_or(false)
}

/// Mark nullifier as used
pub fn set_nullifier_used(env: &Env, nullifier_hash: &BytesN<32>) {
    env.storage()
        .persistent()
        .set(&(KEY_NULLS, nullifier_hash.clone()), &true);
}

// =============================================================================
// TTL Extension
// =============================================================================

/// Extend instance storage TTL
pub fn extend_instance_ttl(env: &Env) {
    const INSTANCE_LIFETIME_THRESHOLD: u32 = 17280; // ~1 day
    const INSTANCE_BUMP_AMOUNT: u32 = 518400; // ~30 days

    env.storage()
        .instance()
        .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
}

pub fn set_root_verifier(env: &Env, chain_id: u128, module: &Address) {
    env.storage()
        .persistent()
        .set(&(KEY_RVERIF, chain_id), module);
}

pub fn get_root_verifier(env: &Env, chain_id: u128) -> Option<Address> {
    env.storage().persistent().get(&(KEY_RVERIF, chain_id))
}

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

pub fn is_paused(env: &Env) -> bool {
    env.storage().instance().get(&KEY_PAUSED).unwrap_or(false)
}

pub fn set_paused(env: &Env, paused: bool) {
    env.storage().instance().set(&KEY_PAUSED, &paused);
}

pub fn get_last_unpaused_at(env: &Env) -> u64 {
    env.storage().instance().get(&KEY_UNPAUSED).unwrap_or(0)
}

pub fn set_last_unpaused_at(env: &Env, at: u64) {
    env.storage().instance().set(&KEY_UNPAUSED, &at);
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

pub fn get_claimable(env: &Env, recipient: &BytesN<32>, token: &BytesN<32>) -> u128 {
    env.storage()
        .persistent()
        .get(&(KEY_CLAIM, recipient.clone(), token.clone()))
        .unwrap_or(0)
}

pub fn set_claimable(env: &Env, recipient: &BytesN<32>, token: &BytesN<32>, amount: u128) {
    env.storage()
        .persistent()
        .set(&(KEY_CLAIM, recipient.clone(), token.clone()), &amount);
}
