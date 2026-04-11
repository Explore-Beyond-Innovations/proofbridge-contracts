//! Storage helpers for the OrderPortal contract

use soroban_sdk::{symbol_short, Address, BytesN, Env, Symbol};

use crate::types::{ChainInfo, ContractConfig, Status};

// =============================================================================
// Storage Keys
// =============================================================================

/// Key for contract configuration
const KEY_CONFIG: Symbol = symbol_short!("config");
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
/// Prefix for manager tracking
const KEY_MGRS: Symbol = symbol_short!("mgrs");
/// Prefix for request token tracking
const KEY_RTOKENS: Symbol = symbol_short!("rtokens");
/// Prefix for request hash tracking
const KEY_RHASHES: Symbol = symbol_short!("rhashes");

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

/// Set order status
pub fn set_order_status(env: &Env, order_hash: &BytesN<32>, status: Status) {
    env.storage()
        .persistent()
        .set(&(KEY_ORDERS, order_hash.clone()), &status);
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
// Persistent Storage - Managers
// =============================================================================

/// Check if address is a manager
pub fn is_manager(env: &Env, addr: &Address) -> bool {
    env.storage()
        .persistent()
        .get(&(KEY_MGRS, addr.clone()))
        .unwrap_or(false)
}

/// Set manager status
pub fn set_manager(env: &Env, addr: &Address, status: bool) {
    env.storage()
        .persistent()
        .set(&(KEY_MGRS, addr.clone()), &status);
}

// =============================================================================
// Persistent Storage - Request Tokens (Replay Protection)
// =============================================================================

/// Check if request token is used
pub fn is_request_token_used(env: &Env, token: &BytesN<32>) -> bool {
    env.storage()
        .persistent()
        .get(&(KEY_RTOKENS, token.clone()))
        .unwrap_or(false)
}

/// Mark request token as used
pub fn set_request_token_used(env: &Env, token: &BytesN<32>) {
    env.storage()
        .persistent()
        .set(&(KEY_RTOKENS, token.clone()), &true);
}

// =============================================================================
// Persistent Storage - Request Hashes (Replay Protection)
// =============================================================================

/// Check if request hash is used
pub fn is_request_hash_used(env: &Env, hash: &BytesN<32>) -> bool {
    env.storage()
        .persistent()
        .get(&(KEY_RHASHES, hash.clone()))
        .unwrap_or(false)
}

/// Mark request hash as used
pub fn set_request_hash_used(env: &Env, hash: &BytesN<32>) {
    env.storage()
        .persistent()
        .set(&(KEY_RHASHES, hash.clone()), &true);
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
