//! Storage keys and helper functions for the AdManager contract

use soroban_sdk::{symbol_short, Address, BytesN, Env, String, Symbol};

use crate::errors::AdManagerError;
use crate::types::{Ad, ChainInfo, ContractConfig, Status};

// =============================================================================
// Storage Keys - Instance Storage (Contract-level)
// =============================================================================

/// Key for contract configuration
const KEY_CONFIG: Symbol = symbol_short!("config");

/// Key for initialized flag
const KEY_INITIALIZED: Symbol = symbol_short!("init");

// =============================================================================
// Storage Key Prefixes - Persistent Storage
// =============================================================================

/// Prefix for chain configurations
const KEY_CHAINS: Symbol = symbol_short!("chains");

/// Prefix for token routes
const KEY_ROUTES: Symbol = symbol_short!("routes");

/// Prefix for ads
const KEY_ADS: Symbol = symbol_short!("ads");

/// Prefix for order statuses
const KEY_ORDERS: Symbol = symbol_short!("orders");

/// Prefix for nullifiers
const KEY_NULLIFIERS: Symbol = symbol_short!("nulls");

/// Prefix for managers
const KEY_MANAGERS: Symbol = symbol_short!("mgrs");

/// Prefix for request tokens (auth tokens)
const KEY_REQ_TOKENS: Symbol = symbol_short!("rtokens");

/// Prefix for request hashes
const KEY_REQ_HASHES: Symbol = symbol_short!("rhashes");

/// Prefix for ad IDs
const KEY_AD_IDS: Symbol = symbol_short!("adids");

// =============================================================================
// Initialization
// =============================================================================

/// Check if contract is initialized
pub fn is_initialized(env: &Env) -> bool {
    env.storage().instance().has(&KEY_INITIALIZED)
}

/// Mark contract as initialized
pub fn set_initialized(env: &Env) {
    env.storage().instance().set(&KEY_INITIALIZED, &true);
}

/// Get contract configuration
pub fn get_config(env: &Env) -> Result<ContractConfig, AdManagerError> {
    env.storage()
        .instance()
        .get(&KEY_CONFIG)
        .ok_or(AdManagerError::NotInitialized)
}

/// Set contract configuration
pub fn set_config(env: &Env, config: &ContractConfig) {
    env.storage().instance().set(&KEY_CONFIG, config);
}

// =============================================================================
// Chain Configuration
// =============================================================================

/// Get chain info for a given chain ID
pub fn get_chain(env: &Env, chain_id: u128) -> Option<ChainInfo> {
    let key = (KEY_CHAINS, chain_id);
    env.storage().persistent().get(&key)
}

/// Set chain info for a given chain ID
pub fn set_chain(env: &Env, chain_id: u128, info: &ChainInfo) {
    let key = (KEY_CHAINS, chain_id);
    env.storage().persistent().set(&key, info);
}

/// Remove chain configuration
pub fn remove_chain(env: &Env, chain_id: u128) {
    let key = (KEY_CHAINS, chain_id);
    env.storage().persistent().remove(&key);
}

// =============================================================================
// Token Routes
// =============================================================================

/// Get token route: (ad_token, order_chain_id) -> order_token
pub fn get_token_route(
    env: &Env,
    ad_token: &BytesN<32>,
    order_chain_id: u128,
) -> Option<BytesN<32>> {
    let key = (KEY_ROUTES, ad_token.clone(), order_chain_id);
    env.storage().persistent().get(&key)
}

/// Set token route
pub fn set_token_route(
    env: &Env,
    ad_token: &BytesN<32>,
    order_chain_id: u128,
    order_token: &BytesN<32>,
) {
    let key = (KEY_ROUTES, ad_token.clone(), order_chain_id);
    env.storage().persistent().set(&key, order_token);
}

/// Remove token route
pub fn remove_token_route(env: &Env, ad_token: &BytesN<32>, order_chain_id: u128) {
    let key = (KEY_ROUTES, ad_token.clone(), order_chain_id);
    env.storage().persistent().remove(&key);
}

// =============================================================================
// Ads
// =============================================================================

/// Get ad by ID
pub fn get_ad(env: &Env, ad_id: &String) -> Option<Ad> {
    let key = (KEY_ADS, ad_id.clone());
    env.storage().persistent().get(&key)
}

/// Set ad
pub fn set_ad(env: &Env, ad_id: &String, ad: &Ad) {
    let key = (KEY_ADS, ad_id.clone());
    env.storage().persistent().set(&key, ad);
}

// =============================================================================
// Orders
// =============================================================================

/// Get order status by hash
pub fn get_order_status(env: &Env, order_hash: &BytesN<32>) -> Status {
    let key = (KEY_ORDERS, order_hash.clone());
    env.storage().persistent().get(&key).unwrap_or(Status::None)
}

/// Set order status
pub fn set_order_status(env: &Env, order_hash: &BytesN<32>, status: Status) {
    let key = (KEY_ORDERS, order_hash.clone());
    env.storage().persistent().set(&key, &status);
}

// =============================================================================
// Nullifiers
// =============================================================================

/// Check if nullifier has been used
pub fn is_nullifier_used(env: &Env, nullifier_hash: &BytesN<32>) -> bool {
    let key = (KEY_NULLIFIERS, nullifier_hash.clone());
    env.storage().persistent().get(&key).unwrap_or(false)
}

/// Mark nullifier as used
pub fn set_nullifier_used(env: &Env, nullifier_hash: &BytesN<32>) {
    let key = (KEY_NULLIFIERS, nullifier_hash.clone());
    env.storage().persistent().set(&key, &true);
}

// =============================================================================
// Managers
// =============================================================================

/// Check if address is a manager
pub fn is_manager(env: &Env, addr: &Address) -> bool {
    let key = (KEY_MANAGERS, addr.clone());
    env.storage().persistent().get(&key).unwrap_or(false)
}

/// Set manager status
pub fn set_manager(env: &Env, addr: &Address, status: bool) {
    let key = (KEY_MANAGERS, addr.clone());
    env.storage().persistent().set(&key, &status);
}

// =============================================================================
// Request Tokens (Auth Tokens)
// =============================================================================

/// Check if request token has been used
pub fn is_request_token_used(env: &Env, token: &BytesN<32>) -> bool {
    let key = (KEY_REQ_TOKENS, token.clone());
    env.storage().persistent().get(&key).unwrap_or(false)
}

/// Mark request token as used
pub fn set_request_token_used(env: &Env, token: &BytesN<32>) {
    let key = (KEY_REQ_TOKENS, token.clone());
    env.storage().persistent().set(&key, &true);
}

// =============================================================================
// Request Hashes
// =============================================================================

/// Check if request hash has been processed
pub fn is_request_hash_used(env: &Env, hash: &BytesN<32>) -> bool {
    let key = (KEY_REQ_HASHES, hash.clone());
    env.storage().persistent().get(&key).unwrap_or(false)
}

/// Mark request hash as processed
pub fn set_request_hash_used(env: &Env, hash: &BytesN<32>) {
    let key = (KEY_REQ_HASHES, hash.clone());
    env.storage().persistent().set(&key, &true);
}

// =============================================================================
// Ad IDs
// =============================================================================

/// Check if ad ID has been used
pub fn is_ad_id_used(env: &Env, ad_id: &String) -> bool {
    let key = (KEY_AD_IDS, ad_id.clone());
    env.storage().persistent().get(&key).unwrap_or(false)
}

/// Mark ad ID as used
pub fn set_ad_id_used(env: &Env, ad_id: &String) {
    let key = (KEY_AD_IDS, ad_id.clone());
    env.storage().persistent().set(&key, &true);
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Extend instance storage TTL
pub fn extend_instance_ttl(env: &Env) {
    const INSTANCE_LIFETIME_THRESHOLD: u32 = 17280; // ~1 day
    const INSTANCE_BUMP_AMOUNT: u32 = 518400; // ~30 days

    env.storage()
        .instance()
        .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
}
