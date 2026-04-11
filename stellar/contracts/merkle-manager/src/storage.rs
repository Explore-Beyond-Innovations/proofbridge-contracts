//! Storage helpers for the MerkleManager contract.

use soroban_sdk::{symbol_short, Address, BytesN, Env, Symbol};

// =============================================================================
// Storage Keys
// =============================================================================

/// Key for the current MMR root
const KEY_ROOT: Symbol = symbol_short!("root");
/// Key for the total node count (size)
const KEY_SIZE: Symbol = symbol_short!("size");
/// Key for the leaf count (width)
const KEY_WIDTH: Symbol = symbol_short!("width");
/// Key for the admin address
const KEY_ADMIN: Symbol = symbol_short!("admin");
/// Key for initialization flag
const KEY_INIT: Symbol = symbol_short!("init");

/// Prefix for node hashes: (KEY_HASHES, index) -> hash
const KEY_HASHES: Symbol = symbol_short!("hashes");
/// Prefix for root history: (KEY_HISTORY, width) -> root
const KEY_HISTORY: Symbol = symbol_short!("history");
/// Prefix for managers: (KEY_MGRS, address) -> bool
const KEY_MGRS: Symbol = symbol_short!("mgrs");

// =============================================================================
// Instance Storage (Contract-level state)
// =============================================================================

/// Check if the contract is initialized.
pub fn is_initialized(env: &Env) -> bool {
    env.storage().instance().has(&KEY_INIT)
}

/// Mark the contract as initialized.
pub fn set_initialized(env: &Env) {
    env.storage().instance().set(&KEY_INIT, &true);
}

/// Get the admin address.
pub fn get_admin(env: &Env) -> Option<Address> {
    env.storage().instance().get(&KEY_ADMIN)
}

/// Set the admin address.
pub fn set_admin(env: &Env, admin: &Address) {
    env.storage().instance().set(&KEY_ADMIN, admin);
}

/// Get the current MMR root.
pub fn get_root(env: &Env) -> BytesN<32> {
    env.storage()
        .instance()
        .get(&KEY_ROOT)
        .unwrap_or(BytesN::from_array(env, &[0u8; 32]))
}

/// Set the current MMR root.
pub fn set_root(env: &Env, root: &BytesN<32>) {
    env.storage().instance().set(&KEY_ROOT, root);
}

/// Get the current size (total node count).
pub fn get_size(env: &Env) -> u128 {
    env.storage().instance().get(&KEY_SIZE).unwrap_or(0)
}

/// Set the current size.
pub fn set_size(env: &Env, size: u128) {
    env.storage().instance().set(&KEY_SIZE, &size);
}

/// Get the current width (leaf count).
pub fn get_width(env: &Env) -> u128 {
    env.storage().instance().get(&KEY_WIDTH).unwrap_or(0)
}

/// Set the current width.
pub fn set_width(env: &Env, width: u128) {
    env.storage().instance().set(&KEY_WIDTH, &width);
}

// =============================================================================
// Persistent Storage (Node hashes, root history, managers)
// =============================================================================

/// Get a node hash by index.
pub fn get_node_hash(env: &Env, index: u128) -> Option<BytesN<32>> {
    env.storage().persistent().get(&(KEY_HASHES, index))
}

/// Set a node hash by index.
pub fn set_node_hash(env: &Env, index: u128, hash: &BytesN<32>) {
    env.storage().persistent().set(&(KEY_HASHES, index), hash);
}

/// Get the root at a specific width (leaf count).
pub fn get_root_at_width(env: &Env, width: u128) -> Option<BytesN<32>> {
    env.storage().persistent().get(&(KEY_HISTORY, width))
}

/// Set the root at a specific width.
pub fn set_root_at_width(env: &Env, width: u128, root: &BytesN<32>) {
    env.storage().persistent().set(&(KEY_HISTORY, width), root);
}

/// Check if an address is a manager.
pub fn is_manager(env: &Env, addr: &Address) -> bool {
    env.storage()
        .persistent()
        .get(&(KEY_MGRS, addr.clone()))
        .unwrap_or(false)
}

/// Set manager status for an address.
pub fn set_manager(env: &Env, addr: &Address, status: bool) {
    env.storage()
        .persistent()
        .set(&(KEY_MGRS, addr.clone()), &status);
}

// =============================================================================
// TTL Extension
// =============================================================================

/// Extend instance storage TTL.
pub fn extend_instance_ttl(env: &Env) {
    const INSTANCE_LIFETIME_THRESHOLD: u32 = 17280; // ~1 day
    const INSTANCE_BUMP_AMOUNT: u32 = 518400; // ~30 days

    env.storage()
        .instance()
        .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
}
