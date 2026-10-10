//! Storage helpers for the MerkleManager contract.

use proofbridge_core::ttl::extend_persistent;
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
/// Pause flag for every state-changing entry point.
/// Pending admin for the two-step handover.
const KEY_PENDADM: Symbol = symbol_short!("pendadm");
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
    let key = (KEY_HASHES, index);
    let v = env.storage().persistent().get(&key);
    // 49S-2: peaks are read on every append; keep the nodes the tree still uses alive.
    if v.is_some() {
        extend_persistent(env, &key);
    }
    v
}

/// Set a node hash by index.
pub fn set_node_hash(env: &Env, index: u128, hash: &BytesN<32>) {
    let key = (KEY_HASHES, index);
    env.storage().persistent().set(&key, hash);
    // C-13: an archived node breaks every later append and proof that walks it.
    extend_persistent(env, &key);
}

/// Get the root at a specific width (leaf count).
pub fn get_root_at_width(env: &Env, width: u128) -> Option<BytesN<32>> {
    let key = (KEY_HISTORY, width);
    let v = env.storage().persistent().get(&key);
    // 49S-2: reached only via the `get_root_at_index` view (the escrows' `get_historical_root`), not
    // by appends or unlocks, so this extends only when a transaction calls that view.
    if v.is_some() {
        extend_persistent(env, &key);
    }
    v
}

/// Set the root at a specific width.
pub fn set_root_at_width(env: &Env, width: u128, root: &BytesN<32>) {
    let key = (KEY_HISTORY, width);
    env.storage().persistent().set(&key, root);
    // C-13: historical roots are what the escrows' unlocks resolve against.
    extend_persistent(env, &key);
}

/// Check if an address is a manager.
pub fn is_manager(env: &Env, addr: &Address) -> bool {
    let key = (KEY_MGRS, addr.clone());
    let v = env.storage().persistent().get(&key).unwrap_or(false);
    // 49S-2: read on every append, written once. On a live network a fresh entry lives ~120 days
    // (above the bump threshold, so the write-time extend was a no-op); extending on the read keeps
    // the row alive as long as the escrow keeps appending, instead of a paid restore around day 120.
    if v {
        extend_persistent(env, &key);
    }
    v
}

/// Set manager status for an address.
pub fn set_manager(env: &Env, addr: &Address, status: bool) {
    let key = (KEY_MGRS, addr.clone());
    env.storage().persistent().set(&key, &status);
    // Written once, read on every append: an archived row would block the escrow's appends.
    extend_persistent(env, &key);
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

pub fn get_pending_admin(env: &Env) -> Option<Address> {
    env.storage().instance().get(&KEY_PENDADM)
}

pub fn set_pending_admin(env: &Env, admin: &Address) {
    env.storage().instance().set(&KEY_PENDADM, admin);
}

pub fn clear_pending_admin(env: &Env) {
    env.storage().instance().remove(&KEY_PENDADM);
}
