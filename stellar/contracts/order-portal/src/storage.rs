//! Storage for the OrderPortal.
//!
//! Everything both escrows keep the same way lives once in `proofbridge_core::escrow_storage` and is re-exported
//! here, so call sites and tests read exactly as before. What stays is the chain record: its field is named for the
//! *other* leg, so the two escrows encode different maps and must not be unified.

use soroban_sdk::{symbol_short, Env, Symbol};

use crate::errors::OrderPortalError;
use crate::types::{ChainInfo, ContractConfig};

pub use proofbridge_core::escrow_storage::*;

/// Prefix for chain configurations
const KEY_CHAINS: Symbol = symbol_short!("chains");

/// The config, or this contract's own `NotInitialized`.
pub fn get_config(env: &Env) -> Result<ContractConfig, OrderPortalError> {
    proofbridge_core::escrow_storage::get_config(env).ok_or(OrderPortalError::NotInitialized)
}

/// Extend instance storage TTL. The numbers live once, in `proofbridge_core::ttl`; this stays as the name the
/// entry points call.
pub fn extend_instance_ttl(env: &Env) {
    proofbridge_core::ttl::extend_instance(env);
}

// ── chain configuration (order-side `ChainInfo`) ─────────────────────────

/// Get chain info for a given chain ID
pub fn get_chain(env: &Env, chain_id: u128) -> Option<ChainInfo> {
    let key = (KEY_CHAINS, chain_id);
    env.storage().persistent().get(&key)
}

/// Which peer chains this escrow accepts, and their counterpart contract. Settlement-bearing, so
/// its TTL is extended (2.3h D2): written once at wiring and then only read, and an archived entry
/// reads as *unsupported* — every lock and every route write on that peer fails until it is
/// restored.
pub fn set_chain(env: &Env, chain_id: u128, info: &ChainInfo) {
    let key = (KEY_CHAINS, chain_id);
    env.storage().persistent().set(&key, info);
    proofbridge_core::ttl::extend_persistent(env, &key);
}

/// Remove chain configuration
pub fn remove_chain(env: &Env, chain_id: u128) {
    let key = (KEY_CHAINS, chain_id);
    env.storage().persistent().remove(&key);
}

// ── forfeit payouts ──────────────────────────────────────────────────────

const KEY_FORFEIT_PAID: Symbol = symbol_short!("forfeit");

/// The deposit was paid to the maker on a forfeit ruling: `record_settled` refuses it. Read only by
/// `record_settled` and the view; its TTL is extended like the order record it qualifies.
pub fn set_paid_by_forfeit(env: &Env, order_hash: &soroban_sdk::BytesN<32>) {
    let key = (KEY_FORFEIT_PAID, order_hash.clone());
    env.storage().persistent().set(&key, &true);
    proofbridge_core::ttl::extend_persistent(env, &key);
}

pub fn is_paid_by_forfeit(env: &Env, order_hash: &soroban_sdk::BytesN<32>) -> bool {
    env.storage()
        .persistent()
        .get(&(KEY_FORFEIT_PAID, order_hash.clone()))
        .unwrap_or(false)
}
