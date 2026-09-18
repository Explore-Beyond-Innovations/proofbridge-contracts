//! Storage for the AdManager.
//!
//! Everything both escrows keep the same way lives once in `proofbridge_core::escrow_storage` and is re-exported
//! here, so call sites and tests read exactly as before. What stays is what is genuinely ad-side: the chain record
//! (its field is named for the *other* leg, so the two escrows encode different maps and must not be unified), the
//! ad itself, ad-id reuse, and the key registry.

use soroban_sdk::{symbol_short, Address, Env, String, Symbol};

use crate::errors::AdManagerError;
use crate::types::{Ad, ChainInfo, ContractConfig};

pub use proofbridge_core::escrow_storage::*;

/// Prefix for chain configurations
const KEY_CHAINS: Symbol = symbol_short!("chains");
/// Prefix for ads
const KEY_ADS: Symbol = symbol_short!("ads");
/// Prefix for ad IDs
const KEY_AD_IDS: Symbol = symbol_short!("adids");
/// The key registry consulted when an ad's settlement signer is set (2.3c D2).
const KEY_KEYREG: Symbol = symbol_short!("keyreg");

/// The config, or this contract's own `NotInitialized`.
pub fn get_config(env: &Env) -> Result<ContractConfig, AdManagerError> {
    proofbridge_core::escrow_storage::get_config(env).ok_or(AdManagerError::NotInitialized)
}

/// Extend instance storage TTL. The numbers live once, in `proofbridge_core::ttl`; this stays as the name the
/// entry points call.
pub fn extend_instance_ttl(env: &Env) {
    proofbridge_core::ttl::extend_instance(env);
}

// ── chain configuration (ad-side `ChainInfo`) ────────────────────────────

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

// ── ads ──────────────────────────────────────────────────────────────────

/// Get ad by ID
pub fn get_ad(env: &Env, ad_id: &String) -> Option<Ad> {
    let key = (KEY_ADS, ad_id.clone());
    env.storage().persistent().get(&key)
}

/// Set ad
/// An ad and its liquidity. Fund-bearing — `ad.balance` is the maker's money — so its TTL is
/// extended on every write (2.3h D2). An idle ad that archives is liquidity its owner cannot
/// withdraw until the entry is restored.
pub fn set_ad(env: &Env, ad_id: &String, ad: &Ad) {
    let key = (KEY_ADS, ad_id.clone());
    env.storage().persistent().set(&key, ad);
    proofbridge_core::ttl::extend_persistent(env, &key);
}

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

// ── the key registry (2.3c) ──────────────────────────────────────────────

pub fn set_key_registry(env: &Env, registry: &Address) {
    env.storage().instance().set(&KEY_KEYREG, registry);
}

pub fn get_key_registry(env: &Env) -> Option<Address> {
    env.storage().instance().get(&KEY_KEYREG)
}
