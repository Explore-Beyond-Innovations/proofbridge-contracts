//! Storage for the AdManager.
//!
//! Everything both escrows keep the same way lives once in `proofbridge_core::escrow_storage` and is re-exported
//! here, so call sites and tests read exactly as before. What stays is what is genuinely ad-side: the chain record
//! (its field is named for the *other* leg, so the two escrows encode different maps and must not be unified), the
//! ad itself, ad-id reuse, and the key registry.

use soroban_sdk::{symbol_short, Address, Env, String, Symbol};

use crate::errors::AdManagerError;
use crate::types::{Ad, ChainInfo, ContractConfig, Halt};

pub use proofbridge_core::escrow_storage::*;

/// Prefix for chain configurations
const KEY_CHAINS: Symbol = symbol_short!("chains");
/// Prefix for ads
const KEY_ADS: Symbol = symbol_short!("ads");
/// Prefix for ad IDs
const KEY_AD_IDS: Symbol = symbol_short!("adids");
/// The key registry consulted when an ad's settlement signer is set (2.3c D2).
const KEY_KEYREG: Symbol = symbol_short!("keyreg");
/// Prefix for a maker's settlement halt (#422).
const KEY_HALT: Symbol = symbol_short!("halt");

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

/// The ad-id uniqueness guard. Extended for the same reason as the nullifier ledger: an archived
/// entry reads as absent, absence reads as *unused*, so an aged-out row lets an ad id be taken twice.
pub fn set_ad_id_used(env: &Env, ad_id: &String) {
    let key = (KEY_AD_IDS, ad_id.clone());
    env.storage().persistent().set(&key, &true);
    proofbridge_core::ttl::extend_persistent(env, &key);
}

// ── the key registry (2.3c) ──────────────────────────────────────────────

pub fn set_key_registry(env: &Env, registry: &Address) {
    env.storage().instance().set(&KEY_KEYREG, registry);
}

pub fn get_key_registry(env: &Env) -> Option<Address> {
    env.storage().instance().get(&KEY_KEYREG)
}

// ── the settlement halt (#422) ────────────────────────────────────────────

/// A maker's halt, absent until they first halt. `last_halted_at` survives a resume: the cancel
/// grace treats a halt at or after the claim opened as a denied payout, resumed since or not.
pub fn get_halt(env: &Env, maker: &Address) -> Option<Halt> {
    let key = (KEY_HALT, maker.clone());
    env.storage().persistent().get(&key)
}

/// Written on every halt and resume; the entry's TTL is extended each time, like every other entry a
/// lever depends on. An archived entry reads as "never halted", so a maker who stays halted for
/// longer than the persistent lifetime re-halts (the runbook says so).
pub fn set_halt(env: &Env, maker: &Address, halt: &Halt) {
    let key = (KEY_HALT, maker.clone());
    env.storage().persistent().set(&key, halt);
    proofbridge_core::ttl::extend_persistent(env, &key);
}
