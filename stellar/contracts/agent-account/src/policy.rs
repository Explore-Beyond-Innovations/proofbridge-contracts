//! The per-agent policy table and its storage.
//!
//! `Owner` / `Targets` / `SchemaVersion` live in instance storage (always in the
//! footprint; the instance is re-extended on every entry point). Policies are
//! persistent, keyed by agent id, re-extended on every write and at use time.
//! A revoked policy stays in place as the tombstone: `revoked: true` is sticky.

use soroban_sdk::{contracttype, Address, BytesN, Env, Symbol, Vec};

use crate::errors::AccountError;

pub const MAX_ALLOWED_ACTIONS: u32 = 4;
pub const MAX_WHITELIST_TOKENS: u32 = 16;
pub const MAX_TARGETS: u32 = 2;
/// Bumped by an `upgrade` whose wasm changes the storage shape; a new wasm
/// migrates or refuses old state deliberately instead of misreading it.
pub const SCHEMA_VERSION: u32 = 1;

/// Agent id: ed25519 pubkey as-is; secp256k1 agents use their 20-byte EVM
/// address left-padded to 32 (`proofbridge_core::secp::evm_address_to_bytes32`).
pub type AgentId = BytesN<32>;

#[contracttype]
#[derive(Clone, Debug)]
pub struct AgentPolicy {
    /// Selectors the agent may invoke on a pinned target; today only `lock_for_order`.
    pub allowed_actions: Vec<Symbol>,
    /// Both `ad_chain_token` and `order_chain_token` of a lock must be listed.
    pub token_whitelist: Vec<BytesN<32>>,
    /// Cap on one lock, in ad-token units (what the escrow actually locks).
    pub max_per_order: u128,
    /// Ledger timestamp; 0 = no expiry; usable while `now < valid_until`.
    pub valid_until: u64,
    /// Sticky tombstone: set by `revoke_agent`, never cleared, blocks re-install.
    pub revoked: bool,
    /// Settlement identity every lock must name (D5).
    pub settlement_signer: BytesN<32>,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Owner,
    Targets,
    SchemaVersion,
    Policy(AgentId),
}

/// The only selector an agent may hold today. `register`, `revoke`,
/// `set_policy`, `withdraw_from_ad`, ... are rejected at install (T-03).
pub fn lock_for_order(env: &Env) -> Symbol {
    Symbol::new(env, "lock_for_order")
}

pub fn get_owner(env: &Env) -> Address {
    env.storage()
        .instance()
        .get(&DataKey::Owner)
        .expect("owner is set at construction")
}

pub fn set_owner(env: &Env, owner: &Address) {
    env.storage().instance().set(&DataKey::Owner, owner);
}

pub fn set_schema_version(env: &Env) {
    env.storage()
        .instance()
        .set(&DataKey::SchemaVersion, &SCHEMA_VERSION);
}

pub fn get_schema_version(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&DataKey::SchemaVersion)
        .unwrap_or(0)
}

pub fn get_targets(env: &Env) -> Vec<Address> {
    env.storage()
        .instance()
        .get(&DataKey::Targets)
        .unwrap_or(Vec::new(env))
}

/// Targets are 1..=2 escrows and never the account itself (F1).
pub fn set_targets(env: &Env, targets: &Vec<Address>) -> Result<(), AccountError> {
    if targets.is_empty() || targets.len() > MAX_TARGETS {
        return Err(AccountError::BadTargets);
    }
    if targets.contains(&env.current_contract_address()) {
        return Err(AccountError::BadTargets);
    }
    env.storage().instance().set(&DataKey::Targets, targets);
    Ok(())
}

pub fn get_policy(env: &Env, agent: &AgentId) -> Option<AgentPolicy> {
    env.storage()
        .persistent()
        .get(&DataKey::Policy(agent.clone()))
}

pub fn set_policy(env: &Env, agent: &AgentId, policy: &AgentPolicy) {
    let key = DataKey::Policy(agent.clone());
    env.storage().persistent().set(&key, policy);
    proofbridge_core::ttl::extend_persistent(env, &key);
}

/// Use-time re-extension: an active policy never archives between owner writes.
pub fn touch_policy(env: &Env, agent: &AgentId) {
    proofbridge_core::ttl::extend_persistent(env, &DataKey::Policy(agent.clone()));
}

/// Install-time validation; the auth path never re-checks these.
pub fn validate(env: &Env, policy: &AgentPolicy) -> Result<(), AccountError> {
    let actions = &policy.allowed_actions;
    if actions.is_empty() || actions.len() > MAX_ALLOWED_ACTIONS {
        return Err(AccountError::BadPolicy);
    }
    let lock = lock_for_order(env);
    for (i, a) in actions.iter().enumerate() {
        if a != lock {
            return Err(AccountError::BadPolicy);
        }
        // no duplicates
        for j in 0..i {
            if actions.get(j as u32) == Some(a.clone()) {
                return Err(AccountError::BadPolicy);
            }
        }
    }

    let tokens = &policy.token_whitelist;
    if tokens.is_empty() || tokens.len() > MAX_WHITELIST_TOKENS {
        return Err(AccountError::BadPolicy);
    }
    for t in tokens.iter() {
        if proofbridge_core::auth::is_zero_bytes32(&t) {
            return Err(AccountError::BadPolicy);
        }
    }

    if policy.max_per_order == 0 {
        return Err(AccountError::BadPolicy);
    }
    // Until 2.3b the only settlement identity a lock can name is this account
    // (F5): the escrow does not bind `ad_creator` to `ad.maker` on Stellar, so
    // a foreign signer here would pin locks the relayer never built.
    if policy.settlement_signer != crate::escrow::required_settlement_signer(env) {
        return Err(AccountError::BadPolicy);
    }
    if policy.valid_until != 0 && policy.valid_until <= env.ledger().timestamp() {
        return Err(AccountError::BadPolicy);
    }
    Ok(())
}
