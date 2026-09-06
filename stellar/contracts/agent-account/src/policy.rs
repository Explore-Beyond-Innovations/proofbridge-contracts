//! The per-agent policy table and its storage.
//!
//! `Owner` / `Targets` live in instance storage (always in the footprint).
//! Policies and the sticky revocation flag are persistent, keyed by agent id,
//! and re-extended on every write.

use soroban_sdk::{contracttype, Address, BytesN, Env, Symbol, Vec};

use crate::errors::AccountError;

pub const MAX_ALLOWED_ACTIONS: u32 = 4;
pub const MAX_WHITELIST_TOKENS: u32 = 16;
pub const MAX_TARGETS: u32 = 2;

const PERSISTENT_LIFETIME_THRESHOLD: u32 = 518_400; // ~30 days
const PERSISTENT_BUMP_AMOUNT: u32 = 3_110_400; // ~180 days

/// Agent id: ed25519 pubkey as-is; secp256k1 agents use their 20-byte EVM
/// address left-padded to 32 (the pinned `toBytes32` convention).
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
    pub revoked: bool,
    /// Settlement identity every lock must name (D5).
    pub settlement_signer: BytesN<32>,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Owner,
    Targets,
    Policy(AgentId),
    Revoked(AgentId),
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

pub fn get_targets(env: &Env) -> Vec<Address> {
    env.storage()
        .instance()
        .get(&DataKey::Targets)
        .unwrap_or(Vec::new(env))
}

pub fn set_targets(env: &Env, targets: &Vec<Address>) -> Result<(), AccountError> {
    if targets.is_empty() || targets.len() > MAX_TARGETS {
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
    bump(env, &key);
}

pub fn is_revoked(env: &Env, agent: &AgentId) -> bool {
    env.storage()
        .persistent()
        .has(&DataKey::Revoked(agent.clone()))
}

pub fn set_revoked(env: &Env, agent: &AgentId) {
    let key = DataKey::Revoked(agent.clone());
    env.storage().persistent().set(&key, &true);
    bump(env, &key);
}

fn bump<K: soroban_sdk::IntoVal<Env, soroban_sdk::Val>>(env: &Env, key: &K) {
    env.storage().persistent().extend_ttl(
        key,
        PERSISTENT_LIFETIME_THRESHOLD,
        PERSISTENT_BUMP_AMOUNT,
    );
}

/// Install-time validation; the auth path never re-checks these.
pub fn validate(env: &Env, policy: &AgentPolicy) -> Result<(), AccountError> {
    let actions = &policy.allowed_actions;
    if actions.is_empty() || actions.len() > MAX_ALLOWED_ACTIONS {
        return Err(AccountError::BadPolicy);
    }
    let lock = lock_for_order(env);
    for a in actions.iter() {
        if a != lock {
            return Err(AccountError::BadPolicy);
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
    if proofbridge_core::auth::is_zero_bytes32(&policy.settlement_signer) {
        return Err(AccountError::BadPolicy);
    }
    if policy.valid_until != 0 && policy.valid_until <= env.ledger().timestamp() {
        return Err(AccountError::BadPolicy);
    }
    Ok(())
}
