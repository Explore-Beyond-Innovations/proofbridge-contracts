//! The per-agent policy table and its storage.
//!
//! `Owner` / `Targets` / `SchemaVersion` live in instance storage (always in the
//! footprint; the instance is re-extended on every entry point). Policies are
//! persistent, keyed by agent id, re-extended on every write and at use time.
//! A revoked policy stays in place as the tombstone: `revoked: true` is sticky.

use soroban_sdk::{contracttype, Address, BytesN, Env, Map, String, Symbol, Vec};

use proofbridge_core::rate_limit::{Bucket, Limit};

use crate::errors::AccountError;

pub const MAX_ALLOWED_ACTIONS: u32 = 4;
pub const MAX_WHITELIST_TOKENS: u32 = 16;
pub const MAX_TARGETS: u32 = 2;
/// Ads a scoped agent may name. Sized like the token whitelist: enough for a real book, small
/// enough that the linear scan in the auth path stays cheap.
pub const MAX_AD_SCOPE: u32 = 16;
/// Bumped by an `upgrade` whose wasm changes the storage shape; a new wasm
/// migrates or refuses old state deliberately instead of misreading it.
/// 2 = 2.1d's `ad_scope` / `limits` / `buckets`.
pub const SCHEMA_VERSION: u32 = 2;

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
    /// Which ads this agent may serve. `None` = every ad this account owns, which is the 2.1c
    /// behaviour and stays the default; `Some(list)` = exactly those. Deliberately not "empty
    /// means all": `validate` already rejects an empty `token_whitelist`, so an empty list means
    /// *invalid* in this struct and must not mean the opposite one field down.
    pub ad_scope: Option<Vec<String>>,
    /// Per-token volume limit for this agent, in ad-token units. Every whitelisted token needs one.
    pub limits: Map<BytesN<32>, Limit>,
    /// Live bucket state, keyed the same way. Lives inside the policy rather than beside it so
    /// there is no second entry that can archive on its own and read back as a full bucket (2.3h).
    pub buckets: Map<BytesN<32>, Bucket>,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Owner,
    Targets,
    SchemaVersion,
    Policy(AgentId),
    /// The account-wide volume row for one token: the limit every agent shares (F7's N-agent
    /// half) and its live bucket, in **one** entry. Splitting them would let the limit archive
    /// while the bucket survives — and then a live bucket with no limit either refuses a
    /// configured token or, worse, refills to full. One entry cannot half-disappear.
    AccountVolume(BytesN<32>),
}

/// The account-wide row. Absence means *unconfigured* and refuses the lock; it never means
/// unlimited (2.3h: absence must not read as permission).
#[contracttype]
#[derive(Clone, Debug)]
pub struct AccountVolume {
    pub limit: Limit,
    pub bucket: Bucket,
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

pub fn get_account_volume(env: &Env, token: &BytesN<32>) -> Option<AccountVolume> {
    env.storage()
        .persistent()
        .get(&DataKey::AccountVolume(token.clone()))
}

pub fn set_account_volume(env: &Env, token: &BytesN<32>, v: &AccountVolume) {
    let key = DataKey::AccountVolume(token.clone());
    env.storage().persistent().set(&key, v);
    proofbridge_core::ttl::extend_persistent(env, &key);
}

/// A limit is well formed when it admits something and eventually refills. A zero `capacity`
/// blocks the agent outright and a zero `refill_per_second` makes the bucket one-shot; both are
/// almost certainly a mis-set field rather than an intent, and both are better refused at install
/// than discovered when locks stop.
pub fn validate_limit(limit: &Limit) -> Result<(), AccountError> {
    if limit.capacity == 0 || limit.refill_per_second == 0 {
        return Err(AccountError::BadPolicy);
    }
    Ok(())
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

    // Every whitelisted token needs a limit, and nothing outside the whitelist may carry one. The
    // whitelist says which tokens are permitted at all; `limits` says how much. A token in one and
    // not the other is a half-written policy, not a default.
    if policy.limits.len() != tokens.len() {
        return Err(AccountError::BadPolicy);
    }
    for t in tokens.iter() {
        match policy.limits.get(t) {
            Some(l) => validate_limit(&l)?,
            None => return Err(AccountError::BadPolicy),
        }
    }

    if let Some(ads) = &policy.ad_scope {
        if ads.is_empty() || ads.len() > MAX_AD_SCOPE {
            return Err(AccountError::BadPolicy);
        }
        for (i, a) in ads.iter().enumerate() {
            if a.is_empty() {
                return Err(AccountError::BadPolicy);
            }
            for j in 0..i {
                if ads.get(j as u32) == Some(a.clone()) {
                    return Err(AccountError::BadPolicy);
                }
            }
        }
    }
    Ok(())
}

/// Does this policy let the agent serve `ad_id`? `None` scope is every ad this account owns.
pub fn ad_in_scope(policy: &AgentPolicy, ad_id: &String) -> bool {
    match &policy.ad_scope {
        None => true,
        Some(ads) => ads.contains(ad_id),
    }
}
