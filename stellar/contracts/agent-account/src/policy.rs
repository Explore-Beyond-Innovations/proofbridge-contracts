//! The per-agent policy table and its storage.
//!
//! `Owner` / `Targets` / `SchemaVersion` live in instance storage (always in the
//! footprint; the instance is re-extended on every entry point). Policies are
//! persistent, keyed by agent id, re-extended on every write and at use time.
//! A revoked policy stays in place as the tombstone: `revoked: true` is sticky.

use soroban_sdk::{contracttype, Address, BytesN, Env, String, Symbol, TryFromVal, Val, Vec};

use proofbridge_core::rate_limit::{Bucket, Limit};

use crate::errors::AccountError;

pub const MAX_ALLOWED_ACTIONS: u32 = 4;
pub const MAX_WHITELIST_TOKENS: u32 = 16;
pub const MAX_TARGETS: u32 = 2;
/// Ads a scoped agent may name. Sized like the token whitelist: enough for a real book, small
/// enough that the linear scan in the auth path stays cheap.
pub const MAX_AD_SCOPE: u32 = 16;
/// Guarded ads per account. The roster lives in the instance, which is loaded on every call, so it
/// is bounded for the same reason the whitelist is.
pub const MAX_GUARDED_ADS: u32 = 16;
/// Bumped by an `upgrade` whose wasm changes the storage shape; the new wasm's `migrate` writes it,
/// and migrates or refuses old state deliberately instead of misreading it.
/// 2 = 2.1d's `ad_scope` / `limits` / `buckets`. 3 = 2.7's single schedule shape: rows written under
/// the old keys (`Schedule(String, Symbol)`, `LockSchedule`, `AccountSchedule`) are never read by
/// this code and archive on their TTL; `migrate` cannot enumerate keys and does not try.
pub const SCHEMA_VERSION: u32 = 3;

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
    /// Per-token size and rate for this agent, in that token's own units. Every whitelisted token
    /// needs one: one number cannot be right for tokens that are not worth the same, which is the
    /// whole reason this is a map and not a scalar.
    pub limits: Vec<TokenLimit>,
    /// Live bucket state, one row per token spent from. Lives inside the policy rather than beside
    /// it so there is no second entry that can archive on its own and read back as a full bucket
    /// (2.3h).
    pub buckets: Vec<TokenBucket>,
}

/// What an agent may do with one token: how big a single lock may be, and how fast it may keep
/// making them.
///
/// The two belong together because the per-order cap is only meaningful *relative to* the bucket:
/// above `capacity` it can never bind, and below it, it is what forces a stolen key to make ten
/// locks instead of one — ten chances for the watchtower to notice before the allowance is gone.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenLimit {
    /// Which token this row is for.
    pub token: BytesN<32>,
    /// Cap on one lock, in this token's own units (what the escrow actually locks).
    pub max_per_order: u128,
    /// The refill bucket for this token.
    pub rate: Limit,
}

/// Live bucket state for one token, carried the same way and for the same reason.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenBucket {
    pub token: BytesN<32>,
    pub bucket: Bucket,
}

/// A `Vec` of rows carrying their own key, not a `Map<BytesN<32>, _>`.
///
/// The map is the obvious shape and it is unreadable off chain: `scValToNative` turns an `ScMap`
/// into a JS object, and a 32-byte key becomes `String(Buffer)` — decoded as UTF-8, so any byte
/// that is not valid UTF-8 lands on U+FFFD and the token id does not round-trip. Every off-chain
/// mirror reads `policy()` through that path, so a map here would hand all of them limits they
/// cannot attribute to a token. A vec of structs decodes losslessly: symbol keys for the fields,
/// the token as a byte value rather than a key.
///
/// The cost on chain is a linear scan bounded by `MAX_WHITELIST_TOKENS` (16), which is what
/// `token_whitelist.contains()` already does beside it.
pub fn limit_for(policy: &AgentPolicy, token: &BytesN<32>) -> Option<TokenLimit> {
    policy.limits.iter().find(|l| &l.token == token)
}

pub fn bucket_for(policy: &AgentPolicy, token: &BytesN<32>) -> Option<Bucket> {
    policy
        .buckets
        .iter()
        .find(|b| &b.token == token)
        .map(|b| b.bucket)
}

/// Replace this token's bucket, or append it the first time it is spent from.
pub fn put_bucket(policy: &mut AgentPolicy, token: &BytesN<32>, bucket: Bucket) {
    for (i, b) in policy.buckets.iter().enumerate() {
        if &b.token == token {
            policy.buckets.set(
                i as u32,
                TokenBucket {
                    token: token.clone(),
                    bucket,
                },
            );
            return;
        }
    }
    policy.buckets.push_back(TokenBucket {
        token: token.clone(),
        bucket,
    });
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
    /// One guarded ad's settings and live bucket. Absent **and not on the roster** = unguarded,
    /// which is every ad today; absent *while on the roster* refuses — see `guarded_ads`.
    GuardRail(String),
    /// A delayed owner call, keyed by where it applies and the function it authorizes. Single use.
    Schedule(Scope, Symbol),
    /// Instance-stored roster of ads the owner has guarded, so an archived row cannot read as
    /// "never guarded".
    GuardedAds,
}

/// Where a schedule applies: one ad (timed by its guardrail) or the whole account (timed by the
/// strictest guardrail on the roster).
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    Ad(String),
    Account,
}

/// The owner's own brake on one ad (design 02 §2.8): instant to protect, slow to extract.
///
/// Per **ad**, not per token, and that is forced rather than chosen. `withdraw_from_ad` does not
/// carry the token — it is a property of the ad — and reading it means calling back into the escrow
/// that is currently calling this account, which Soroban refuses outright. `ad_id` is in the
/// arguments, and an ad holds exactly one token, so per-ad is per-token by another name.
///
/// Limit and live bucket share **one** entry, for the reason `AccountVolume` does: split them and
/// the ceiling can archive while the bucket survives.
#[contracttype]
#[derive(Clone, Debug)]
pub struct GuardRail {
    /// A single withdrawal at or below this needs no announcement — but it still spends `bucket`,
    /// or "below the threshold" would mean "unlimited, one call at a time".
    pub threshold: u128,
    /// Seconds between announcing an extractive call and being able to make it.
    pub delay: u64,
    /// Seconds a matured schedule stays usable. One that never expires is a standing authorization
    /// sitting in storage for whoever finds the key next.
    pub window: u64,
    /// The flow the ad may lose without announcing anything, refilling continuously. This is what
    /// design 02 §2.8's residual is denominated in — "the sub-threshold flow rate until detected,
    /// **not the balance**" — and without it a threshold bounds one call and nothing bounds N.
    pub rate: Limit,
    pub bucket: Bucket,
}

/// One announced owner call, bound to `args_commitment` of its exact argument list: a schedule for
/// 100 to alice does not authorize 101, or 100 to someone else, or a different guardrail.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schedule {
    pub commitment: BytesN<32>,
    pub ready_at: u64,
    pub expires_at: u64,
}

/// Which ads carry a guardrail, in **instance** storage.
///
/// This exists so that a missing per-ad row cannot read as "unguarded". The per-ad entry is
/// persistent and archives after ~180 days of no writes; an ad left alone that long would otherwise
/// silently lose its brake, which is absence reading as permission — the failure contracts#25 fixed
/// for the route and verifier rows. The instance is re-extended by every entry point, so the roster
/// does not archive, and an ad on it whose row is gone **refuses** instead.
pub fn guarded_ads(env: &Env) -> Vec<String> {
    env.storage()
        .instance()
        .get(&DataKey::GuardedAds)
        .unwrap_or(Vec::new(env))
}

fn set_guarded_ads(env: &Env, ads: &Vec<String>) {
    env.storage().instance().set(&DataKey::GuardedAds, ads);
}

pub fn is_guarded(env: &Env, ad_id: &String) -> bool {
    guarded_ads(env).contains(ad_id)
}

/// Any ad on the roster makes the whole account guarded for the account-wide changes. The roster,
/// not the rows: an archived row still counts, so absence never reads as permission.
pub fn any_guarded(env: &Env) -> bool {
    !guarded_ads(env).is_empty()
}

/// The delay and window an account-wide change must honour: the longest delay and the shortest
/// window across every guarded ad, so no one ad's brake can be stepped around through the account.
pub fn account_timelock(env: &Env) -> Result<(u64, u64), AccountError> {
    let roster = guarded_ads(env);
    if roster.is_empty() {
        return Err(AccountError::NoGuardRail);
    }
    let mut delay = 0u64;
    let mut window = u64::MAX;
    for ad in roster.iter() {
        let g = get_guard_rail(env, &ad).ok_or(AccountError::GuardRailArchived)?;
        delay = delay.max(g.delay);
        window = window.min(g.window);
    }
    Ok((delay, window))
}

pub fn get_guard_rail(env: &Env, ad_id: &String) -> Option<GuardRail> {
    env.storage()
        .persistent()
        .get(&DataKey::GuardRail(ad_id.clone()))
}

pub fn put_guard_rail(env: &Env, ad_id: &String, g: &GuardRail) -> Result<(), AccountError> {
    let key = DataKey::GuardRail(ad_id.clone());
    env.storage().persistent().set(&key, g);
    proofbridge_core::ttl::extend_persistent(env, &key);
    let mut roster = guarded_ads(env);
    if !roster.contains(ad_id) {
        if roster.len() >= MAX_GUARDED_ADS {
            return Err(AccountError::BadGuardRail);
        }
        roster.push_back(ad_id.clone());
        set_guarded_ads(env, &roster);
    }
    Ok(())
}

pub fn remove_guard_rail(env: &Env, ad_id: &String) {
    env.storage()
        .persistent()
        .remove(&DataKey::GuardRail(ad_id.clone()));
    let roster = guarded_ads(env);
    let mut next = Vec::new(env);
    for a in roster.iter() {
        if &a != ad_id {
            next.push_back(a);
        }
    }
    set_guarded_ads(env, &next);
}

/// Use-time re-extension, the convention `touch_policy` sets: an ad in active use never archives
/// between owner writes. The roster covers the idle case; this keeps the common one off it.
pub fn touch_guard_rail(env: &Env, ad_id: &String) {
    proofbridge_core::ttl::extend_persistent(env, &DataKey::GuardRail(ad_id.clone()));
}

/// Is `next` at least as strict as `cur` on every axis?
///
/// Tightening reduces what a stolen owner key can do, so it is protective and instant. Loosening
/// increases it, so it goes through the delay — which is the whole feature. Design 02 §2.8's
/// protective list is every action that *reduces* an attacker's power; relaxing a brake is not one,
/// and treating it as one removes the delay rather than relocating it.
pub fn is_tightening(cur: &GuardRail, next: &GuardRail) -> bool {
    next.threshold <= cur.threshold
        && next.delay >= cur.delay
        && next.window <= cur.window
        && next.rate.capacity <= cur.rate.capacity
        && next.rate.refill_per_second <= cur.rate.refill_per_second
}

pub fn get_schedule(env: &Env, scope: &Scope, action: &Symbol) -> Option<Schedule> {
    env.storage()
        .persistent()
        .get(&DataKey::Schedule(scope.clone(), action.clone()))
}

pub fn set_schedule(env: &Env, scope: &Scope, action: &Symbol, s: &Schedule) {
    let key = DataKey::Schedule(scope.clone(), action.clone());
    env.storage().persistent().set(&key, s);
    proofbridge_core::ttl::extend_persistent(env, &key);
}

/// Spent, or cancelled. Removing rather than flagging is what makes a schedule single-use: a spent
/// row left behind is an authorization waiting to be replayed.
pub fn clear_schedule(env: &Env, scope: &Scope, action: &Symbol) {
    env.storage()
        .persistent()
        .remove(&DataKey::Schedule(scope.clone(), action.clone()));
}

/// The actions a scope can schedule.
pub fn actions_for(env: &Env, scope: &Scope) -> [Symbol; 4] {
    match scope {
        Scope::Ad(_) => ad_actions(env),
        Scope::Account => account_actions(env),
    }
}

/// Every schedule this ad's settings timed: its own rows and the account-wide ones (which take the
/// strictest guardrail, so this ad's too). Called when a guardrail is disarmed or loosened: a
/// matured row that outlives the settings it was made under would let the next arming be bypassed
/// by an announcement nobody remembers.
pub fn clear_all_schedules(env: &Env, ad_id: &String) {
    for scope in [Scope::Ad(ad_id.clone()), Scope::Account] {
        for a in actions_for(env, &scope) {
            clear_schedule(env, &scope, &a);
        }
    }
}

/// 49S-1: every pending row in `scope` matures no earlier than `not_before`. Called when the delay
/// that times the scope rises, so the new delay applies to what was pending. The window keeps its
/// length, or a re-stamped row would expire before it opens.
pub fn restamp(env: &Env, scope: &Scope, not_before: u64) {
    for a in actions_for(env, scope) {
        if let Some(mut s) = get_schedule(env, scope, &a) {
            if s.ready_at < not_before {
                s.expires_at = s.expires_at.saturating_add(not_before - s.ready_at);
                s.ready_at = not_before;
                set_schedule(env, scope, &a, &s);
            }
        }
    }
}

/// Account-wide changes that go through the timelock while any ad is guarded (D6).
pub fn act_upgrade(env: &Env) -> Symbol {
    Symbol::new(env, "upgrade")
}

pub fn act_set_policy(env: &Env) -> Symbol {
    Symbol::new(env, "set_policy")
}

pub fn act_set_account_limit(env: &Env) -> Symbol {
    Symbol::new(env, "set_account_limit")
}

pub fn act_set_targets(env: &Env) -> Symbol {
    Symbol::new(env, "set_targets")
}

/// The per-ad calls an owner announces on a guarded ad.
pub fn ad_actions(env: &Env) -> [Symbol; 4] {
    [
        withdraw_from_ad(env),
        close_ad(env),
        lock_for_order(env),
        set_guard_rail(env),
    ]
}

pub fn account_actions(env: &Env) -> [Symbol; 4] {
    [
        act_upgrade(env),
        act_set_policy(env),
        act_set_account_limit(env),
        act_set_targets(env),
    ]
}

/// `sha256(XDR(ScVal::Vec(args)))`: the commitment a schedule names for a call's arguments.
pub fn args_commitment(env: &Env, args: &Vec<Val>) -> BytesN<32> {
    use soroban_sdk::xdr::ToXdr;
    env.crypto().sha256(&args.clone().to_xdr(env)).to_bytes()
}

fn subset<T>(small: &Vec<T>, big: &Vec<T>) -> bool
where
    T: Clone + PartialEq + soroban_sdk::IntoVal<Env, Val> + TryFromVal<Env, Val>,
{
    small.iter().all(|x| big.contains(&x))
}

/// Is `next` no wider than `cur` on every axis? Anything else is loosening.
///
/// Tightening means: actions, tokens and ad scope are subsets (an unscoped `cur` admits any scope,
/// a scoped `cur` never admits `None`); every token row has a cap, capacity and refill no higher
/// than `cur`'s row for it (a missing row is loosening); expiry is no later (a `cur` with no
/// expiry admits any, a `cur` with one never admits 0); the settlement signer is unchanged.
/// Adding an agent key is loosening by definition, so there is no `cur` to compare against.
pub fn is_policy_tightening(cur: &AgentPolicy, next: &AgentPolicy) -> bool {
    if !subset(&next.allowed_actions, &cur.allowed_actions)
        || !subset(&next.token_whitelist, &cur.token_whitelist)
        || next.settlement_signer != cur.settlement_signer
    {
        return false;
    }
    let expiry_ok =
        cur.valid_until == 0 || (next.valid_until != 0 && next.valid_until <= cur.valid_until);
    if !expiry_ok {
        return false;
    }
    let scope_ok = match (&cur.ad_scope, &next.ad_scope) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(c), Some(n)) => subset(n, c),
    };
    if !scope_ok {
        return false;
    }
    next.limits.iter().all(|l| match limit_for(cur, &l.token) {
        Some(c) => {
            l.max_per_order <= c.max_per_order
                && l.rate.capacity <= c.rate.capacity
                && l.rate.refill_per_second <= c.rate.refill_per_second
        }
        None => false,
    })
}

/// A new account limit is tightening only against an existing row, and only if neither number
/// rises. No row means unconfigured, which refuses every lock, so any first limit is loosening.
pub fn is_limit_tightening(cur: Option<&AccountVolume>, next: &Limit) -> bool {
    match cur {
        Some(v) => {
            next.capacity <= v.limit.capacity && next.refill_per_second <= v.limit.refill_per_second
        }
        None => false,
    }
}

/// Carry `cur`'s spent buckets into `next`, settled at the old rate and clamped to the new one.
/// An instant tightening write must not hand the agent a full bucket.
pub fn carry_buckets(cur: &AgentPolicy, next: &mut AgentPolicy, now: u64) {
    for l in next.limits.clone().iter() {
        if let (Some(b), Some(c)) = (bucket_for(cur, &l.token), limit_for(cur, &l.token)) {
            let settled = proofbridge_core::rate_limit::available(&c.rate, &b, now);
            let level = settled.min(l.rate.capacity);
            put_bucket(
                next,
                &l.token,
                Bucket {
                    level,
                    last_ts: now,
                },
            );
        }
    }
}

/// The calls that move the maker's money out of reach, named here so the owner path, the schedule
/// entry point and the tests agree on one list (`ad_actions`). `lock_for_order` is included because it moves the
/// ad's free balance into escrow — it is bounded for the agent by `limits`, and leaving it unbounded
/// for the owner would be a hole in a feature whose subject is bounding the owner.
pub fn withdraw_from_ad(env: &Env) -> Symbol {
    Symbol::new(env, "withdraw_from_ad")
}

pub fn close_ad(env: &Env) -> Symbol {
    Symbol::new(env, "close_ad")
}

/// Loosening or disarming a guard_rail: extractive, because it increases what the key can take.
pub fn set_guard_rail(env: &Env) -> Symbol {
    Symbol::new(env, "set_guard_rail")
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

/// Read a policy. Current shape only: a `#[contracttype]` decode traps on any other field set, so
/// once real accounts exist a shape change must ship a read fallback (design 02, "Stored shapes").
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

/// ...and a per-token row adds the size cap. Above `capacity` the cap can never bind, so a larger
/// one is inert — refused rather than silently ignored, because an owner who wrote it meant
/// something by it.
pub fn validate_token_limit(tl: &TokenLimit) -> Result<(), AccountError> {
    validate_limit(&tl.rate)?;
    if tl.max_per_order == 0 || tl.max_per_order > tl.rate.capacity {
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
    for (i, t) in tokens.iter().enumerate() {
        if proofbridge_core::auth::is_zero_bytes32(&t) {
            return Err(AccountError::BadPolicy);
        }
        // Duplicates, like `allowed_actions` and `ad_scope`. **`limits`' containment argument
        // below depends on this**: it concludes one row per token from a count plus a lookup, and
        // that only follows if the whitelist itself holds N distinct tokens. Removing this check
        // on the grounds that a repeated token looks harmless would silently break that.
        for j in 0..i {
            if tokens.get(j as u32) == Some(t.clone()) {
                return Err(AccountError::BadPolicy);
            }
        }
    }

    // The settlement signer is the owner's to name (2.6 D9): the agent's derived identity M, not
    // this account. `check_contract_call` still pins `ad_creator` to this account, and a changed
    // signer is loosening (`is_policy_tightening`), so on a guarded account it waits the delay.
    if proofbridge_core::auth::is_zero_bytes32(&policy.settlement_signer) {
        return Err(AccountError::BadPolicy);
    }
    if policy.valid_until != 0 && policy.valid_until <= env.ledger().timestamp() {
        return Err(AccountError::BadPolicy);
    }

    // Every whitelisted token needs exactly one limit, and nothing outside the whitelist may carry
    // one. The whitelist says which tokens are permitted at all; `limits` says how much, and a
    // token in one and not the other is a half-written policy rather than a default.
    //
    // Two checks are enough, and a third would be unreachable. The loop below finds a row for every
    // whitelisted token, which is ≥ N distinct rows for N tokens; with the count pinned to N there
    // is no room left for a duplicate or for a row naming a token that is not on the list. An
    // explicit "every row is whitelisted, and no row repeats" pass was written here first and could
    // not be made to fail — the length plus the forward lookup already cover it.
    //
    // **This rests on the duplicate check twenty-five lines above**: "N distinct rows" only follows
    // if `token_whitelist` itself holds N distinct tokens. The two travel together.
    if policy.limits.len() != tokens.len() {
        return Err(AccountError::BadPolicy);
    }
    for t in tokens.iter() {
        match limit_for(policy, &t) {
            Some(l) => validate_token_limit(&l)?,
            None => return Err(AccountError::BadPolicy),
        }
        // And the account-wide ceiling has to exist too, or this policy installs cleanly and then
        // fails on its first lock with `NoVolumeLimit`. Fail-closed either way, but the owner
        // deserves the answer at install rather than from an agent that mysteriously cannot work,
        // and `set_account_limit` before `set_policy` is an ordering nothing else states.
        if get_account_volume(env, &t).is_none() {
            return Err(AccountError::NoVolumeLimit);
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
