//! AgentAccount — a maker's Soroban custom account (2.1c, #325).
//!
//! Custody stays here (`ad.maker` on the AdManager escrow). Two ways to
//! authorize a call on this account:
//!   - the **owner** (any `Address`, G or C, never this account) authorizes
//!     `__check_auth(payload)` itself, and may do anything;
//!   - an **agent** signs the Soroban auth payload and may only make calls that
//!     pass `check_contract_call`: a pinned escrow, an allowed selector, and
//!     lock args inside its policy (token whitelist, per-order cap, settlement
//!     identity). Never guarded by open orders; `revoke_agent` is instant.
//!
//! The account is owner-upgradeable (`upgrade`): the owner is already sovereign
//! over every fund movement, so code control adds no trust, and it is what lets
//! 2.1d/2.1e/2.1f/2.3b change shape without makers redeploying and re-creating
//! ads. While any ad is guarded, `upgrade` sits behind the extractive timelock (D6).
//!
//! Volume buckets are 2.1d (`min_rate` was withdrawn, see 2.1 design 06 §2); the
//! revoke → retirement runtime wiring and the extractive timelock are 2.1e; CAP-85
//! tolerance is 2.1f.

#![no_std]

mod auth;
mod errors;
mod escrow;
mod events;
mod fingerprint;
mod policy;

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl,
    crypto::Hash,
    vec, Address, BytesN, ContractExecutable, Env, IntoVal, String, Symbol, Val, Vec,
};

use escrow::{spend_account_schedule, spend_schedule};
use policy::{BoundSchedule, GuardRail, TokenLimit};
use proofbridge_core::rate_limit::{self, Bucket, Limit};

pub use auth::{AccountSig, Ed25519Sig, SecpSig};
pub use errors::AccountError;
pub use escrow::settlement_signer_of;
pub use policy::{
    lock_for_order, AccountVolume, AgentId, AgentPolicy, MAX_AD_SCOPE, MAX_ALLOWED_ACTIONS,
    MAX_TARGETS, MAX_WHITELIST_TOKENS, SCHEMA_VERSION,
};

#[contract]
pub struct AgentAccount;

#[contractimpl]
impl AgentAccount {
    /// Pins the owner and the escrows an agent may call (AdManager today).
    /// Neither may be this account (F1): with `owner == self` the owner path
    /// would pass the host's direct-invoker rule with no signature at all.
    pub fn __constructor(
        env: Env,
        owner: Address,
        targets: Vec<Address>,
    ) -> Result<(), AccountError> {
        if owner == env.current_contract_address() {
            return Err(AccountError::BadOwner);
        }
        policy::set_owner(&env, &owner);
        policy::set_targets(&env, &targets)?;
        policy::set_schema_version(&env);
        proofbridge_core::ttl::extend_instance(&env);
        events::TargetsSet { targets }.publish(&env);
        Ok(())
    }

    /// Owner-only. Needed across an escrow redeploy. While any ad is guarded, adding a target the
    /// account does not already have widens where an agent may call, so it is scheduled (C-29).
    pub fn set_targets(env: Env, targets: Vec<Address>) -> Result<(), AccountError> {
        policy::get_owner(&env).require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        if policy::any_guarded(&env) {
            let cur = policy::get_targets(&env);
            if targets.iter().any(|t| !cur.contains(&t)) {
                let args: Vec<Val> = vec![&env, targets.to_val()];
                let commitment = policy::args_commitment(&env, &args);
                let now = env.ledger().timestamp();
                spend_account_schedule(&env, &policy::act_set_targets(&env), &commitment, now)?;
            }
        }
        policy::set_targets(&env, &targets)?;
        events::TargetsSet { targets }.publish(&env);
        Ok(())
    }

    /// Owner-only. Installs or replaces the agent's policy. A revoked agent id
    /// can never be re-installed (sticky); use a new key.
    ///
    /// While any ad is guarded, a **loosening** write needs a matured `set_policy` schedule
    /// (`schedule_account_extractive`) naming `sha256(XDR(ScVal::Vec(args)))` of this call. Only a
    /// write that is no wider than the live policy on every axis is instant: a new agent key, a new
    /// action, token or ad, a wider or dropped ad scope, a higher cap, capacity or refill, a later or
    /// removed expiry, or a changed settlement signer all count as loosening (`is_policy_tightening`).
    /// An instant tightening keeps the agent's spent buckets rather than refilling them.
    pub fn set_policy(
        env: Env,
        agent_id: BytesN<32>,
        allowed_actions: Vec<Symbol>,
        token_whitelist: Vec<BytesN<32>>,
        valid_until: u64,
        settlement_signer: BytesN<32>,
        ad_scope: Option<Vec<String>>,
        limits: Vec<TokenLimit>,
    ) -> Result<(), AccountError> {
        policy::get_owner(&env).require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        if policy::get_policy(&env, &agent_id).is_some_and(|p| p.revoked) {
            return Err(AccountError::AgentRevoked);
        }
        // Re-installing resets the agent's spend, except an instant tightening on a guarded account,
        // which carries it (else "tighten" would top the agent up). The account-wide bucket binds either way.
        let args: Vec<Val> = vec![
            &env,
            agent_id.to_val(),
            allowed_actions.to_val(),
            token_whitelist.to_val(),
            valid_until.into_val(&env),
            settlement_signer.to_val(),
            ad_scope.into_val(&env),
            limits.to_val(),
        ];
        let mut p = AgentPolicy {
            allowed_actions,
            token_whitelist,
            valid_until,
            revoked: false,
            settlement_signer: settlement_signer.clone(),
            ad_scope,
            limits,
            buckets: Vec::new(&env),
        };
        policy::validate(&env, &p)?;
        if policy::any_guarded(&env) {
            let now = env.ledger().timestamp();
            match policy::get_policy(&env, &agent_id) {
                Some(cur) if policy::is_policy_tightening(&cur, &p) => {
                    policy::carry_buckets(&cur, &mut p, now);
                }
                _ => {
                    let commitment = policy::args_commitment(&env, &args);
                    spend_account_schedule(&env, &policy::act_set_policy(&env), &commitment, now)?;
                }
            }
        }
        let fingerprint = fingerprint::fingerprint(&env, &p)?;
        policy::set_policy(&env, &agent_id, &p);
        events::PolicySet {
            agent_id,
            settlement_signer,
            valid_until,
            fingerprint,
        }
        .publish(&env);
        Ok(())
    }

    /// Owner-only. The account-wide volume limit for one token — the ceiling every agent shares,
    /// so N agents drain one pool instead of getting N private ones (risk 01 F7).
    ///
    /// Re-configuring keeps the live bucket where it is rather than refilling it. An owner who
    /// could reset the aggregate by re-setting the limit would have a cap that resets on demand,
    /// which is the fixed window this replaced.
    ///
    /// While any ad is guarded, a first limit for a token or a higher capacity or refill is
    /// loosening and needs a matured `set_account_limit` schedule naming the call's argument
    /// commitment. Lowering either number stays instant.
    pub fn set_account_limit(
        env: Env,
        token: BytesN<32>,
        limit: Limit,
    ) -> Result<(), AccountError> {
        policy::get_owner(&env).require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        policy::validate_limit(&limit)?;
        let now = env.ledger().timestamp();
        let current = policy::get_account_volume(&env, &token);
        if policy::any_guarded(&env) && !policy::is_limit_tightening(current.as_ref(), &limit) {
            let args: Vec<Val> = vec![&env, token.to_val(), limit.into_val(&env)];
            let commitment = policy::args_commitment(&env, &args);
            spend_account_schedule(&env, &policy::act_set_account_limit(&env), &commitment, now)?;
        }
        let bucket = match current {
            Some(v) => {
                // Settle at the OLD rate first, then re-stamp. Carrying the old `last_ts` into a
                // new limit would re-price the whole idle interval at the new `refill_per_second`:
                // drain the bucket, wait, raise the rate, and the next lock sees a full bucket —
                // the cap-that-resets-on-demand this method exists to prevent, reached through the
                // rate instead of the level. Then clamp, so a lowered capacity applies at once and
                // never tops up.
                let settled = rate_limit::available(&v.limit, &v.bucket, now);
                let level = if settled > limit.capacity {
                    limit.capacity
                } else {
                    settled
                };
                Bucket {
                    level,
                    last_ts: now,
                }
            }
            None => Bucket::full(&limit, now),
        };
        policy::set_account_volume(&env, &token, &policy::AccountVolume { limit, bucket });
        events::AccountLimitSet {
            token,
            capacity: limit.capacity,
            refill_per_second: limit.refill_per_second,
        }
        .publish(&env);
        Ok(())
    }

    /// Owner-only. Arm, tighten, loosen or (with `None`) disarm this ad's guardrail.
    ///
    /// **Arming and tightening are instant; loosening and disarming go through the delay.** Design
    /// 02 §2.8's protective list is every action that *reduces* an attacker's power — that is why
    /// delaying them "only helps an attacker". Relaxing a brake does the opposite. An earlier
    /// version of this made disarming instant on the argument that a thief "waits out" a delay
    /// anyway; that argument defeats the withdrawal timelock it was defending, and the arithmetic
    /// runs the other way. Delay on both: the attacker waits `delay` whichever route they take.
    /// Disarm instant: disarm, then withdraw, and the wait is zero. The delay is not relocated, it
    /// is removed.
    pub fn set_guard_rail(
        env: Env,
        ad_id: String,
        guard_rail: Option<GuardRail>,
    ) -> Result<(), AccountError> {
        policy::get_owner(&env).require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        let now = env.ledger().timestamp();
        let current = policy::get_guard_rail(&env, &ad_id);
        // On the roster with no row is archived, not unarmed: refuse, as the owner path does (C-33).
        if current.is_none() && policy::is_guarded(&env, &ad_id) {
            return Err(AccountError::GuardRailArchived);
        }

        let loosening = match (&current, &guard_rail) {
            // Arming from nothing only ever reduces what the key can do.
            (None, _) => false,
            (Some(_), None) => true,
            (Some(cur), Some(next)) => !policy::is_tightening(cur, next),
        };
        if loosening {
            spend_schedule(&env, &ad_id, &policy::set_guard_rail(&env), 0, None, now)?;
        }

        match guard_rail {
            Some(g) => {
                // A zero delay is a guardrail that does nothing and a zero window one that can
                // never be used; a zero-capacity or zero-refill bucket blocks every sub-threshold
                // withdrawal, which is a brake nobody would leave on. All read as a mis-set field.
                if g.delay == 0 || g.window == 0 {
                    return Err(AccountError::BadGuardRail);
                }
                if g.rate.capacity == 0 || g.rate.refill_per_second == 0 {
                    return Err(AccountError::BadGuardRail);
                }
                // Changing the settings settles the old bucket first, then clamps — the same rule
                // `set_account_limit` follows, and for the same reason: carrying the idle interval
                // into a new rate would re-price it and hand back a full bucket.
                let settled = match &current {
                    Some(cur) => {
                        let level = rate_limit::available(&cur.rate, &cur.bucket, now);
                        if level > g.rate.capacity {
                            g.rate.capacity
                        } else {
                            level
                        }
                    }
                    None => g.rate.capacity,
                };
                let armed = GuardRail {
                    bucket: Bucket {
                        level: settled,
                        last_ts: now,
                    },
                    ..g
                };
                // The delays pending rows were timed under, read before this write changes them.
                let ad_delay_before = current.as_ref().map(|c| c.delay).unwrap_or(0);
                let account_delay_before =
                    policy::account_timelock(&env).map(|(d, _)| d).unwrap_or(0);
                policy::put_guard_rail(&env, &ad_id, &armed)?;
                // Settings the schedules were made under are gone, so the schedules go with them.
                if loosening {
                    policy::clear_all_schedules(&env, &ad_id);
                } else {
                    // 49S-1: a pending change waits the NEW delay, or a stolen key's 1-day upgrade
                    // lands after the owner arms a 7-day guard. Only a delay that rises re-stamps:
                    // a threshold-only tightening leaves pending clocks alone.
                    if armed.delay > ad_delay_before {
                        policy::restamp_ad_schedules(&env, &ad_id, now + armed.delay);
                    }
                    if armed.delay > account_delay_before {
                        policy::restamp_account_schedules(&env, now + armed.delay);
                    }
                }
                events::GuardRailSet {
                    ad_id,
                    armed: true,
                    threshold: armed.threshold,
                    delay: armed.delay,
                    window: armed.window,
                }
                .publish(&env);
            }
            None => {
                policy::remove_guard_rail(&env, &ad_id);
                policy::clear_all_schedules(&env, &ad_id);
                events::GuardRailSet {
                    ad_id,
                    armed: false,
                    threshold: 0,
                    delay: 0,
                    window: 0,
                }
                .publish(&env);
            }
        }
        Ok(())
    }

    /// Owner-only. Announce an extractive call and start its clock.
    ///
    /// The account cannot delay a call — `__check_auth` answers yes or no — so the timelock is two
    /// transactions: this one, then the call itself once the delay has elapsed. `amount` and `to`
    /// are stored and later compared exactly, or a schedule for a small withdrawal would authorize
    /// a large one, or one to a different address.
    pub fn schedule_extractive(
        env: Env,
        ad_id: String,
        action: Symbol,
        amount: u128,
        to: Address,
    ) -> Result<(), AccountError> {
        policy::get_owner(&env).require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        let withdraw = policy::withdraw_from_ad(&env);
        let close = policy::close_ad(&env);
        let guard_change = policy::set_guard_rail(&env);
        if action != withdraw && action != close && action != guard_change {
            return Err(AccountError::ActionNotAllowed);
        }
        // Only `withdraw_from_ad` has an amount to match. Accepting one for the others would store
        // a row that can never be spent, while the event published it as though it meant something.
        if action != withdraw && amount != 0 {
            return Err(AccountError::BadGuardRail);
        }
        let g = guard_rail_for_schedule(&env, &ad_id)?;
        let (ready_at, expires_at) = window_from_now(&env, g.delay, g.window)?;
        let s = policy::Schedule {
            amount,
            to: to.clone(),
            ready_at,
            expires_at,
        };
        policy::set_schedule(&env, &ad_id, &action, &s);
        events::ExtractiveScheduled {
            ad_id,
            action,
            amount,
            to,
            ready_at,
            expires_at,
        }
        .publish(&env);
        Ok(())
    }

    /// Owner-only. Schedule an above-threshold owner `lock_for_order` on a guarded ad (C-32).
    ///
    /// `amount` is the ad-side amount the escrow will lock and `commitment` is
    /// `sha256(XDR(ScVal::Vec([order])))`, so the schedule authorizes that one order and nothing
    /// else. One pending lock per ad; a new one replaces it. Cancel with `cancel_extractive`.
    pub fn schedule_lock(
        env: Env,
        ad_id: String,
        amount: u128,
        commitment: BytesN<32>,
    ) -> Result<(), AccountError> {
        policy::get_owner(&env).require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        let g = guard_rail_for_schedule(&env, &ad_id)?;
        let (ready_at, expires_at) = window_from_now(&env, g.delay, g.window)?;
        policy::set_lock_schedule(
            &env,
            &ad_id,
            &BoundSchedule {
                commitment: commitment.clone(),
                amount,
                ready_at,
                expires_at,
            },
        );
        events::LockScheduled {
            ad_id,
            amount,
            commitment,
            ready_at,
            expires_at,
        }
        .publish(&env);
        Ok(())
    }

    /// Owner-only. Stand a schedule down — the lever an owner reaches for on seeing an
    /// `ExtractiveScheduled` event they did not cause. `lock_for_order` cancels the ad's lock
    /// schedule.
    pub fn cancel_extractive(env: Env, ad_id: String, action: Symbol) -> Result<(), AccountError> {
        policy::get_owner(&env).require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        // Existence checked, so the audit trail this event exists for does not fill with
        // cancellations of schedules that were never made.
        if action == policy::lock_for_order(&env) {
            if policy::get_lock_schedule(&env, &ad_id).is_none() {
                return Err(AccountError::NotScheduled);
            }
            policy::clear_lock_schedule(&env, &ad_id);
        } else {
            if policy::get_schedule(&env, &ad_id, &action).is_none() {
                return Err(AccountError::NotScheduled);
            }
            policy::clear_schedule(&env, &ad_id, &action);
        }
        events::ExtractiveCancelled { ad_id, action }.publish(&env);
        Ok(())
    }

    /// Owner-only. Announce an account-wide change (D6): `upgrade` (commitment = the new wasm
    /// hash), or a loosening `set_policy` / `set_account_limit` / `set_targets` (commitment =
    /// `sha256(XDR(ScVal::Vec(args)))` of that call). The delay is the longest and the window the
    /// shortest across every guarded ad. One pending row per action; a new one replaces it.
    pub fn schedule_account_extractive(
        env: Env,
        action: Symbol,
        commitment: BytesN<32>,
    ) -> Result<(), AccountError> {
        policy::get_owner(&env).require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        if !policy::account_actions(&env).contains(&action) {
            return Err(AccountError::ActionNotAllowed);
        }
        let (delay, window) = policy::account_timelock(&env)?;
        let (ready_at, expires_at) = window_from_now(&env, delay, window)?;
        policy::set_account_schedule(
            &env,
            &action,
            &BoundSchedule {
                commitment: commitment.clone(),
                amount: 0,
                ready_at,
                expires_at,
            },
        );
        events::AccountExtractiveScheduled {
            action,
            commitment,
            ready_at,
            expires_at,
        }
        .publish(&env);
        Ok(())
    }

    /// Owner-only. Stand an account-wide schedule down.
    pub fn cancel_account_extractive(env: Env, action: Symbol) -> Result<(), AccountError> {
        policy::get_owner(&env).require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        if policy::get_account_schedule(&env, &action).is_none() {
            return Err(AccountError::NotScheduled);
        }
        policy::clear_account_schedule(&env, &action);
        events::AccountExtractiveCancelled { action }.publish(&env);
        Ok(())
    }

    pub fn lock_schedule(env: Env, ad_id: String) -> Option<BoundSchedule> {
        policy::get_lock_schedule(&env, &ad_id)
    }

    pub fn account_schedule(env: Env, action: Symbol) -> Option<BoundSchedule> {
        policy::get_account_schedule(&env, &action)
    }

    pub fn guard_rail(env: Env, ad_id: String) -> Option<GuardRail> {
        policy::get_guard_rail(&env, &ad_id)
    }

    pub fn guarded_ads(env: Env) -> Vec<String> {
        policy::guarded_ads(&env)
    }

    pub fn schedule(env: Env, ad_id: String, action: Symbol) -> Option<policy::Schedule> {
        policy::get_schedule(&env, &ad_id, &action)
    }

    /// The canonical fingerprint of a **live** policy — the value the EVM module stores for the same
    /// agent — and all zeroes when there is none or it is revoked, which is what the EVM's
    /// `fingerprintOf` answers, so a consumer comparing the chains reads "no agent here" the same
    /// way on both. The pure hash ignores `revoked` on purpose; it is this view that must not.
    pub fn policy_fingerprint(env: Env, agent_id: BytesN<32>) -> Result<BytesN<32>, AccountError> {
        match policy::get_policy(&env, &agent_id) {
            Some(p) if !p.revoked => fingerprint::fingerprint(&env, &p),
            _ => Ok(BytesN::from_array(&env, &[0u8; 32])),
        }
    }

    /// Owner-only, instant, idempotent: the agent's next signed call fails.
    /// Orders already co-signed under the agent's BLS key still settle through
    /// the registry; retire the slot there (2.1e wires that off the event).
    pub fn revoke_agent(env: Env, agent_id: BytesN<32>) -> Result<(), AccountError> {
        policy::get_owner(&env).require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        let mut p = policy::get_policy(&env, &agent_id).ok_or(AccountError::NoPolicyForAgent)?;
        if p.revoked {
            return Ok(());
        }
        p.revoked = true;
        policy::set_policy(&env, &agent_id, &p);
        events::AgentRevoked { agent_id }.publish(&env);
        Ok(())
    }

    /// Owner-only. Replaces this account's code; storage (owner, targets, policies) stays.
    /// While any ad is guarded it needs a matured `upgrade` schedule naming exactly this wasm
    /// hash (C-5). Call `migrate` next: the swap lands after this call returns, so a version
    /// written here would be the old code's (C-40).
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) -> Result<(), AccountError> {
        policy::get_owner(&env).require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        if policy::any_guarded(&env) {
            let now = env.ledger().timestamp();
            spend_account_schedule(&env, &policy::act_upgrade(&env), &new_wasm_hash, now)?;
        }
        env.deployer()
            .update_current_contract(ContractExecutable::Wasm(new_wasm_hash.clone()));
        events::Upgraded { new_wasm_hash }.publish(&env);
        Ok(())
    }

    /// Owner-only. Runs under the new code after `upgrade` and moves the schema marker to what
    /// this code expects. Policies migrate lazily on read (`policy::get_policy`); a marker newer
    /// than this code is a downgrade and is refused.
    pub fn migrate(env: Env) -> Result<u32, AccountError> {
        policy::get_owner(&env).require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        let from = policy::get_schema_version(&env);
        if from > SCHEMA_VERSION {
            return Err(AccountError::SchemaTooNew);
        }
        policy::set_schema_version(&env);
        events::Migrated {
            from,
            to: SCHEMA_VERSION,
        }
        .publish(&env);
        Ok(SCHEMA_VERSION)
    }

    // ---- views ----

    pub fn owner(env: Env) -> Address {
        policy::get_owner(&env)
    }

    pub fn targets(env: Env) -> Vec<Address> {
        policy::get_targets(&env)
    }

    pub fn policy(env: Env, agent_id: BytesN<32>) -> Option<AgentPolicy> {
        policy::get_policy(&env, &agent_id)
    }

    /// True iff a policy exists and is revoked (the sticky tombstone).
    pub fn is_revoked(env: Env, agent_id: BytesN<32>) -> bool {
        policy::get_policy(&env, &agent_id).is_some_and(|p| p.revoked)
    }

    pub fn schema_version(env: Env) -> u32 {
        policy::get_schema_version(&env)
    }
}

/// The ad's guardrail for a new schedule: `NoGuardRail` off the roster, `GuardRailArchived` on it.
fn guard_rail_for_schedule(env: &Env, ad_id: &String) -> Result<GuardRail, AccountError> {
    match policy::get_guard_rail(env, ad_id) {
        Some(g) => Ok(g),
        None if policy::is_guarded(env, ad_id) => Err(AccountError::GuardRailArchived),
        None => Err(AccountError::NoGuardRail),
    }
}

/// `(ready_at, expires_at)` from now. Checked: an absurd delay is an error the owner can act on,
/// not an opaque overflow panic.
fn window_from_now(env: &Env, delay: u64, window: u64) -> Result<(u64, u64), AccountError> {
    let now = env.ledger().timestamp();
    let ready_at = now.checked_add(delay).ok_or(AccountError::BadGuardRail)?;
    let expires_at = ready_at
        .checked_add(window)
        .ok_or(AccountError::BadGuardRail)?;
    Ok((ready_at, expires_at))
}

#[contractimpl(contracttrait)]
impl CustomAccountInterface for AgentAccount {
    type Signature = AccountSig;
    type Error = AccountError;

    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signature: AccountSig,
        auth_contexts: Vec<Context>,
    ) -> Result<(), AccountError> {
        proofbridge_core::ttl::extend_instance(&env);
        let agent_id = match signature {
            AccountSig::Owner => {
                // The owner authorizes this exact payload (not the whole
                // __check_auth frame) in its own auth entry. Sovereign: no context
                // inspection, so create_ad/fund_ad's token transfer sub-context passes.
                let payload: BytesN<32> = signature_payload.to_bytes();
                policy::get_owner(&env).require_auth_for_args(vec![&env, payload.into_val(&env)]);
                // 2.1e: the owner path used to stop here. It still authorizes everything the owner
                // could do before — only the two extractive escrow calls, and only on a guarded ad,
                // now have to have been announced first.
                // Every contract context, not just the pinned escrows. Filtering on `targets` here
                // meant `set_targets` — owner-only and instant — could point them elsewhere and
                // remove the guard without touching it. `check_owner_call` keys on the selector and
                // the ad, so an unrelated contract is only ever refused for an ad this owner armed.
                for ctx in auth_contexts.iter() {
                    if let Context::Contract(c) = ctx {
                        escrow::check_owner_call(&env, &c)?;
                    }
                }
                return Ok(());
            }
            AccountSig::Agent(s) => auth::verify_ed25519(&env, &signature_payload, &s),
            AccountSig::AgentSecp(s) => auth::verify_secp(&env, &signature_payload, &s)?,
        };

        let mut p = policy::get_policy(&env, &agent_id).ok_or(AccountError::NoPolicyForAgent)?;
        if p.revoked {
            return Err(AccountError::AgentRevoked);
        }
        if p.valid_until != 0 && env.ledger().timestamp() >= p.valid_until {
            return Err(AccountError::PolicyExpired);
        }
        policy::touch_policy(&env, &agent_id);

        if auth_contexts.is_empty() {
            return Err(AccountError::UnsupportedContext);
        }
        let targets = policy::get_targets(&env);
        for ctx in auth_contexts.iter() {
            match ctx {
                Context::Contract(c) => escrow::check_contract_call(&env, &targets, &mut p, &c)?,
                // An agent never creates contracts or moves funds directly.
                // 2.1f revisits CAP-85 variants; today anything else fails closed.
                _ => return Err(AccountError::UnsupportedContext),
            }
        }
        // Once, after every context: `p` carries the volume debited by all of them. A failure
        // anywhere above returns Err and the host discards the whole frame, so there is no
        // half-applied state to undo here.
        policy::set_policy(&env, &agent_id, &p);
        Ok(())
    }
}

#[cfg(test)]
mod test;

#[cfg(test)]
mod fingerprint_test;

#[cfg(test)]
mod parity_test;
