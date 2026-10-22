//! AgentAccount — a maker's Soroban custom account (2.1c, #325).
//!
//! The account is the ad's maker on the AdManager escrow and an authorization gateway: it never
//! holds what the owner pays in (plan 46). Funds can still come to rest in it, a withdrawal or close
//! paid to the account itself, a refunded dispute bond, a claimed credit, and leave only through
//! `sweep`, timed while any ad is guarded. Two parties act through it:
//!   - the **owner** (any `Address`, G or C, never this account) calls the account's own
//!     functions with ordinary transactions: the configuration setters, and the ad actions
//!     `create_ad` / `fund_ad` / `call` / `sweep` (owner.rs). Money the owner pays in goes from the
//!     owner's wallet to the escrow in the same call. The guard rail runs on every extractive one;
//!   - an **agent** signs the Soroban auth payload and may only make calls that
//!     pass `check_contract_call`: a pinned escrow, the policy's action, and
//!     lock args inside its policy (ad and order token lists, per-order cap,
//!     settlement identity). Never guarded by open orders; `revoke_agent` is instant.
//!
//! The owner no longer signs *as* the account (`AccountSig::Owner` is refused): that path let a
//! direct token transfer out past the guard rail, and needs an auth entry some wallets can't sign.
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

mod args;
mod auth;
mod errors;
mod escrow;
mod events;
mod owner;
mod policy;

use soroban_sdk::{
    auth::{Context, CustomAccountInterface, InvokerContractAuthEntry},
    contract, contractimpl,
    crypto::Hash,
    vec, Address, BytesN, ContractExecutable, Env, IntoVal, String, Symbol, TryFromVal, Val, Vec,
};

use escrow::spend;
use policy::{GuardRail, TokenLimit};
use proofbridge_core::rate_limit::{self, Bucket, Limit};

pub use auth::{AccountSig, Ed25519Sig, SecpSig};
pub use errors::AccountError;
pub use escrow::settlement_signer_of;
pub use policy::{
    lock_for_order, AccountVolume, AgentId, AgentPolicy, Schedule, Scope, MAX_AD_ID_BYTES,
    MAX_AD_SCOPE, MAX_GUARD_DELAY, MAX_TARGETS, MAX_VALID_UNTIL, MAX_WHITELIST_TOKENS,
    MIN_GUARD_WINDOW, SCHEMA_VERSION,
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
                let now = env.ledger().timestamp();
                spend(
                    &env,
                    &Scope::Account,
                    &policy::act_set_targets(&env),
                    &args,
                    now,
                )?;
            }
        }
        policy::set_targets(&env, &targets)?;
        events::TargetsSet { targets }.publish(&env);
        Ok(())
    }

    /// Owner-only. Installs or replaces the agent's policy. A revoked agent id
    /// can never be re-installed (sticky); use a new key.
    ///
    /// While any ad is guarded, a **loosening** write needs a matured
    /// `schedule(Account, set_policy, args)` for exactly this call's arguments. Only a
    /// write that is no wider than the live policy on every axis is instant: a new agent key, a
    /// changed action, a new ad token, order token or ad, a wider or dropped ad scope, a higher cap,
    /// capacity or refill, a later or removed expiry, or a changed settlement signer all count as
    /// loosening (`is_policy_tightening`). An instant tightening keeps the agent's spent buckets
    /// rather than refilling them.
    ///
    /// `PolicySet` carries every installed field, so a watcher computes the policy's fingerprint
    /// off chain (`@proofbridge/order-params`) without a storage read.
    pub fn set_policy(
        env: Env,
        agent_id: BytesN<32>,
        allowed_action: Symbol,
        ad_tokens: Vec<TokenLimit>,
        order_tokens: Vec<BytesN<32>>,
        valid_until: u64,
        settlement_signer: BytesN<32>,
        ad_scope: Option<Vec<String>>,
    ) -> Result<(), AccountError> {
        policy::get_owner(&env).require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        // An all-zero id is no key at all; the EVM module refuses it too (plan 46 D11).
        if proofbridge_core::auth::is_zero_bytes32(&agent_id) {
            return Err(AccountError::BadPolicy);
        }
        if policy::get_policy(&env, &agent_id).is_some_and(|p| p.revoked) {
            return Err(AccountError::AgentRevoked);
        }
        // Re-installing resets the agent's spend, except an instant tightening on a guarded account,
        // which carries it (else "tighten" would top the agent up). The account-wide bucket binds either way.
        let args: Vec<Val> = vec![
            &env,
            agent_id.to_val(),
            allowed_action.to_val(),
            ad_tokens.to_val(),
            order_tokens.to_val(),
            valid_until.into_val(&env),
            settlement_signer.to_val(),
            ad_scope.into_val(&env),
        ];
        let mut p = AgentPolicy {
            allowed_action,
            ad_tokens,
            order_tokens,
            valid_until,
            revoked: false,
            settlement_signer,
            ad_scope,
            buckets: Vec::new(&env),
        };
        policy::validate(&env, &p)?;
        if policy::any_guarded(&env) {
            let now = env.ledger().timestamp();
            match policy::get_policy(&env, &agent_id) {
                Some(cur) if policy::is_policy_tightening(&cur, &p) => {
                    policy::carry_buckets(&cur, &mut p, now);
                }
                _ => spend(
                    &env,
                    &Scope::Account,
                    &policy::act_set_policy(&env),
                    &args,
                    now,
                )?,
            }
        }
        policy::set_policy(&env, &agent_id, &p);
        events::PolicySet {
            agent_id,
            allowed_action: p.allowed_action,
            ad_tokens: p.ad_tokens,
            order_tokens: p.order_tokens,
            ad_scope: p.ad_scope,
            valid_until: p.valid_until,
            settlement_signer: p.settlement_signer,
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
    /// loosening and needs a matured `schedule(Account, set_account_limit, [token, limit])`.
    /// Lowering either number stays instant.
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
            spend(
                &env,
                &Scope::Account,
                &policy::act_set_account_limit(&env),
                &args,
                now,
            )?;
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
    ///
    /// A loosening or disarm spends `schedule(Ad(ad_id), set_guard_rail, [ad_id, guard_rail])` for
    /// exactly these values: a schedule for one loosening authorizes that one, not any loosening,
    /// and a disarm needs a schedule committed to `None`.
    pub fn set_guard_rail(
        env: Env,
        ad_id: String,
        guard_rail: Option<GuardRail>,
    ) -> Result<(), AccountError> {
        policy::get_owner(&env).require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        let now = env.ledger().timestamp();
        if let Some(g) = &guard_rail {
            policy::check_guard_bounds(g)?;
        }
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
            let args = args::guard_rail_args(&env, &ad_id, &guard_rail);
            spend(
                &env,
                &Scope::Ad(ad_id.clone()),
                &policy::set_guard_rail(&env),
                &args,
                now,
            )?;
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
                // The delays and windows pending rows were timed under, read before this write
                // changes them.
                let ad_delay_before = current.as_ref().map(|c| c.delay).unwrap_or(0);
                let ad_window_before = current.as_ref().map(|c| c.window).unwrap_or(u64::MAX);
                let (account_delay_before, account_window_before) =
                    policy::account_timelock(&env).unwrap_or((0, u64::MAX));
                policy::put_guard_rail(&env, &ad_id, &armed)?;
                // Settings the schedules were made under are gone, so the schedules go with them.
                if loosening {
                    policy::clear_all_schedules(&env, &ad_id);
                } else {
                    // 49S-1: a pending change waits the NEW delay, or a stolen key's 1-day upgrade
                    // lands after the owner arms a 7-day guard. Only a delay that rises re-stamps:
                    // a threshold-only tightening leaves pending clocks alone.
                    if armed.delay > ad_delay_before {
                        policy::restamp(&env, &Scope::Ad(ad_id.clone()), now + armed.delay);
                    }
                    if armed.delay > account_delay_before {
                        policy::restamp(&env, &Scope::Account, now + armed.delay);
                    }
                    // 81-6: and closes within the NEW window, after any restamp moved it.
                    if armed.window < ad_window_before {
                        policy::clamp_windows(&env, &Scope::Ad(ad_id.clone()), armed.window);
                    }
                    if let Ok((_, w)) = policy::account_timelock(&env) {
                        if w < account_window_before {
                            policy::clamp_windows(&env, &Scope::Account, w);
                        }
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

    /// Owner-only. 81-7: take the rail off an ad this account closed, at once. The ad must be on a
    /// pinned escrow, this account's, not open, empty and with nothing locked: a dead ad has nothing
    /// left to extract, so its rail only holds the roster (16 ads at most) and the account-wide delay.
    /// Its schedules go with it, as on any disarm. A live ad's rail, and any whose removal would lower
    /// the account-wide delay or lengthen its window (P3-80-a; the last guarded ad always does), still
    /// come off only through `set_guard_rail(None)`.
    pub fn disarm_closed_ad(env: Env, escrow: Address, ad_id: String) -> Result<(), AccountError> {
        policy::get_owner(&env).require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        owner::require_target(&env, &escrow)?;
        if !policy::is_guarded(&env, &ad_id) {
            return Err(AccountError::NoGuardRail);
        }
        if !owner::is_closed_ad(&env, &escrow, &ad_id)? {
            return Err(AccountError::AdNotClosed);
        }
        // P3-80-a: never at once if it lowers the account's delay or lengthens its window (the last ad
        // always does); arming is instant and unchecked, so the roster's size proves nothing
        let (delay, window) = policy::timelock_without(&env, None)?;
        let (delay_after, window_after) = policy::timelock_without(&env, Some(&ad_id))?;
        if delay_after < delay || window_after > window {
            return Err(AccountError::DisarmLowersTimelock);
        }
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
        Ok(())
    }

    /// Owner-only. Announce a delayed call and start its clock.
    ///
    /// The account cannot delay a call (`__check_auth` answers yes or no), so the timelock is two
    /// transactions: this one, then the call itself once the delay has elapsed. `args` is the exact
    /// argument list of that call, in call order; only `args_commitment(args)` is stored, and the
    /// call must match it. Per scope:
    ///   - `Ad(ad_id)`: `withdraw_from_ad [ad_id, amount, to]`, `close_ad [ad_id, to]`,
    ///     `lock_for_order [order]`, `set_guard_rail [ad_id, Option<GuardRail>]`,
    ///     `set_settlement_signer [ad_id, identity]` (R2); timed by that ad's guardrail.
    ///   - `Account`: `upgrade [new_wasm_hash]`, `sweep [token, to, amount]`,
    ///     `resume_settlement [maker]` (R2), and the loosening `set_policy` / `set_account_limit` /
    ///     `set_targets` with their own arguments; timed by the longest delay and shortest window
    ///     across every guarded ad (D6).
    ///
    /// The args must have the call's shape (`BadArgs`) and, on an ad, name that ad
    /// (`ScopeMismatch`). `set_guard_rail` is committed with its bucket zeroed (live state the
    /// write re-stamps). The `Scheduled` event carries the args in clear, except `set_policy`'s,
    /// which can exceed the network event limit and carry the commitment only.
    ///
    /// One pending row per (scope, action); a new one replaces it.
    pub fn schedule(
        env: Env,
        scope: Scope,
        action: Symbol,
        args: Vec<Val>,
    ) -> Result<(), AccountError> {
        policy::get_owner(&env).require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        // The action must belong to the scope (each decoder refuses any other with
        // `ActionNotAllowed`), its args must be the call's own shape and, on an ad, name that ad: a
        // schedule that could never be spent would still publish an event a watcher reads as a
        // pending call.
        let mut args = args;
        let (delay, window) = match &scope {
            Scope::Ad(ad_id) => {
                let (named, _) = args::decode_ad_call(&env, &action, &args)?;
                if &named != ad_id {
                    return Err(AccountError::ScopeMismatch);
                }
                if action == policy::set_guard_rail(&env) {
                    let g: Option<GuardRail> = args
                        .get(1)
                        .and_then(|v| Option::<GuardRail>::try_from_val(&env, &v).ok())
                        .ok_or(AccountError::BadArgs)?;
                    // R1: a change that could never be made can't be announced either.
                    if let Some(next) = &g {
                        policy::check_guard_bounds(next)?;
                    }
                    args = args::guard_rail_args(&env, ad_id, &g);
                }
                let g = guard_rail_for_schedule(&env, ad_id)?;
                (g.delay, g.window)
            }
            Scope::Account => {
                args::check_account_call(&env, &action, &args)?;
                policy::account_timelock(&env)?
            }
        };
        let (ready_at, expires_at) = window_from_now(&env, delay, window)?;
        let commitment = policy::args_commitment(&env, &args);
        policy::set_schedule(
            &env,
            &scope,
            &action,
            &Schedule {
                commitment: commitment.clone(),
                ready_at,
                expires_at,
            },
        );
        // A maximal `set_policy`'s args (16 ad ids of 1,024 bytes, 16 token limits) measure 21 KB of
        // event against the network's 16,384-byte limit, so its event carries the commitment alone;
        // the policy itself is published by `PolicySet` when it is applied. Every other action's
        // args are small and ride in clear.
        let args = if action == policy::act_set_policy(&env) {
            Vec::new(&env)
        } else {
            args
        };
        events::Scheduled {
            scope,
            action,
            args,
            commitment,
            ready_at,
            expires_at,
        }
        .publish(&env);
        Ok(())
    }

    /// Owner-only. Stand a schedule down: the lever an owner reaches for on seeing a `Scheduled`
    /// event they did not cause.
    pub fn cancel(env: Env, scope: Scope, action: Symbol) -> Result<(), AccountError> {
        policy::get_owner(&env).require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        // Existence checked, so the audit trail this event exists for does not fill with
        // cancellations of schedules that were never made.
        if policy::get_schedule(&env, &scope, &action).is_none() {
            return Err(AccountError::NotScheduled);
        }
        policy::clear_schedule(&env, &scope, &action);
        events::Cancelled { scope, action }.publish(&env);
        Ok(())
    }

    /// The pending schedule for (scope, action), if any. Named apart from `schedule` because
    /// Soroban exports are flat names.
    pub fn scheduled(env: Env, scope: Scope, action: Symbol) -> Option<Schedule> {
        policy::get_schedule(&env, &scope, &action)
    }

    pub fn guard_rail(env: Env, ad_id: String) -> Option<GuardRail> {
        policy::get_guard_rail(&env, &ad_id)
    }

    /// The account-wide (longest delay, shortest window); (0, u64::MAX) with nothing guarded.
    pub fn account_timelock(env: Env) -> Result<(u64, u64), AccountError> {
        policy::timelock_without(&env, None)
    }

    /// The same with `ad_id` left out: `disarm_closed_ad` refuses when its delay is lower or its window
    /// longer.
    pub fn account_timelock_without(env: Env, ad_id: String) -> Result<(u64, u64), AccountError> {
        policy::timelock_without(&env, Some(&ad_id))
    }

    pub fn guarded_ads(env: Env) -> Vec<String> {
        policy::guarded_ads(&env)
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
    /// While any ad is guarded it needs a matured `schedule(Account, upgrade, [new_wasm_hash])`
    /// for exactly this hash (C-5). Call `migrate` next: the swap lands after this call returns, so a version
    /// written here would be the old code's (C-40).
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) -> Result<(), AccountError> {
        policy::get_owner(&env).require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        if policy::any_guarded(&env) {
            let now = env.ledger().timestamp();
            let args: Vec<Val> = vec![&env, new_wasm_hash.to_val()];
            spend(
                &env,
                &Scope::Account,
                &policy::act_upgrade(&env),
                &args,
                now,
            )?;
        }
        env.deployer()
            .update_current_contract(ContractExecutable::Wasm(new_wasm_hash.clone()));
        events::Upgraded { new_wasm_hash }.publish(&env);
        Ok(())
    }

    /// Owner-only. Runs under the new code after `upgrade` and moves the schema marker to what
    /// this code expects. A marker newer than this code is a downgrade and is refused.
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

    // ---- the owner's ad actions (plan 46) ----

    /// Owner-only. Opens an ad with this account as its maker, funded from the owner's wallet in
    /// this one call: the amount comes in from the owner and goes straight on to the escrow, so the
    /// account holds nothing before or after (plan 46 D2). `ad_manager` must be a pinned target.
    /// `token` is the contract the escrow pulls: the ad token's own, or the escrow's wrapped native
    /// token for XLM (`get_config`); any mismatch fails the escrow's pull and reverts everything.
    pub fn create_ad(
        env: Env,
        ad_manager: Address,
        token: Address,
        ad_id: String,
        ad_token: BytesN<32>,
        amount: u128,
        order_chain_id: u128,
        ad_recipient: BytesN<32>,
        settlement_signer: BytesN<32>,
    ) -> Result<(), AccountError> {
        let owner = policy::get_owner(&env);
        owner.require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        owner::require_target(&env, &ad_manager)?;
        owner::require_ad_token(&env, &token, &ad_token)?;
        let me = env.current_contract_address();
        let args: Vec<Val> = vec![
            &env,
            me.to_val(),
            ad_id.to_val(),
            ad_token.to_val(),
            amount.into_val(&env),
            order_chain_id.into_val(&env),
            ad_recipient.to_val(),
            settlement_signer.to_val(),
        ];
        owner::pay_through(&env, &owner, &token, amount, &ad_manager, |env| {
            env.invoke_contract::<()>(&ad_manager, &Symbol::new(env, "create_ad"), args);
        })
    }

    /// Owner-only. Adds liquidity to one of this account's ads, from the owner's wallet in this one
    /// call, as `create_ad`. `token` as there, checked against the ad the escrow holds (80-8).
    pub fn fund_ad(
        env: Env,
        ad_manager: Address,
        token: Address,
        ad_id: String,
        amount: u128,
    ) -> Result<(), AccountError> {
        let owner = policy::get_owner(&env);
        owner.require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        owner::require_target(&env, &ad_manager)?;
        owner::require_ad_token(
            &env,
            &token,
            &owner::ad_token_of(&env, &ad_manager, &ad_id)?,
        )?;
        let args: Vec<Val> = vec![&env, ad_id.to_val(), amount.into_val(&env)];
        owner::pay_through(&env, &owner, &token, amount, &ad_manager, |env| {
            env.invoke_contract::<()>(&ad_manager, &Symbol::new(env, "fund_ad"), args);
        })
    }

    /// Owner-only. Any other call on a pinned escrow as this account: withdraw, close, a manual
    /// lock, a dispute and its response, the settlement signer, halt and resume. The guard rail runs
    /// first (an extractive call on a guarded ad needs its matured schedule).
    ///
    /// `pay` optionally brings `(token, amount)` in from the owner's wallet for the call (a dispute's
    /// bond). `approvals` are the nested calls the escrow will make as this account, as simulating
    /// the call reports them: a token `transfer` from this account, or an `open_dispute` whose
    /// nested calls are only such transfers. The account's balance of every token involved must be
    /// the same afterwards, so an approval only ever forwards what this call paid in.
    pub fn call(
        env: Env,
        target: Address,
        fn_name: Symbol,
        args: Vec<Val>,
        pay: Option<(Address, u128)>,
        approvals: Vec<InvokerContractAuthEntry>,
    ) -> Result<Val, AccountError> {
        let owner = policy::get_owner(&env);
        owner.require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        owner::require_target(&env, &target)?;
        escrow::check_owner_call(&env, &fn_name, &args)?;
        owner::call_with(&env, &owner, &target, &fn_name, args, pay, approvals)
    }

    /// Owner-only. The one way out for funds at rest in the account (a refunded dispute bond, a
    /// claimed credit). While any ad is guarded it needs a matured
    /// `schedule(Account, sweep, [token, to, amount])` for exactly this call.
    pub fn sweep(env: Env, token: Address, to: Address, amount: u128) -> Result<(), AccountError> {
        policy::get_owner(&env).require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        if policy::any_guarded(&env) {
            let now = env.ledger().timestamp();
            let args: Vec<Val> = vec![&env, token.to_val(), to.to_val(), amount.into_val(&env)];
            spend(&env, &Scope::Account, &policy::act_sweep(&env), &args, now)?;
        }
        soroban_sdk::token::TokenClient::new(&env, &token).transfer(
            &env.current_contract_address(),
            &to,
            &owner::to_i128(amount)?,
        );
        Ok(())
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

    /// The account-wide volume limit and its live bucket for one token (plan 46 D11, as the EVM
    /// module's `accountLimit` / `accountBucket`).
    pub fn account_volume(env: Env, token: BytesN<32>) -> Option<AccountVolume> {
        policy::get_account_volume(&env, &token)
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
            // Plan 46: the owner acts through `create_ad` / `fund_ad` / `call` / `sweep`, never by
            // signing as the account. Accepting it here would let a direct token transfer out of the
            // account past the guard rail, and needs an auth entry xBull and LOBSTR can't sign.
            AccountSig::Owner => return Err(AccountError::OwnerPathRetired),
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
mod parity_test;
