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
//! ads. Once 2.1e adds the extractive-action timelock, `upgrade` sits behind it.
//!
//! Volume buckets and `min_rate` are 2.1d; the revoke → retirement runtime
//! wiring and the extractive timelock are 2.1e; CAP-85 tolerance is 2.1f.

#![no_std]

mod auth;
mod errors;
mod escrow;
mod events;
mod policy;

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl,
    crypto::Hash,
    vec, Address, BytesN, ContractExecutable, Env, IntoVal, String, Symbol, Vec,
};

use escrow::spend_schedule;
use policy::{Guardrail, TokenLimit};
use proofbridge_core::rate_limit::{self, Bucket, Limit};

pub use auth::{AccountSig, Ed25519Sig, SecpSig};
pub use errors::AccountError;
pub use escrow::{required_settlement_signer, settlement_signer_of};
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

    /// Owner-only. Needed across an escrow redeploy.
    pub fn set_targets(env: Env, targets: Vec<Address>) -> Result<(), AccountError> {
        policy::get_owner(&env).require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        policy::set_targets(&env, &targets)?;
        events::TargetsSet { targets }.publish(&env);
        Ok(())
    }

    /// Owner-only. Installs or replaces the agent's policy. A revoked agent id
    /// can never be re-installed (sticky); use a new key.
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
        // Re-installing resets the agent's spend. That is the owner's call by construction: a
        // policy write is the owner saying what the agent may do from now on, and carrying a
        // half-drained bucket across a deliberate re-configure would make the new limits a lie.
        // The account-wide bucket is untouched, so the aggregate still binds across the reset.
        let p = AgentPolicy {
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
        policy::set_policy(&env, &agent_id, &p);
        events::PolicySet {
            agent_id,
            settlement_signer,
            valid_until,
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
    pub fn set_account_limit(
        env: Env,
        token: BytesN<32>,
        limit: Limit,
    ) -> Result<(), AccountError> {
        policy::get_owner(&env).require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        policy::validate_limit(&limit)?;
        let now = env.ledger().timestamp();
        let bucket = match policy::get_account_volume(&env, &token) {
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
        events::AccountLimitSet { token }.publish(&env);
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
    pub fn set_guardrail(
        env: Env,
        ad_id: String,
        guardrail: Option<Guardrail>,
    ) -> Result<(), AccountError> {
        policy::get_owner(&env).require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        let now = env.ledger().timestamp();
        let current = policy::get_guardrail(&env, &ad_id);

        let loosening = match (&current, &guardrail) {
            // Arming from nothing only ever reduces what the key can do.
            (None, _) => false,
            (Some(_), None) => true,
            (Some(cur), Some(next)) => !policy::is_tightening(cur, next),
        };
        if loosening {
            spend_schedule(&env, &ad_id, &policy::set_guardrail(&env), 0, None, now)?;
        }

        match guardrail {
            Some(g) => {
                // A zero delay is a guardrail that does nothing and a zero window one that can
                // never be used; a zero-capacity or zero-refill bucket blocks every sub-threshold
                // withdrawal, which is a brake nobody would leave on. All read as a mis-set field.
                if g.delay == 0 || g.window == 0 {
                    return Err(AccountError::BadGuardrail);
                }
                if g.rate.capacity == 0 || g.rate.refill_per_second == 0 {
                    return Err(AccountError::BadGuardrail);
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
                let armed = Guardrail {
                    bucket: Bucket {
                        level: settled,
                        last_ts: now,
                    },
                    ..g
                };
                policy::put_guardrail(&env, &ad_id, &armed)?;
                // Settings the schedules were made under are gone, so the schedules go with them.
                if loosening {
                    policy::clear_all_schedules(&env, &ad_id);
                }
                events::GuardrailSet {
                    ad_id,
                    armed: true,
                    threshold: armed.threshold,
                    delay: armed.delay,
                    window: armed.window,
                }
                .publish(&env);
            }
            None => {
                policy::remove_guardrail(&env, &ad_id);
                policy::clear_all_schedules(&env, &ad_id);
                events::GuardrailSet {
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
        let guard_change = policy::set_guardrail(&env);
        if action != withdraw && action != close && action != guard_change {
            return Err(AccountError::ActionNotAllowed);
        }
        // Only `withdraw_from_ad` has an amount to match. Accepting one for the others would store
        // a row that can never be spent, while the event published it as though it meant something.
        if action != withdraw && amount != 0 {
            return Err(AccountError::BadGuardrail);
        }
        let g = policy::get_guardrail(&env, &ad_id).ok_or(AccountError::NoGuardrail)?;
        let now = env.ledger().timestamp();
        // Checked: `overflow-checks` is on for the workspace, so an absurd delay would otherwise
        // panic with an opaque host error instead of one the owner can act on.
        let ready_at = now.checked_add(g.delay).ok_or(AccountError::BadGuardrail)?;
        let expires_at = ready_at
            .checked_add(g.window)
            .ok_or(AccountError::BadGuardrail)?;
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

    /// Owner-only. Stand a schedule down — the lever an owner reaches for on seeing an
    /// `ExtractiveScheduled` event they did not cause.
    pub fn cancel_extractive(env: Env, ad_id: String, action: Symbol) -> Result<(), AccountError> {
        policy::get_owner(&env).require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        // Existence checked, so the audit trail this event exists for does not fill with
        // cancellations of schedules that were never made.
        if policy::get_schedule(&env, &ad_id, &action).is_none() {
            return Err(AccountError::NotScheduled);
        }
        policy::clear_schedule(&env, &ad_id, &action);
        events::ExtractiveCancelled { ad_id, action }.publish(&env);
        Ok(())
    }

    pub fn guardrail(env: Env, ad_id: String) -> Option<Guardrail> {
        policy::get_guardrail(&env, &ad_id)
    }

    pub fn guarded_ads(env: Env) -> Vec<String> {
        policy::guarded_ads(&env)
    }

    pub fn schedule(env: Env, ad_id: String, action: Symbol) -> Option<policy::Schedule> {
        policy::get_schedule(&env, &ad_id, &action)
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

    /// Owner-only. Replaces this account's code; storage (owner, targets,
    /// policies) stays. The new wasm reads `schema_version` and migrates or
    /// refuses old state. 2.1e puts this behind the extractive timelock.
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) -> Result<(), AccountError> {
        policy::get_owner(&env).require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        env.deployer()
            .update_current_contract(ContractExecutable::Wasm(new_wasm_hash.clone()));
        // The marker has to move with the code, or `schema_version()` reports whatever the
        // constructor wrote years ago and nothing can branch on it. Policies migrate lazily on
        // read (`policy::get_policy`); this is the part that says which shape new writes take.
        policy::set_schema_version(&env);
        events::Upgraded { new_wasm_hash }.publish(&env);
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

    pub fn schema_version(env: Env) -> u32 {
        policy::get_schema_version(&env)
    }
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
