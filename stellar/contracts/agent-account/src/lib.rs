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
    vec, Address, BytesN, ContractExecutable, Env, IntoVal, Symbol, Vec,
};

pub use auth::{AccountSig, Ed25519Sig, SecpSig};
pub use errors::AccountError;
pub use escrow::{required_settlement_signer, settlement_signer_of};
pub use policy::{
    lock_for_order, AgentId, AgentPolicy, MAX_ALLOWED_ACTIONS, MAX_TARGETS, MAX_WHITELIST_TOKENS,
    SCHEMA_VERSION,
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
        max_per_order: u128,
        valid_until: u64,
        settlement_signer: BytesN<32>,
    ) -> Result<(), AccountError> {
        policy::get_owner(&env).require_auth();
        proofbridge_core::ttl::extend_instance(&env);
        if policy::get_policy(&env, &agent_id).is_some_and(|p| p.revoked) {
            return Err(AccountError::AgentRevoked);
        }
        let p = AgentPolicy {
            allowed_actions,
            token_whitelist,
            max_per_order,
            valid_until,
            revoked: false,
            settlement_signer: settlement_signer.clone(),
        };
        policy::validate(&env, &p)?;
        policy::set_policy(&env, &agent_id, &p);
        events::PolicySet {
            agent_id,
            settlement_signer,
            valid_until,
            max_per_order,
        }
        .publish(&env);
        Ok(())
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
                return Ok(());
            }
            AccountSig::Agent(s) => auth::verify_ed25519(&env, &signature_payload, &s),
            AccountSig::AgentSecp(s) => auth::verify_secp(&env, &signature_payload, &s)?,
        };

        let p = policy::get_policy(&env, &agent_id).ok_or(AccountError::NoPolicyForAgent)?;
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
                Context::Contract(c) => escrow::check_contract_call(&env, &targets, &p, &c)?,
                // An agent never creates contracts or moves funds directly.
                // 2.1f revisits CAP-85 variants; today anything else fails closed.
                _ => return Err(AccountError::UnsupportedContext),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test;
