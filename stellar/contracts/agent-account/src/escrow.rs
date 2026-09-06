//! What the account knows about the escrow call it authorizes.
//!
//! `LockParams` mirrors `ad-manager`'s `OrderParams` (same 13 field names and
//! types). Soroban decodes structs by field name, so a mismatch between the two
//! fails the conversion rather than mis-reading a field.

use soroban_sdk::{
    auth::ContractContext, contracttype, Address, BytesN, Env, String, TryIntoVal, Vec,
};

use crate::errors::AccountError;
use crate::policy::{self, AgentPolicy};

#[contracttype]
#[derive(Clone, Debug)]
pub struct LockParams {
    pub order_chain_token: BytesN<32>,
    pub ad_chain_token: BytesN<32>,
    pub amount: u128,
    pub bridger: BytesN<32>,
    pub order_chain_id: u128,
    pub src_order_portal: BytesN<32>,
    pub order_recipient: BytesN<32>,
    pub ad_id: String,
    pub ad_creator: BytesN<32>,
    pub ad_recipient: BytesN<32>,
    pub salt: u128,
    pub order_decimals: u32,
    pub ad_decimals: u32,
}

/// The settlement identity a lock names. Until 2.3b lands the 17-field order
/// this is `ad_creator` (the relayer enforces `settlementSigner == adIdentity`
/// the same way); 2.3b swaps this one line to `ad_settlement_signer`.
pub fn settlement_signer_of(params: &LockParams) -> BytesN<32> {
    params.ad_creator.clone()
}

/// Target ∈ pinned escrows, selector ∈ allowed_actions, then the lock's args
/// against the policy. Fails closed on anything it cannot decode.
pub fn check_contract_call(
    env: &Env,
    targets: &Vec<Address>,
    policy: &AgentPolicy,
    c: &ContractContext,
) -> Result<(), AccountError> {
    if !targets.contains(&c.contract) {
        return Err(AccountError::TargetNotAllowed);
    }
    if !policy.allowed_actions.contains(&c.fn_name) {
        return Err(AccountError::ActionNotAllowed);
    }
    if c.fn_name != policy::lock_for_order(env) {
        // Only lock_for_order can be installed today (policy::validate), so
        // this is unreachable; kept so a future selector cannot slip through
        // without its own arg rule.
        return Err(AccountError::ActionNotAllowed);
    }

    if c.args.len() != 1 {
        return Err(AccountError::BadArgs);
    }
    let raw = c.args.get(0).ok_or(AccountError::BadArgs)?;
    let params: LockParams = raw.try_into_val(env).map_err(|_| AccountError::BadArgs)?;

    if !policy.token_whitelist.contains(&params.ad_chain_token)
        || !policy.token_whitelist.contains(&params.order_chain_token)
    {
        return Err(AccountError::TokenNotAllowed);
    }

    // The escrow locks `scale(amount, order_decimals, ad_decimals)` of the ad
    // token; the cap is denominated in the same units.
    let ad_amount = proofbridge_core::decimal_scaling::scale(
        params.amount,
        params.order_decimals,
        params.ad_decimals,
    )
    .map_err(|_| AccountError::BadArgs)?;
    if ad_amount > policy.max_per_order {
        return Err(AccountError::CapExceeded);
    }

    if settlement_signer_of(&params) != policy.settlement_signer {
        return Err(AccountError::SettlementSignerMismatch);
    }
    Ok(())
}
