//! What the account knows about the escrow call it authorizes.
//!
//! The lock argument is read as a `Map<Symbol, Val>` and only the keys the
//! policy needs are decoded (F4a), so the account is width-agnostic: the 2.3b
//! 17-field order decodes the same way. A missing key or a wrong type is
//! `BadArgs` (fail closed).

use soroban_sdk::{auth::ContractContext, Address, BytesN, Env, Map, Symbol, TryFromVal, Val, Vec};

use crate::errors::AccountError;
use crate::policy::{self, AgentPolicy};

/// The settlement identity a policy may name today: this account. 2.3b (the
/// 17-field order with `ad_settlement_signer`) relaxes this to the owner's
/// settlement EOA; that is the one swap point, with `settlement_signer_of`.
pub fn required_settlement_signer(env: &Env) -> BytesN<32> {
    proofbridge_core::eip712::contract_address_to_bytes32(env)
}

/// The settlement identity a lock names. Until 2.3b this is `ad_creator`; 2.3b
/// swaps this one line to `ad_settlement_signer`.
pub fn settlement_signer_of(
    env: &Env,
    lock: &Map<Symbol, Val>,
) -> Result<BytesN<32>, AccountError> {
    field(env, lock, "ad_creator")
}

fn field<T: TryFromVal<Env, Val>>(
    env: &Env,
    lock: &Map<Symbol, Val>,
    name: &str,
) -> Result<T, AccountError> {
    let v = lock
        .get(Symbol::new(env, name))
        .ok_or(AccountError::BadArgs)?;
    T::try_from_val(env, &v).map_err(|_| AccountError::BadArgs)
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
    let lock: Map<Symbol, Val> = Map::try_from_val(env, &raw).map_err(|_| AccountError::BadArgs)?;

    let ad_chain_token: BytesN<32> = field(env, &lock, "ad_chain_token")?;
    let order_chain_token: BytesN<32> = field(env, &lock, "order_chain_token")?;
    if !policy.token_whitelist.contains(&ad_chain_token)
        || !policy.token_whitelist.contains(&order_chain_token)
    {
        return Err(AccountError::TokenNotAllowed);
    }

    // The escrow locks `scale(amount, order_decimals, ad_decimals)` of the ad
    // token; the cap is denominated in the same units.
    let amount: u128 = field(env, &lock, "amount")?;
    let order_decimals: u32 = field(env, &lock, "order_decimals")?;
    let ad_decimals: u32 = field(env, &lock, "ad_decimals")?;
    let ad_amount = proofbridge_core::decimal_scaling::scale(amount, order_decimals, ad_decimals)
        .map_err(|_| AccountError::BadArgs)?;
    if ad_amount > policy.max_per_order {
        return Err(AccountError::CapExceeded);
    }

    // `ad_creator` is the ad's maker, i.e. this account, always (the EVM escrow
    // reverts NotMaker; the Stellar one does not check, so the account does).
    let ad_creator: BytesN<32> = field(env, &lock, "ad_creator")?;
    if ad_creator != proofbridge_core::eip712::contract_address_to_bytes32(env) {
        return Err(AccountError::SettlementSignerMismatch);
    }
    if settlement_signer_of(env, &lock)? != policy.settlement_signer {
        return Err(AccountError::SettlementSignerMismatch);
    }
    Ok(())
}
