//! The argument shapes of the calls a schedule can authorize.
//!
//! One decoder for `schedule` and the owner path, so a `Scheduled` event always describes a call
//! that could be spent and the owner path refuses an escrow call it cannot read. Anything that
//! does not decode in the call's own shape is `BadArgs`.

use soroban_sdk::{Address, BytesN, Env, Map, String, Symbol, TryFromVal, Val, Vec};

use crate::errors::AccountError;
use crate::policy::{self, GuardRail, TokenLimit};
use proofbridge_core::rate_limit::{Bucket, Limit};

fn arg<T: TryFromVal<Env, Val>>(env: &Env, args: &Vec<Val>, i: u32) -> Result<T, AccountError> {
    let v = args.get(i).ok_or(AccountError::BadArgs)?;
    T::try_from_val(env, &v).map_err(|_| AccountError::BadArgs)
}

fn arity(args: &Vec<Val>, n: u32) -> Result<(), AccountError> {
    if args.len() != n {
        return Err(AccountError::BadArgs);
    }
    Ok(())
}

/// A vec whose every element decodes as `T` (an SDK `Vec<T>` decodes its elements lazily).
fn typed_vec<T: TryFromVal<Env, Val>>(env: &Env, v: &Val) -> Result<(), AccountError> {
    let raw: Vec<Val> = Vec::try_from_val(env, v).map_err(|_| AccountError::BadArgs)?;
    for x in raw.iter() {
        T::try_from_val(env, &x).map_err(|_| AccountError::BadArgs)?;
    }
    Ok(())
}

fn field<T: TryFromVal<Env, Val>>(
    env: &Env,
    m: &Map<Symbol, Val>,
    name: &str,
) -> Result<T, AccountError> {
    let v = m.get(Symbol::new(env, name)).ok_or(AccountError::BadArgs)?;
    T::try_from_val(env, &v).map_err(|_| AccountError::BadArgs)
}

/// An ad-scope call, decoded in its own shape: the ad it names and the amount the threshold reads
/// (the withdrawal, the lock's ad-side amount, 0 for `close_ad` and `set_guard_rail`).
pub fn decode_ad_call(
    env: &Env,
    action: &Symbol,
    args: &Vec<Val>,
) -> Result<(String, u128), AccountError> {
    if *action == policy::withdraw_from_ad(env) {
        arity(args, 3)?;
        arg::<Address>(env, args, 2)?;
        Ok((arg(env, args, 0)?, arg(env, args, 1)?))
    } else if *action == policy::close_ad(env) {
        arity(args, 2)?;
        arg::<Address>(env, args, 1)?;
        Ok((arg(env, args, 0)?, 0))
    } else if *action == policy::lock_for_order(env) {
        arity(args, 1)?;
        let m: Map<Symbol, Val> = arg(env, args, 0)?;
        let amount: u128 = field(env, &m, "amount")?;
        let order_decimals: u32 = field(env, &m, "order_decimals")?;
        let ad_decimals: u32 = field(env, &m, "ad_decimals")?;
        let ad_amount =
            proofbridge_core::decimal_scaling::scale(amount, order_decimals, ad_decimals)
                .map_err(|_| AccountError::BadArgs)?;
        Ok((field(env, &m, "ad_id")?, ad_amount))
    } else if *action == policy::set_guard_rail(env) {
        arity(args, 2)?;
        arg::<Option<GuardRail>>(env, args, 1)?;
        Ok((arg(env, args, 0)?, 0))
    } else {
        Err(AccountError::ActionNotAllowed)
    }
}

/// An account-scope call's arguments in its own shape.
pub fn check_account_call(env: &Env, action: &Symbol, args: &Vec<Val>) -> Result<(), AccountError> {
    if *action == policy::act_upgrade(env) {
        arity(args, 1)?;
        arg::<BytesN<32>>(env, args, 0)?;
    } else if *action == policy::act_set_targets(env) {
        arity(args, 1)?;
        typed_vec::<Address>(env, &args.get(0).ok_or(AccountError::BadArgs)?)?;
    } else if *action == policy::act_set_account_limit(env) {
        arity(args, 2)?;
        arg::<BytesN<32>>(env, args, 0)?;
        arg::<Limit>(env, args, 1)?;
    } else if *action == policy::act_set_policy(env) {
        // (agent_id, allowed_actions, token_whitelist, valid_until, settlement_signer, ad_scope,
        // limits), as `set_policy` takes them.
        arity(args, 7)?;
        let at = |i: u32| args.get(i).ok_or(AccountError::BadArgs);
        arg::<BytesN<32>>(env, args, 0)?;
        typed_vec::<Symbol>(env, &at(1)?)?;
        typed_vec::<BytesN<32>>(env, &at(2)?)?;
        arg::<u64>(env, args, 3)?;
        arg::<BytesN<32>>(env, args, 4)?;
        let scope = at(5)?;
        if !scope.is_void() {
            typed_vec::<String>(env, &scope)?;
        }
        typed_vec::<TokenLimit>(env, &at(6)?)?;
    } else {
        return Err(AccountError::ActionNotAllowed);
    }
    Ok(())
}

/// `set_guard_rail`'s args as committed: the bucket is live state the contract re-stamps at write
/// time, so it is zeroed. A client that re-reads `guard_rail(ad)` after the bucket moved still
/// builds the same commitment.
pub fn guard_rail_args(env: &Env, ad_id: &String, g: &Option<GuardRail>) -> Vec<Val> {
    use soroban_sdk::IntoVal;
    let settings: Option<GuardRail> = g.clone().map(|g| GuardRail {
        bucket: Bucket {
            level: 0,
            last_ts: 0,
        },
        ..g
    });
    soroban_sdk::vec![env, ad_id.into_val(env), settings.into_val(env)]
}
