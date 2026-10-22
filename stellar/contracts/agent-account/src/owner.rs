//! The owner's ad actions (plan 46): what `create_ad`, `fund_ad`, `call` and `sweep` share.
//!
//! The account is the ad's maker and an authorization gateway; it never holds what the owner pays
//! in. Money the owner pays in (a deposit, a top-up, a dispute bond) comes from the owner's wallet
//! and goes on to the escrow in the same call. (Funds can still come to rest here, a payout to the
//! account or a refunded bond; they leave through `sweep`.) The escrow pulls it *from the account*, a call the
//! account doesn't make itself, so the host asks the account to authorize it: the account
//! pre-approves exactly that transfer (`authorize_as_current_contract`), and nothing else. Every
//! touched token's balance is checked unchanged afterwards.

use soroban_sdk::{
    auth::{ContractContext, InvokerContractAuthEntry, SubContractInvocation},
    token::TokenClient,
    vec, Address, BytesN, Env, IntoVal, Symbol, TryFromVal, Val, Vec,
};

use crate::errors::AccountError;
use crate::policy;

/// The escrow calls go only to a pinned target, so no other contract (a token above all) can be
/// reached as this account through the owner's functions.
pub fn require_target(env: &Env, target: &Address) -> Result<(), AccountError> {
    if policy::get_targets(env).contains(target) {
        Ok(())
    } else {
        Err(AccountError::TargetNotAllowed)
    }
}

/// `token` is the ad token's own contract. For native XLM it is the escrow's wrapped native token,
/// which the account can't read; a wrong one fails the escrow's pull and reverts the call.
pub fn require_ad_token(
    env: &Env,
    token: &Address,
    ad_token: &BytesN<32>,
) -> Result<(), AccountError> {
    if proofbridge_core::token::is_native_token(ad_token) {
        return Ok(());
    }
    match proofbridge_core::token::bytes32_to_token_address(env, ad_token) {
        Some(t) if t == *token => Ok(()),
        _ => Err(AccountError::BadArgs),
    }
}

/// The ad's token as the escrow holds it (`get_ad(ad_id).token`). Read as a map, so the account
/// stays independent of the escrow's types. An ad the escrow doesn't know is `BadArgs`.
pub fn ad_token_of(
    env: &Env,
    ad_manager: &Address,
    ad_id: &soroban_sdk::String,
) -> Result<BytesN<32>, AccountError> {
    let ad: Option<soroban_sdk::Map<Symbol, Val>> = env.invoke_contract(
        ad_manager,
        &Symbol::new(env, "get_ad"),
        vec![env, ad_id.to_val()],
    );
    ad.and_then(|m| m.get(Symbol::new(env, "token")))
        .and_then(|v| BytesN::<32>::try_from_val(env, &v).ok())
        .ok_or(AccountError::BadArgs)
}

pub fn to_i128(amount: u128) -> Result<i128, AccountError> {
    i128::try_from(amount).map_err(|_| AccountError::BadArgs)
}

/// `amount` of `token` in from the owner, approved on to `payee`, then `f` (the escrow call that
/// pulls it). The account's balance of `token` must end where it started.
pub fn pay_through<F: FnOnce(&Env)>(
    env: &Env,
    owner: &Address,
    token: &Address,
    amount: u128,
    payee: &Address,
    f: F,
) -> Result<(), AccountError> {
    let me = env.current_contract_address();
    let client = TokenClient::new(env, token);
    let before = client.balance(&me);
    let amount = to_i128(amount)?;
    client.transfer(owner, &me, &amount);
    env.authorize_as_current_contract(vec![env, transfer_approval(env, token, &me, payee, amount)]);
    f(env);
    if client.balance(&me) != before {
        return Err(AccountError::FundsLeft);
    }
    Ok(())
}

fn transfer_approval(
    env: &Env,
    token: &Address,
    from: &Address,
    to: &Address,
    amount: i128,
) -> InvokerContractAuthEntry {
    InvokerContractAuthEntry::Contract(SubContractInvocation {
        context: ContractContext {
            contract: token.clone(),
            fn_name: Symbol::new(env, "transfer"),
            args: vec![env, from.to_val(), to.to_val(), amount.into_val(env)],
        },
        sub_invocations: Vec::new(env),
    })
}

/// `call`'s body: the optional payment in, the approvals, the escrow call, then the balance check
/// on every token the payment or an approval names.
pub fn call_with(
    env: &Env,
    owner: &Address,
    target: &Address,
    fn_name: &Symbol,
    args: Vec<Val>,
    pay: Option<(Address, u128)>,
    approvals: Vec<InvokerContractAuthEntry>,
) -> Result<Val, AccountError> {
    let me = env.current_contract_address();
    let mut tokens: Vec<Address> = Vec::new(env);
    for a in approvals.iter() {
        approved_tokens(env, &me, target, &a, true, &mut tokens)?;
    }
    if let Some((t, _)) = &pay {
        if !tokens.contains(t) {
            tokens.push_back(t.clone());
        }
    }
    let mut before: Vec<i128> = Vec::new(env);
    for t in tokens.iter() {
        before.push_back(TokenClient::new(env, &t).balance(&me));
    }
    if let Some((t, amount)) = &pay {
        TokenClient::new(env, t).transfer(owner, &me, &to_i128(*amount)?);
    }
    if !approvals.is_empty() {
        env.authorize_as_current_contract(approvals);
    }
    let ret: Val = env.invoke_contract(target, fn_name, args);
    for (i, t) in tokens.iter().enumerate() {
        if TokenClient::new(env, &t).balance(&me) != before.get(i as u32).unwrap_or_default() {
            return Err(AccountError::FundsLeft);
        }
    }
    Ok(ret)
}

/// An approval is one of:
///   - a token `transfer` from this account, with nothing nested;
///   - at the root, an `open_dispute` filed by this account against the escrow being called, whose
///     nested calls are only such transfers;
///   - at the root, a `record_response` with nothing nested, this account as the responder, for
///     the escrow being called (80-1: the dispute manager asks the responder itself to authorize).
///
/// Anything else, an `approve` above all (an allowance outlives the call), is refused. Collects the
/// tokens the transfers name.
fn approved_tokens(
    env: &Env,
    me: &Address,
    target: &Address,
    entry: &InvokerContractAuthEntry,
    root: bool,
    tokens: &mut Vec<Address>,
) -> Result<(), AccountError> {
    let InvokerContractAuthEntry::Contract(inv) = entry else {
        return Err(AccountError::BadApproval);
    };
    let c = &inv.context;
    if c.fn_name == Symbol::new(env, "transfer") {
        let from = c
            .args
            .get(0)
            .and_then(|v| Address::try_from_val(env, &v).ok())
            .ok_or(AccountError::BadApproval)?;
        if from != *me || !inv.sub_invocations.is_empty() {
            return Err(AccountError::BadApproval);
        }
        if !tokens.contains(&c.contract) {
            tokens.push_back(c.contract.clone());
        }
        return Ok(());
    }
    let addr = |i: u32| {
        c.args
            .get(i)
            .and_then(|v| Address::try_from_val(env, &v).ok())
            .ok_or(AccountError::BadApproval)
    };
    // `open_dispute(escrow, order_hash, peer_chain_id, filer, …)`: one filing, by this account,
    // against the escrow being called (80-5); the nested transfers carry the bond.
    if root && c.fn_name == Symbol::new(env, "open_dispute") {
        if addr(0)? != *target || addr(3)? != *me {
            return Err(AccountError::BadApproval);
        }
        for s in inv.sub_invocations.iter() {
            approved_tokens(env, me, target, &s, false, tokens)?;
        }
        return Ok(());
    }
    // `record_response(escrow, order_hash, responder, evidence)`: moves nothing.
    if root && c.fn_name == Symbol::new(env, "record_response") {
        if !inv.sub_invocations.is_empty() || addr(0)? != *target || addr(2)? != *me {
            return Err(AccountError::BadApproval);
        }
        return Ok(());
    }
    Err(AccountError::BadApproval)
}
