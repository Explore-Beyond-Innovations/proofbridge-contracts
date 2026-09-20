//! What the account knows about the escrow call it authorizes.
//!
//! The lock argument is read as a `Map<Symbol, Val>` and only the keys the
//! policy needs are decoded (F4a), so the account is width-agnostic: the 2.3b
//! 17-field order decodes the same way. A missing key or a wrong type is
//! `BadArgs` (fail closed).

use soroban_sdk::{
    auth::ContractContext, Address, BytesN, Env, Map, String, Symbol, TryFromVal, Val, Vec,
};

use proofbridge_core::rate_limit::{self, Bucket};

use crate::errors::AccountError;
use crate::policy::{self, AccountVolume, AgentPolicy};

/// The settlement identity a policy may name today: this account. 2.3b (the
/// 17-field order with `ad_settlement_signer`) relaxes this to the owner's
/// settlement EOA; that is the one swap point, with `settlement_signer_of`.
pub fn required_settlement_signer(env: &Env) -> BytesN<32> {
    proofbridge_core::eip712::contract_address_to_bytes32(env)
}

/// The settlement identity a lock names: the order's `ad_settlement_signer` (2.3b).
pub fn settlement_signer_of(
    env: &Env,
    lock: &Map<Symbol, Val>,
) -> Result<BytesN<32>, AccountError> {
    field(env, lock, "ad_settlement_signer")
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

/// Target ∈ pinned escrows, selector ∈ allowed_actions, then the lock's args against the policy:
/// settlement signer, whitelist, ad scope (reach), scaling and the cap (size), the buckets (rate).
/// Fails closed on anything it cannot decode.
///
/// **This writes.** Since 2.1d the last thing it does is debit two volume buckets, so the name
/// undersells it: a passing check has consumed allowance. That is deliberate — the auth frame is
/// the only place that sees every authorized lock.
///
/// Two consequences worth knowing. Simulation consumes nothing while apply does. And the buckets
/// are charged for locks that actually *happen*: any later failure — a rejected context, the
/// escrow itself reverting — discards the frame and the debit with it.
pub fn check_contract_call(
    env: &Env,
    targets: &Vec<Address>,
    policy: &mut AgentPolicy,
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

    // One order, shared with the EVM module and the relayer's TypeScript check, and pinned by the
    // shared fixture's precedence cases (T-60): **reach, then size, then rate**. Who and what the
    // lock is for, before how much, before how much lately. A lock with two faults is refused for
    // the earlier one on every implementation, so the relayer's pre-flight reason is the chain's.
    //
    // ---- reach ----
    // `ad_creator` is the ad's maker, i.e. this account, always (the EVM escrow
    // reverts NotMaker; the Stellar one does not check, so the account does).
    let ad_creator: BytesN<32> = field(env, &lock, "ad_creator")?;
    if ad_creator != proofbridge_core::eip712::contract_address_to_bytes32(env) {
        return Err(AccountError::SettlementSignerMismatch);
    }
    if settlement_signer_of(env, &lock)? != policy.settlement_signer {
        return Err(AccountError::SettlementSignerMismatch);
    }

    let ad_chain_token: BytesN<32> = field(env, &lock, "ad_chain_token")?;
    let order_chain_token: BytesN<32> = field(env, &lock, "order_chain_token")?;
    if !policy.token_whitelist.contains(&ad_chain_token)
        || !policy.token_whitelist.contains(&order_chain_token)
    {
        return Err(AccountError::TokenNotAllowed);
    }

    let ad_id: String = field(env, &lock, "ad_id")?;
    if !policy::ad_in_scope(policy, &ad_id) {
        return Err(AccountError::AdNotAllowed);
    }

    // ---- size ----
    // The escrow locks `scale(amount, order_decimals, ad_decimals)` of the ad token; the cap is
    // denominated in the same units. Per token, because the whitelist can hold sixteen of them and
    // one number cannot be right for two assets of different value — 1,000,000 units is a few
    // cents of XLM and a few hundred dollars of wETH. Decimal scaling cannot fix that: it converts
    // units, and what differs here is worth, which nothing on chain knows.
    let amount: u128 = field(env, &lock, "amount")?;
    let order_decimals: u32 = field(env, &lock, "order_decimals")?;
    let ad_decimals: u32 = field(env, &lock, "ad_decimals")?;
    let ad_amount = proofbridge_core::decimal_scaling::scale(amount, order_decimals, ad_decimals)
        .map_err(|_| AccountError::BadArgs)?;
    // A zero lock is refused here as it is by the EVM module and the relayer's check. The escrow
    // refuses one itself (`ZeroAmount`), so allowing it was harmless and still wrong: a policy
    // that says yes to what the chain is certain to refuse. `BadArgs` is this account's word for
    // an amount it will not scale, which is the word the shared fixture already maps.
    if ad_amount == 0 {
        return Err(AccountError::BadArgs);
    }
    let token_limit =
        policy::limit_for(policy, &ad_chain_token).ok_or(AccountError::NoVolumeLimit)?;
    if ad_amount > token_limit.max_per_order {
        return Err(AccountError::CapExceeded);
    }

    // ---- rate ----
    // Last, and the only step that writes. A rejected `__check_auth` takes the whole frame with
    // it, so a refused lock cannot spend allowance whichever way round these go; the order is for
    // cost, for legibility, and so that all three implementations name the same fault.
    spend_volume(env, policy, &ad_chain_token, ad_amount)
}

/// Debit the agent's bucket and the account's, in ad-token units.
///
/// Both are refilled and checked **before either is written**, so a lock that clears the agent but
/// not the account leaves neither drained. Getting that order wrong would let a rejected lock still
/// cost the agent its allowance.
fn spend_volume(
    env: &Env,
    policy: &mut AgentPolicy,
    token: &BytesN<32>,
    amount: u128,
) -> Result<(), AccountError> {
    let now = env.ledger().timestamp();

    // A whitelisted token with no limit is refused, not waved through: the whitelist says which
    // tokens are permitted at all, `limits` says how much, and silence in the second is not
    // permission. `validate` already makes the two agree at install; this is the read-side half of
    // that, and it is what a policy written by an older wasm would trip on.
    let agent_limit = policy::limit_for(policy, token)
        .ok_or(AccountError::NoVolumeLimit)?
        .rate;
    // No stored bucket means never spent — the policy entry holds the buckets, so this cannot be
    // an entry that quietly archived and read back as full.
    let agent_bucket =
        policy::bucket_for(policy, token).unwrap_or_else(|| Bucket::full(&agent_limit, now));

    // Absence here means *unconfigured*, and refuses. The limit and the bucket share one entry
    // precisely so this read cannot see a live bucket with a vanished ceiling.
    let account = policy::get_account_volume(env, token).ok_or(AccountError::NoVolumeLimit)?;

    let next_agent = rate_limit::try_spend(&agent_limit, &agent_bucket, amount, now)
        .ok_or(AccountError::VolumeExceeded)?;
    let next_account = rate_limit::try_spend(&account.limit, &account.bucket, amount, now)
        .ok_or(AccountError::VolumeExceeded)?;

    // The agent's bucket is updated in the caller's copy and persisted once after every context
    // has run. Writing it here would be wrong as well as wasteful: an auth entry carrying two
    // locks hands each context the same policy, so a per-context write would have the second
    // overwrite the first's debit and make the second lock free.
    policy::put_bucket(policy, token, next_agent);
    policy::set_account_volume(
        env,
        token,
        &AccountVolume {
            limit: account.limit,
            bucket: next_account,
        },
    );
    Ok(())
}

/// Spend a matured schedule for exactly this call, or refuse.
///
/// Shared by the owner's escrow path and by `set_guard_rail`'s loosening branch, so "announced,
/// matured, unexpired, exact, single-use" means one thing in both places. `to` is `None` where the
/// call has no destination to pin (loosening a guardrail).
pub fn spend_schedule(
    env: &Env,
    ad_id: &String,
    action: &Symbol,
    amount: u128,
    to: Option<Address>,
    now: u64,
) -> Result<(), AccountError> {
    let s = policy::get_schedule(env, ad_id, action).ok_or(AccountError::NotScheduled)?;
    // Exact on both, or a schedule for 100 to alice authorizes 101, or 100 to someone else.
    if s.amount != amount || now < s.ready_at || now >= s.expires_at {
        return Err(AccountError::NotScheduled);
    }
    if let Some(dest) = to {
        if s.to != dest {
            return Err(AccountError::NotScheduled);
        }
    }
    // Single use. A spent row left in place is an authorization waiting to be replayed.
    policy::clear_schedule(env, ad_id, action);
    Ok(())
}

/// The owner path's half of `check_contract_call` (2.1e).
/// Instant to protect, slow to extract. Three calls move the maker's money out of reach and are
/// constrained on a guarded ad; everything else the owner does — `set_settlement_signer`, funding,
/// creating ads, and the token sub-contexts those spawn — passes exactly as before, because
/// delaying a protective action only helps whoever stole the key.
///
/// **Not gated on `targets`.** An earlier version only ran this when the called contract was a
/// pinned escrow, which `set_targets` — owner-only and instant — could simply point elsewhere,
/// removing the guard without touching it. The selector and the ad are what matter; an unrelated
/// contract that happens to share a name is only ever refused for an ad this owner guarded.
///
/// Like the agent path, this **writes**: spending a schedule removes it, and a sub-threshold
/// withdrawal spends the bucket.
pub fn check_owner_call(env: &Env, c: &ContractContext) -> Result<(), AccountError> {
    let withdraw = policy::withdraw_from_ad(env);
    let close = policy::close_ad(env);
    let lock = policy::lock_for_order(env);
    if c.fn_name != withdraw && c.fn_name != close && c.fn_name != lock {
        return Ok(());
    }

    // `lock_for_order` carries the order struct; the other two take `ad_id` first. Fail closed on
    // anything that does not decode: an extractive call the account cannot read is one it cannot
    // judge.
    let (ad_id, amount, to) = if c.fn_name == lock {
        let raw = c.args.get(0).ok_or(AccountError::BadArgs)?;
        let m: Map<Symbol, Val> =
            Map::try_from_val(env, &raw).map_err(|_| AccountError::BadArgs)?;
        let amount: u128 = field(env, &m, "amount")?;
        let order_decimals: u32 = field(env, &m, "order_decimals")?;
        let ad_decimals: u32 = field(env, &m, "ad_decimals")?;
        let ad_amount =
            proofbridge_core::decimal_scaling::scale(amount, order_decimals, ad_decimals)
                .map_err(|_| AccountError::BadArgs)?;
        (field::<String>(env, &m, "ad_id")?, ad_amount, None)
    } else {
        let ad_id: String = c
            .args
            .get(0)
            .and_then(|v| String::try_from_val(env, &v).ok())
            .ok_or(AccountError::BadArgs)?;
        if c.fn_name == withdraw {
            let amount: u128 = c
                .args
                .get(1)
                .and_then(|v| u128::try_from_val(env, &v).ok())
                .ok_or(AccountError::BadArgs)?;
            let to: Address = c
                .args
                .get(2)
                .and_then(|v| Address::try_from_val(env, &v).ok())
                .ok_or(AccountError::BadArgs)?;
            (ad_id, amount, Some(to))
        } else {
            let to: Address = c
                .args
                .get(1)
                .and_then(|v| Address::try_from_val(env, &v).ok())
                .ok_or(AccountError::BadArgs)?;
            (ad_id, 0u128, Some(to))
        }
    };

    if !policy::is_guarded(env, &ad_id) {
        // Unguarded: every ad today, and a per-maker choice (design 02 §2.8). Absence means
        // unguarded only because the roster says this ad was never armed.
        return Ok(());
    }
    // On the roster but no row: the entry archived. Refuse rather than read it as unguarded — the
    // failure contracts#25 fixed for the route and verifier rows, one feature over.
    let mut g = policy::get_guard_rail(env, &ad_id).ok_or(AccountError::GuardRailArchived)?;
    policy::touch_guard_rail(env, &ad_id);
    let now = env.ledger().timestamp();

    // `close_ad` carries no amount and empties the ad, and the balance is unreadable without
    // re-entering the escrow that is calling us, so no threshold can gate it: always announced.
    let announced = if c.fn_name == close {
        true
    } else {
        amount > g.threshold
    };

    if announced {
        return spend_schedule(env, &ad_id, &c.fn_name, amount, to, now);
    }

    // Under the threshold, and still bounded: the bucket is what makes design 02 §2.8's residual a
    // *flow rate* rather than the balance. Without it, N calls of threshold size drain the ad as
    // fast as transactions land, and one auth entry can carry several.
    let next = proofbridge_core::rate_limit::try_spend(&g.rate, &g.bucket, amount, now)
        .ok_or(AccountError::VolumeExceeded)?;
    g.bucket = next;
    policy::put_guard_rail(env, &ad_id, &g)?;
    Ok(())
}
