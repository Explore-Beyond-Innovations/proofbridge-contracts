//! The 24-hour delay on admin setters, with a one-time setup bypass (#586). Mirrors `Timelock.sol`.
//!
//! A timelocked setter is its own execute. Before activation it is the admin's, instantly (the setup
//! bypass). After activation it runs only when `sha256(xdr((function name, argument list)))` was
//! proposed at least [`DELAY`] seconds ago and at most [`GRACE`] after that, in the current admin
//! epoch (a handover voids the old admin's proposals), and then anyone may call it; the proposal is
//! consumed. A brake (an instant de-trust) records its time under a key, and a proposal on that key
//! made at or before the brake can never run. The bypass closes on [`activate`] or on the first
//! [`propose`] and never reopens. One copy for every contract that carries it.

use soroban_sdk::{
    contractevent, symbol_short,
    xdr::{FromXdr, ToXdr},
    Address, Bytes, BytesN, Env, Symbol, Val, Vec,
};

use crate::escrow_ops::Fault;
use crate::ttl::extend_persistent;

/// The minimum time between a proposal and its execution: 24 hours.
pub const DELAY: u64 = 24 * 60 * 60;

/// How long a ripe proposal stays executable before it expires: 14 days.
pub const GRACE: u64 = 14 * 24 * 60 * 60;

/// Instance: the bypass is closed. One-way.
const KEY_TL_ACTIVE: Symbol = symbol_short!("tlactive");
/// Persistent: `(tleta, id) -> (eta, epoch)`, a pending proposal.
const KEY_TL_ETA: Symbol = symbol_short!("tleta");
/// Instance: the admin epoch, bumped on every accepted handover.
const KEY_TL_EPOCH: Symbol = symbol_short!("tlepoch");
/// Persistent: `(tlbrake, key) -> u64`, when a brake on `key` was last pulled.
const KEY_TL_BRAKE: Symbol = symbol_short!("tlbrake");

#[contractevent(topics = ["tl_active"], data_format = "single-value")]
pub struct TimelockActivated {
    pub at: u64,
}

#[contractevent(topics = ["tl_prop"], data_format = "vec")]
pub struct ActionProposed {
    #[topic]
    pub id: BytesN<32>,
    pub eta: u64,
    pub fn_name: Symbol,
    pub args: Vec<Val>,
}

#[contractevent(topics = ["tl_cancel"], data_format = "single-value")]
pub struct ActionCancelled {
    #[topic]
    pub id: BytesN<32>,
    pub at: u64,
}

#[contractevent(topics = ["tl_exec"], data_format = "single-value")]
pub struct ActionExecuted {
    #[topic]
    pub id: BytesN<32>,
    pub at: u64,
}

pub fn is_active(env: &Env) -> bool {
    env.storage().instance().has(&KEY_TL_ACTIVE)
}

fn epoch(env: &Env) -> u32 {
    env.storage().instance().get(&KEY_TL_EPOCH).unwrap_or(0)
}

/// D6: a new admin starts with no pending proposals; call from `accept_admin`.
pub fn bump_epoch(env: &Env) {
    env.storage()
        .instance()
        .set(&KEY_TL_EPOCH, &(epoch(env) + 1));
}

fn proposal(env: &Env, id: &BytesN<32>) -> Option<(u64, u32)> {
    env.storage().persistent().get(&(KEY_TL_ETA, id.clone()))
}

/// The earliest execution time of a proposal that can still run (this epoch, not expired); 0 = none.
pub fn eta(env: &Env, id: &BytesN<32>) -> u64 {
    match proposal(env, id) {
        Some((at, e)) if e == epoch(env) && env.ledger().timestamp() <= at + GRACE => at,
        _ => 0,
    }
}

/// The proposal id of a call: `sha256` of the XDR of `(fn_name, args)`.
pub fn action_id(env: &Env, fn_name: &Symbol, args: &Vec<Val>) -> BytesN<32> {
    env.crypto()
        .sha256(&(fn_name.clone(), args.clone()).to_xdr(env))
        .into()
}

/// A brake key: `sha256` of the XDR of `(fn_name, what)`, naming what the brake de-trusts.
pub fn brake_key(env: &Env, fn_name: &str, what: Val) -> BytesN<32> {
    env.crypto()
        .sha256(&(Symbol::new(env, fn_name), what).to_xdr(env))
        .into()
}

/// Close the bypass for good. The caller has authenticated the admin.
pub fn activate(env: &Env) -> Result<(), Fault> {
    if is_active(env) {
        return Err(Fault::TimelockAlreadyActive);
    }
    set_active(env);
    Ok(())
}

fn set_active(env: &Env) {
    env.storage().instance().set(&KEY_TL_ACTIVE, &true);
    TimelockActivated {
        at: env.ledger().timestamp(),
    }
    .publish(env);
}

/// Queue a call: `args` is the XDR of the call's argument list (an `ScVal::Vec`, the arguments in
/// order, each with the setter's own type), so any tool can build it. Closes the bypass if still
/// open. A voided (other epoch) or expired entry does not block a new one. The caller has
/// authenticated the admin.
pub fn propose(env: &Env, fn_name: Symbol, args: Bytes) -> Result<BytesN<32>, Fault> {
    let args = Vec::<Val>::from_xdr(env, &args).map_err(|_| Fault::TimelockBadArgs)?;
    if !is_active(env) {
        set_active(env);
    }
    let id = action_id(env, &fn_name, &args);
    if eta(env, &id) != 0 {
        return Err(Fault::TimelockAlreadyProposed);
    }
    let at = env.ledger().timestamp() + DELAY;
    let key = (KEY_TL_ETA, id.clone());
    env.storage().persistent().set(&key, &(at, epoch(env)));
    extend_persistent(env, &key);
    ActionProposed {
        id: id.clone(),
        eta: at,
        fn_name,
        args,
    }
    .publish(env);
    Ok(id)
}

/// Drop a pending proposal. The caller has authenticated the admin.
pub fn cancel(env: &Env, id: BytesN<32>) -> Result<(), Fault> {
    if proposal(env, &id).is_none() {
        return Err(Fault::TimelockNotProposed);
    }
    env.storage().persistent().remove(&(KEY_TL_ETA, id.clone()));
    ActionCancelled {
        id,
        at: env.ledger().timestamp(),
    }
    .publish(env);
    Ok(())
}

/// The gate at the top of a timelocked setter: before activation the admin's auth; after, a ripe,
/// unexpired proposal of this epoch for exactly `(fn_name, args)`, consumed here, from anyone.
pub fn gate(env: &Env, admin: &Address, fn_name: &str, args: Vec<Val>) -> Result<(), Fault> {
    gate_keyed(env, admin, fn_name, args, None)
}

/// As [`gate`], and refused when a brake on `key` was pulled at or after the proposal was made.
pub fn gate_keyed(
    env: &Env,
    admin: &Address,
    fn_name: &str,
    args: Vec<Val>,
    key: Option<BytesN<32>>,
) -> Result<(), Fault> {
    if !is_active(env) {
        admin.require_auth();
        return Ok(());
    }
    let id = action_id(env, &Symbol::new(env, fn_name), &args);
    let (at, e) = proposal(env, &id).ok_or(Fault::TimelockNotProposed)?;
    if e != epoch(env) {
        return Err(Fault::TimelockNotProposed);
    }
    let now = env.ledger().timestamp();
    if now < at {
        return Err(Fault::TimelockTooEarly);
    }
    if now > at + GRACE {
        return Err(Fault::TimelockExpired);
    }
    if let Some(k) = key {
        let braked: u64 = env
            .storage()
            .persistent()
            .get(&(KEY_TL_BRAKE, k))
            .unwrap_or(0);
        if braked != 0 && at - DELAY <= braked {
            return Err(Fault::TimelockCancelledByBrake);
        }
    }
    env.storage().persistent().remove(&(KEY_TL_ETA, id.clone()));
    ActionExecuted { id, at: now }.publish(env);
    Ok(())
}

/// A brake (removing an appender or an escrow, a revocation) stays instant for the admin and voids
/// every proposal on `key` made up to now; anything else is gated, keyed by `key`.
pub fn gate_unless(
    env: &Env,
    admin: &Address,
    brake: bool,
    fn_name: &str,
    args: Vec<Val>,
    key: BytesN<32>,
) -> Result<(), Fault> {
    if brake {
        admin.require_auth();
        let k = (KEY_TL_BRAKE, key);
        env.storage()
            .persistent()
            .set(&k, &env.ledger().timestamp());
        extend_persistent(env, &k);
        return Ok(());
    }
    gate_keyed(env, admin, fn_name, args, Some(key))
}
