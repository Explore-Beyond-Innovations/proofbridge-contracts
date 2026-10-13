//! The 24-hour delay on admin setters, with a one-time setup bypass (#586). Mirrors `Timelock.sol`.
//!
//! A timelocked setter is its own execute. Before activation it is the admin's, instantly (the setup
//! bypass). After activation it runs only when `sha256(xdr((function name, argument list)))` was
//! proposed at least [`DELAY`] seconds ago, and then anyone may call it; the proposal is consumed. The
//! bypass closes on [`activate`] or on the first [`propose`] and never reopens. One copy for the four
//! contracts that carry it (both escrows, the merkle-manager, the dispute-manager).

use soroban_sdk::{
    contractevent, symbol_short, xdr::ToXdr, Address, BytesN, Env, Symbol, Val, Vec,
};

use crate::escrow_ops::Fault;
use crate::ttl::extend_persistent;

/// The minimum time between a proposal and its execution: 24 hours.
pub const DELAY: u64 = 24 * 60 * 60;

/// Instance: the bypass is closed. One-way.
const KEY_TL_ACTIVE: Symbol = symbol_short!("tlactive");
/// Persistent: `(tleta, id) -> u64`, the earliest execution time of a pending proposal.
const KEY_TL_ETA: Symbol = symbol_short!("tleta");

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

/// The earliest execution time of a pending proposal; 0 = none.
pub fn eta(env: &Env, id: &BytesN<32>) -> u64 {
    env.storage()
        .persistent()
        .get(&(KEY_TL_ETA, id.clone()))
        .unwrap_or(0)
}

/// The proposal id of a call: `sha256` of the XDR of `(fn_name, args)`.
pub fn action_id(env: &Env, fn_name: &Symbol, args: &Vec<Val>) -> BytesN<32> {
    env.crypto()
        .sha256(&(fn_name.clone(), args.clone()).to_xdr(env))
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

/// Queue a call. Closes the bypass if still open. The caller has authenticated the admin.
pub fn propose(env: &Env, fn_name: Symbol, args: Vec<Val>) -> Result<BytesN<32>, Fault> {
    if !is_active(env) {
        set_active(env);
    }
    let id = action_id(env, &fn_name, &args);
    if eta(env, &id) != 0 {
        return Err(Fault::TimelockAlreadyProposed);
    }
    let eta = env.ledger().timestamp() + DELAY;
    let key = (KEY_TL_ETA, id.clone());
    env.storage().persistent().set(&key, &eta);
    extend_persistent(env, &key);
    ActionProposed {
        id: id.clone(),
        eta,
        fn_name,
        args,
    }
    .publish(env);
    Ok(id)
}

/// Drop a pending proposal. The caller has authenticated the admin.
pub fn cancel(env: &Env, id: BytesN<32>) -> Result<(), Fault> {
    if eta(env, &id) == 0 {
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

/// The gate at the top of a timelocked setter: before activation the admin's auth; after, a ripe
/// proposal for exactly `(fn_name, args)`, consumed here, from anyone.
pub fn gate(env: &Env, admin: &Address, fn_name: &str, args: Vec<Val>) -> Result<(), Fault> {
    if !is_active(env) {
        admin.require_auth();
        return Ok(());
    }
    let id = action_id(env, &Symbol::new(env, fn_name), &args);
    let at = eta(env, &id);
    if at == 0 {
        return Err(Fault::TimelockNotProposed);
    }
    if env.ledger().timestamp() < at {
        return Err(Fault::TimelockTooEarly);
    }
    env.storage().persistent().remove(&(KEY_TL_ETA, id.clone()));
    ActionExecuted {
        id,
        at: env.ledger().timestamp(),
    }
    .publish(env);
    Ok(())
}

/// A brake (removing an appender or an escrow) stays instant for the admin; anything else is gated.
pub fn gate_unless(
    env: &Env,
    admin: &Address,
    brake: bool,
    fn_name: &str,
    args: Vec<Val>,
) -> Result<(), Fault> {
    if brake {
        admin.require_auth();
        return Ok(());
    }
    gate(env, admin, fn_name, args)
}
