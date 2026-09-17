//! What the two escrows do the same way: the admin surface, the pull-payment escrow, and the whole
//! termination core (2.3e).
//!
//! These were two copies before. A copy that drifts is the failure mode that matters here — the
//! pause arithmetic and the terminal transitions have to agree across the legs or a window closes on
//! one chain and not the other — so they live once and each escrow calls in.
//!
//! **The error seam.** Each contract's `#[contracterror]` enum is its own ABI: the discriminants
//! differ and must keep differing. So nothing here returns a contract error. A check that can fail
//! returns [`Fault`], an opaque reason, and each contract converts it once through `From` — one
//! small `match` per crate rather than a trait that grows a constructor per check.

use soroban_sdk::{Address, BytesN, Env};

use crate::cross_contract;
use crate::errors::ProofBridgeError;
use crate::escrow_events;
use crate::escrow_storage as storage;
use crate::types::{ClaimEntry, ClaimRecord, ContractConfig, DisputeOutcome, RouteTiming, Status};

/// Why a shared check refused. Each escrow maps this onto its own error enum.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Fault {
    ContractPaused,
    NoRouteTiming,
    DeadlineTooSoon,
    TooEarly,
    NotClaimable,
    NotClaimed,
    NoRootAnchor,
    RootNotAnchored,
    NotFilled,
    SettledRecorded,
    NothingToClaim,
    InvalidTiming,
    NotPendingAdmin,
    /// No dispute module is wired, so disputes are unavailable on this escrow.
    NoDisputeManager,
    /// The order is not in a state a dispute can be filed on.
    NotDisputable,
    /// The module's window has not closed, so there is nothing to apply yet.
    DisputeNotResolved,
}

// =============================================================================
// Pause
// =============================================================================

pub fn require_not_paused(env: &Env) -> Result<(), Fault> {
    if storage::is_paused(env) {
        return Err(Fault::ContractPaused);
    }
    Ok(())
}

/// Start the pause clock, once: a second `pause` while paused must not move the start.
pub fn pause(env: &Env, config: &ContractConfig) {
    if !storage::is_paused(env) {
        storage::set_last_paused_at(env, env.ledger().timestamp());
    }
    storage::set_paused(env, true);
    escrow_events::Paused {
        admin: config.admin.clone(),
    }
    .publish(env);
}

/// A pause freezes evidence, so it stops the clocks: the seconds spent paused move every window
/// that was open by exactly that much (see [`window_end`]).
pub fn unpause(env: &Env, config: &ContractConfig) {
    if storage::is_paused(env) {
        let paused_for = env
            .ledger()
            .timestamp()
            .saturating_sub(storage::get_last_paused_at(env));
        storage::set_paused_seconds(
            env,
            storage::get_paused_seconds(env).saturating_add(paused_for),
        );
    }
    storage::set_paused(env, false);
    escrow_events::Unpaused {
        admin: config.admin.clone(),
    }
    .publish(env);
}

// =============================================================================
// Admin handover
// =============================================================================

pub fn transfer_admin(env: &Env, config: &ContractConfig, to: Address) {
    storage::set_pending_admin(env, &to);
    escrow_events::AdminTransferStarted {
        from: config.admin.clone(),
        to,
    }
    .publish(env);
}

/// The standing nomination, or `NotPendingAdmin`. Paired with [`accept_admin`]: the caller reads the
/// nominee here, authorises it, then commits — so the lookup can never be skipped, and
/// `require_auth` stays in the contract where an auditor reads the entry point.
pub fn pending_admin(env: &Env) -> Result<Address, Fault> {
    storage::get_pending_admin(env).ok_or(Fault::NotPendingAdmin)
}

/// Commit the handover. `pending` must be the address [`pending_admin`] returned and the caller must
/// have authorised it.
pub fn accept_admin(env: &Env, config: &mut ContractConfig, pending: Address) {
    let old = core::mem::replace(&mut config.admin, pending.clone());
    storage::set_config(env, config);
    storage::clear_pending_admin(env);
    escrow_events::AdminTransferred {
        from: old,
        to: pending,
    }
    .publish(env);
}

// =============================================================================
// Admin setters
// =============================================================================

pub fn set_root_verifier(env: &Env, chain_id: u128, module: Address) {
    storage::set_root_verifier(env, chain_id, &module);
    escrow_events::RootVerifierSet { chain_id, module }.publish(env);
}

/// Set the termination clocks for a peer chain (2.3e D6). Validated; unset fails closed.
pub fn set_route_timing(env: &Env, chain_id: u128, timing: RouteTiming) -> Result<(), Fault> {
    crate::timing::validate(&timing).map_err(|_| Fault::InvalidTiming)?;
    storage::set_route_timing(env, chain_id, &timing);
    escrow_events::RouteTimingSet { chain_id, timing }.publish(env);
    crate::ttl::extend_instance(env);
    Ok(())
}

/// Set the notary the evidence paths read (2.3e D7). Settlement never touches it.
pub fn set_root_anchor(env: &Env, anchor: Address) {
    storage::set_root_anchor(env, &anchor);
    escrow_events::RootAnchorSet { anchor }.publish(env);
    crate::ttl::extend_instance(env);
}

// =============================================================================
// Pull payments
// =============================================================================

/// Best-effort push; a recipient that cannot be paid is credited instead, so it can never block
/// settlement.
pub fn pay_or_credit(
    env: &Env,
    w_native: &Address,
    recipient: &BytesN<32>,
    token: &BytesN<32>,
    amount: u128,
) {
    if crate::token::try_transfer_to_recipient_bytes32(env, token, w_native, recipient, amount) {
        return;
    }
    let owed = storage::get_claimable(env, recipient, token);
    storage::set_claimable(env, recipient, token, owed + amount);
    escrow_events::PayoutCredited {
        recipient: recipient.clone(),
        token: token.clone(),
        amount,
    }
    .publish(env);
}

/// Pay out a credited amount. Permissionless: funds can only go to the credited recipient.
pub fn claim<E: ProofBridgeError + From<Fault>>(
    env: &Env,
    config: &ContractConfig,
    recipient: BytesN<32>,
    token: BytesN<32>,
) -> Result<(), E> {
    let amount = storage::get_claimable(env, &recipient, &token);
    if amount == 0 {
        return Err(Fault::NothingToClaim.into());
    }
    storage::set_claimable(env, &recipient, &token, 0);
    crate::token::transfer_to_recipient_bytes32::<E>(
        env,
        &token,
        &config.w_native_token,
        &recipient,
        amount,
    )?;
    escrow_events::PayoutClaimed {
        recipient,
        token,
        amount,
    }
    .publish(env);
    Ok(())
}

// =============================================================================
// Termination core (2.3e)
// =============================================================================

/// The route's clocks, or `NoRouteTiming` (the `RootVerifierNotSet` posture).
pub fn timing(env: &Env, chain_id: u128) -> Result<RouteTiming, Fault> {
    storage::get_route_timing(env, chain_id).ok_or(Fault::NoRouteTiming)
}

/// `deadline >= now + min_window` at every lock/create (2.3e D5): the precondition that makes
/// "no lock can follow the deadline" hold for `cancel_never_locked`.
pub fn require_min_window(env: &Env, chain_id: u128, deadline: u64) -> Result<(), Fault> {
    let t = timing(env, chain_id)?;
    if deadline < env.ledger().timestamp() + t.min_window {
        return Err(Fault::DeadlineTooSoon);
    }
    Ok(())
}

pub fn require_reached(env: &Env, at: u64) -> Result<(), Fault> {
    if env.ledger().timestamp() < at {
        return Err(Fault::TooEarly);
    }
    Ok(())
}

/// The leg must be exactly `expected` (`Open` before a claim, `None` before a never-locked cancel).
pub fn require_status(env: &Env, order_hash: &BytesN<32>, expected: Status) -> Result<(), Fault> {
    if storage::get_order_status(env, order_hash) != expected {
        return Err(Fault::NotClaimable);
    }
    Ok(())
}

/// `Open` or in a presentation window: evidence may still settle or refund it.
pub fn require_presentable(env: &Env, order_hash: &BytesN<32>) -> Result<(), Fault> {
    match storage::get_order_status(env, order_hash) {
        // `Disputed` belongs here because evidence beats arbitration at any time (2.3g D5) —
        // including while a ruling's own window runs, which is what makes a ruling overridable.
        Status::Open | Status::Claimed | Status::Disputed => Ok(()),
        _ => Err(Fault::NotClaimable),
    }
}

/// When the leg's presentation window ends, in real time. Once claimed: the claim's `finalize_at`
/// plus every second the escrow has been paused since the claim opened (exact across any number of
/// pauses). Before a claim: `deadline + buffer` plus every second paused since the leg was locked
/// (its own snapshot; a pause before the deadline counts too — it froze both unlocks, and more time
/// for evidence is the safe direction). A pause stops the clocks and never reopens a closed window:
/// a pause after the end adds its length, but the clock moved on by the same length.
/// One number serves both sides of the race: the unlock cutoff is this minus the margin, the
/// finalize needs it reached. Saturating: a far deadline never panics (EVM uses uint256).
pub fn window_end(env: &Env, order_hash: &BytesN<32>, deadline: u64, buffer: u64) -> u64 {
    let order = storage::get_order(env, order_hash);
    let paused = storage::get_paused_seconds(env);
    if order.status == Status::Claimed {
        if let Some(claim) = storage::get_claim(env, order_hash) {
            return claim
                .finalize_at
                .saturating_add(paused.saturating_sub(claim.paused_at_open));
        }
    }
    deadline
        .saturating_add(buffer)
        .saturating_add(paused.saturating_sub(order.paused_at_open))
}

/// `Claimed` and the window is over.
pub fn require_finalizable(env: &Env, order_hash: &BytesN<32>, buffer: u64) -> Result<(), Fault> {
    if storage::get_order_status(env, order_hash) != Status::Claimed {
        return Err(Fault::NotClaimed);
    }
    require_reached(env, window_end(env, order_hash, 0, buffer))
}

/// Gate for the evidence paths: the root must be notarized by the wired anchor (D7).
pub fn require_anchored(env: &Env, chain_id: u128, root: &BytesN<32>) -> Result<(), Fault> {
    let anchor = storage::get_root_anchor(env).ok_or(Fault::NoRootAnchor)?;
    if !cross_contract::is_anchored(env, &anchor, chain_id, root) {
        return Err(Fault::RootNotAnchored);
    }
    Ok(())
}

/// Open a presentation window on an `Open` leg; only a finalize or evidence closes it.
pub fn open_claim(env: &Env, order_hash: &BytesN<32>, entry: ClaimEntry, finalize_at: u64) {
    storage::set_claim(
        env,
        order_hash,
        &ClaimRecord {
            opened_at: env.ledger().timestamp(),
            finalize_at,
            paused_at_open: storage::get_paused_seconds(env),
            entry,
        },
    );
    storage::set_order_status(env, order_hash, Status::Claimed);
    escrow_events::ClaimOpened {
        order_hash: order_hash.clone(),
        entry,
        finalize_at,
    }
    .publish(env);
}

// =============================================================================
// Disputes (2.3g)
// =============================================================================

/// The module, or `NoDisputeManager`.
pub fn dispute_manager(env: &Env) -> Result<Address, Fault> {
    storage::get_dispute_manager(env).ok_or(Fault::NoDisputeManager)
}

/// `Open | Claimed → Disputed`, with the bond handed straight to the module.
///
/// Note the direction, and the order. The escrow calls the module and the module never calls back —
/// filing has to begin here anyway, because a leg stores `{status, paused_at_open}` and nothing
/// else, so only this contract can hash an order and vouch for the amount that sizes the bond. And
/// the module call runs *before* the status is committed, so a caller that ever swallowed its
/// failure would leave the order `Open` with no record — a failed filing — rather than `Disputed`
/// with no record, which is an order nobody can finalize.
pub fn open_dispute(
    env: &Env,
    escrow: &Address,
    order_hash: &BytesN<32>,
    amount: u128,
    peer_chain_id: u128,
    filer: &Address,
    evidence: &BytesN<32>,
) -> Result<u128, Fault> {
    match storage::get_order_status(env, order_hash) {
        Status::Open | Status::Claimed => {}
        _ => return Err(Fault::NotDisputable),
    }
    let manager = dispute_manager(env)?;
    let bond = cross_contract::DisputeManagerClient::new(env, &manager).open_dispute(
        escrow,
        order_hash,
        &amount,
        &peer_chain_id,
        filer,
        evidence,
    );
    storage::set_order_status(env, order_hash, Status::Disputed);
    Ok(bond)
}

/// The module's verdict, once its window has closed. `None` becomes the fallback's mutual refund.
pub fn dispute_outcome(
    env: &Env,
    order_hash: &BytesN<32>,
) -> Result<(DisputeOutcome, Option<Address>), Fault> {
    let manager = dispute_manager(env)?;
    let (outcome, window_over, initiator) =
        cross_contract::DisputeManagerClient::new(env, &manager).outcome_of(order_hash);
    if !window_over {
        return Err(Fault::DisputeNotResolved);
    }
    let settled = if outcome == DisputeOutcome::None {
        DisputeOutcome::MutualRefund
    } else {
        outcome
    };
    Ok((settled, initiator))
}

/// Tell the module the dispute is over so it can route the bond and close its record.
/// `filer_is_bridger` is absolute, not relative to the calling escrow. Each leg authenticates a
/// different party, so "the filer is my counterparty" means opposite things on the two escrows —
/// phrasing it that way inverted the routing on the follower leg, returning a forfeited bond and
/// forfeiting a vindicated one.
pub fn settle_bond(
    env: &Env,
    escrow: &Address,
    order_hash: &BytesN<32>,
    filer_is_bridger: bool,
) -> Result<(), Fault> {
    let manager = dispute_manager(env)?;
    cross_contract::DisputeManagerClient::new(env, &manager).settle_bond(
        escrow,
        order_hash,
        &filer_is_bridger,
    );
    Ok(())
}

/// Evidence terminated a disputed order, so the dispute is over whatever the arbiter thought.
/// A no-op when nothing was disputed, so the evidence paths can call it unconditionally.
pub fn close_dispute_by_evidence(env: &Env, escrow: &Address, order_hash: &BytesN<32>) {
    if let Some(manager) = storage::get_dispute_manager(env) {
        let client = cross_contract::DisputeManagerClient::new(env, &manager);
        if client.is_disputed(order_hash) {
            client.settle_bond(escrow, order_hash, &false);
        }
    }
}

/// `Open | Claimed → Filled`: close the window, count out. The SETTLED leaf (D8) is appended by
/// `record_settled`, a separate call — a verify plus a Poseidon2 MMR append measured 105.8M
/// instructions against a 96.1M unlock. (That was read as "over budget" against the SDK harness
/// default of 100M; the network's actual limit is 400M, so the split now rests on matching the EVM
/// leg so the relayer batches one shape, not on the CPU figure.) Counting out mirrors the leg's
/// open (2.3c D1).
pub fn fill(env: &Env, order_hash: &BytesN<32>, account: &BytesN<32>, by_evidence: bool) {
    storage::set_order_status(env, order_hash, Status::Filled);
    storage::remove_claim(env, order_hash);
    storage::set_in_flight(env, account, storage::get_in_flight(env, account) - 1);
    escrow_events::OrderSettled {
        order_hash: order_hash.clone(),
        by_evidence,
    }
    .publish(env);
}

/// `→ Cancelled`: close the window, count out. The leaf, where there is one, and the funds are the
/// caller's.
pub fn cancel(env: &Env, order_hash: &BytesN<32>, account: &BytesN<32>, by_evidence: bool) {
    storage::set_order_status(env, order_hash, Status::Cancelled);
    storage::remove_claim(env, order_hash);
    storage::set_in_flight(env, account, storage::get_in_flight(env, account) - 1);
    escrow_events::OrderCancelled {
        order_hash: order_hash.clone(),
        by_evidence,
    }
    .publish(env);
}

/// Append this leg's SETTLED leaf for a `Filled` order, once (D8): what lets the other escrow's
/// presenter prove this one paid. Permissionless; the caller only names the order.
pub fn record_settled<E: ProofBridgeError + From<Fault>>(
    env: &Env,
    merkle_manager: &Address,
    order_hash: &BytesN<32>,
) -> Result<(), E> {
    if storage::get_order_status(env, order_hash) != Status::Filled {
        return Err(Fault::NotFilled.into());
    }
    if storage::is_settled_recorded(env, order_hash) {
        return Err(Fault::SettledRecorded.into());
    }
    storage::set_settled_recorded(env, order_hash);
    cross_contract::append_to_merkle::<E>(
        env,
        merkle_manager,
        order_hash,
        cross_contract::LEAF_DOMAIN_SETTLED,
    )?;
    escrow_events::SettledRecorded {
        order_hash: order_hash.clone(),
    }
    .publish(env);
    crate::ttl::extend_instance(env);
    Ok(())
}
