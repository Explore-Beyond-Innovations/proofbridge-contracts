//! What the two escrows do the same way: the admin surface, the pull-payment escrow, and the whole
//! termination core (2.3e).
//!
//! These were two copies before. A copy that drifts is the failure mode that matters here — the
//! pause arithmetic and the terminal transitions have to agree across the legs or a window closes on
//! one chain and not the other — so they live once and each escrow calls in.
//!
//! **The error seam.** Each contract's `#[contracterror]` enum is its own ABI: the discriminants
//! differ and must keep differing. So nothing in this crate returns a contract error. A check that can fail
//! returns [`Fault`], an opaque reason, and each contract converts it once through `From` — one
//! small `match` per crate rather than a trait that grows a constructor per check.

use soroban_sdk::{Address, BytesN, Env};

use crate::cross_contract;
use crate::escrow_events;
use crate::escrow_storage as storage;
use crate::types::{ClaimEntry, ClaimRecord, ContractConfig, DisputeOutcome, RouteTiming, Status};

/// Why a shared check refused. Each escrow maps this onto its own error enum.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Fault {
    ContractPaused,
    NoRouteTiming,
    DeadlineTooSoon,
    /// #453: the deadline is past `now + MAX_ORDER_WINDOW`.
    DeadlineTooFar,
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
    /// C-10: the primary's window has closed, so a dispute can no longer be filed.
    DisputeWindowClosed,
    /// C-31: the dispute module trapped or failed in the host; no contract error to relay.
    DisputeModuleRejected,
    /// 49S-3: the module's own refusals, relayed so the frontend and relayer can tell them apart.
    DisputeNoParams,
    DisputeNotEscrow,
    DisputeExists,
    DisputeWrongEscrow,
    DisputeNotResponder,
    DisputeChallengeClosed,
    /// 49S-3: the module could not move the bond (a token refusal, e.g. no trustline or a shortfall).
    DisputeBondTransferFailed,
    /// D5: the module's answer rules (window closed, already answered, empty answer), relayed.
    DisputeResponseWindowClosed,
    DisputeAlreadyResponded,
    DisputeZeroResponse,
    /// The ruling closed the answer window (D5, R1).
    DisputeAlreadyRuled,
    /// A public input at or above the field prime (2.3h, residual 9). Defence in depth: both shipped
    /// verifiers already reject one, but the escrow's nullifier ledger keys on raw bytes, so a
    /// verifier that reduced instead would turn one proof into many nullifiers.
    NonCanonicalInput,
    /// A token address that names no contract (the zero / native marker where a contract is due).
    TokenZeroAddress,
    /// The MerkleManager refused or trapped the append.
    MerkleAppendFailed,
    /// The verifier refused the proof (or trapped).
    InvalidProof,
    /// Decimal scaling: a decimals value above `decimal_scaling::MAX_DECIMALS`.
    DecimalsOutOfRange,
    /// Decimal scaling: scaling down would lose precision.
    NonExactDownscale,
    /// Decimal scaling: the scaled amount overflows.
    DecimalOverflow,
    /// 32 bytes that cannot be an account address (all zero).
    InvalidAccountAddress,
}

impl From<crate::decimal_scaling::DecimalScalingError> for Fault {
    fn from(e: crate::decimal_scaling::DecimalScalingError) -> Self {
        use crate::decimal_scaling::DecimalScalingError::*;
        match e {
            DecimalsOutOfRange => Fault::DecimalsOutOfRange,
            NonExactDownscale => Fault::NonExactDownscale,
            Overflow => Fault::DecimalOverflow,
        }
    }
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
    storage::add_wired_chain(env, chain_id);
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
pub fn claim(
    env: &Env,
    config: &ContractConfig,
    recipient: BytesN<32>,
    token: BytesN<32>,
) -> Result<(), Fault> {
    let amount = storage::get_claimable(env, &recipient, &token);
    if amount == 0 {
        return Err(Fault::NothingToClaim);
    }
    storage::set_claimable(env, &recipient, &token, 0);
    crate::token::transfer_to_recipient_bytes32(
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

/// `now + min_window <= deadline <= now + MAX_ORDER_WINDOW` at every lock/create. The floor (2.3e
/// D5) makes "no lock can follow the deadline" hold for `cancel_never_locked`; the ceiling (#453)
/// keeps the order inside the key registry's memory of a dead slot.
pub fn require_min_window(env: &Env, chain_id: u128, deadline: u64) -> Result<(), Fault> {
    let t = timing(env, chain_id)?;
    let now = env.ledger().timestamp();
    if deadline < now + t.min_window {
        return Err(Fault::DeadlineTooSoon);
    }
    if deadline > now + crate::timing::MAX_ORDER_WINDOW {
        return Err(Fault::DeadlineTooFar);
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

/// The module new filings go to, or `NoDisputeManager`.
pub fn dispute_manager(env: &Env) -> Result<Address, Fault> {
    storage::get_dispute_manager(env).ok_or(Fault::NoDisputeManager)
}

/// The module this order was filed with (C-11), or `NoDisputeManager` if it never was. Every call
/// after filing reads this one, so swapping the escrow's module only affects new filings (D5).
pub fn order_dispute_manager(env: &Env, order_hash: &BytesN<32>) -> Result<Address, Fault> {
    storage::get_order_dispute_manager(env, order_hash).ok_or(Fault::NoDisputeManager)
}

/// `Open | Claimed → Disputed`, with the bond handed straight to the module.
///
/// Note the direction, and the order. The escrow calls the module and the module never calls back —
/// filing has to begin here anyway, because a leg stores `{status, paused_at_open}` and nothing
/// else, so only this contract can hash an order and vouch for the amount that sizes the bond. And
/// the module call runs *before* the status is committed, so a caller that ever swallowed its
/// failure would leave the order `Open` with no record — a failed filing — rather than `Disputed`
/// with no record, which is an order nobody can finalize.
#[allow(clippy::too_many_arguments)]
pub fn open_dispute(
    env: &Env,
    escrow: &Address,
    order_hash: &BytesN<32>,
    amount: u128,
    peer_chain_id: u128,
    filer: &Address,
    evidence: &BytesN<32>,
    deadline: u64,
    buffer: u64,
) -> Result<u128, Fault> {
    match storage::get_order_status(env, order_hash) {
        Status::Open | Status::Claimed => {}
        _ => return Err(Fault::NotDisputable),
    }
    // C-10 (D4): no filing once the primary's window has closed, so a dispute cannot outlive the
    // follower's backstop. The last second of the window still files.
    if env.ledger().timestamp() > window_end(env, order_hash, deadline, buffer) {
        return Err(Fault::DisputeWindowClosed);
    }
    let manager = dispute_manager(env)?;
    let bond = cross_contract::DisputeManagerClient::new(env, &manager)
        .try_open_dispute(
            escrow,
            order_hash,
            &amount,
            &peer_chain_id,
            filer,
            evidence,
            &deadline,
            &buffer,
            // c41-J: the module adds every second paused past this snapshot, so the order's own
            // (from the lock, not the filing) makes its floor the primary's window end to the
            // second — a pause between lock and filing extends the unlock and the dispute alike.
            &storage::get_order(env, order_hash).paused_at_open,
        )
        .map_err(dispute_module_fault)?
        .map_err(|_| Fault::DisputeModuleRejected)?;
    storage::set_order_dispute_manager(env, order_hash, &manager);
    storage::set_order_status(env, order_hash, Status::Disputed);
    Ok(bond)
}

/// 49S-3: a `try_*` call into the dispute module fails either with the module's own contract error
/// (relayed by its discriminant — the DisputeManager's `#[contracterror]` codes) or with a host
/// failure (a trap, a missing contract), which stays `DisputeModuleRejected`.
pub fn dispute_module_fault(e: Result<soroban_sdk::Error, soroban_sdk::InvokeError>) -> Fault {
    use crate::dispute::error_code as code;
    use soroban_sdk::xdr::ScErrorType;
    match e {
        Ok(err) if err.is_type(ScErrorType::Contract) => match err.get_code() {
            code::NOT_ESCROW => Fault::DisputeNotEscrow,
            code::DISPUTE_EXISTS => Fault::DisputeExists,
            code::CHALLENGE_CLOSED => Fault::DisputeChallengeClosed,
            code::NOT_RESPONDER => Fault::DisputeNotResponder,
            code::NO_DISPUTE_PARAMS => Fault::DisputeNoParams,
            code::WRONG_ESCROW => Fault::DisputeWrongEscrow,
            code::BOND_TRANSFER_FAILED => Fault::DisputeBondTransferFailed,
            code::RESPONSE_WINDOW_CLOSED => Fault::DisputeResponseWindowClosed,
            code::ALREADY_RESPONDED => Fault::DisputeAlreadyResponded,
            code::ZERO_RESPONSE => Fault::DisputeZeroResponse,
            code::ALREADY_RULED => Fault::DisputeAlreadyRuled,
            _ => Fault::DisputeModuleRejected,
        },
        _ => Fault::DisputeModuleRejected,
    }
}

/// The module's verdict, once its window has closed. `None` becomes the fallback's mutual refund.
pub fn dispute_outcome(
    env: &Env,
    order_hash: &BytesN<32>,
) -> Result<(DisputeOutcome, Option<Address>), Fault> {
    let manager = order_dispute_manager(env, order_hash)?;
    let (outcome, window_over, initiator) =
        cross_contract::DisputeManagerClient::new(env, &manager)
            .try_outcome_of(order_hash, &storage::get_paused_seconds(env))
            .map_err(dispute_module_fault)?
            .map_err(|_| Fault::DisputeModuleRejected)?;
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

/// The module's ruling as it stands (`None` while unruled), whether or not its window is over: the
/// finalize-time view needs it before the window closes (D4).
pub fn dispute_ruling(env: &Env, order_hash: &BytesN<32>) -> Result<DisputeOutcome, Fault> {
    let manager = order_dispute_manager(env, order_hash)?;
    let (outcome, _, _) = cross_contract::DisputeManagerClient::new(env, &manager)
        .try_outcome_of(order_hash, &storage::get_paused_seconds(env))
        .map_err(dispute_module_fault)?
        .map_err(|_| Fault::DisputeModuleRejected)?;
    Ok(outcome)
}

/// The dispute's challenge deadline in real time, from the order's own module (#422, C-11).
pub fn dispute_challenge_deadline(env: &Env, order_hash: &BytesN<32>) -> Result<u64, Fault> {
    let manager = order_dispute_manager(env, order_hash)?;
    cross_contract::DisputeManagerClient::new(env, &manager)
        .try_challenge_deadline_of(order_hash, &storage::get_paused_seconds(env))
        .map_err(dispute_module_fault)?
        .map_err(|_| Fault::DisputeModuleRejected)
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
    outcome: DisputeOutcome,
    filer_is_bridger: bool,
) -> Result<(), Fault> {
    let manager = order_dispute_manager(env, order_hash)?;
    cross_contract::DisputeManagerClient::new(env, &manager)
        .try_settle_bond(escrow, order_hash, &outcome, &filer_is_bridger)
        .map_err(dispute_module_fault)?
        .map_err(|_| Fault::DisputeModuleRejected)
}

/// Record the counterparty's response. Escrow-only on the module's side, because only the escrow
/// knows the order's two parties (D11). The pause counter rides along: the module cannot read back
/// into its caller, and the answer deadline is the pause-adjusted challenge deadline (D5).
pub fn record_response(
    env: &Env,
    escrow: &Address,
    order_hash: &BytesN<32>,
    responder: &Address,
    evidence: &BytesN<32>,
) -> Result<(), Fault> {
    let manager = order_dispute_manager(env, order_hash)?;
    cross_contract::DisputeManagerClient::new(env, &manager)
        .try_record_response(
            escrow,
            order_hash,
            responder,
            evidence,
            &storage::get_paused_seconds(env),
        )
        .map_err(dispute_module_fault)?
        .map_err(|_| Fault::DisputeModuleRejected)
}

/// Who filed, or `None` when nothing is disputed here. The escrows need it to answer
/// `filer_is_bridger` on the evidence paths, where no ruling is involved.
pub fn dispute_filer(env: &Env, order_hash: &BytesN<32>) -> Result<Option<Address>, Fault> {
    let Some(manager) = storage::get_order_dispute_manager(env, order_hash) else {
        return Ok(None);
    };
    cross_contract::DisputeManagerClient::new(env, &manager)
        .try_initiator_of(order_hash)
        .map_err(dispute_module_fault)?
        .map_err(|_| Fault::DisputeModuleRejected)
}

/// Evidence terminated a disputed order, so the dispute is over whatever the arbiter thought.
///
/// The caller must have found a filer first (`dispute_filer`), which is what makes the record exist:
/// the call goes straight to `settle_bond`, and a record that is gone comes back as the module's
/// `NotDisputed`, relayed as `DisputeModuleRejected` — it fails closed. It is a no-op only when no
/// module was ever recorded for the order. Every path that admits `Disputed` must close the dispute,
/// or the bond has no exit at all: once the status leaves `Disputed`, `finalize_dispute` can never
/// run again and the module holds the bond forever.
///
/// `outcome` is what the path proved, not what anyone ruled: a settle is `TradeProceeds`, a
/// cancel-refund is `MutualRefund`. Reading the record's ruling here would route the bond by a
/// finding this evidence has just overturned.
pub fn close_dispute_by_evidence(
    env: &Env,
    escrow: &Address,
    order_hash: &BytesN<32>,
    outcome: DisputeOutcome,
    filer_is_bridger: bool,
) -> Result<(), Fault> {
    let Some(manager) = storage::get_order_dispute_manager(env, order_hash) else {
        return Ok(());
    };
    cross_contract::DisputeManagerClient::new(env, &manager)
        .try_settle_bond(escrow, order_hash, &outcome, &filer_is_bridger)
        .map_err(dispute_module_fault)?
        .map_err(|_| Fault::DisputeModuleRejected)
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
/// `→ Resolved`: the dispute terminal. Mirrors `cancel`'s bookkeeping — in particular it clears the
/// claim, so "terminal implies no open claim" holds here too. A `Claimed` leg that is then disputed
/// and resolved would otherwise keep a live claim with a past `finalize_at`, which #345's
/// conservation sweep and the relayer's projections both read.
pub fn resolve(env: &Env, order_hash: &BytesN<32>, account: &BytesN<32>) {
    storage::set_order_status(env, order_hash, Status::Resolved);
    storage::remove_claim(env, order_hash);
    storage::set_in_flight(env, account, storage::get_in_flight(env, account) - 1);
}

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
pub fn record_settled(
    env: &Env,
    merkle_manager: &Address,
    order_hash: &BytesN<32>,
) -> Result<(), Fault> {
    if storage::get_order_status(env, order_hash) != Status::Filled {
        return Err(Fault::NotFilled);
    }
    if storage::is_settled_recorded(env, order_hash) {
        return Err(Fault::SettledRecorded);
    }
    storage::set_settled_recorded(env, order_hash);
    cross_contract::append_to_merkle(
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
