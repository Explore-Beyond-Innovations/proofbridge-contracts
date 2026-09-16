//! The events both escrows emit, defined once.
//!
//! Every event here is byte-identical on the two legs — same topics, same data format, same field
//! names and order — so it is the same wire record whichever escrow emitted it, and an indexer can
//! read one shape. What is genuinely per-leg (an ad's lifecycle, a lock, a chain record that names
//! the *other* leg's contract) stays in the contract's own `events` module.

use soroban_sdk::{contractevent, Address, BytesN};

use crate::types::{ClaimEntry, RouteTiming};

// =============================================================================
// Settlement
// =============================================================================

#[contractevent(topics = ["ord_unlck"], data_format = "vec")]
pub struct OrderUnlocked {
    #[topic]
    pub order_hash: BytesN<32>,
    pub recipient: BytesN<32>,
    pub nullifier_hash: BytesN<32>,
}

// =============================================================================
// Admin / pause
// =============================================================================

#[contractevent(topics = ["rverif"], data_format = "single-value")]
pub struct RootVerifierSet {
    #[topic]
    pub chain_id: u128,
    pub module: Address,
}

#[contractevent(topics = ["paused"], data_format = "single-value")]
pub struct Paused {
    pub admin: Address,
}

#[contractevent(topics = ["unpaused"], data_format = "single-value")]
pub struct Unpaused {
    pub admin: Address,
}

#[contractevent(topics = ["adm_start"], data_format = "single-value")]
pub struct AdminTransferStarted {
    #[topic]
    pub from: Address,
    pub to: Address,
}

#[contractevent(topics = ["adm_done"], data_format = "single-value")]
pub struct AdminTransferred {
    #[topic]
    pub from: Address,
    pub to: Address,
}

// =============================================================================
// Pull payments
// =============================================================================

#[contractevent(topics = ["pay_cred"], data_format = "vec")]
pub struct PayoutCredited {
    #[topic]
    pub recipient: BytesN<32>,
    pub token: BytesN<32>,
    pub amount: u128,
}

#[contractevent(topics = ["pay_clm"], data_format = "vec")]
pub struct PayoutClaimed {
    #[topic]
    pub recipient: BytesN<32>,
    pub token: BytesN<32>,
    pub amount: u128,
}

// =============================================================================
// Termination (2.3e)
// =============================================================================

/// The termination clocks for a peer chain were set (D6).
#[contractevent(topics = ["timing"], data_format = "vec")]
pub struct RouteTimingSet {
    #[topic]
    pub chain_id: u128,
    pub timing: RouteTiming,
}

/// The notary the evidence paths read was set (D7).
#[contractevent(topics = ["anchor"], data_format = "single-value")]
pub struct RootAnchorSet {
    pub anchor: Address,
}

/// A presentation window opened on this leg; it may be finalized at `finalize_at`.
#[contractevent(topics = ["clm_open"], data_format = "vec")]
pub struct ClaimOpened {
    #[topic]
    pub order_hash: BytesN<32>,
    pub entry: ClaimEntry,
    pub finalize_at: u64,
}

/// The leg reached `Filled`; `by_evidence` is true for `present_settled`, false for the co-signed
/// `unlock`.
#[contractevent(topics = ["ord_setl"], data_format = "single-value")]
pub struct OrderSettled {
    #[topic]
    pub order_hash: BytesN<32>,
    pub by_evidence: bool,
}

/// The leg reached `Cancelled`; `by_evidence` is true for the evidence path (a proof of the
/// primary's cancel leaf), false for a clock-driven finalize.
#[contractevent(topics = ["ord_cncl"], data_format = "single-value")]
pub struct OrderCancelled {
    #[topic]
    pub order_hash: BytesN<32>,
    pub by_evidence: bool,
}

/// The leg's SETTLED leaf was appended (`record_settled`, the follow-up to a fill on Soroban).
#[contractevent(topics = ["setl_leaf"], data_format = "single-value")]
pub struct SettledRecorded {
    #[topic]
    pub order_hash: BytesN<32>,
}
