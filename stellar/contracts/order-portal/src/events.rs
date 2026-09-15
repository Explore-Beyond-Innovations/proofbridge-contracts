//! Event types for the OrderPortal contract
//!
//! Uses the `#[contractevent]` macro (SDK v23+) instead of the deprecated
//! `env.events().publish()` API.

use soroban_sdk::{contractevent, Address, BytesN, String};

use crate::types::{ClaimEntry, RouteTiming};

// =============================================================================
// Chain / Route Events
// =============================================================================

#[contractevent(topics = ["chain_set"], data_format = "vec")]
pub struct ChainSet {
    #[topic]
    pub chain_id: u128,
    pub ad_manager: BytesN<32>,
    pub supported: bool,
}

#[contractevent(topics = ["route_set"], data_format = "vec")]
pub struct TokenRouteSet {
    #[topic]
    pub order_token: BytesN<32>,
    pub ad_token: BytesN<32>,
    pub ad_chain_id: u128,
}

#[contractevent(topics = ["route_rm"], data_format = "vec")]
pub struct TokenRouteRemoved {
    #[topic]
    pub order_token: BytesN<32>,
    pub ad_chain_id: u128,
}

// =============================================================================
// Order Events
// =============================================================================

#[contractevent(topics = ["ord_creat"], data_format = "vec")]
pub struct OrderCreated {
    #[topic]
    pub order_hash: BytesN<32>,
    pub bridger: BytesN<32>,
    pub order_chain_token: BytesN<32>,
    pub amount: u128,
    pub ad_chain_id: u128,
    pub ad_chain_token: BytesN<32>,
    pub ad_manager: BytesN<32>,
    pub ad_id: String,
    pub ad_creator: BytesN<32>,
    pub ad_recipient: BytesN<32>,
}

#[contractevent(topics = ["ord_unlck"], data_format = "vec")]
pub struct OrderUnlocked {
    #[topic]
    pub order_hash: BytesN<32>,
    pub recipient: BytesN<32>,
    pub nullifier_hash: BytesN<32>,
}

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
// Termination Events (2.3e)
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

/// The leg reached `Filled` and its SETTLED leaf was appended; `by_evidence` is true for
/// `present_settled`, false for the co-signed `unlock`.
#[contractevent(topics = ["ord_setl"], data_format = "single-value")]
pub struct OrderSettled {
    #[topic]
    pub order_hash: BytesN<32>,
    pub by_evidence: bool,
}

/// The leg reached `Cancelled`; `by_evidence` is true for `refund_by_cancel` (a proof of the
/// primary's cancel leaf), false for the clock-driven backstop finalize.
#[contractevent(topics = ["ord_cncl"], data_format = "single-value")]
pub struct OrderCancelled {
    #[topic]
    pub order_hash: BytesN<32>,
    pub by_evidence: bool,
}

/// The bridger's deposit went back to them (`Cancelled`).
#[contractevent(topics = ["ord_rfnd"], data_format = "vec")]
pub struct OrderRefunded {
    #[topic]
    pub order_hash: BytesN<32>,
    pub bridger: BytesN<32>,
    pub amount: u128,
}

/// The leg's SETTLED leaf was appended (`record_settled`, the follow-up to a fill on Soroban).
#[contractevent(topics = ["setl_leaf"], data_format = "single-value")]
pub struct SettledRecorded {
    #[topic]
    pub order_hash: BytesN<32>,
}
