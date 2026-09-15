//! Event types for the AdManager contract
//!
//! Uses the `#[contractevent]` macro (SDK v23+) instead of the deprecated
//! `env.events().publish()` API.

use soroban_sdk::{contractevent, Address, BytesN, String};

use crate::types::{ClaimEntry, RouteTiming};

// =============================================================================
// Admin Events
// =============================================================================

#[contractevent(topics = ["init"], data_format = "vec")]
pub struct Initialized {
    #[topic]
    pub admin: Address,
    pub verifier: Address,
    pub merkle_manager: Address,
    pub chain_id: u128,
}

// =============================================================================
// Chain / Route Events
// =============================================================================

#[contractevent(topics = ["chain_set"], data_format = "vec")]
pub struct ChainSet {
    #[topic]
    pub chain_id: u128,
    pub order_portal: BytesN<32>,
    pub supported: bool,
}

#[contractevent(topics = ["route_set"], data_format = "vec")]
pub struct TokenRouteSet {
    #[topic]
    pub ad_token: BytesN<32>,
    pub order_token: BytesN<32>,
    pub order_chain_id: u128,
}

#[contractevent(topics = ["route_rm"], data_format = "vec")]
pub struct TokenRouteRemoved {
    #[topic]
    pub ad_token: BytesN<32>,
    pub order_token: BytesN<32>,
    pub order_chain_id: u128,
}

// =============================================================================
// Ad Events
// =============================================================================

#[contractevent(topics = ["ad_create"], data_format = "vec")]
pub struct AdCreated {
    #[topic]
    pub ad_id: String,
    pub maker: Address,
    pub token: BytesN<32>,
    pub init_amount: u128,
    pub order_chain_id: u128,
    pub settlement_signer: BytesN<32>,
}

/// The key registry the escrow consults was set (2.3c D2).
#[contractevent(topics = ["keyreg_set"], data_format = "vec")]
pub struct KeyRegistrySet {
    pub registry: Address,
}

/// A maker re-pointed an ad's settlement signer — the third kill lever (2.3c D3).
#[contractevent(topics = ["signer_set"], data_format = "vec")]
pub struct SettlementSignerSet {
    #[topic]
    pub ad_id: String,
    pub previous: BytesN<32>,
    pub next: BytesN<32>,
}

#[contractevent(topics = ["ad_fund"], data_format = "vec")]
pub struct AdFunded {
    #[topic]
    pub ad_id: String,
    pub maker: Address,
    pub amount: u128,
    pub new_balance: u128,
}

#[contractevent(topics = ["ad_wdraw"], data_format = "vec")]
pub struct AdWithdrawn {
    #[topic]
    pub ad_id: String,
    pub maker: Address,
    pub amount: u128,
    pub new_balance: u128,
}

#[contractevent(topics = ["ad_close"], data_format = "single-value")]
pub struct AdClosed {
    #[topic]
    pub ad_id: String,
    pub maker: Address,
}

// =============================================================================
// Order Events
// =============================================================================

#[contractevent(topics = ["ord_lock"], data_format = "vec")]
pub struct OrderLocked {
    #[topic]
    pub order_hash: BytesN<32>,
    pub ad_id: String,
    pub maker: Address,
    pub token: BytesN<32>,
    pub amount: u128,
    pub bridger: BytesN<32>,
    pub recipient: BytesN<32>,
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

/// The leg reached `Cancelled` (never by evidence on the primary: it is the leaf's author).
#[contractevent(topics = ["ord_cncl"], data_format = "single-value")]
pub struct OrderCancelled {
    #[topic]
    pub order_hash: BytesN<32>,
    pub by_evidence: bool,
}

/// A lock was released back to the ad's free balance by an unchallenged cancel.
#[contractevent(topics = ["lock_cncl"], data_format = "vec")]
pub struct LockCancelled {
    #[topic]
    pub order_hash: BytesN<32>,
    pub ad_id: String,
    pub amount: u128,
}

/// The leg's SETTLED leaf was appended (`record_settled`, the follow-up to a fill on Soroban).
#[contractevent(topics = ["setl_leaf"], data_format = "single-value")]
pub struct SettledRecorded {
    #[topic]
    pub order_hash: BytesN<32>,
}
