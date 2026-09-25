//! Event types for the AdManager contract.
//!
//! Uses the `#[contractevent]` macro (SDK v23+) instead of the deprecated
//! `env.events().publish()` API. Everything both escrows emit the same way — settlement, admin,
//! pause, pull payments, the whole termination set — is defined once in
//! `proofbridge_core::escrow_events` and re-exported here; what is left below is this leg's own.

use soroban_sdk::{contractevent, Address, BytesN, String};

pub use proofbridge_core::escrow_events::*;

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

/// The maker halted the co-signed payout of every order against their ads (#422).
#[contractevent(topics = ["halt"], data_format = "single-value")]
pub struct SettlementHalted {
    #[topic]
    pub maker: Address,
}

/// The maker lifted their halt.
#[contractevent(topics = ["resume"], data_format = "single-value")]
pub struct SettlementResumed {
    #[topic]
    pub maker: Address,
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

// =============================================================================
// Termination Events (2.3e)
// =============================================================================

/// A lock was released back to the ad's free balance by an unchallenged cancel.
#[contractevent(topics = ["lock_cncl"], data_format = "vec")]
pub struct LockCancelled {
    #[topic]
    pub order_hash: BytesN<32>,
    pub ad_id: String,
    pub amount: u128,
}
