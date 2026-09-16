//! Event types for the OrderPortal contract.
//!
//! Uses the `#[contractevent]` macro (SDK v23+) instead of the deprecated
//! `env.events().publish()` API. Everything both escrows emit the same way — settlement, admin,
//! pause, pull payments, the whole termination set — is defined once in
//! `proofbridge_core::escrow_events` and re-exported here; what is left below is this leg's own.

use soroban_sdk::{contractevent, BytesN, String};

pub use proofbridge_core::escrow_events::*;

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

// =============================================================================
// Termination Events (2.3e)
// =============================================================================

/// The bridger's deposit went back to them (`Cancelled`).
#[contractevent(topics = ["ord_rfnd"], data_format = "vec")]
pub struct OrderRefunded {
    #[topic]
    pub order_hash: BytesN<32>,
    pub bridger: BytesN<32>,
    pub amount: u128,
}
