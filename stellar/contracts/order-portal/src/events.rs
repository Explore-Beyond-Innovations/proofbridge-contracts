//! Event types for the OrderPortal contract
//!
//! Uses the `#[contractevent]` macro (SDK v23+) instead of the deprecated
//! `env.events().publish()` API.

use soroban_sdk::{contractevent, Address, BytesN, String};

// =============================================================================
// Admin Events
// =============================================================================

#[contractevent(topics = ["mgr_upd"], data_format = "single-value")]
pub struct ManagerUpdated {
    #[topic]
    pub manager: Address,
    pub status: bool,
}

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
