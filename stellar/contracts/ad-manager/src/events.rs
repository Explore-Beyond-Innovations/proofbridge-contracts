//! Event types for the AdManager contract
//!
//! Uses the `#[contractevent]` macro (SDK v23+) instead of the deprecated
//! `env.events().publish()` API.

use soroban_sdk::{contractevent, Address, BytesN, String};

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
