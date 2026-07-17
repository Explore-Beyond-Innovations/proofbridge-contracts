//! Event types for the OrderPortal contract
//!
//! Uses the `#[contractevent]` macro (SDK v23+) instead of the deprecated
//! `env.events().publish()` API.

use soroban_sdk::{contractevent, Address, BytesN, String};

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
