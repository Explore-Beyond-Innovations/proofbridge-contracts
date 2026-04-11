//! Data types for the OrderPortal contract

use soroban_sdk::{contracttype, BytesN, String};

pub use proofbridge_core::token::NATIVE_TOKEN_ADDRESS;
pub use proofbridge_core::types::{ContractConfig, Status};

// =============================================================================
// Chain Configuration
// =============================================================================

/// Configuration for supported destination (ad) chains
#[contracttype]
#[derive(Clone, Debug)]
pub struct ChainInfo {
    /// Whether the destination chain is supported
    pub supported: bool,
    /// AdManager contract address on the destination chain
    pub ad_manager: BytesN<32>,
}

// =============================================================================
// Order Types
// =============================================================================

/// Parameters for creating or unlocking an order (order-portal variant)
#[contracttype]
#[derive(Clone, Debug)]
pub struct OrderParams {
    /// Token being deposited on this (order) chain
    pub order_chain_token: BytesN<32>,
    /// Token on the destination (ad) chain
    pub ad_chain_token: BytesN<32>,
    /// Amount of order_chain_token to deposit
    pub amount: u128,
    /// Address of the bridger (user creating the order)
    pub bridger: BytesN<32>,
    /// Recipient address on the ad chain (receives unlocked funds there)
    pub order_recipient: BytesN<32>,
    /// Destination (ad) chain ID
    pub ad_chain_id: u128,
    /// AdManager contract address on the ad chain
    pub ad_manager: BytesN<32>,
    /// Ad ID on the ad chain
    pub ad_id: String,
    /// Maker address (ad creator) on the ad chain
    pub ad_creator: BytesN<32>,
    /// Ad maker's recipient address on this (order) chain
    pub ad_recipient: BytesN<32>,
    /// Unique nonce to avoid hash collisions / replay
    pub salt: u128,
}
