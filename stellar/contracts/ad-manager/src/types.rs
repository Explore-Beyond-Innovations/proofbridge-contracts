//! Data structures for the AdManager contract

use soroban_sdk::{contracttype, Address, BytesN, String};

pub use proofbridge_core::token::NATIVE_TOKEN_ADDRESS;
pub use proofbridge_core::types::{ContractConfig, Status};

/// Source chain configuration
#[contracttype]
#[derive(Clone, Debug)]
pub struct ChainInfo {
    /// Whether orders from this chain are accepted
    pub supported: bool,
    /// Address of the OrderPortal contract on the source chain
    pub order_portal: BytesN<32>,
}

/// Liquidity advertisement created by a maker
#[contracttype]
#[derive(Clone, Debug)]
pub struct Ad {
    /// Source chain ID this ad serves
    pub order_chain_id: u128,
    /// Maker's recipient address on the order chain
    pub ad_recipient: BytesN<32>,
    /// Ad owner address on this chain
    pub maker: Address,
    /// Token address (or native marker) on this chain
    pub token: BytesN<32>,
    /// Total token balance deposited
    pub balance: u128,
    /// Portion of balance reserved for open orders
    pub locked: u128,
    /// Whether the ad is accepting new orders
    pub open: bool,
}

/// Parameters describing a cross-chain order (ad-manager variant)
#[contracttype]
#[derive(Clone, Debug)]
pub struct OrderParams {
    /// Token address on the source (order) chain
    pub order_chain_token: BytesN<32>,
    /// Token address on this (ad) chain
    pub ad_chain_token: BytesN<32>,
    /// Amount to reserve/release
    pub amount: u128,
    /// Bridger address on source chain
    pub bridger: BytesN<32>,
    /// Source chain ID
    pub order_chain_id: u128,
    /// OrderPortal address on source chain
    pub src_order_portal: BytesN<32>,
    /// Recipient address on this chain
    pub order_recipient: BytesN<32>,
    /// Target ad ID
    pub ad_id: String,
    /// Expected maker (ad owner)
    pub ad_creator: BytesN<32>,
    /// Expected maker recipient on order chain
    pub ad_recipient: BytesN<32>,
    /// Unique nonce to avoid hash collisions
    pub salt: u128,
}
