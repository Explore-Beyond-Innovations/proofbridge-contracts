//! Shared data types for ProofBridge contracts

use soroban_sdk::{contracttype, Address};

// =============================================================================
// Order Lifecycle
// =============================================================================

/// Order lifecycle status
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Status {
    /// Not present in storage
    None = 0,
    /// Liquidity reserved / Created and funded
    Open = 1,
    /// Unlocked and paid
    Filled = 2,
}

impl Default for Status {
    fn default() -> Self {
        Status::None
    }
}

// =============================================================================
// Contract Configuration
// =============================================================================

/// Immutable contract configuration set at initialization
#[contracttype]
#[derive(Clone, Debug)]
pub struct ContractConfig {
    /// Admin address
    pub admin: Address,
    /// Verifier contract address
    pub verifier: Address,
    /// MerkleManager contract address
    pub merkle_manager: Address,
    /// Wrapped native token (XLM) contract address
    pub w_native_token: Address,
    /// This chain's ID
    pub chain_id: u128,
}
