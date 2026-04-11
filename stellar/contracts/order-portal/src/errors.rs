//! Error types for the OrderPortal contract

use soroban_sdk::contracterror;

/// Errors that can occur in the OrderPortal contract
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum OrderPortalError {
    // ==========================================================================
    // Validation Errors (1-20)
    // ==========================================================================

    /// Token address is zero
    TokenZeroAddress = 1,
    /// Amount is zero
    ZeroAmount = 2,
    /// Bridger must be the transaction sender
    BridgerMustBeSender = 3,
    /// Ad recipient is zero address
    InvalidAdRecipient = 4,
    /// Route has zero address
    RoutesZeroAddress = 5,
    /// Insufficient liquidity/value provided
    InsufficientLiquidity = 6,

    // ==========================================================================
    // Chain/Route Errors (10-20)
    // ==========================================================================

    /// Destination chain is not supported
    AdChainNotSupported = 10,
    /// AdManager address doesn't match configuration
    AdManagerMismatch = 11,
    /// Token route is not configured
    MissingRoute = 12,
    /// Ad chain token doesn't match route
    AdTokenMismatch = 13,

    // ==========================================================================
    // Order Errors (20-30)
    // ==========================================================================

    /// Order already exists for this hash
    OrderExists = 20,
    /// Order is not open
    OrderNotOpen = 21,
    /// Nullifier hash has already been used
    NullifierUsed = 22,
    /// ZK proof verification failed
    InvalidProof = 23,

    // ==========================================================================
    // Auth Errors (30-40)
    // ==========================================================================

    /// Address is zero
    ZeroAddress = 30,
    /// Message hash is invalid (zero)
    InvalidMessage = 31,
    /// Auth token has already been used
    TokenAlreadyUsed = 32,
    /// Request token has expired
    RequestTokenExpired = 33,
    /// Signer is zero address
    ZeroSigner = 34,
    /// Signer is not authorized as manager
    InvalidSigner = 35,
    /// Request hash has already been processed
    RequestHashProcessed = 36,

    // ==========================================================================
    // External Call Errors (40-50)
    // ==========================================================================

    /// MerkleManager append failed
    MerkleAppendFailed = 40,
    /// Verifier call failed
    VerifierCallFailed = 41,

    // ==========================================================================
    // Initialization Errors (50-60)
    // ==========================================================================

    /// Contract is already initialized
    AlreadyInitialized = 50,
    /// Contract is not initialized
    NotInitialized = 51,
}

impl proofbridge_core::errors::ProofBridgeError for OrderPortalError {
    fn token_zero_address() -> Self { Self::TokenZeroAddress }
    fn merkle_append_failed() -> Self { Self::MerkleAppendFailed }
    fn invalid_proof() -> Self { Self::InvalidProof }
    fn invalid_message() -> Self { Self::InvalidMessage }
    fn token_already_used() -> Self { Self::TokenAlreadyUsed }
    fn request_token_expired() -> Self { Self::RequestTokenExpired }
    fn invalid_signer() -> Self { Self::InvalidSigner }
}
