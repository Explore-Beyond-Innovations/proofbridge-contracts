//! Error types for the AdManager contract

use soroban_sdk::contracterror;

/// All possible errors that can occur in the AdManager contract
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum AdManagerError {
    // Validation errors (1-9)
    /// Token address is zero/invalid
    TokenZeroAddress = 1,
    /// Amount provided is zero
    ZeroAmount = 2,
    /// Ad with given ID not found
    AdNotFound = 3,
    /// Caller is not the ad maker/owner
    NotMaker = 4,
    /// Ad is closed and not accepting operations
    AdClosed = 5,
    /// Not enough available liquidity
    InsufficientLiquidity = 6,
    /// Bridger address is zero/invalid
    BridgerZero = 7,
    /// Recipient address is zero/invalid
    RecipientZero = 8,
    /// Ad has active locked funds
    ActiveLocks = 9,

    // Chain/route errors (10-16)
    /// Source chain is not supported
    ChainNotSupported = 10,
    /// OrderPortal address doesn't match configured
    OrderPortalMismatch = 11,
    /// Order chain ID doesn't match ad's chain
    OrderChainMismatch = 12,
    /// No token route exists for the pair
    MissingRoute = 13,
    /// Order token doesn't match route
    OrderTokenMismatch = 14,
    /// Ad token doesn't match expected
    AdTokenMismatch = 15,
    /// Ad recipient doesn't match expected
    AdRecipientMismatch = 16,

    // Order errors (17-20)
    /// Order already exists
    OrderExists = 17,
    /// Order is not in Open state
    OrderNotOpen = 18,
    /// Nullifier has already been used
    NullifierUsed = 19,
    /// ZK proof verification failed
    InvalidProof = 20,

    // Auth errors (21-27)
    /// Address is zero/invalid
    ZeroAddress = 21,
    /// Message hash is invalid
    InvalidMessage = 22,
    /// Auth token has already been used
    TokenAlreadyUsed = 23,
    /// Request token has expired
    RequestTokenExpired = 24,
    /// Signature recovered zero address
    ZeroSigner = 25,
    /// Signer is not a valid manager
    InvalidSigner = 26,
    /// Request hash has already been processed
    RequestHashProcessed = 27,

    // External call errors (28)
    /// MerkleManager append failed
    MerkleAppendFailed = 28,

    // Ad ID errors (29)
    /// Ad ID has already been used
    UsedAdId = 29,

    // Initialization errors (30-31)
    /// Contract already initialized
    AlreadyInitialized = 30,
    /// Contract not yet initialized
    NotInitialized = 31,

    // Signature errors (32-33)
    /// Invalid signature length
    InvalidSignatureLength = 32,
    /// Signature verification failed
    SignatureVerificationFailed = 33,

    // Decimal scaling errors (34-38)
    /// Decimals value is outside the supported range
    DecimalsOutOfRange = 34,
    /// Downscaling would lose precision (amount not exactly divisible)
    NonExactDownscale = 35,
    /// Overflow while scaling amount between decimal precisions
    DecimalOverflow = 36,
    /// Signed orderDecimals does not match on-chain token decimals
    OrderDecimalsMismatch = 37,
    /// Signed adDecimals does not match on-chain token decimals
    AdDecimalsMismatch = 38,

    // Address decode errors (40-41)
    /// Recipient bytes do not decode to a valid Stellar account address
    InvalidAccountAddress = 40,
    /// Strkey produced by account-address validation was not valid ASCII
    AccountValidationInvalidStrkey = 41,
}

impl proofbridge_core::errors::ProofBridgeError for AdManagerError {
    fn token_zero_address() -> Self {
        Self::TokenZeroAddress
    }
    fn merkle_append_failed() -> Self {
        Self::MerkleAppendFailed
    }
    fn invalid_proof() -> Self {
        Self::InvalidProof
    }
    fn invalid_message() -> Self {
        Self::InvalidMessage
    }
    fn token_already_used() -> Self {
        Self::TokenAlreadyUsed
    }
    fn request_token_expired() -> Self {
        Self::RequestTokenExpired
    }
    fn invalid_signer() -> Self {
        Self::InvalidSigner
    }
    fn decimals_out_of_range() -> Self {
        Self::DecimalsOutOfRange
    }
    fn non_exact_downscale() -> Self {
        Self::NonExactDownscale
    }
    fn decimal_overflow() -> Self {
        Self::DecimalOverflow
    }
    fn order_decimals_mismatch() -> Self {
        Self::OrderDecimalsMismatch
    }
    fn ad_decimals_mismatch() -> Self {
        Self::AdDecimalsMismatch
    }
    fn invalid_account_address() -> Self {
        Self::InvalidAccountAddress
    }
    fn account_validation_invalid_strkey() -> Self {
        Self::AccountValidationInvalidStrkey
    }
}
