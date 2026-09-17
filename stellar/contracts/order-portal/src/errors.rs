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

    // ==========================================================================
    // Decimal Scaling Errors (60-70)
    // ==========================================================================
    /// Decimals value is outside the supported range
    DecimalsOutOfRange = 60,
    /// Downscaling would lose precision (amount not exactly divisible)
    NonExactDownscale = 61,
    /// Overflow while scaling amount between decimal precisions
    DecimalOverflow = 62,
    /// Signed orderDecimals does not match on-chain token decimals
    OrderDecimalsMismatch = 63,
    /// Signed adDecimals does not match on-chain token decimals
    AdDecimalsMismatch = 64,
    /// Gate 2: the root-verification module rejected the target root.
    RootNotValid = 65,
    /// Gate 2: no root-verification module configured for the route.
    RootVerifierNotSet = 66,
    ContractPaused = 71,
    NotPendingAdmin = 72,
    NothingToClaim = 73,

    // ==========================================================================
    // Address Decode Errors (70-80)
    // ==========================================================================
    /// Recipient bytes do not decode to a valid Stellar account address
    InvalidAccountAddress = 70,
    /// The order's deadline has passed; it can no longer be unlocked.
    OrderExpired = 74,

    // ==========================================================================
    // Termination (2.3e) — 75-82
    // ==========================================================================
    /// No route timing set for the peer chain; every timed path fails closed
    NoRouteTiming = 75,
    /// set_route_timing: the clocks violate the D6 rules
    InvalidTiming = 76,
    /// The order's deadline is closer than the route's min_window
    DeadlineTooSoon = 77,
    /// The order is not in a state this path accepts (Open / Claimed, as documented)
    NotClaimable = 78,
    /// The clock the caller relies on has not been reached
    TooEarly = 79,
    /// No presentation window is open on the order
    NotClaimed = 80,
    /// No root anchor is set; the evidence paths fail closed
    NoRootAnchor = 81,
    /// The anchor has not notarized the root (or its delay has not passed)
    RootNotAnchored = 82,
    /// record_settled: the order's SETTLED leaf is already in the MMR
    SettledRecorded = 83,
    /// record_settled: the order is not `Filled`
    NotFilled = 84,

    // Disputes (2.3g)
    /// No dispute module is wired, so disputes are unavailable on this escrow.
    NoDisputeManager = 85,
    /// The order is not in a state a dispute can be filed on.
    NotDisputable = 86,
    /// The module's window has not closed, so there is nothing to apply yet.
    DisputeNotResolved = 87,
    /// Only the order's two parties may file or respond to a dispute (D11).
    NotAParty = 88,
    /// A public input at or above the field prime (2.3h, residual 9): the verifier would
    /// reduce it, so two distinct 32-byte values would present as one element.
    NonCanonicalInput = 89,
}

impl proofbridge_core::errors::ProofBridgeError for OrderPortalError {
    fn token_zero_address() -> Self {
        Self::TokenZeroAddress
    }
    fn merkle_append_failed() -> Self {
        Self::MerkleAppendFailed
    }
    fn invalid_proof() -> Self {
        Self::InvalidProof
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
}

/// The shared escrow code reports an opaque reason; this is where it becomes this contract's own
/// `#[contracterror]` discriminant, which is ABI and stays this contract's.
impl From<proofbridge_core::escrow_ops::Fault> for OrderPortalError {
    fn from(f: proofbridge_core::escrow_ops::Fault) -> Self {
        use proofbridge_core::escrow_ops::Fault::*;
        match f {
            ContractPaused => OrderPortalError::ContractPaused,
            NoRouteTiming => OrderPortalError::NoRouteTiming,
            DeadlineTooSoon => OrderPortalError::DeadlineTooSoon,
            TooEarly => OrderPortalError::TooEarly,
            NotClaimable => OrderPortalError::NotClaimable,
            NotClaimed => OrderPortalError::NotClaimed,
            NoRootAnchor => OrderPortalError::NoRootAnchor,
            RootNotAnchored => OrderPortalError::RootNotAnchored,
            NotFilled => OrderPortalError::NotFilled,
            SettledRecorded => OrderPortalError::SettledRecorded,
            NothingToClaim => OrderPortalError::NothingToClaim,
            InvalidTiming => OrderPortalError::InvalidTiming,
            NotPendingAdmin => OrderPortalError::NotPendingAdmin,
            NoDisputeManager => OrderPortalError::NoDisputeManager,
            NotDisputable => OrderPortalError::NotDisputable,
            NonCanonicalInput => OrderPortalError::NonCanonicalInput,
            DisputeNotResolved => OrderPortalError::DisputeNotResolved,
        }
    }
}
