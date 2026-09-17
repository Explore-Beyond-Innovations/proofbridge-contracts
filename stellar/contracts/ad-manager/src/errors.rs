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

    // Auth errors (21)
    /// Address is zero/invalid
    ZeroAddress = 21,

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
    /// Gate 2: the root-verification module rejected the target root.
    RootNotValid = 39,
    /// Gate 2: no root-verification module configured for the route.
    RootVerifierNotSet = 45,
    ContractPaused = 41,
    NotPendingAdmin = 42,
    NothingToClaim = 43,
    /// Order route does not match the route the ad committed to at creation.
    RouteMismatch = 44,

    // Address decode errors (40-41)
    /// Recipient bytes do not decode to a valid Stellar account address
    InvalidAccountAddress = 40,
    /// The order's deadline has passed; it can no longer be unlocked.
    OrderExpired = 46,
    /// No key registry is set; createAd / set_settlement_signer fail closed (2.3c D2)
    NoKeyRegistry = 47,
    /// The settlement signer is the zero account
    SettlementSignerZero = 48,
    /// The settlement signer has no live, unexpired key in the registry
    SignerNotRegistered = 49,
    /// The order's ad_settlement_signer is not the one this ad declared
    SettlementSignerMismatch = 50,

    // Termination (2.3e) — 51-58
    /// No route timing set for the peer chain; every timed path fails closed
    NoRouteTiming = 51,
    /// set_route_timing: the clocks violate the D6 rules
    InvalidTiming = 52,
    /// The lock's deadline is closer than the route's min_window
    DeadlineTooSoon = 53,
    /// The order is not in a state this path accepts (Open / Claimed / None, as documented)
    NotClaimable = 54,
    /// The clock the caller relies on has not been reached
    TooEarly = 55,
    /// No presentation window is open on the order
    NotClaimed = 56,
    /// No root anchor is set; the evidence paths fail closed
    NoRootAnchor = 57,
    /// The anchor has not notarized the root (or its delay has not passed)
    RootNotAnchored = 58,
    /// record_settled: the order's SETTLED leaf is already in the MMR
    SettledRecorded = 59,
    /// record_settled: the order is not `Filled`
    NotFilled = 60,

    // Disputes (2.3g)
    /// No dispute module is wired, so disputes are unavailable on this escrow.
    NoDisputeManager = 61,
    /// The order is not in a state a dispute can be filed on.
    NotDisputable = 62,
    /// The module's window has not closed, so there is nothing to apply yet.
    DisputeNotResolved = 63,
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
impl From<proofbridge_core::escrow_ops::Fault> for AdManagerError {
    fn from(f: proofbridge_core::escrow_ops::Fault) -> Self {
        use proofbridge_core::escrow_ops::Fault::*;
        match f {
            ContractPaused => AdManagerError::ContractPaused,
            NoRouteTiming => AdManagerError::NoRouteTiming,
            DeadlineTooSoon => AdManagerError::DeadlineTooSoon,
            TooEarly => AdManagerError::TooEarly,
            NotClaimable => AdManagerError::NotClaimable,
            NotClaimed => AdManagerError::NotClaimed,
            NoRootAnchor => AdManagerError::NoRootAnchor,
            RootNotAnchored => AdManagerError::RootNotAnchored,
            NotFilled => AdManagerError::NotFilled,
            SettledRecorded => AdManagerError::SettledRecorded,
            NothingToClaim => AdManagerError::NothingToClaim,
            InvalidTiming => AdManagerError::InvalidTiming,
            NotPendingAdmin => AdManagerError::NotPendingAdmin,
            NoDisputeManager => AdManagerError::NoDisputeManager,
            NotDisputable => AdManagerError::NotDisputable,
            DisputeNotResolved => AdManagerError::DisputeNotResolved,
        }
    }
}
