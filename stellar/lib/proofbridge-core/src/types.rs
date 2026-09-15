//! Shared data types for ProofBridge contracts

use soroban_sdk::{contracttype, Address};

// =============================================================================
// Order Lifecycle
// =============================================================================

/// Order lifecycle status. `Filled` and `Cancelled` are terminal; `Claimed` is a presentation
/// window (2.3e); `Disputed` / `Resolved` are reserved for 2.3g so it never renumbers.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Status {
    /// Not present in storage
    None = 0,
    /// Liquidity reserved / Created and funded
    Open = 1,
    /// Unlocked and paid (the SETTLED leaf is appended)
    Filled = 2,
    /// A presentation window is open; evidence settles it, silence cancels it
    Claimed = 3,
    /// Refunded / released (the primary appends the CANCEL leaf)
    Cancelled = 4,
    /// Reserved (2.3g)
    Disputed = 5,
    /// Reserved (2.3g)
    Resolved = 6,
}

// =============================================================================
// Termination (2.3e)
// =============================================================================

/// The per-peer-chain clocks the termination primitive reads (2.3e D6), in seconds. Admin-set per
/// route, validated once at write time (`timing::validate`), fail-closed when unset.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteTiming {
    /// Shortest `deadline - now` a lock/create accepts.
    pub min_window: u64,
    /// The primary's presentation window after the deadline; the follower's backstop window after its claim.
    pub buffer: u64,
    /// How much before the window's end the primary stops accepting the co-signed unlock.
    pub margin: u64,
    /// How long after the deadline the follower may open a backstop claim.
    pub long_backstop: u64,
    /// How much before the deadline the follower's co-signed unlock stops (0 = off).
    pub claim_stagger: u64,
}

/// Which clock opened a presentation window; 2.3g's dispute entry hangs off the same record.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ClaimEntry {
    None = 0,
    Deadline = 1,
    Backstop = 2,
    Dispute = 3,
}

/// One pause of an escrow: `end == 0` while it is still paused. The history is what makes a
/// pre-claim window's pause overlap exact, however many pauses fell inside it.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PauseSpan {
    pub start: u64,
    pub end: u64,
}

/// The open presentation window on an order (`Claimed` ⇔ a record exists). `paused_at_open` is
/// the escrow's paused-seconds counter when the window opened: the window's real end is
/// `finalize_at` plus whatever the escrow has been paused since (a pause stops the clocks, it
/// never reopens a closed window).
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimRecord {
    pub opened_at: u64,
    pub finalize_at: u64,
    pub paused_at_open: u64,
    pub entry: ClaimEntry,
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
