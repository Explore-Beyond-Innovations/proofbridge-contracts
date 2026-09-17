//! Shared data types for ProofBridge contracts

use soroban_sdk::{contracttype, Address, BytesN};

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

/// How a dispute ended (2.3g).
///
/// `TradeProceeds` stays in the enum because it *is* the outcome of an evidence termination —
/// removing it would misname the result. The arbiter is refused it at the boundary instead, which
/// is a guard on the caller rather than on the vocabulary. Discriminants mirror the EVM enum.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum DisputeOutcome {
    None = 0,
    MutualRefund = 1,
    TradeProceeds = 2,
    BridgerForfeit = 3,
    MakerForfeit = 4,
}

/// Per-peer-chain dispute parameters, admin-set and validated at the write.
///
/// Deliberately not more fields on `RouteTiming`: that five-tuple is read by the deploy CLI, the
/// relayer and the manifest, and widening it would ripple through all three.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisputeParams {
    /// How long after filing the arbiter may still rule. Pause-aware at read time.
    pub challenge_period: u64,
    /// The bond floor, in the wrapped native token. Dominates on small orders.
    pub bond_floor: u128,
    /// Basis points of the order amount. Dominates on large ones.
    pub bond_bps: u32,
}

/// One dispute, keyed by order hash.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisputeRecord {
    pub initiator: Address,
    pub bond: u128,
    /// Unadjusted. Every read goes through `effective_challenge_deadline`, which applies the
    /// escrow's paused seconds once; storing an already-adjusted value here would double-count.
    pub challenge_deadline: u64,
    /// The *escrow's* paused-seconds counter when the dispute opened. The escrow's, not this
    /// module's: a pause matters because it stops the parties presenting, and presentation is gated
    /// by the escrow.
    pub paused_at_open: u64,
    pub initiator_evidence: BytesN<32>,
    pub responder_evidence: BytesN<32>,
    pub ruling: DisputeOutcome,
    /// Which escrow opened it — the only one allowed to finalize it.
    pub escrow: Address,
    /// The order's signed deadline and the route's buffer, handed over by the escrow at filing.
    /// They keep a short challenge period from finalizing a dispute before the order's own deadline
    /// (D3, T-50) — without them a third party could cancel an order with a week still to run.
    pub order_deadline: u64,
    pub buffer: u64,
}

/// The order's leg on this chain: its status and the escrow's paused-seconds counter when the leg
/// opened (a pause stops the window's clock; the window is measured from this snapshot).
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderRecord {
    pub status: Status,
    pub paused_at_open: u64,
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
