//! Shared data types for ProofBridge contracts

use soroban_sdk::{contracttype, Address, BytesN};

// =============================================================================
// Order Lifecycle
// =============================================================================

/// Order lifecycle status. `Filled`, `Cancelled` and `Resolved` are terminal; `Claimed` is a
/// presentation window (2.3e); `Disputed` and `Resolved` are the dispute's states (2.3g).
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
    /// A dispute is open on this (primary) leg
    Disputed = 5,
    /// The dispute finalized (terminal)
    Resolved = 6,
}

// =============================================================================
// Termination (2.3e)
// =============================================================================

/// The per-peer-chain clocks the termination primitive reads (2.3e D6), in seconds. Admin-set per
/// route, validated once at write time (`timing::validate`), fail-closed when unset. Versioned: each
/// set writes a new version and every order reads the version it opened under.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteTiming {
    /// Shortest `deadline - now` a lock/create accepts.
    pub min_window: u64,
    /// The primary's presentation window after the deadline.
    pub buffer: u64,
    /// How much before the window's end the primary stops accepting the co-signed unlock.
    pub margin: u64,
    /// How much before the deadline the follower's co-signed unlock stops (0 = off).
    pub claim_stagger: u64,
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
/// Deliberately not more fields on `RouteTiming`: that tuple is read by the deploy CLI, the
/// relayer and the manifest, and widening it would ripple through all three.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisputeParams {
    /// How long after filing the arbiter may still rule.
    pub challenge_period: u64,
    /// The route's flat bond, in the wrapped native token. The same for every order on the route.
    pub bond_floor: u128,
}

/// A route's bond in the order's own token (#586): `max(min_bond, amount × bond_bps / 10,000)`.
/// Unset means the route posts the flat `DisputeParams::bond_floor` in wrapped native.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BondConfig {
    pub min_bond: u128,
    pub bond_bps: u32,
}

/// One dispute, keyed by order hash.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisputeRecord {
    pub initiator: Address,
    pub bond: u128,
    /// The one deadline, in real time: the filing's, then the ruling's.
    pub challenge_deadline: u64,
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
    /// The bond's token (#586): the wrapped native token for the flat floor, else the order's token
    /// on a route with a `BondConfig`. Payouts and credits are in this token.
    pub bond_token: Address,
}

/// The order's leg on this chain.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderRecord {
    pub status: Status,
    /// When the leg opened (#422): a registry kill of the signer since then is a denied payout.
    pub locked_at: u64,
    /// On the ad chain, the key-registry epoch the order was locked under (#465): the denied rule
    /// reads that registry, so a later migration cannot erase a kill. 0 on the order portal.
    pub registry_epoch: u32,
    /// The route-timing version the leg opened under; every window reads it, so a retiming moves no
    /// live order.
    pub timing_version: u32,
    /// On the ad chain, the order chain's anchor delay at the lock; the evidence grace reads
    /// `max(this, current)`. 0 on the order portal and with no anchor wired.
    pub anchor_delay: u32,
    /// On the ad chain, the settlement signer's co-signing slot the lock pinned (2.7 plan 12 C): the
    /// one slot the co-signed unlock accepts and the denial rule reads. 0 on the order portal.
    pub pinned_slot: u32,
    /// On the ad chain: the pin was moved by a re-pin (`repin_order`). A re-pin is a maker-side
    /// lever, so the denial rule counts it for the rest of the order's life; a slot left behind can
    /// no longer erase a kill the rule would have counted. False on the order portal.
    pub repinned: bool,
    /// On the ad chain (#586): the fee bps live at the lock, which the payout charges, so a fee change
    /// never moves a live order. 0 on the order portal.
    pub lp_fee_bps: u32,
    pub protocol_fee_bps: u32,
}

/// The open presentation window on an order (`Claimed` ⇔ a record exists).
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimRecord {
    pub opened_at: u64,
    pub finalize_at: u64,
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
