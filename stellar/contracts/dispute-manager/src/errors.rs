//! Errors for the DisputeManager.
//!
//! Its own `#[contracterror]` enum with its own discriminants, like every other contract here —
//! they are ABI, so they are never shared across crates even when the names match.

use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DisputeManagerError {
    /// Already initialized.
    AlreadyInitialized = 1,
    /// Not initialized.
    NotInitialized = 2,
    /// The caller is not an escrow this module serves.
    NotEscrow = 3,
    /// The caller is not the arbiter.
    NotArbiter = 4,
    /// An address argument was the zero/unset address.
    ZeroAddress = 5,
    /// A dispute is already open on this order.
    DisputeExists = 10,
    /// The order has no open dispute.
    NotDisputed = 11,
    /// The arbiter cannot rule that the trade went through — only evidence reaches that.
    ArbiterCannotSettle = 12,
    /// The value sent does not cover the route's bond.
    BondTooSmall = 13,
    /// The challenge period has not expired yet.
    ChallengeOpen = 14,
    /// The challenge period has expired; the arbiter can no longer rule.
    ChallengeClosed = 15,
    /// Only the counterparty may respond.
    NotResponder = 16,
    /// Dispute parameters are not set for this route: fail closed rather than dispute for free.
    NoDisputeParams = 17,
    /// `challenge_period` below the minimum.
    InvalidChallengePeriod = 18,
    /// `bond_floor` is zero.
    InvalidBondFloor = 19,
    /// `bond_bps` above the ceiling.
    InvalidBondBps = 20,
    /// The escrow finalizing is not the one that opened the dispute.
    WrongEscrow = 21,
    /// Nothing credited to claim.
    NothingToClaim = 22,
    /// The arbiter already ruled, so the no-ruling fallback does not apply.
    AlreadyRuled = 23,
}
