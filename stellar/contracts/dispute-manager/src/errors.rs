//! Errors for the DisputeManager.
//!
//! Its own `#[contracterror]` enum with its own discriminants, like every other contract here —
//! they are ABI. The codes the escrows relay are also defined in `proofbridge_core::dispute::error_code`;
//! a test pins each pair.

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
    // 4 (`NotArbiter`) and 5 (`ZeroAddress`) are retired: no path returned them (the arbiter is
    // checked by `require_auth`). Numbers are ABI and never reused.
    /// A dispute is already open on this order.
    DisputeExists = 10,
    /// The order has no open dispute.
    NotDisputed = 11,
    /// The arbiter cannot rule that the trade went through — only evidence reaches that.
    ArbiterCannotSettle = 12,
    // 13 (`BondTooSmall`) and 14 (`ChallengeOpen`) are retired: the bond is pulled at the exact
    // amount, and the no-ruling claim that raised 14 is gone (the fallback lives in finalize).
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
    /// The arbiter already ruled, which closes the answer window.
    AlreadyRuled = 23,
    /// 49S-3: the bond token refused the transfer (no trustline, a shortfall, a frozen account).
    BondTransferFailed = 24,
    /// D5: answers close with the challenge window, the instant the arbiter's ruling does.
    ResponseWindowClosed = 25,
    /// D5: the responder slot takes one answer; the first one stands.
    AlreadyResponded = 26,
    /// D5: an empty answer is refused, so "answered" is exactly "the slot is non-zero".
    ZeroResponse = 27,
}
