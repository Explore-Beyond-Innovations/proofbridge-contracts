//! Error types for the RootAnchor contract

use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RootAnchorError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    ContractPaused = 3,
    NotPendingAdmin = 4,
    /// The caller is not in the signer set
    NotSigner = 5,
    /// threshold must be in 1..=signers.len()
    BadThreshold = 6,
    /// The same signer listed twice
    DuplicateSigner = 7,
    /// A root's ledger sequence must exceed the chain's latest anchored one
    SeqNotMonotonic = 8,
    /// A route's delay is bounded by MAX_ANCHOR_DELAY
    DelayTooLong = 9,
    /// Nothing to revoke for this (chain, root)
    NoSuchAnchor = 10,
    /// A later approval named a different ledger sequence than the pending root's first one
    SeqMismatch = 11,
    /// #586: the timelock is already active.
    TimelockAlreadyActive = 12,
    /// #586: this exact call is already proposed.
    TimelockAlreadyProposed = 13,
    /// #586: no pending proposal for this exact call (or it was voided by a handover).
    TimelockNotProposed = 14,
    /// #586: the proposal's 24 hours have not passed.
    TimelockTooEarly = 15,
    /// #586: a proposal's argument bytes are not the XDR of an argument list.
    TimelockBadArgs = 16,
    /// #586: the proposal's 14-day window to run has passed.
    TimelockExpired = 17,
    /// #586: a brake on what the proposal would re-enable was pulled after it was proposed.
    TimelockCancelledByBrake = 18,
}
