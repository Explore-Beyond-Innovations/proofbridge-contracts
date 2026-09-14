//! Error types for the BLSKeyRegistry contract

use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RegistryError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    /// Submitted nonce != the account's stored nonce (replay, or stale PoP).
    BadNonce = 3,
    /// The G1 identity point can never be a key (it passes a naive PoP pairing).
    IdentityKey = 4,
    /// PoP pairing check failed (wrong key, wrong DST, or tampered message).
    InvalidPop = 5,
    /// Owner auth does not resolve to `account`.
    OwnerMismatch = 6,
    NotRegistered = 7,
    /// Revoke while the account has locked funds / open orders.
    AccountInFlight = 8,
    ContractPaused = 9,
    NotPendingAdmin = 10,
    /// MAX_ACTIVE_SLOTS stored and none past valid_until + GRACE_PERIOD.
    RegistryFull = 11,
    /// Slot id never assigned, pruned, or revoked.
    NoSuchSlot = 12,
    /// Slot exists but ledger timestamp >= valid_until.
    SlotExpired = 13,
    /// The commitment already occupied a slot for this account.
    KeyPreviouslyUsed = 14,
    /// set_valid_until is shorten-only and never 0.
    BadValidUntil = 15,
    /// 2.1b: proof-carried registration is not wired or not enabled
    ProofRegistrationDisabled = 16,
    /// The home-chain root the leaf proof cites is not anchored (or still inside its delay)
    RootNotAnchored = 17,
    /// The leaf inclusion proof did not verify for the rebuilt registration subject
    InvalidLeafProof = 18,
    /// The leaf's home chain is not one the registry accepts leaves from (or is this chain)
    SourceNotAllowed = 19,
    /// Enabling proof registration with no source chains
    ProofRegistrationRefsUnset = 20,
}
