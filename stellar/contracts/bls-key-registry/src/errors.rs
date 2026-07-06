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
}
