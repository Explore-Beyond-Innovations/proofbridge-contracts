//! Error types for the MerkleManager contract.

use soroban_sdk::contracterror;

/// Errors that can occur in the MerkleManager contract.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum MerkleError {
    /// Contract has already been initialized
    AlreadyInitialized = 1,
    /// Contract has not been initialized
    NotInitialized = 2,
    /// Caller is not a registered manager
    NotManager = 3,
    /// Address cannot be zero
    ZeroAddress = 4,
    // 5–9 retired (four never-returned MMR errors and `ContractPaused` with the pause); the
    // numbers stay unused so no surviving code moves.
    NotPendingAdmin = 10,
}
