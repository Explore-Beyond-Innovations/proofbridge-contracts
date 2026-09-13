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
    /// A new root's ledger sequence must exceed the chain's latest anchored one
    SeqNotMonotonic = 8,
    /// A later approval named a different sequence than the first
    SeqMismatch = 9,
}
