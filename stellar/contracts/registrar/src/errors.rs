//! Error types for the Registrar contract

use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RegistrarError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    /// The MerkleManager refused the append (the registrar is not a manager)
    AppendFailed = 3,
    /// `epoch` is below the account's `next_epoch`: a replayed signature or a duplicate leaf
    StaleEpoch = 4,
}
