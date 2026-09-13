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
}
