//! Error types for the CounterpartyVerifier contract

use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum VerifierError {
    AlreadyInitialized = 1,
}
