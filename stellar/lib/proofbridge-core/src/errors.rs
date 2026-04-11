//! Common error trait for shared functions
//!
//! Each contract defines its own `#[contracterror]` enum with different
//! discriminant values. This trait lets shared functions construct the
//! correct error variant without knowing the concrete type.

/// Trait that contract-specific error types must implement so shared
/// functions can construct the appropriate error variant.
pub trait ProofBridgeError: Copy {
    fn token_zero_address() -> Self;
    fn merkle_append_failed() -> Self;
    fn invalid_proof() -> Self;
    fn invalid_message() -> Self;
    fn token_already_used() -> Self;
    fn request_token_expired() -> Self;
    fn invalid_signer() -> Self;
}
