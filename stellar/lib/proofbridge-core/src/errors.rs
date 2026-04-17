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
    fn decimals_out_of_range() -> Self;
    fn non_exact_downscale() -> Self;
    fn decimal_overflow() -> Self;
    fn order_decimals_mismatch() -> Self;
    fn ad_decimals_mismatch() -> Self;
}

/// Convert a [`crate::decimal_scaling::DecimalScalingError`] into the
/// contract-specific error type.
pub fn map_decimal_scaling_error<E: ProofBridgeError>(
    err: crate::decimal_scaling::DecimalScalingError,
) -> E {
    use crate::decimal_scaling::DecimalScalingError::*;
    match err {
        DecimalsOutOfRange => E::decimals_out_of_range(),
        NonExactDownscale => E::non_exact_downscale(),
        Overflow => E::decimal_overflow(),
    }
}
