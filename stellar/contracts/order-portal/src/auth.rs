//! Auth helpers for the OrderPortal contract
//!
//! Wallet authorization uses Soroban's `require_auth`; root authenticity is
//! enforced by the mandatory root-verifier (BLS co-signature) gate in `unlock`.

pub use proofbridge_core::auth::is_zero_bytes32;
