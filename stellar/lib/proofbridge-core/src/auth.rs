//! Shared auth helpers
//!
//! Wallet authorization is handled by Soroban's `require_auth` on each entry
//! point; root authenticity is enforced by the BLS co-signature gate.

use soroban_sdk::BytesN;

/// Check if a BytesN<32> is all zeros
pub fn is_zero_bytes32(bytes: &BytesN<32>) -> bool {
    let arr = bytes.to_array();
    arr.iter().all(|&b| b == 0)
}
