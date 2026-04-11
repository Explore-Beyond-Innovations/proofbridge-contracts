//! Token handling for the OrderPortal contract
//!
//! Thin wrappers over proofbridge_core::token, specialized with OrderPortalError.

use soroban_sdk::{Address, BytesN, Env};

use crate::errors::OrderPortalError;

pub use proofbridge_core::token::bytes32_to_account_address;

/// Transfer tokens from user to contract using BytesN<32> token address
pub fn transfer_from_user_bytes32(
    env: &Env,
    token_bytes: &BytesN<32>,
    w_native_addr: &Address,
    from: &Address,
    amount: u128,
) -> Result<(), OrderPortalError> {
    proofbridge_core::token::transfer_from_user_bytes32(
        env,
        token_bytes,
        w_native_addr,
        from,
        amount,
    )
}

/// Transfer tokens from contract to recipient using BytesN<32> addresses
pub fn transfer_to_recipient_bytes32(
    env: &Env,
    token_bytes: &BytesN<32>,
    w_native_addr: &Address,
    recipient_bytes: &BytesN<32>,
    amount: u128,
) -> Result<(), OrderPortalError> {
    proofbridge_core::token::transfer_to_recipient_bytes32(
        env,
        token_bytes,
        w_native_addr,
        recipient_bytes,
        amount,
    )
}
