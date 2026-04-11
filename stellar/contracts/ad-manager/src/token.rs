//! Token handling for the AdManager contract
//!
//! Re-exports shared token functions specialized with AdManagerError.

use soroban_sdk::{Address, BytesN, Env};

use crate::errors::AdManagerError;

/// Transfer tokens from user to contract using BytesN<32> token address
pub fn transfer_from_user_bytes32(
    env: &Env,
    token_bytes: &BytesN<32>,
    w_native_addr: &Address,
    from: &Address,
    amount: u128,
) -> Result<(), AdManagerError> {
    proofbridge_core::token::transfer_from_user_bytes32(
        env,
        token_bytes,
        w_native_addr,
        from,
        amount,
    )
}

/// Transfer tokens from contract to user using BytesN<32> token address
pub fn transfer_to_user_bytes32(
    env: &Env,
    token_bytes: &BytesN<32>,
    w_native_addr: &Address,
    to: &Address,
    amount: u128,
) -> Result<(), AdManagerError> {
    proofbridge_core::token::transfer_to_user_bytes32(env, token_bytes, w_native_addr, to, amount)
}

/// Transfer tokens from contract to recipient using BytesN<32> addresses
pub fn transfer_to_recipient_bytes32(
    env: &Env,
    token_bytes: &BytesN<32>,
    w_native_addr: &Address,
    recipient_bytes: &BytesN<32>,
    amount: u128,
) -> Result<(), AdManagerError> {
    proofbridge_core::token::transfer_to_recipient_bytes32(
        env,
        token_bytes,
        w_native_addr,
        recipient_bytes,
        amount,
    )
}
