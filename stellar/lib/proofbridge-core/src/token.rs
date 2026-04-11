//! Token handling shared between AdManager and OrderPortal contracts

use soroban_sdk::{token, Address, BytesN, Env, String as SorobanString};
use stellar_strkey::Contract;

use crate::errors::ProofBridgeError;

// =============================================================================
// Constants
// =============================================================================

/// Native token placeholder address (all 0xEE bytes)
/// Equivalent to EVM's 0xEeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE
pub const NATIVE_TOKEN_ADDRESS: [u8; 32] = [
    0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
    0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
    0xEE, 0xEE,
];

// =============================================================================
// Native Token Check
// =============================================================================

/// Check if the given token address represents the native token (XLM)
pub fn is_native_token(token_addr: &BytesN<32>) -> bool {
    token_addr.to_array() == NATIVE_TOKEN_ADDRESS
}

// =============================================================================
// BytesN<32> to Address Conversion
// =============================================================================

/// Convert BytesN<32> token address to Soroban Address
///
/// Returns None for the native token marker (use w_native_token instead).
pub fn bytes32_to_token_address(env: &Env, bytes: &BytesN<32>) -> Option<Address> {
    if is_native_token(bytes) {
        return None;
    }

    let contract_id = bytes.to_array();
    let strkey = Contract(contract_id).to_string();

    let strkey_bytes = strkey.as_bytes();
    let soroban_str = SorobanString::from_str(env, core::str::from_utf8(strkey_bytes).unwrap());
    Some(Address::from_string(&soroban_str))
}

/// Convert BytesN<32> account address (Ed25519 public key) to Soroban Address
pub fn bytes32_to_account_address(env: &Env, bytes: &BytesN<32>) -> Address {
    use stellar_strkey::ed25519::PublicKey;

    let pubkey = PublicKey(bytes.to_array());
    let strkey = pubkey.to_string();

    let strkey_bytes = strkey.as_bytes();
    let soroban_str = SorobanString::from_str(env, core::str::from_utf8(strkey_bytes).unwrap());
    Address::from_string(&soroban_str)
}

// =============================================================================
// Token Operations
// =============================================================================

/// Transfer tokens using BytesN<32> token address
///
/// For native tokens, uses the wrapped native token contract.
pub fn transfer_tokens<E: ProofBridgeError>(
    env: &Env,
    token_bytes: &BytesN<32>,
    w_native_addr: &Address,
    from: &Address,
    to: &Address,
    amount: u128,
) -> Result<(), E> {
    let amount_i128 = amount as i128;

    if is_native_token(token_bytes) {
        let token_client = token::Client::new(env, w_native_addr);
        token_client.transfer(from, to, &amount_i128);
    } else {
        if let Some(token_addr) = bytes32_to_token_address(env, token_bytes) {
            let token_client = token::Client::new(env, &token_addr);
            token_client.transfer(from, to, &amount_i128);
        } else {
            return Err(E::token_zero_address());
        }
    }

    Ok(())
}

/// Transfer tokens from user to contract using BytesN<32> token address
pub fn transfer_from_user_bytes32<E: ProofBridgeError>(
    env: &Env,
    token_bytes: &BytesN<32>,
    w_native_addr: &Address,
    from: &Address,
    amount: u128,
) -> Result<(), E> {
    let contract_addr = env.current_contract_address();
    transfer_tokens(env, token_bytes, w_native_addr, from, &contract_addr, amount)
}

/// Transfer tokens from contract to user using BytesN<32> token address
pub fn transfer_to_user_bytes32<E: ProofBridgeError>(
    env: &Env,
    token_bytes: &BytesN<32>,
    w_native_addr: &Address,
    to: &Address,
    amount: u128,
) -> Result<(), E> {
    let contract_addr = env.current_contract_address();
    transfer_tokens(env, token_bytes, w_native_addr, &contract_addr, to, amount)
}

/// Transfer tokens from contract to recipient using BytesN<32> addresses
pub fn transfer_to_recipient_bytes32<E: ProofBridgeError>(
    env: &Env,
    token_bytes: &BytesN<32>,
    w_native_addr: &Address,
    recipient_bytes: &BytesN<32>,
    amount: u128,
) -> Result<(), E> {
    let contract_addr = env.current_contract_address();
    let recipient = bytes32_to_account_address(env, recipient_bytes);
    transfer_tokens(env, token_bytes, w_native_addr, &contract_addr, &recipient, amount)
}
