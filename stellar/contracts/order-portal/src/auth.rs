//! Authentication and signature verification for the OrderPortal contract

use soroban_sdk::{Address, BytesN, Env, String};

pub use proofbridge_core::auth::{
    hash_request, hash_string_field, is_zero_bytes32, verify_ed25519_signature,
};

use crate::errors::OrderPortalError;
use crate::storage;

/// Validate pre-authorization signature and return the signer address
pub fn pre_auth_validations(
    env: &Env,
    message: &BytesN<32>,
    auth_token: &BytesN<32>,
    time_to_expire: u64,
    signature: &BytesN<64>,
    public_key: &BytesN<32>,
) -> Result<Address, OrderPortalError> {
    if is_zero_bytes32(message) {
        return Err(OrderPortalError::InvalidMessage);
    }

    if storage::is_request_token_used(env, auth_token) {
        return Err(OrderPortalError::TokenAlreadyUsed);
    }

    let current_timestamp = env.ledger().timestamp();
    if current_timestamp > time_to_expire {
        return Err(OrderPortalError::RequestTokenExpired);
    }

    verify_ed25519_signature(env, public_key, message, signature);

    let signer = proofbridge_core::auth::get_signer_address(env, public_key);

    if !storage::is_manager(env, &signer) {
        return Err(OrderPortalError::InvalidSigner);
    }

    storage::set_request_token_used(env, auth_token);

    Ok(signer)
}

// =============================================================================
// Contract-Specific Request Hash Functions
// =============================================================================

/// Create request hash for createOrder
pub fn create_order_request_hash(
    env: &Env,
    ad_id: &String,
    order_hash: &BytesN<32>,
    auth_token: &BytesN<32>,
    time_to_expire: u64,
    chain_id: u128,
    contract_address: &BytesN<32>,
) -> BytesN<32> {
    let mut params = [0u8; 64];

    let ad_id_hash = hash_string_field(ad_id);
    params[0..32].copy_from_slice(&ad_id_hash);
    params[32..64].copy_from_slice(&order_hash.to_array());

    hash_request(
        env,
        auth_token,
        time_to_expire,
        "createOrder",
        &params,
        chain_id,
        contract_address,
    )
}

/// Create request hash for unlock
pub fn unlock_order_request_hash(
    env: &Env,
    ad_id: &String,
    order_hash: &BytesN<32>,
    target_root: &BytesN<32>,
    auth_token: &BytesN<32>,
    time_to_expire: u64,
    chain_id: u128,
    contract_address: &BytesN<32>,
) -> BytesN<32> {
    proofbridge_core::auth::unlock_order_request_hash(
        env,
        ad_id,
        order_hash,
        target_root,
        auth_token,
        time_to_expire,
        chain_id,
        contract_address,
    )
}
