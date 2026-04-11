//! Authentication and signature verification for the AdManager contract

use soroban_sdk::{Address, BytesN, Env, String};

pub use proofbridge_core::auth::{
    hash_request, hash_string_field, is_zero_bytes32, verify_ed25519_signature,
};

use crate::errors::AdManagerError;
use crate::storage;

/// Validate pre-authorization signature and return the signer address
///
/// This function:
/// 1. Validates the message hash is not zero
/// 2. Checks auth_token hasn't been used
/// 3. Verifies time_to_expire hasn't passed
/// 4. Verifies the Ed25519 signature
/// 5. Checks signer is a registered manager
/// 6. Marks auth_token as used
pub fn pre_auth_validations(
    env: &Env,
    message: &BytesN<32>,
    auth_token: &BytesN<32>,
    time_to_expire: u64,
    signature: &BytesN<64>,
    public_key: &BytesN<32>,
) -> Result<Address, AdManagerError> {
    if is_zero_bytes32(message) {
        return Err(AdManagerError::InvalidMessage);
    }

    if storage::is_request_token_used(env, auth_token) {
        return Err(AdManagerError::TokenAlreadyUsed);
    }

    let current_timestamp = env.ledger().timestamp();
    if current_timestamp > time_to_expire {
        return Err(AdManagerError::RequestTokenExpired);
    }

    verify_ed25519_signature(env, public_key, message, signature);

    let signer = proofbridge_core::auth::get_signer_address(env, public_key);

    if !storage::is_manager(env, &signer) {
        return Err(AdManagerError::InvalidSigner);
    }

    storage::set_request_token_used(env, auth_token);

    Ok(signer)
}

// =============================================================================
// Contract-Specific Request Hash Functions
// =============================================================================

/// Create request hash for createAd
pub fn create_ad_request_hash(
    env: &Env,
    ad_id: &String,
    ad_token: &BytesN<32>,
    initial_amount: u128,
    order_chain_id: u128,
    ad_recipient: &BytesN<32>,
    auth_token: &BytesN<32>,
    time_to_expire: u64,
    chain_id: u128,
    contract_address: &BytesN<32>,
) -> BytesN<32> {
    let mut params = [0u8; 128];
    let mut offset = 0;

    let ad_id_hash = hash_string_field(ad_id);
    params[offset..offset + 32].copy_from_slice(&ad_id_hash);
    offset += 32;

    params[offset..offset + 32].copy_from_slice(&ad_token.to_array());
    offset += 32;

    params[offset..offset + 16].copy_from_slice(&initial_amount.to_be_bytes());
    offset += 16;

    params[offset..offset + 16].copy_from_slice(&order_chain_id.to_be_bytes());
    offset += 16;

    params[offset..offset + 32].copy_from_slice(&ad_recipient.to_array());

    hash_request(
        env,
        auth_token,
        time_to_expire,
        "createAd",
        &params,
        chain_id,
        contract_address,
    )
}

/// Create request hash for fundAd
pub fn fund_ad_request_hash(
    env: &Env,
    ad_id: &String,
    amount: u128,
    auth_token: &BytesN<32>,
    time_to_expire: u64,
    chain_id: u128,
    contract_address: &BytesN<32>,
) -> BytesN<32> {
    let mut params = [0u8; 48];

    let ad_id_hash = hash_string_field(ad_id);
    params[0..32].copy_from_slice(&ad_id_hash);
    params[32..48].copy_from_slice(&amount.to_be_bytes());

    hash_request(
        env,
        auth_token,
        time_to_expire,
        "fundAd",
        &params,
        chain_id,
        contract_address,
    )
}

/// Create request hash for withdrawFromAd
pub fn withdraw_from_ad_request_hash(
    env: &Env,
    ad_id: &String,
    amount: u128,
    to: &Address,
    auth_token: &BytesN<32>,
    time_to_expire: u64,
    chain_id: u128,
    contract_address: &BytesN<32>,
) -> BytesN<32> {
    let mut params = [0u8; 80];

    let ad_id_hash = hash_string_field(ad_id);
    params[0..32].copy_from_slice(&ad_id_hash);
    params[32..48].copy_from_slice(&amount.to_be_bytes());
    params[48..80]
        .copy_from_slice(&proofbridge_core::eip712::address_to_bytes32(env, to).to_array());

    hash_request(
        env,
        auth_token,
        time_to_expire,
        "withdrawFromAd",
        &params,
        chain_id,
        contract_address,
    )
}

/// Create request hash for closeAd
pub fn close_ad_request_hash(
    env: &Env,
    ad_id: &String,
    to: &Address,
    auth_token: &BytesN<32>,
    time_to_expire: u64,
    chain_id: u128,
    contract_address: &BytesN<32>,
) -> BytesN<32> {
    let mut params = [0u8; 64];

    let ad_id_hash = hash_string_field(ad_id);
    params[0..32].copy_from_slice(&ad_id_hash);
    params[32..64]
        .copy_from_slice(&proofbridge_core::eip712::address_to_bytes32(env, to).to_array());

    hash_request(
        env,
        auth_token,
        time_to_expire,
        "closeAd",
        &params,
        chain_id,
        contract_address,
    )
}

/// Create request hash for lockForOrder
pub fn lock_for_order_request_hash(
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
        "lockForOrder",
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
