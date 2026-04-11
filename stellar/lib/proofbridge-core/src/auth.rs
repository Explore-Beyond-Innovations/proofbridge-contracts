//! Authentication and signature verification shared between contracts

use soroban_sdk::{Address, Bytes, BytesN, Env, String};

use crate::eip712;

// =============================================================================
// Signature Verification
// =============================================================================

/// Verify Ed25519 signature.
///
/// **Panics** on invalid signature — this is standard Soroban behavior
/// (same as `require_auth`). The transaction is aborted on failure.
pub fn verify_ed25519_signature(
    env: &Env,
    public_key: &BytesN<32>,
    message: &BytesN<32>,
    signature: &BytesN<64>,
) {
    let msg_bytes = Bytes::from_slice(env, &message.to_array());
    env.crypto()
        .ed25519_verify(public_key, &msg_bytes, signature);
}

/// Get address from Ed25519 public key
///
/// Converts an Ed25519 public key to its corresponding Stellar account address.
pub fn get_signer_address(env: &Env, public_key: &BytesN<32>) -> Address {
    use stellar_strkey::ed25519::PublicKey;

    let pubkey = PublicKey(public_key.to_array());
    let strkey = pubkey.to_string();

    let strkey_bytes = strkey.as_bytes();
    let soroban_str = String::from_str(env, core::str::from_utf8(strkey_bytes).unwrap());
    Address::from_string(&soroban_str)
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Check if a BytesN<32> is all zeros
pub fn is_zero_bytes32(bytes: &BytesN<32>) -> bool {
    let arr = bytes.to_array();
    arr.iter().all(|&b| b == 0)
}

/// Hash a String field with keccak256 for use in request params
pub fn hash_string_field(s: &String) -> [u8; 32] {
    let len = s.len() as usize;
    let mut buf = [0u8; 256];
    s.copy_into_slice(&mut buf[..len]);
    eip712::keccak256(&buf[..len])
}

// =============================================================================
// Request Hash Functions
// =============================================================================

/// Hash a request for pre-authorization.
///
/// Creates a hash of: (auth_token, time_to_expire, action, params, chain_id, contract_address)
/// Uses keccak256 for EVM compatibility.
pub fn hash_request(
    env: &Env,
    auth_token: &BytesN<32>,
    time_to_expire: u64,
    action: &str,
    params: &[u8],
    chain_id: u128,
    contract_address: &BytesN<32>,
) -> BytesN<32> {
    // Fixed: 32 (auth_token) + 8 (time_to_expire) + 32 (action_hash) + 16 (chain_id) + 32 (contract_address) = 120
    // Max params: 5 fields * 32 bytes = 160 → total max ~280
    let mut buf = [0u8; 512];
    let mut offset = 0;

    // auth_token (32 bytes)
    buf[offset..offset + 32].copy_from_slice(&auth_token.to_array());
    offset += 32;

    // time_to_expire (8 bytes, big-endian)
    buf[offset..offset + 8].copy_from_slice(&time_to_expire.to_be_bytes());
    offset += 8;

    // action string hash (keccak256 for EVM compatibility)
    let action_hash = eip712::keccak256(action.as_bytes());
    buf[offset..offset + 32].copy_from_slice(&action_hash);
    offset += 32;

    // params (variable length)
    buf[offset..offset + params.len()].copy_from_slice(params);
    offset += params.len();

    // chain_id (16 bytes, big-endian)
    buf[offset..offset + 16].copy_from_slice(&chain_id.to_be_bytes());
    offset += 16;

    // contract_address (32 bytes)
    buf[offset..offset + 32].copy_from_slice(&contract_address.to_array());
    offset += 32;

    let hash = eip712::keccak256(&buf[..offset]);
    BytesN::from_array(env, &hash)
}

/// Create request hash for unlock (shared between both contracts)
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
    // params: ad_id_hash(32) + order_hash(32) + target_root(32) = 96
    let mut params = [0u8; 96];

    let ad_id_hash = hash_string_field(ad_id);
    params[0..32].copy_from_slice(&ad_id_hash);
    params[32..64].copy_from_slice(&order_hash.to_array());
    params[64..96].copy_from_slice(&target_root.to_array());

    hash_request(
        env,
        auth_token,
        time_to_expire,
        "unlockOrder",
        &params,
        chain_id,
        contract_address,
    )
}
