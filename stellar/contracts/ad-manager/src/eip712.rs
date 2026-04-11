//! EIP-712 compatible hashing for the AdManager contract
//!
//! Re-exports shared EIP-712 utilities and provides the contract-specific
//! struct_hash_order and hash_order functions that depend on the ad-manager's
//! OrderParams type.

pub use proofbridge_core::eip712::{
    abi_encode_address, abi_encode_string, abi_encode_uint256, contract_address_to_bytes32,
    hash_typed_data_v4, keccak256, ORDER_TYPEHASH,
};

use soroban_sdk::{BytesN, Env};

use crate::types::OrderParams;

// =============================================================================
// Order Struct Hash (contract-specific)
// =============================================================================

/// Compute the struct hash for an Order (ad-manager variant)
///
/// The ad-manager's OrderParams has `src_order_portal` and `order_chain_id` as
/// fields, and takes `ad_chain_id` and `ad_manager` as external parameters.
pub fn struct_hash_order(
    params: &OrderParams,
    ad_chain_id: u128,
    ad_manager: &BytesN<32>,
) -> [u8; 32] {
    // Total size: 14 fields * 32 bytes = 448 bytes
    let mut data = [0u8; 448];
    let mut offset = 0;

    // ORDER_TYPEHASH
    data[offset..offset + 32].copy_from_slice(&ORDER_TYPEHASH);
    offset += 32;

    // orderChainToken
    data[offset..offset + 32].copy_from_slice(&abi_encode_address(&params.order_chain_token));
    offset += 32;

    // adChainToken
    data[offset..offset + 32].copy_from_slice(&abi_encode_address(&params.ad_chain_token));
    offset += 32;

    // amount
    data[offset..offset + 32].copy_from_slice(&abi_encode_uint256(params.amount));
    offset += 32;

    // bridger
    data[offset..offset + 32].copy_from_slice(&abi_encode_address(&params.bridger));
    offset += 32;

    // orderChainId
    data[offset..offset + 32].copy_from_slice(&abi_encode_uint256(params.order_chain_id));
    offset += 32;

    // srcOrderPortal
    data[offset..offset + 32].copy_from_slice(&abi_encode_address(&params.src_order_portal));
    offset += 32;

    // orderRecipient
    data[offset..offset + 32].copy_from_slice(&abi_encode_address(&params.order_recipient));
    offset += 32;

    // adChainId
    data[offset..offset + 32].copy_from_slice(&abi_encode_uint256(ad_chain_id));
    offset += 32;

    // adManager
    data[offset..offset + 32].copy_from_slice(&abi_encode_address(ad_manager));
    offset += 32;

    // keccak256(bytes(adId))
    let ad_id_hash = abi_encode_string(&params.ad_id);
    data[offset..offset + 32].copy_from_slice(&ad_id_hash);
    offset += 32;

    // adCreator
    data[offset..offset + 32].copy_from_slice(&abi_encode_address(&params.ad_creator));
    offset += 32;

    // adRecipient
    data[offset..offset + 32].copy_from_slice(&abi_encode_address(&params.ad_recipient));
    offset += 32;

    // salt
    data[offset..offset + 32].copy_from_slice(&abi_encode_uint256(params.salt));

    keccak256(&data)
}

/// Compute the complete order hash
pub fn hash_order(
    env: &Env,
    params: &OrderParams,
    ad_chain_id: u128,
    ad_manager: &BytesN<32>,
) -> BytesN<32> {
    let struct_h = struct_hash_order(params, ad_chain_id, ad_manager);
    let order_hash = hash_typed_data_v4(&struct_h);
    BytesN::from_array(env, &order_hash)
}
