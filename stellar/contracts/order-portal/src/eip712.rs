//! EIP-712 compatible hashing for the OrderPortal contract
//!
//! Re-exports shared EIP-712 utilities and provides the contract-specific
//! struct_hash_order and hash_order functions that depend on the order-portal's
//! OrderParams type.

pub use proofbridge_core::eip712::{
    abi_encode_uint256, contract_address_to_bytes32, hash_typed_data_v4, keccak256, ORDER_TYPEHASH,
};

use soroban_sdk::{BytesN, Env};

use crate::types::OrderParams;

// =============================================================================
// Order Struct Hash (contract-specific)
// =============================================================================

/// Compute the struct hash for an Order (order-portal variant)
///
/// The order-portal's OrderParams has `ad_manager` and `ad_chain_id` as fields,
/// and takes `order_chain_id` and `order_portal` as external parameters.
pub fn struct_hash_order(
    params: &OrderParams,
    order_chain_id: u128,
    order_portal: &[u8; 32],
) -> [u8; 32] {
    // 16 elements * 32 bytes = 512 bytes (typehash + 15 fields)
    let mut data = [0u8; 512];

    // ORDER_TYPEHASH
    data[0..32].copy_from_slice(&ORDER_TYPEHASH);

    // orderChainToken
    data[32..64].copy_from_slice(&params.order_chain_token.to_array());

    // adChainToken
    data[64..96].copy_from_slice(&params.ad_chain_token.to_array());

    // amount
    data[96..128].copy_from_slice(&abi_encode_uint256(params.amount));

    // bridger
    data[128..160].copy_from_slice(&params.bridger.to_array());

    // orderChainId
    data[160..192].copy_from_slice(&abi_encode_uint256(order_chain_id));

    // orderPortal (this contract)
    data[192..224].copy_from_slice(order_portal);

    // orderRecipient
    data[224..256].copy_from_slice(&params.order_recipient.to_array());

    // adChainId
    data[256..288].copy_from_slice(&abi_encode_uint256(params.ad_chain_id));

    // adManager
    data[288..320].copy_from_slice(&params.ad_manager.to_array());

    // keccak256(bytes(adId))
    let ad_id_len = params.ad_id.len() as usize;
    let mut ad_id_bytes = [0u8; 256];
    params.ad_id.copy_into_slice(&mut ad_id_bytes[..ad_id_len]);
    let ad_id_hash = keccak256(&ad_id_bytes[..ad_id_len]);
    data[320..352].copy_from_slice(&ad_id_hash);

    // adCreator
    data[352..384].copy_from_slice(&params.ad_creator.to_array());

    // adRecipient
    data[384..416].copy_from_slice(&params.ad_recipient.to_array());

    // salt
    data[416..448].copy_from_slice(&abi_encode_uint256(params.salt));

    // orderDecimals (uint8 padded to uint256)
    data[448..480].copy_from_slice(&abi_encode_uint256(params.order_decimals as u128));

    // adDecimals (uint8 padded to uint256)
    data[480..512].copy_from_slice(&abi_encode_uint256(params.ad_decimals as u128));

    keccak256(&data)
}

/// Compute the complete order hash for given parameters
pub fn hash_order(
    env: &Env,
    params: &OrderParams,
    order_chain_id: u128,
    order_portal: &BytesN<32>,
) -> BytesN<32> {
    let struct_h = struct_hash_order(params, order_chain_id, &order_portal.to_array());
    let digest = hash_typed_data_v4(&struct_h);
    BytesN::from_array(env, &digest)
}
