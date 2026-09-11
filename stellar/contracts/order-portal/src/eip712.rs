//! EIP-712 order hashing for the OrderPortal: maps its `OrderParams` onto the shared 17-field
//! `Order` (`proofbridge_core::eip712`), which owns the preimage layout.

// some are used only by the tests
#[allow(unused_imports)]
pub use proofbridge_core::eip712::{
    abi_encode_uint256, contract_address_to_bytes32, hash_typed_data_v4, keccak256, ORDER_TYPEHASH,
};

use proofbridge_core::eip712::{abi_encode_string, abi_encode_u256, Order};
use soroban_sdk::{BytesN, Env};

use crate::types::OrderParams;

/// The OrderPortal's view of the order: `order_chain_id` and `order_portal` are this chain and
/// contract.
pub fn order_of(params: &OrderParams, order_chain_id: u128, order_portal: &[u8; 32]) -> Order {
    Order {
        order_chain_token: params.order_chain_token.to_array(),
        ad_chain_token: params.ad_chain_token.to_array(),
        amount: params.amount,
        bridger: params.bridger.to_array(),
        order_chain_id,
        order_portal: *order_portal,
        order_recipient: params.order_recipient.to_array(),
        ad_chain_id: params.ad_chain_id,
        ad_manager: params.ad_manager.to_array(),
        ad_id_hash: abi_encode_string(&params.ad_id),
        ad_creator: params.ad_creator.to_array(),
        ad_recipient: params.ad_recipient.to_array(),
        salt: abi_encode_u256(&params.salt),
        order_decimals: params.order_decimals,
        ad_decimals: params.ad_decimals,
        deadline: params.deadline,
        ad_settlement_signer: params.ad_settlement_signer.to_array(),
    }
}

/// Struct hash of the order (order-portal variant).
pub fn struct_hash_order(
    params: &OrderParams,
    order_chain_id: u128,
    order_portal: &[u8; 32],
) -> [u8; 32] {
    proofbridge_core::eip712::struct_hash_order(&order_of(params, order_chain_id, order_portal))
}

/// The complete order hash.
pub fn hash_order(
    env: &Env,
    params: &OrderParams,
    order_chain_id: u128,
    order_portal: &BytesN<32>,
) -> BytesN<32> {
    let struct_h = struct_hash_order(params, order_chain_id, &order_portal.to_array());
    BytesN::from_array(env, &hash_typed_data_v4(&struct_h))
}
