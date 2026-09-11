//! EIP-712 order hashing for the AdManager: maps its `OrderParams` onto the shared 17-field
//! `Order` (`proofbridge_core::eip712`), which owns the preimage layout.

// some are used only by the tests
#[allow(unused_imports)]
pub use proofbridge_core::eip712::{
    abi_encode_address, abi_encode_string, abi_encode_uint256, contract_address_to_bytes32,
    hash_typed_data_v4, keccak256, ORDER_TYPEHASH,
};

use proofbridge_core::eip712::{abi_encode_u256, Order};
use soroban_sdk::{BytesN, Env};

use crate::types::OrderParams;

/// The AdManager's view of the order: `ad_chain_id` and `ad_manager` are this chain and contract.
pub fn order_of(params: &OrderParams, ad_chain_id: u128, ad_manager: &BytesN<32>) -> Order {
    Order {
        order_chain_token: params.order_chain_token.to_array(),
        ad_chain_token: params.ad_chain_token.to_array(),
        amount: params.amount,
        bridger: params.bridger.to_array(),
        order_chain_id: params.order_chain_id,
        order_portal: params.src_order_portal.to_array(),
        order_recipient: params.order_recipient.to_array(),
        ad_chain_id,
        ad_manager: ad_manager.to_array(),
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

/// Struct hash of the order (ad-manager variant).
pub fn struct_hash_order(
    params: &OrderParams,
    ad_chain_id: u128,
    ad_manager: &BytesN<32>,
) -> [u8; 32] {
    proofbridge_core::eip712::struct_hash_order(&order_of(params, ad_chain_id, ad_manager))
}

/// The complete order hash.
pub fn hash_order(
    env: &Env,
    params: &OrderParams,
    ad_chain_id: u128,
    ad_manager: &BytesN<32>,
) -> BytesN<32> {
    let order_hash = hash_typed_data_v4(&struct_hash_order(params, ad_chain_id, ad_manager));
    BytesN::from_array(env, &order_hash)
}
