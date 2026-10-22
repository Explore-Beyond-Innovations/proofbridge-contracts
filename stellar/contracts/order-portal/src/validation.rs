//! Order validation logic for the OrderPortal contract.
//!
//! Validates order parameters against chain configuration and token routes.

use soroban_sdk::Env;

use proofbridge_core::decimal_scaling;
use proofbridge_core::escrow_ops::Fault;
use proofbridge_core::token;

use crate::auth;
use crate::errors::OrderPortalError;
use crate::storage;
use crate::types::OrderParams;

/// Validate order parameters against chain and route configuration.
///
/// Checks:
/// 1. Amount > 0
/// 2. Ad recipient is non-zero; the order recipient is non-zero and isn't the maker or its signer
/// 3. Destination chain is supported
/// 4. AdManager matches chain configuration
/// 5. Token route exists and matches
pub fn validate_order(env: &Env, params: &OrderParams) -> Result<(), OrderPortalError> {
    if params.amount == 0 {
        return Err(OrderPortalError::ZeroAmount);
    }
    // #586: the fee the bridger deposits against is fixed here, in the hash; the ad chain's lock
    // refuses it unless it is that chain's live fee. Out of range can never lock, so refused now.
    let max = proofbridge_core::fees::MAX_FEE_BPS;
    if params.lp_fee_bps > max || params.protocol_fee_bps > max {
        return Err(OrderPortalError::InvalidFee);
    }

    // Validate recipient: must be non-zero and decode to a Stellar account
    // address. Soroban contract (`C...`) addresses are not supported here.
    if auth::is_zero_bytes32(&params.ad_recipient) {
        return Err(OrderPortalError::InvalidAdRecipient);
    }
    let _ = token::bytes32_to_account_address(env, &params.ad_recipient)?;

    // 643-b1: the relayer's R1/R2 at the source, so a direct create_order can't land a deposit no lock will take
    if auth::is_zero_bytes32(&params.order_recipient) {
        return Err(OrderPortalError::RecipientZero);
    }
    if params.order_recipient == params.ad_creator
        || params.order_recipient == params.ad_settlement_signer
    {
        return Err(OrderPortalError::RecipientIsMaker);
    }

    // Decimal range checks (both sides must be within supported bounds).
    decimal_scaling::assert_in_range(params.order_decimals).map_err(Fault::from)?;
    decimal_scaling::assert_in_range(params.ad_decimals).map_err(Fault::from)?;

    let chain_info =
        storage::get_chain(env, params.ad_chain_id).ok_or(OrderPortalError::AdChainNotSupported)?;

    if chain_info.ad_manager != params.ad_manager {
        return Err(OrderPortalError::AdManagerMismatch);
    }

    let route = storage::get_token_route(env, &params.order_chain_token, params.ad_chain_id)
        .ok_or(OrderPortalError::MissingRoute)?;
    if route != params.ad_chain_token {
        return Err(OrderPortalError::AdTokenMismatch);
    }

    Ok(())
}
