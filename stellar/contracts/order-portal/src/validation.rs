//! Order validation logic for the OrderPortal contract.
//!
//! Validates order parameters against chain configuration and token routes.
//! Mirrors the EVM `validateOrder` function.

use soroban_sdk::Env;

use proofbridge_core::decimal_scaling;
use proofbridge_core::errors::map_decimal_scaling_error;

use crate::auth;
use crate::errors::OrderPortalError;
use crate::storage;
use crate::types::OrderParams;

/// Validate order parameters against chain and route configuration.
///
/// Checks:
/// 1. Amount > 0
/// 2. Ad recipient is non-zero
/// 3. Destination chain is supported
/// 4. AdManager matches chain configuration
/// 5. Token route exists and matches
pub fn validate_order(env: &Env, params: &OrderParams) -> Result<(), OrderPortalError> {
    // Check amount > 0
    if params.amount == 0 {
        return Err(OrderPortalError::ZeroAmount);
    }

    // Check ad_recipient not zero
    if auth::is_zero_bytes32(&params.ad_recipient) {
        return Err(OrderPortalError::InvalidAdRecipient);
    }

    // Decimal range checks (both sides must be within supported bounds).
    // On-chain decimals *match* is checked separately in the contract entrypoint
    // (requires a live SAC / wrapped-native contract, not available in pure
    // validation unit tests).
    decimal_scaling::assert_in_range(params.order_decimals)
        .map_err(map_decimal_scaling_error::<OrderPortalError>)?;
    decimal_scaling::assert_in_range(params.ad_decimals)
        .map_err(map_decimal_scaling_error::<OrderPortalError>)?;

    // Check chain is supported
    let chain_info =
        storage::get_chain(env, params.ad_chain_id).ok_or(OrderPortalError::AdChainNotSupported)?;
    if !chain_info.supported {
        return Err(OrderPortalError::AdChainNotSupported);
    }

    // Check ad_manager matches
    if chain_info.ad_manager != params.ad_manager {
        return Err(OrderPortalError::AdManagerMismatch);
    }

    // Check token route exists and matches
    let route = storage::get_token_route(env, &params.order_chain_token, params.ad_chain_id)
        .ok_or(OrderPortalError::MissingRoute)?;
    if route != params.ad_chain_token {
        return Err(OrderPortalError::AdTokenMismatch);
    }

    Ok(())
}
