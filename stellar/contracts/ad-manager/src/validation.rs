//! Order validation logic for the AdManager contract.
//!
//! Validates order parameters against ad configuration, chain configuration,
//! and token routes. Mirrors the EVM `validateOrder` function.

use soroban_sdk::Env;

use crate::auth;
use crate::errors::AdManagerError;
use crate::storage;
use crate::types::{Ad, OrderParams};

/// Validate order parameters against ad and chain configuration.
///
/// Checks:
/// 1. Ad is open
/// 2. Amount > 0
/// 3. Bridger and recipient are non-zero
/// 4. Source chain is supported
/// 5. Order portal matches (if configured)
/// 6. Order chain matches ad's configured chain
/// 7. Token route exists and matches
/// 8. Ad token matches
/// 9. Ad recipient matches
pub fn validate_order(env: &Env, ad: &Ad, params: &OrderParams) -> Result<(), AdManagerError> {
    // Check ad is open
    if !ad.open {
        return Err(AdManagerError::AdClosed);
    }

    // Check amount > 0
    if params.amount == 0 {
        return Err(AdManagerError::ZeroAmount);
    }

    // Check bridger not zero
    if auth::is_zero_bytes32(&params.bridger) {
        return Err(AdManagerError::BridgerZero);
    }

    // Check recipient not zero
    if auth::is_zero_bytes32(&params.order_recipient) {
        return Err(AdManagerError::RecipientZero);
    }

    // Check source chain is supported
    let chain_info =
        storage::get_chain(env, params.order_chain_id).ok_or(AdManagerError::ChainNotSupported)?;
    if !chain_info.supported {
        return Err(AdManagerError::ChainNotSupported);
    }

    // Check order portal matches (if configured)
    if !auth::is_zero_bytes32(&chain_info.order_portal)
        && chain_info.order_portal != params.src_order_portal
    {
        return Err(AdManagerError::OrderPortalMismatch);
    }

    // Check order chain matches ad's chain
    if params.order_chain_id != ad.order_chain_id {
        return Err(AdManagerError::OrderChainMismatch);
    }

    // Check token route exists and matches
    let routed = storage::get_token_route(env, &params.ad_chain_token, params.order_chain_id)
        .ok_or(AdManagerError::MissingRoute)?;
    if routed != params.order_chain_token {
        return Err(AdManagerError::OrderTokenMismatch);
    }

    // Check ad token matches
    if params.ad_chain_token != ad.token {
        return Err(AdManagerError::AdTokenMismatch);
    }

    // Check ad recipient matches
    if params.ad_recipient != ad.ad_recipient {
        return Err(AdManagerError::AdRecipientMismatch);
    }

    Ok(())
}
