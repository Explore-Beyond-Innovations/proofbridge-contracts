//! Cross-chain decimal scaling helper.
//!
//! When the order-chain token and ad-chain token have different decimal
//! precisions (e.g. EVM wETH with 18 decimals vs. Stellar wETH SAC with 7),
//! the signed `amount` in `OrderParams` must be rescaled before being used for
//! pool accounting or transfers on the ad chain.
//!
//! Mirrors `contracts/evm/src/libraries/DecimalScaling.sol`.

/// Maximum decimals accepted on either side. Any value ≥ this is treated as
/// invalid and will reject the order. Keeping the cap at 30 bounds the
/// intermediate `10^(abs(from-to))` term to 10^30, safely below u128::MAX.
pub const MAX_DECIMALS: u32 = 30;

/// Errors returned by decimal scaling operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DecimalScalingError {
    /// `decimals` is greater than [`MAX_DECIMALS`].
    DecimalsOutOfRange,
    /// Scaling down would lose precision (amount is not a multiple of 10^delta).
    NonExactDownscale,
    /// Arithmetic overflow while computing the scaled amount.
    Overflow,
}

/// Assert that the given decimals value is within the supported range.
pub fn assert_in_range(decimals: u32) -> Result<(), DecimalScalingError> {
    if decimals > MAX_DECIMALS {
        return Err(DecimalScalingError::DecimalsOutOfRange);
    }
    Ok(())
}

/// Scale `amount` from `from_dec` decimals to `to_dec` decimals.
///
/// - `from_dec == to_dec`: returns `amount` unchanged.
/// - `to_dec > from_dec`: multiplies by `10^(to_dec - from_dec)` with checked
///   arithmetic, returning [`DecimalScalingError::Overflow`] on overflow.
/// - `to_dec < from_dec`: divides by `10^(from_dec - to_dec)`, requiring the
///   division to be exact (otherwise returns
///   [`DecimalScalingError::NonExactDownscale`]).
pub fn scale(amount: u128, from_dec: u32, to_dec: u32) -> Result<u128, DecimalScalingError> {
    assert_in_range(from_dec)?;
    assert_in_range(to_dec)?;

    if from_dec == to_dec {
        return Ok(amount);
    }

    if to_dec > from_dec {
        let delta = to_dec - from_dec;
        let factor = 10u128
            .checked_pow(delta)
            .ok_or(DecimalScalingError::Overflow)?;
        amount
            .checked_mul(factor)
            .ok_or(DecimalScalingError::Overflow)
    } else {
        let delta = from_dec - to_dec;
        let factor = 10u128
            .checked_pow(delta)
            .ok_or(DecimalScalingError::Overflow)?;
        if amount % factor != 0 {
            return Err(DecimalScalingError::NonExactDownscale);
        }
        Ok(amount / factor)
    }
}
