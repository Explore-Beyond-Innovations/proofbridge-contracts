// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {AddressCast} from "./AddressCast.sol";

/**
 * @title DecimalScaling
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice Shared helper for converting a token amount between two decimal
 *         representations. Used by both OrderPortal and AdManager so they can
 *         never disagree on the scaling math for a given signed OrderParams.
 *
 *         - Scale-up (toDec > fromDec): multiply by 10^diff. Overflow-checked
 *           by Solidity 0.8 — reverts on overflow.
 *         - Scale-down (toDec < fromDec): divide by 10^diff. Reverts if the
 *           source amount is not exactly divisible, because truncation would
 *           silently change the economic value of the order.
 *
 *         `MAX_DECIMALS` caps both operands to keep the `10 ** diff` factor
 *         well inside `uint256` headroom and to reject unrealistic tokens at
 *         the contract boundary.
 */
library DecimalScaling {
    uint8 internal constant MAX_DECIMALS = 30;
    /// @notice Hard-coded decimals for the native-token sentinel.
    uint8 internal constant NATIVE_DECIMALS = 18;

    error DecimalScaling__DecimalsOutOfRange(uint8 value);
    error DecimalScaling__NonExactDownscale(uint256 amount, uint8 fromDec, uint8 toDec);
    error DecimalScaling__DecimalsMismatch(uint8 expected, uint8 provided);
    error DecimalScaling__DecimalsUnavailable(address token);

    /**
     * @notice Convert `amount` from `fromDec` decimals to `toDec` decimals.
     */
    function scale(uint256 amount, uint8 fromDec, uint8 toDec) internal pure returns (uint256) {
        assertInRange(fromDec);
        assertInRange(toDec);
        if (fromDec == toDec) return amount;
        if (toDec > fromDec) {
            uint256 factor = 10 ** uint256(toDec - fromDec);
            return amount * factor;
        }
        uint256 down = 10 ** uint256(fromDec - toDec);
        if (amount % down != 0) {
            revert DecimalScaling__NonExactDownscale(amount, fromDec, toDec);
        }
        return amount / down;
    }

    function assertInRange(uint8 decimals) internal pure {
        if (decimals > MAX_DECIMALS) revert DecimalScaling__DecimalsOutOfRange(decimals);
    }

    /**
     * @notice Assert a signed decimals value matches the on-chain token.
     * @dev Native sentinel is treated as {NATIVE_DECIMALS} (18). Every other
     *      token is queried via `IERC20Metadata.decimals()`. `decimals()` is
     *      optional per EIP-20, so the call is wrapped in a try/catch that
     *      surfaces a typed error rather than a bubbled low-level revert —
     *      protocol tokens are admin-admitted, but this gives operators a
     *      clear diagnostic if a bad token slips through. Defence-in-depth
     *      against a signer choosing a mismatched scaling factor for a real
     *      token.
     */
    function assertMatchesOnChain(address token, uint8 signed) internal view {
        if (AddressCast.isNative(token)) {
            if (NATIVE_DECIMALS != signed) revert DecimalScaling__DecimalsMismatch(NATIVE_DECIMALS, signed);
            return;
        }
        try IERC20Metadata(token).decimals() returns (uint8 actual) {
            if (actual != signed) revert DecimalScaling__DecimalsMismatch(actual, signed);
        } catch {
            revert DecimalScaling__DecimalsUnavailable(token);
        }
    }
}
