// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/**
 * @title AddressCast
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice Cross-chain address-cast helpers. EVM addresses are 20 bytes but
 *         `OrderParams` carries all address-like fields as 32 bytes for
 *         parity with wider-address chains (e.g. Stellar). The checked cast
 *         enforces the top 12 bytes are zero before narrowing.
 */
library AddressCast {
    /// @notice Upper 12 bytes of a supposed EVM address were non-zero.
    error AddressCast__NotEvmAddress(bytes32 value);

    /// @notice Native-token placeholder address (0xEeeE… sentinel).
    address internal constant NATIVE_TOKEN_ADDRESS = address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);

    /// @notice Left-pad an EVM address into a cross-chain 32-byte id.
    function toBytes32(address value) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(value)));
    }

    /**
     * @notice Extract an EVM address from a 32-byte cross-chain id.
     * @dev Reverts with `AddressCast__NotEvmAddress` if the top 12 bytes are set.
     */
    function toAddressChecked(bytes32 value) internal pure returns (address) {
        assertEvmAddress(value);
        return address(uint160(uint256(value)));
    }

    /**
     * @notice Assert `value` is a valid EVM address (top 12 bytes are zero).
     * @dev Same check as `toAddressChecked` but without the narrowing cast.
     *      Use at validation sites where the address itself isn't needed yet,
     *      so callers don't have to discard an unused return value.
     */
    function assertEvmAddress(bytes32 value) internal pure {
        if (uint256(value) >> 160 != 0) revert AddressCast__NotEvmAddress(value);
    }

    /// @notice Whether `token` is the native-token sentinel.
    function isNative(address token) internal pure returns (bool) {
        return token == NATIVE_TOKEN_ADDRESS;
    }
}
