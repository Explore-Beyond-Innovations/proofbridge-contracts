// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {FieldElement} from "src/libraries/FieldElement.sol";

/**
 * @title TestField
 * @notice Canonical stand-ins for the values a proof actually carries.
 * @dev Nullifiers and roots are Poseidon2 outputs, so they are field elements — always below the
 *      BN254 prime. A bare `bytes32("N")` is left-aligned ASCII, which is enormous, and a raw
 *      `keccak256(...)` is uniform over 2^256; the prime is about 0.19 of that, so four in five of
 *      either are values no proof could ever produce.
 *
 *      The fixtures used them anyway, and 2.3h's canonicality check is what surfaced it. Using this
 *      instead keeps test inputs in the space production inputs come from.
 */
library TestField {
    /// @notice A canonical field element derived from a label. Distinct labels give distinct values.
    function fe(string memory label) internal pure returns (bytes32 v) {
        v = bytes32(uint256(keccak256(bytes(label))) % FieldElement.prime());
    }
}
