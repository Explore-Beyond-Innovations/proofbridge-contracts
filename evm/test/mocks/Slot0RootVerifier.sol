// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IRootVerifier} from "src/interfaces/IRootVerifier.sol";

/// @notice Accepts a root only when the envelope's slot 0 is `expected`: pins which account the
///         escrow asked the verifier to resolve (isRootValid is view, so it can't record).
contract Slot0RootVerifier is IRootVerifier {
    bytes32 public immutable expected;

    constructor(bytes32 expected_) {
        expected = expected_;
    }

    function isRootValid(uint256, bytes32, bytes calldata metadata) external view returns (bool) {
        (bytes32 slot0,,) = abi.decode(metadata, (bytes32, bytes32, bytes));
        return slot0 == expected;
    }
}
