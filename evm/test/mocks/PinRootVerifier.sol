// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IRootVerifier} from "src/interfaces/IRootVerifier.sol";

/// Accepts a root only when the envelope's pinned slot is `expected`: pins what the escrow vouches
/// for (the AdManager its order's pin, the OrderPortal the unpinned sentinel).
contract PinRootVerifier is IRootVerifier {
    uint32 public immutable expected;

    constructor(uint32 expected_) {
        expected = expected_;
    }

    function isRootValid(uint256, bytes32, bytes calldata metadata) external view returns (bool) {
        (,,, uint32 pin,,,) = abi.decode(metadata, (bytes32, bytes32, bytes32, uint32, bytes32, uint8, bytes));
        return pin == expected;
    }
}
