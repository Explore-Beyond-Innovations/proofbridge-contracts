// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IRootVerifier} from "src/interfaces/IRootVerifier.sol";

/// @notice Configurable root-verification stub for tests.
contract MockRootVerifier is IRootVerifier {
    bool public ok;

    constructor(bool ok_) {
        ok = ok_;
    }

    function isRootValid(uint256, bytes32, bytes calldata) external view returns (bool) {
        return ok;
    }
}
