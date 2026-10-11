// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IPositionGuard} from "src/interfaces/IBLSKeyRegistry.sol";

/// Stands in for the escrows the deploy CLI wires as registry guards: no open positions, so
/// `revoke` proceeds.
contract IdleGuard is IPositionGuard {
    function hasOpenPositions(bytes32) external pure returns (bool) {
        return false;
    }
}
