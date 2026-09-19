// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IAdManager} from "src/interfaces/IAdManager.sol";
import {ProofBridgeAgentPolicy} from "src/agent/ProofBridgeAgentPolicy.sol";

/// @dev Exposes the module's internals so the pieces that are not reachable through a UserOp — the
///      decimal scaling and the calldata decoder — can be tested directly rather than inferred.
contract PolicyHarness is ProofBridgeAgentPolicy {
    function adAmount(IAdManager.OrderParams memory params) external pure returns (bool, uint256) {
        return _adAmount(params);
    }

    function decodeCalls(bytes calldata callData) external pure returns (bool ok, uint256 count) {
        Call[] memory calls;
        (ok, calls) = _decodeCalls(callData);
        count = calls.length;
    }
}
