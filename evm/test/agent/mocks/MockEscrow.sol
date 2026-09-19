// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IAdManager} from "src/interfaces/IAdManager.sol";

/// @dev Stands in for `AdManager` in the module's tests: the policy only ever reasons about the
///      target address, the selector and the decoded params, so the escrow's own behaviour is not
///      what is under test. `failNext` covers the one thing that is — that a call which reverts
///      after validation leaves the buckets alone.
contract MockEscrow {
    uint256 public locks;
    bool public failNext;
    bytes32 public lastOrderHash;

    error MockEscrow__Refused();

    function setFailNext(bool value) external {
        failNext = value;
    }

    /// @dev Payable on purpose: a non-payable escrow would refuse ETH by itself and the test that
    ///      the *policy* refuses it would pass for the wrong reason.
    function lockForOrder(IAdManager.OrderParams calldata params) external payable returns (bytes32 orderHash) {
        if (failNext) revert MockEscrow__Refused();
        locks += 1;
        orderHash = keccak256(abi.encode(params.adId, params.salt));
        lastOrderHash = orderHash;
    }

    /// @dev A selector the policy has no action id for, to prove the whitelist is a whitelist.
    function withdrawFromAd(string calldata, uint256, address) external {
        locks += 1000;
    }
}
