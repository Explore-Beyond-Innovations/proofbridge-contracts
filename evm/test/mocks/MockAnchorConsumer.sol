// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IRootAnchor} from "src/interfaces/IRootAnchor.sol";

/// @notice Stands in for the escrow's follower refund (2.3e): proceeds only against an anchored root.
contract MockAnchorConsumer {
    IRootAnchor public immutable anchor;

    error NotAnchored(uint256 chainId, bytes32 root);

    constructor(IRootAnchor anchor_) {
        anchor = anchor_;
    }

    function refund(uint256 chainId, bytes32 root) external view returns (bool) {
        if (!anchor.isAnchored(chainId, root)) revert NotAnchored(chainId, root);
        return true;
    }
}
