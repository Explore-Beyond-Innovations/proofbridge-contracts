// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {DecimalScaling} from "./DecimalScaling.sol";
import {OrderHash} from "./OrderHash.sol";

/// @title ProofBridgeUtils — the one deployed library both escrows link: today the order digest, the
///        width check and the decimal scaling, i.e. what both escrows must agree on about one order.
/// @dev EIP-170 headroom: these entry points are `public`, so the escrows DELEGATECALL one copy per
///      chain instead of inlining `DecimalScaling` and `OrderHash`. The logic stays in those two
///      (internal, still inlined into tests and the agent module); this is only the deployed door.
library ProofBridgeUtils {
    function scale(uint256 amount, uint8 fromDec, uint8 toDec) public pure returns (uint256) {
        return DecimalScaling.scale(amount, fromDec, toDec);
    }

    function assertInRange(uint8 decimals) public pure {
        DecimalScaling.assertInRange(decimals);
    }

    function assertMatchesOnChain(address token, uint8 signed) public view {
        DecimalScaling.assertMatchesOnChain(token, signed);
    }

    function checkWidths(uint256 amount, uint256 orderChainId, uint256 adChainId, uint256 deadline) public pure {
        OrderHash.checkWidths(amount, orderChainId, adChainId, deadline);
    }

    function digest(OrderHash.Order memory o) public pure returns (bytes32) {
        return OrderHash.digest(o);
    }
}
