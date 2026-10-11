// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {DecimalScaling} from "./DecimalScaling.sol";
import {OrderHash} from "./OrderHash.sol";
import {IKeyRegistry} from "../interfaces/IKeyRegistry.sol";
import {IAdManager} from "../interfaces/IAdManager.sol";

/// @title ProofBridgeUtils — the one deployed library both escrows link: today the order digest, the
///        width check and the decimal scaling, i.e. what both escrows must agree on about one order,
///        plus the AdManager's settlement-signer gate.
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

    /// The AdManager's settlement-signer gate, here for EIP-170 headroom: a registry is wired, the
    /// signer is non-zero with a usable key, and it is the maker itself or has approved the maker.
    function requireSettlementSigner(IKeyRegistry registry, bytes32 signer, bytes32 maker) public view {
        if (address(registry) == address(0)) revert IAdManager.AdManager__NoKeyRegistry();
        if (signer == bytes32(0)) revert IAdManager.AdManager__SettlementSignerZero();
        if (!registry.hasUsableSlot(signer)) revert IAdManager.AdManager__SignerNotRegistered(signer);
        if (signer != maker && !registry.isApprovedMaker(signer, maker)) {
            revert IAdManager.AdManager__SignerNotApproved(signer, maker);
        }
    }
}
