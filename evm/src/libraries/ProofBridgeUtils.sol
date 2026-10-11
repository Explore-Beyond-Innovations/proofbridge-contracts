// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {DecimalScaling} from "./DecimalScaling.sol";
import {OrderHash} from "./OrderHash.sol";
import {IKeyRegistry} from "../interfaces/IKeyRegistry.sol";
import {IAdManager} from "../interfaces/IAdManager.sol";
import {IEscrow} from "../interfaces/IEscrow.sol";
import {RouteTiming} from "./RouteTiming.sol";

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
        _requireSettlementSigner(registry, signer, maker);
    }

    /// The lock's gate (2.7 plan 12 D7): the settlement-signer gate, and the slot it pins exists, is
    /// usable now and is the signer's (`commitmentAt` answers).
    function requireLockSigner(IKeyRegistry registry, bytes32 signer, bytes32 maker, uint32 slot) public view {
        _requireSettlementSigner(registry, signer, maker);
        _requireUsableSlot(registry, signer, slot);
    }

    /// The AdManager's re-pin (2.7 plan 12 D12, Q2), here for EIP-170 headroom: the order is `Open` and
    /// not past `deadline - claimStagger` (its own timing version), the signer's consent in the order's
    /// registry (`registryAt[o.registryEpoch]`) names
    /// this order and its current pin, and the new slot is usable now. Moves the pin.
    function repin(
        IEscrow.Order storage o,
        mapping(uint32 => IKeyRegistry) storage registryAt,
        RouteTiming.Timing storage t,
        bytes32 signer,
        bytes32 orderHash,
        uint256 deadline
    ) public {
        IKeyRegistry registry = registryAt[o.registryEpoch];
        uint256 cutoff = deadline - t.claimStagger;
        if (o.status != IEscrow.Status.Open) revert IEscrow.Escrow__OrderNotOpen(orderHash);
        if (block.timestamp > cutoff) revert IEscrow.Escrow__OrderExpired(cutoff);
        uint32 from = o.pinnedSlot;
        (uint32 fromSlot, uint32 to, uint64 nonce) = registry.repinApproval(signer, orderHash);
        if (nonce == 0 || fromSlot != from) revert IAdManager.AdManager__NoRepin(orderHash);
        _requireUsableSlot(registry, signer, to);
        o.pinnedSlot = to;
        emit IAdManager.OrderRepinned(orderHash, from, to);
    }

    /// #464: does `verifier` verify against a registry other than `expected`? A verifier that does not
    /// answer `registry()` is not a BLS co-signature verifier: no split. No verifier: no split.
    function registrySplit(address verifier, address expected)
        public
        view
        returns (bool split, address verifierRegistry)
    {
        if (verifier == address(0)) return (false, address(0));
        (bool ok, bytes memory ret) = verifier.staticcall(abi.encodeWithSignature("registry()"));
        if (!ok || ret.length != 32) return (false, address(0));
        verifierRegistry = abi.decode(ret, (address));
        split = verifierRegistry != expected;
    }

    /// The denial rule's registry half (#464, #465, plan 12 C): with no registry wired nothing denies;
    /// a verifier on another registry denies; else the order's pinned slot expiring at or before
    /// `until` denies.
    function registryDenies(IKeyRegistry registry, address verifier, bytes32 signer, uint32 slot, uint256 until)
        public
        view
        returns (bool)
    {
        if (address(registry) == address(0)) return false;
        (bool split,) = registrySplit(verifier, address(registry));
        if (split) return true;
        uint64 e = registry.expiredAt(signer, slot);
        return e != 0 && e <= until;
    }

    function _requireUsableSlot(IKeyRegistry registry, bytes32 signer, uint32 slot) private view {
        try registry.commitmentAt(signer, slot) returns (bytes32) {}
        catch {
            revert IAdManager.AdManager__SlotNotUsable(signer, slot);
        }
    }

    function _requireSettlementSigner(IKeyRegistry registry, bytes32 signer, bytes32 maker) private view {
        if (address(registry) == address(0)) revert IAdManager.AdManager__NoKeyRegistry();
        if (signer == bytes32(0)) revert IAdManager.AdManager__SettlementSignerZero();
        if (!registry.hasUsableSlot(signer)) revert IAdManager.AdManager__SignerNotRegistered(signer);
        if (signer != maker && !registry.isApprovedMaker(signer, maker)) {
            revert IAdManager.AdManager__SignerNotApproved(signer, maker);
        }
    }
}
