// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {TestField} from "test/utils/TestField.sol";
import {statusOf} from "test/utils/OrderStatus.sol";
import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IEscrow} from "src/interfaces/IEscrow.sol";
import {IRootVerifier} from "src/interfaces/IRootVerifier.sol";
import {RouteTiming} from "src/libraries/RouteTiming.sol";
import {RootVerifierRegistry} from "src/libraries/RootVerifierRegistry.sol";
import {AdManagerTest} from "./Admanager.t.sol";

/// Accepts a root only when the envelope's pinned slot is `expected`: pins what the escrow vouches for.
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

/// 2.7 plan 12 C on the AdManager: the lock pins the settlement signer's co-signing slot, the unlock
/// vouches for it, and the signer's consent can move it while the order is open.
contract SlotPinTest is AdManagerTest {
    bytes32 internal signer;

    function setUp() public virtual override {
        super.setUp();
        signer = _b32(maker); // the default ad's settlement signer is the maker itself
    }

    function _order(uint256 salt) internal returns (IAdManager.OrderParams memory p) {
        test_fundAd_makerOnly();
        p = _defaultParams(lastAdId);
        p.amount = 60 ether;
        p.salt = salt;
    }

    function _lockPinned(uint256 salt, uint32 slot) internal returns (IAdManager.OrderParams memory p, bytes32 h) {
        p = _order(salt);
        vm.prank(maker);
        h = adManager.lockForOrder(p, slot);
    }

    function _pin(bytes32 h) internal view returns (uint32 slot, uint32 epoch) {
        (,, epoch, slot) = adManager.orders(h);
    }

    // ---- the lock (D7, D8) ----

    function test_lock_recordsThePinnedSlotAndTheEpoch() public {
        keyRegistry.setSlotExpiry(signer, 2, 0); // slots 0..2 exist, all unbounded
        (, bytes32 h) = _lockPinned(1, 2);
        (uint32 slot, uint32 epoch) = _pin(h);
        assertEq(slot, 2, "the pinned slot");
        assertEq(epoch, adManager.registryEpoch(), "the registry epoch the lock recorded");
    }

    function test_lock_refusesAMissingSlot() public {
        IAdManager.OrderParams memory p = _order(2);
        vm.prank(maker);
        vm.expectRevert(abi.encodeWithSelector(IAdManager.AdManager__SlotNotUsable.selector, signer, uint32(5)));
        adManager.lockForOrder(p, 5);
    }

    function test_lock_refusesADeadSlot() public {
        keyRegistry.setSlotExpiry(signer, 1, uint64(block.timestamp));
        IAdManager.OrderParams memory p = _order(3);
        vm.prank(maker);
        vm.expectRevert(abi.encodeWithSelector(IAdManager.AdManager__SlotNotUsable.selector, signer, uint32(1)));
        adManager.lockForOrder(p, 1);
        vm.prank(maker);
        adManager.lockForOrder(p, 0); // the live one locks
    }

    /// A slot id another account holds is not the signer's: it does not exist for the signer.
    function test_lock_refusesAnotherAccountsSlot() public {
        bytes32 other = keccak256("another account");
        keyRegistry.set(other, true);
        keyRegistry.setSlotExpiry(other, 3, 0);
        IAdManager.OrderParams memory p = _order(4);
        vm.prank(maker);
        vm.expectRevert(abi.encodeWithSelector(IAdManager.AdManager__SlotNotUsable.selector, signer, uint32(3)));
        adManager.lockForOrder(p, 3);
    }

    // ---- the envelope (D11) ----

    function test_unlock_vouchesForThePinnedSlot() public {
        keyRegistry.setSlotExpiry(signer, 1, 0);
        (IAdManager.OrderParams memory p,) = _lockPinned(5, 1);
        address pv0 = address(new PinRootVerifier(0));
        vm.prank(admin);
        adManager.setRootVerifier(orderChainId, pv0);
        vm.expectRevert(
            abi.encodeWithSelector(RootVerifierRegistry.RootNotValid.selector, orderChainId, bytes32(uint256(7)))
        );
        adManager.unlock(p, TestField.fe("P1"), bytes32(uint256(7)), hex"", hex"");
        address pv1 = address(new PinRootVerifier(1));
        vm.prank(admin);
        adManager.setRootVerifier(orderChainId, pv1);
        adManager.unlock(p, TestField.fe("P1"), bytes32(uint256(7)), hex"", hex"");
    }

    // ---- the re-pin (D12, Q2) ----

    function test_repin_movesThePin_andTheUnlockVouchesForTheNewOne() public {
        keyRegistry.setSlotExpiry(signer, 1, 0);
        (IAdManager.OrderParams memory p, bytes32 h) = _lockPinned(6, 0);
        keyRegistry.setRepin(signer, h, 0, 1);
        vm.expectEmit(true, false, false, true, address(adManager));
        emit IAdManager.OrderRepinned(h, 0, 1);
        adManager.repinOrder(p);
        (uint32 slot,) = _pin(h);
        assertEq(slot, 1);
        address pv1 = address(new PinRootVerifier(1));
        vm.prank(admin);
        adManager.setRootVerifier(orderChainId, pv1);
        adManager.unlock(p, TestField.fe("P2"), bytes32(uint256(7)), hex"", hex"");
    }

    function test_repin_needsTheSignersConsentFromTheCurrentPin() public {
        keyRegistry.setSlotExpiry(signer, 2, 0);
        (IAdManager.OrderParams memory p, bytes32 h) = _lockPinned(7, 0);
        vm.expectRevert(abi.encodeWithSelector(IAdManager.AdManager__NoRepin.selector, h));
        adManager.repinOrder(p);
        keyRegistry.setRepin(signer, h, 1, 2); // consent from a slot the order is not pinned to
        vm.expectRevert(abi.encodeWithSelector(IAdManager.AdManager__NoRepin.selector, h));
        adManager.repinOrder(p);
        (uint32 slot,) = _pin(h);
        assertEq(slot, 0, "unchanged");
    }

    function test_repin_refusesAnUnusableTarget() public {
        keyRegistry.setSlotExpiry(signer, 1, uint64(block.timestamp));
        (IAdManager.OrderParams memory p, bytes32 h) = _lockPinned(8, 0);
        keyRegistry.setRepin(signer, h, 0, 1);
        vm.expectRevert(abi.encodeWithSelector(IAdManager.AdManager__SlotNotUsable.selector, signer, uint32(1)));
        adManager.repinOrder(p);
    }

    function test_repin_onlyWhileOpen() public {
        keyRegistry.setSlotExpiry(signer, 1, 0);
        (IAdManager.OrderParams memory p, bytes32 h) = _lockPinned(9, 0);
        keyRegistry.setRepin(signer, h, 0, 1);
        vm.warp(p.deadline);
        adManager.claimCancel(p);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderNotOpen.selector, h));
        adManager.repinOrder(p);
    }

    /// Q2: not past `deadline - claimStagger`, after which no new maker payout lands on the order leg.
    function test_repin_closesAtTheClaimStagger() public {
        vm.prank(admin);
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(1 hours, 30 minutes, 0, 10 minutes));
        keyRegistry.setSlotExpiry(signer, 1, 0);
        (IAdManager.OrderParams memory p, bytes32 h) = _lockPinned(10, 0);
        keyRegistry.setRepin(signer, h, 0, 1);
        uint256 cutoff = p.deadline - 10 minutes;
        vm.warp(cutoff + 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderExpired.selector, cutoff));
        adManager.repinOrder(p);
        vm.warp(cutoff);
        adManager.repinOrder(p);
        assertEq(uint256(statusOf(address(adManager), h)), uint256(IEscrow.Status.Open));
    }
}
