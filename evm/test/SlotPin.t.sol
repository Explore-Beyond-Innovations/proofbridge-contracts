// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {TestField} from "test/utils/TestField.sol";
import {statusOf} from "test/utils/OrderStatus.sol";
import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IEscrow} from "src/interfaces/IEscrow.sol";
import {RouteTiming} from "src/libraries/RouteTiming.sol";
import {RootVerifierRegistry} from "src/libraries/RootVerifierRegistry.sol";
import {AdManagerTest} from "./Admanager.t.sol";
import {MockKeyRegistry} from "./mocks/MockKeyRegistry.sol";
import {PinRootVerifier} from "./mocks/PinRootVerifier.sol";

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

    // ---- a re-pin is a denial, and a dead pin stays (the October review's re-pin holes) ----

    /// The pin's slot was killed: it cannot be moved away, and the kill keeps denying the payout — the
    /// cancel waits the evidence grace (buffer 30 min, no anchor: 60 min after the deadline).
    function test_repin_refusesLeavingAnExpiredSlot_andTheCancelWaitsTheGrace() public {
        keyRegistry.setSlotExpiry(signer, 1, 0);
        (IAdManager.OrderParams memory p, bytes32 h) = _lockPinned(11, 0);
        keyRegistry.setRepin(signer, h, 0, 1);
        vm.warp(block.timestamp + 10);
        keyRegistry.setSlotExpiry(signer, 0, uint64(block.timestamp)); // the kill
        vm.expectRevert(abi.encodeWithSelector(IAdManager.AdManager__SlotNotUsable.selector, signer, uint32(0)));
        adManager.repinOrder(p);
        (uint32 slot,) = _pin(h);
        assertEq(slot, 0, "the dead pin stays");
        vm.warp(p.deadline);
        adManager.claimCancel(p);
        assertEq(adManager.cancelFinalizesAt(p), p.deadline + 60 minutes, "the kill still denies");
    }

    /// A re-pin alone is a lever the maker's side holds (it refuses every pair signed under the old
    /// pin), so the cancel waits the grace although both slots are live.
    function test_repinAlone_isADenial_theCancelWaitsTheGrace() public {
        keyRegistry.setSlotExpiry(signer, 1, 0);
        (IAdManager.OrderParams memory p, bytes32 h) = _lockPinned(12, 0);
        keyRegistry.setRepin(signer, h, 0, 1);
        adManager.repinOrder(p);
        vm.warp(p.deadline);
        adManager.claimCancel(p);
        assertEq(adManager.cancelFinalizesAt(p), p.deadline + 60 minutes, "a re-pin denies");
        vm.warp(p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);
        vm.warp(p.deadline + 60 minutes);
        adManager.finalizeCancel(p);
    }

    /// Two live slots and no re-pin: ordinary timing (the control for the case above).
    function test_noRepin_twoLiveSlots_ordinaryTiming() public {
        keyRegistry.setSlotExpiry(signer, 1, 0);
        (IAdManager.OrderParams memory p,) = _lockPinned(13, 0);
        vm.warp(p.deadline);
        adManager.claimCancel(p);
        assertEq(adManager.cancelFinalizesAt(p), p.deadline + 30 minutes);
    }

    /// A pin shortened to die inside the window, then moved away while still usable: the denial stays
    /// with the order, not with the slot it left.
    function test_shortenedPin_repinnedAway_stillWaitsTheGrace() public {
        keyRegistry.setSlotExpiry(signer, 1, 0);
        (IAdManager.OrderParams memory p, bytes32 h) = _lockPinned(14, 0);
        keyRegistry.setSlotExpiry(signer, 0, uint64(p.deadline - 10)); // a shorten naming a date inside the window
        keyRegistry.setRepin(signer, h, 0, 1);
        adManager.repinOrder(p); // slot 0 is still usable now
        (uint32 slot,) = _pin(h);
        assertEq(slot, 1);
        vm.warp(p.deadline);
        adManager.claimCancel(p);
        assertEq(adManager.cancelFinalizesAt(p), p.deadline + 60 minutes, "the shorten is not laundered");
    }

    /// The consent is read from the registry the order was locked under, whatever is wired later.
    function test_repin_readsTheOrdersRegistry_acrossAMigration() public {
        MockKeyRegistry second = new MockKeyRegistry();
        second.set(signer, true);
        second.setSlotExpiry(signer, 1, 0);
        vm.prank(admin);
        adManager.setKeyRegistry(second);
        (IAdManager.OrderParams memory p, bytes32 h) = _lockPinned(15, 0);
        (, uint32 epoch) = _pin(h);
        assertEq(epoch, adManager.registryEpoch(), "locked under the second registry");
        MockKeyRegistry third = new MockKeyRegistry();
        third.set(signer, true);
        vm.prank(admin);
        adManager.setKeyRegistry(third);
        keyRegistry.setRepin(signer, h, 0, 1); // a consent on the first registry
        third.setRepin(signer, h, 0, 1); // and on the live one: neither is the order's
        vm.expectRevert(abi.encodeWithSelector(IAdManager.AdManager__NoRepin.selector, h));
        adManager.repinOrder(p);
        second.setRepin(signer, h, 0, 1);
        adManager.repinOrder(p);
        (uint32 slot,) = _pin(h);
        assertEq(slot, 1);
    }
}
