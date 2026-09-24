// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {TestField} from "test/utils/TestField.sol";

import {IEscrow} from "src/interfaces/IEscrow.sol";
import {IAdManager} from "src/interfaces/IAdManager.sol";
import {AdManagerCancellationTest} from "./Cancellation.t.sol";

/*//////////////////////////////////////////////////////////////
          #422 — the maker's settlement halt (F1 residual)
//////////////////////////////////////////////////////////////*/

/// One custody-key transaction stops the co-signed payout of every open order against the maker's
/// ads; evidence still pays; a denied order's cancel waits the evidence grace. The base timing here
/// is buffer 30 min, no anchor wired, so the grace is the buffer alone until a test wires one.
contract SettlementHaltTest is AdManagerCancellationTest {
    bytes32 internal constant ROOT = bytes32(uint256(5));

    function _unlock(IAdManager.OrderParams memory p, string memory nullifier) internal {
        vm.prank(bridger);
        adManager.unlock(p, TestField.fe(nullifier), ROOT, hex"", hex"");
    }

    function _halt() internal {
        vm.prank(maker);
        adManager.haltSettlement();
    }

    function _resume() internal {
        vm.prank(maker);
        adManager.resumeSettlement();
    }

    /*//////////////////////////// the switch ////////////////////////////*/

    function test_halt_refusesTheCoSignedUnlock_resumeAdmitsIt() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lock(1);

        vm.expectEmit(true, true, true, true);
        emit IAdManager.SettlementHalted(maker);
        _halt();
        assertTrue(adManager.halted(maker));

        vm.expectRevert(abi.encodeWithSelector(IAdManager.AdManager__Halted.selector, maker));
        _unlock(p, "N1");
        assertEq(uint256(adManager.orders(h)), uint256(IEscrow.Status.Open), "nothing moved");

        vm.expectEmit(true, true, true, true);
        emit IAdManager.SettlementResumed(maker);
        _resume();
        _unlock(p, "N1");
        assertEq(uint256(adManager.orders(h)), uint256(IEscrow.Status.Filled));
    }

    function test_halt_isKeyedByMaker_someoneElsesHaltChangesNothing() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lock(2);
        vm.prank(bridger);
        adManager.haltSettlement();
        _unlock(p, "N1");
        assertEq(uint256(adManager.orders(h)), uint256(IEscrow.Status.Filled));
    }

    /// A runbook that fires the halt twice is not an error, and the second halt still refuses.
    function test_halt_isIdempotent_secondHaltStillRefuses() public {
        (IAdManager.OrderParams memory p,) = _lock(2);
        _halt();
        vm.warp(block.timestamp + 100);
        _halt();
        vm.expectRevert(abi.encodeWithSelector(IAdManager.AdManager__Halted.selector, maker));
        _unlock(p, "N1");
    }

    /// An incident lever is never pause-gated (the same rule as `setSettlementSigner`).
    function test_halt_andResume_workWhilePaused() public {
        vm.prank(admin);
        adManager.pause();
        _halt();
        _resume();
    }

    /*//////////////////////////// evidence wins ////////////////////////////*/

    /// Rule 2: a halted maker's counterparty is still paid on an anchored SETTLED leaf.
    function test_presentSettled_ignoresTheHalt() public {
        _wireAnchor();
        (IAdManager.OrderParams memory p, bytes32 h) = _lock(3);
        _halt();
        _claim(p);
        bytes32 root = bytes32(uint256(0xf00d));
        _anchorRoot(root);

        vm.warp(p.deadline + 10 minutes);
        adManager.presentSettled(p, root, hex"");
        assertEq(uint256(adManager.orders(h)), uint256(IEscrow.Status.Filled));
        assertEq(adToken.balanceOf(recipient), 60 ether, "the bridger's recipient is paid");
    }

    /*//////////////////////////// the cancel clock ////////////////////////////*/

    /// Halted before the claim: the cancel waits the grace (buffer, with no anchor wired).
    function test_finalizeCancel_haltedSinceBeforeTheClaim_waitsTheGrace() public {
        (IAdManager.OrderParams memory p,) = _lock(4);
        _halt();
        _claim(p);
        vm.warp(p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);
        vm.warp(p.deadline + 60 minutes - 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);
        vm.warp(p.deadline + 60 minutes);
        adManager.finalizeCancel(p);
        assertEq(_locked(), 0, "the lock is released after the grace");
    }

    /// Halted after the claim opened and resumed before the window ended: still denied. The resume
    /// can come after the presentation cutoff, when it no longer helps the counterparty.
    function test_finalizeCancel_haltedThenResumedAfterTheClaim_stillWaits() public {
        (IAdManager.OrderParams memory p,) = _lock(5);
        _claim(p);
        vm.warp(p.deadline + 10 minutes);
        _halt();
        vm.warp(p.deadline + 20 minutes);
        _resume();
        assertFalse(adManager.halted(maker));
        vm.warp(p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);
        vm.warp(p.deadline + 60 minutes);
        adManager.finalizeCancel(p);
    }

    /// Halted from before the claim and resumed only after the window's last useful second: the
    /// halt covered the whole window, so the payout was denied and the cancel waits.
    function test_finalizeCancel_haltedThroughTheClaim_resumedAtTheEnd_stillWaits() public {
        (IAdManager.OrderParams memory p,) = _lock(12);
        _halt();
        _claim(p);
        vm.warp(p.deadline + 30 minutes - 1);
        _resume();
        vm.warp(p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);
        vm.warp(p.deadline + 60 minutes);
        adManager.finalizeCancel(p);
    }

    /// A halt lifted before the claim opened never denied this window: ordinary timing.
    function test_finalizeCancel_haltLiftedBeforeTheClaim_ordinaryTiming() public {
        (IAdManager.OrderParams memory p,) = _lock(6);
        _halt();
        vm.warp(block.timestamp + 1);
        _resume();
        vm.warp(block.timestamp + 1);
        _claim(p);
        vm.warp(p.deadline + 30 minutes);
        adManager.finalizeCancel(p);
        assertEq(_locked(), 0);
    }

    /// A halt in the same second the claim opened counts (the safe direction of `>=`).
    function test_finalizeCancel_haltInTheClaimsSecond_counts() public {
        (IAdManager.OrderParams memory p,) = _lock(7);
        _claim(p);
        _halt();
        vm.warp(p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);
    }

    /// With an anchor wired the grace is its delay for the order chain plus the buffer.
    function test_finalizeCancel_grace_isAnchorDelayPlusBuffer() public {
        _wireAnchor();
        vm.prank(admin);
        anchor.setAnchorDelay(orderChainId, 2 hours);
        (IAdManager.OrderParams memory p,) = _lock(8);
        _halt();
        _claim(p);
        vm.warp(p.deadline + 30 minutes + 2 hours);
        vm.expectRevert(
            abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 30 minutes + 2 hours + 30 minutes)
        );
        adManager.finalizeCancel(p);
        vm.warp(p.deadline + 30 minutes + 2 hours + 30 minutes);
        adManager.finalizeCancel(p);
    }

    /// Lever 2: the signer fully retired in the registry is a denied payout too (the one-sided
    /// retirement race that exists today, closed by the same grace).
    function test_finalizeCancel_signerWithNoUsableSlot_waitsTheGrace() public {
        (IAdManager.OrderParams memory p,) = _lock(9);
        _claim(p);
        keyRegistry.set(p.adSettlementSigner, false);
        vm.warp(p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);
        vm.warp(p.deadline + 60 minutes);
        adManager.finalizeCancel(p);
    }

    /// The grace stacks on a pause the same way the window does: paused seconds extend the end.
    function test_finalizeCancel_grace_stacksOnAPause() public {
        (IAdManager.OrderParams memory p,) = _lock(10);
        _halt();
        _claim(p);
        vm.prank(admin);
        adManager.pause();
        vm.warp(p.deadline + 15 minutes);
        vm.prank(admin);
        adManager.unpause();
        // 15 min paused: window ends at +45, grace ends at +75.
        vm.warp(p.deadline + 75 minutes - 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 75 minutes));
        adManager.finalizeCancel(p);
        vm.warp(p.deadline + 75 minutes);
        adManager.finalizeCancel(p);
    }

    /*//////////////////////////// T-06 ////////////////////////////*/

    /// T-06: a locked, co-signed order stops settling after one custody-key transaction, cannot be
    /// cancelled inside the grace, and reaches `Cancelled` with the CANCEL leaf and the counter
    /// cleared after it. The co-signature is the permissive root verifier here; the shape is the
    /// same with a real aggregate, which the unlock never reaches once halted.
    function test_T06_haltedOrder_stopsSettling_andStillTerminates() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lock(11);
        uint256 leaves = adManager.getMerkleLeafCount();
        uint256 balanceBefore = _balance();

        _halt();
        vm.expectRevert(abi.encodeWithSelector(IAdManager.AdManager__Halted.selector, maker));
        _unlock(p, "N1");

        _claim(p);
        vm.warp(p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);

        // At the window's last second (inclusive) the halt is still what refuses; a second later the
        // cutoff closes the co-signed path on its own.
        vm.expectRevert(abi.encodeWithSelector(IAdManager.AdManager__Halted.selector, maker));
        _unlock(p, "N1");
        vm.warp(p.deadline + 30 minutes + 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderExpired.selector, p.deadline + 30 minutes));
        _unlock(p, "N1");

        vm.warp(p.deadline + 60 minutes);
        adManager.finalizeCancel(p);
        assertEq(uint256(adManager.orders(h)), uint256(IEscrow.Status.Cancelled));
        assertEq(adManager.getMerkleLeafCount(), leaves + 1, "the CANCEL leaf");
        assertEq(_locked(), 0);
        assertEq(_balance(), balanceBefore, "the ad keeps its funds");
        assertEq(adManager.inFlightOf(p.adSettlementSigner), 0);
    }
}
