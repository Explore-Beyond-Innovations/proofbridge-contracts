// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {TestField} from "test/utils/TestField.sol";

import {IEscrow} from "src/interfaces/IEscrow.sol";
import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IOrderPortal} from "src/interfaces/IOrderPortal.sol";
import {IRootAnchor} from "src/interfaces/IRootAnchor.sol";
import {IVerifier} from "src/interfaces/IVerifier.sol";
import {IMerkleManager} from "src/interfaces/IMerkleManager.sol";
import {IwNativeToken} from "src/wNativeToken.sol";
import {HonkVerifier} from "src/Verifier.sol";
import {RootAnchor} from "src/RootAnchor.sol";
import {LeafDomain} from "src/libraries/LeafDomain.sol";
import {RouteTiming} from "src/libraries/RouteTiming.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {AdManagerTest, MockAdManager} from "./Admanager.t.sol";
import {OrderPortalTest} from "./OrderPortal.t.sol";
import {statusOf} from "test/utils/OrderStatus.sol";

/*//////////////////////////////////////////////////////////////
                  2.3e — the termination primitive
//////////////////////////////////////////////////////////////*/

/// Shared plumbing: a real RootAnchor (signer = this test, threshold 1), live event proofs through the
/// events circuit, and the option to swap the permissive mock verifier for the real Honk verifier by
/// etching its code over the mock (the verifier is stateless, so the escrows keep their immutable).
abstract contract CancellationHarness {
    uint64 internal nextSeq = 1;

    function _anchorOf(address admin, address signer) internal returns (RootAnchor) {
        address[] memory s = new address[](1);
        s[0] = signer;
        return new RootAnchor(admin, s, 1);
    }
}

/*//////////////////////////////////////////////////////////////
                        THE PRIMARY (AdManager)
//////////////////////////////////////////////////////////////*/

contract AdManagerCancellationTest is AdManagerTest, CancellationHarness {
    RootAnchor internal anchor;
    RouteTiming.Timing internal baseTiming = RouteTiming.Timing(0, 30 minutes, 0, 0);

    function setUp() public virtual override {
        super.setUp();
        anchor = _anchorOf(admin, address(this));
    }

    /*//////////////////////////// helpers ////////////////////////////*/

    function _wireAnchor() internal {
        vm.prank(admin);
        adManager.setRootAnchor(IRootAnchor(address(anchor)));
    }

    function _anchorRoot(bytes32 root) internal {
        anchor.anchor(orderChainId, root, nextSeq++);
    }

    function _setTiming(RouteTiming.Timing memory t) internal {
        vm.prank(admin);
        adManager.setRouteTiming(orderChainId, t);
    }

    /// A funded ad and one lock on it (60 ether of a 100 + 300 ether ad).
    function _lock(uint256 salt) internal returns (IAdManager.OrderParams memory p, bytes32 h) {
        test_fundAd_makerOnly();
        (p, h) = _openOrder(lastAdId, address(adToken), 60 ether, salt, bridger, recipient);
    }

    function _claim(IAdManager.OrderParams memory p) internal {
        vm.warp(p.deadline);
        adManager.claimCancel(p);
    }

    function _locked() internal view returns (uint256 locked) {
        (,,,,,,,, locked) = adManager.ads(lastAdId);
    }

    function _balance() internal view returns (uint256 balance) {
        (,,,,,,, balance,) = adManager.ads(lastAdId);
    }

    function _useRealVerifier() internal {
        vm.etch(address(verifier), address(new HonkVerifier()).code);
    }

    function _eventProof(uint256 domain, bytes32 subject) internal returns (bytes memory proof, bytes32 root) {
        string[] memory a = new string[](5);
        a[0] = "npx";
        a[1] = "tsx";
        a[2] = "js-scripts/deposits/generateEventClaim.ts";
        a[3] = vm.toString(domain);
        a[4] = vm.toString(subject);
        bytes32[] memory pub;
        (proof, pub) = abi.decode(vm.ffi(a), (bytes, bytes32[]));
        root = pub[2];
    }

    /*//////////////////////////// admin ////////////////////////////*/

    function test_setRouteTiming_validationMatrix() public {
        vm.startPrank(admin);
        // Field 3 is retired with the follower's backstop: a tuple only it refused is accepted now.
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(0, 2 hours, 0, 0));
        vm.expectRevert(abi.encodeWithSelector(RouteTiming.RouteTiming__Invalid.selector, uint8(1)));
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(0, 29 minutes, 0, 0));
        vm.expectRevert(abi.encodeWithSelector(RouteTiming.RouteTiming__Invalid.selector, uint8(2)));
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(1 hours, 1 hours, 1 hours, 0));
        vm.expectRevert(abi.encodeWithSelector(RouteTiming.RouteTiming__Invalid.selector, uint8(4)));
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(30 minutes, 1 hours, 0, 30 minutes));
        vm.expectRevert(abi.encodeWithSelector(RouteTiming.RouteTiming__Invalid.selector, uint8(5)));
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(1 minutes, 1 hours, 2 minutes, 0));

        // The D6 defaults, and the stagger switched off with a zero window. Each write is a new
        // version; setUp wrote version 1.
        uint32 v1 = adManager.timingVersion(orderChainId);
        RouteTiming.Timing memory live = RouteTiming.Timing(1 hours, 2 hours, 120, 30 minutes);
        vm.expectEmit(true, true, true, true);
        emit IEscrow.RouteTimingSet(orderChainId, v1 + 1, live);
        adManager.setRouteTiming(orderChainId, live);
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(0, 30 minutes, 0, 0));
        vm.stopPrank();

        assertEq(adManager.timingVersion(orderChainId), v1 + 2);
        (uint64 minWindow, uint64 buffer, uint64 margin, uint64 stagger) = adManager.routeTimingAt(orderChainId, v1 + 2);
        assertEq(minWindow, 0);
        assertEq(buffer, 30 minutes);
        assertEq(margin, 0);
        assertEq(stagger, 0);
        // The earlier version is never edited in place.
        (minWindow, buffer, margin, stagger) = adManager.routeTimingAt(orderChainId, v1 + 1);
        assertEq(minWindow, 1 hours);
        assertEq(buffer, 2 hours);
        assertEq(margin, 120);
        assertEq(stagger, 30 minutes);
        (, buffer,,) = adManager.routeTimingAt(orderChainId, 0);
        assertEq(buffer, 0, "version 0 is unset");

        vm.prank(nonAdmin);
        vm.expectRevert();
        adManager.setRouteTiming(orderChainId, live);
    }

    function test_setRootAnchor_adminOnly_nonZero_emits() public {
        vm.prank(nonAdmin);
        vm.expectRevert();
        adManager.setRootAnchor(IRootAnchor(address(anchor)));

        vm.prank(admin);
        vm.expectRevert(IEscrow.Escrow__ZeroAddress.selector);
        adManager.setRootAnchor(IRootAnchor(address(0)));

        vm.prank(admin);
        vm.expectEmit(true, true, true, true);
        emit IEscrow.RootAnchorSet(address(anchor));
        adManager.setRootAnchor(IRootAnchor(address(anchor)));
        assertEq(address(adManager.rootAnchor()), address(anchor));
    }

    /// Every timed path fails closed on a route with no timing: the NoRootVerifier posture.
    function test_timing_unset_failsClosed() public {
        MockAdManager bare = new MockAdManager(
            admin,
            IVerifier(address(verifier)),
            IMerkleManager(address(merkleManager)),
            IwNativeToken(address(_wNativeToken))
        );
        vm.startPrank(admin);
        merkleManager.setManager(address(bare), true);
        bare.setPeerEscrow(orderChainId, _b32(orderPortal));
        bare.setTokenRoute(address(adToken), orderChainId, _b32(orderToken));
        bare.setKeyRegistry(keyRegistry);
        vm.stopPrank();

        vm.startPrank(maker);
        adToken.approve(address(bare), initAmt);
        bare.createAd("bare", address(adToken), initAmt, orderChainId, _b32(adRecipient), _b32(maker));
        IAdManager.OrderParams memory p = _defaultParams("bare");
        vm.expectRevert(abi.encodeWithSelector(RouteTiming.RouteTiming__NotSet.selector, orderChainId));
        bare.lockForOrder(p);
        vm.stopPrank();

        vm.warp(p.deadline);
        vm.expectRevert(abi.encodeWithSelector(RouteTiming.RouteTiming__NotSet.selector, orderChainId));
        bare.cancelNeverLocked(p);
    }

    /// The two evidence paths fail closed with no anchor; settlement never reads it.
    function test_anchor_unset_failsClosed_settlementNeverReadsIt() public {
        (IAdManager.OrderParams memory p,) = _lock(1);
        vm.expectRevert(IEscrow.Escrow__NoRootAnchor.selector);
        adManager.presentSettled(p, bytes32(uint256(1)), hex"");
        // The co-signed unlock does not care.
        adManager.unlock(p, TestField.fe("A1"), bytes32(uint256(1)), hex"", hex"");
    }

    /*//////////////////////////// T-45: the window bound + never-locked ////////////////////////////*/

    function test_T45_lock_refusesDeadlineInsideMinWindow() public {
        _setTiming(RouteTiming.Timing(1 hours, 30 minutes, 0, 0));
        test_fundAd_makerOnly();
        IAdManager.OrderParams memory p = _defaultParams(lastAdId);
        p.deadline = block.timestamp + 30 minutes;
        vm.prank(maker);
        vm.expectRevert(
            abi.encodeWithSelector(IEscrow.Escrow__DeadlineTooSoon.selector, p.deadline, block.timestamp + 1 hours)
        );
        adManager.lockForOrder(p);

        p.deadline = block.timestamp + 1 hours;
        vm.prank(maker);
        adManager.lockForOrder(p);
    }

    /// #453: a lock accepts a deadline at most `MAX_ORDER_WINDOW` out, to the second.
    function test_453_lock_refusesDeadlinePastTheOrderWindow() public {
        test_fundAd_makerOnly();
        IAdManager.OrderParams memory p = _defaultParams(lastAdId);
        uint256 maxAllowed = block.timestamp + RouteTiming.MAX_ORDER_WINDOW;
        p.deadline = maxAllowed + 1;
        vm.prank(maker);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__DeadlineTooFar.selector, p.deadline, maxAllowed));
        adManager.lockForOrder(p);

        p.deadline = maxAllowed;
        vm.prank(maker);
        adManager.lockForOrder(p);
    }

    /// #453: the buffer and the minimum window have ceilings; each cap itself is accepted.
    function test_453_setRouteTiming_upperBounds() public {
        uint64 maxBuffer = RouteTiming.MAX_BUFFER;
        uint64 maxWindow = RouteTiming.MAX_ORDER_WINDOW;
        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSelector(RouteTiming.RouteTiming__Invalid.selector, uint8(1)));
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(0, maxBuffer + 1, 0, 0));
        vm.expectRevert(abi.encodeWithSelector(RouteTiming.RouteTiming__Invalid.selector, uint8(5)));
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(maxWindow / 2 + 1, 1 hours, 0, 0));
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(0, maxBuffer, 0, 0));
        // #457-2: at most half the order window, so a deadline at twice it still fits the cap.
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(maxWindow / 2, 1 hours, 0, 0));
        vm.stopPrank();
    }

    function test_T45_cancelNeverLocked_onlyNoneAtDeadline_appendsLeaf() public {
        test_fundAd_makerOnly();
        IAdManager.OrderParams memory p = _defaultParams(lastAdId);
        bytes32 h = adManager.hashOrderPublic(p);
        uint256 leaves = adManager.getMerkleLeafCount();

        vm.warp(p.deadline - 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline));
        adManager.cancelNeverLocked(p);
        assertEq(adManager.getMerkleLeafCount(), leaves, "no leaf before the deadline");

        vm.warp(p.deadline);
        vm.expectEmit(true, true, true, true);
        emit IEscrow.OrderCancelled(h, false);
        adManager.cancelNeverLocked(p);
        assertEq(uint256(statusOf(address(adManager), h)), uint256(IEscrow.Status.Cancelled));
        assertEq(adManager.getMerkleLeafCount(), leaves + 1, "the cancel leaf");
        assertEq(adManager.inFlightOf(p.adSettlementSigner), 0, "nothing was counted");

        // Single-shot, and a lock can never follow it.
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimable.selector, h, IEscrow.Status.Cancelled));
        adManager.cancelNeverLocked(p);
        vm.prank(maker);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderExists.selector, h));
        adManager.lockForOrder(p);
    }

    function test_T45_cancelNeverLocked_unsupportedChain_reverts() public {
        IAdManager.OrderParams memory p = _defaultParams("x");
        p.orderChainId = unsupportedChainId;
        vm.warp(p.deadline);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__ChainNotSupported.selector, unsupportedChainId));
        adManager.cancelNeverLocked(p);
    }

    function test_cancelNeverLocked_refusesAnOpenLock() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lock(2);
        vm.warp(p.deadline);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimable.selector, h, IEscrow.Status.Open));
        adManager.cancelNeverLocked(p);
    }

    /*//////////////////////////// claim → window → finalize ////////////////////////////*/

    function test_claimCancel_atDeadline_opensWindow_movesNoFunds() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lock(3);
        uint256 lockedBefore = _locked();

        vm.warp(p.deadline - 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline));
        adManager.claimCancel(p);

        vm.warp(p.deadline);
        vm.expectEmit(true, true, true, true);
        emit IEscrow.ClaimOpened(h, uint64(p.deadline + 30 minutes));
        adManager.claimCancel(p);

        (uint64 openedAt, uint64 finalizeAt) = adManager.claims(h);
        assertEq(openedAt, p.deadline);
        assertEq(finalizeAt, p.deadline + 30 minutes, "deadline-anchored");
        assertEq(uint256(statusOf(address(adManager), h)), uint256(IEscrow.Status.Claimed));
        assertEq(_locked(), lockedBefore, "a claim moves nothing");
        assertEq(adManager.inFlightOf(p.adSettlementSigner), 1, "still in flight");

        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimable.selector, h, IEscrow.Status.Claimed));
        adManager.claimCancel(p);
    }

    /// A late claim does not shorten the window: finalizeAt is `deadline + buffer` whenever the claim lands.
    function test_claimCancel_late_isStillDeadlineAnchored() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lock(4);
        vm.warp(p.deadline + 25 minutes);
        adManager.claimCancel(p);
        (, uint64 finalizeAt) = adManager.claims(h);
        assertEq(finalizeAt, p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 30 minutes));
        adManager.finalizeCancel(p);
    }

    /// T-50 (the Open entry): the window is the full buffer.
    function test_T50_finalizeCancel_revertsOneSecondBeforeTheWindowEnds() public {
        (IAdManager.OrderParams memory p,) = _lock(5);
        _claim(p);
        vm.warp(p.deadline + 30 minutes - 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 30 minutes));
        adManager.finalizeCancel(p);
        vm.warp(p.deadline + 30 minutes);
        adManager.finalizeCancel(p);
    }

    /// T-39 + T-44: the leaf appears exactly with `Cancelled`; the lock returns to the ad; the counter clears.
    function test_T39_finalizeCancel_releasesLock_appendsLeaf_clearsCounter() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lock(6);
        uint256 balanceBefore = _balance();
        uint256 leaves = adManager.getMerkleLeafCount();
        assertEq(leaves, 1, "the ORDER leaf");

        // From Open: nothing to finalize.
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimed.selector, h));
        adManager.finalizeCancel(p);

        _claim(p);
        vm.warp(p.deadline + 30 minutes);
        vm.expectEmit(true, true, true, true);
        emit IEscrow.OrderCancelled(h, false);
        vm.expectEmit(true, true, true, true);
        emit IAdManager.LockCancelled(lastAdId, h, 60 ether);
        adManager.finalizeCancel(p);

        assertEq(uint256(statusOf(address(adManager), h)), uint256(IEscrow.Status.Cancelled));
        assertEq(_locked(), 0, "lock released");
        assertEq(_balance(), balanceBefore, "the ad keeps its funds");
        assertEq(adManager.getMerkleLeafCount(), leaves + 1, "the CANCEL leaf");
        assertEq(adManager.inFlightOf(p.adSettlementSigner), 0, "T-44");
        (, uint64 finalizeAt) = adManager.claims(h);
        assertEq(finalizeAt, 0, "claim record cleared");

        // Terminal: nothing else appends or moves.
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimed.selector, h));
        adManager.finalizeCancel(p);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimable.selector, h, IEscrow.Status.Cancelled));
        adManager.claimCancel(p);
        // Back inside the unlock window, so the status (not the cutoff) is what refuses.
        vm.warp(p.deadline);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderNotOpen.selector, h));
        adManager.unlock(p, TestField.fe("C1"), bytes32(0), hex"", hex"");
        _wireAnchor();
        _anchorRoot(bytes32(uint256(9)));
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimable.selector, h, IEscrow.Status.Cancelled));
        adManager.presentSettled(p, bytes32(uint256(9)), hex"");
        assertEq(adManager.getMerkleLeafCount(), leaves + 1, "no second leaf");
    }

    /*//////////////////////////// T-45a / T-45b: the co-signed unlock is the presentation ////////////////////////////*/

    function test_T45a_fastUnlockRace_bridgerUnlocksInsideTheWindow() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lock(7);
        _claim(p);
        uint256 leaves = adManager.getMerkleLeafCount();

        vm.warp(p.deadline + 15 minutes);
        vm.expectEmit(true, true, true, true);
        emit IEscrow.OrderSettled(h, false);
        adManager.unlock(p, TestField.fe("R1"), bytes32(uint256(1)), hex"", hex"");

        assertEq(uint256(statusOf(address(adManager), h)), uint256(IEscrow.Status.Filled));
        assertEq(adManager.getMerkleLeafCount(), leaves, "the fill itself appends nothing");
        adManager.recordSettled(p);
        assertEq(adManager.getMerkleLeafCount(), leaves + 1, "T-59: the SETTLED leaf, no cancel leaf");
        (, uint64 finalizeAt) = adManager.claims(h);
        assertEq(finalizeAt, 0, "window closed");
        assertEq(adManager.inFlightOf(p.adSettlementSigner), 0);

        vm.warp(p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimed.selector, h));
        adManager.finalizeCancel(p);
    }

    function test_T45b_primaryUnlock_validBeforeBufferMinusMargin() public {
        _setTiming(RouteTiming.Timing(120, 30 minutes, 120, 0));
        (IAdManager.OrderParams memory p,) = _lock(8);
        uint256 cutoff = p.deadline + 30 minutes - 120;

        // Strict: the cutoff itself is refused.
        vm.warp(cutoff);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderExpired.selector, cutoff));
        adManager.unlock(p, TestField.fe("M1"), bytes32(0), hex"", hex"");

        vm.warp(cutoff - 1);
        adManager.unlock(p, TestField.fe("M1"), bytes32(0), hex"", hex"");
    }

    /// With a zero margin the unlock and the cancel never share a second: one second before the
    /// window's end the unlock passes and the cancel is too early; at the end the unlock and a filing
    /// are refused and the cancel finalizes.
    function test_noSharedLastSecond_unlockBeforeTheEnd_cancelAtIt() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lock(9);
        (IAdManager.OrderParams memory q, bytes32 hq) =
            _openOrder(lastAdId, address(adToken), 60 ether, 10, bridger, recipient);
        _claim(p);
        _claim(q);
        uint256 end = p.deadline + 30 minutes;

        vm.warp(end - 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, end));
        adManager.finalizeCancel(q);
        adManager.unlock(q, TestField.fe("S1"), bytes32(0), hex"", hex"");
        assertEq(uint256(statusOf(address(adManager), hq)), uint256(IEscrow.Status.Filled));

        vm.warp(end);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderExpired.selector, end));
        adManager.unlock(p, TestField.fe("S2"), bytes32(0), hex"", hex"");
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__DisputeWindowClosed.selector, h, end));
        vm.prank(maker);
        adManager.dispute(p, bytes32("evidence"));
        adManager.finalizeCancel(p);
        assertEq(uint256(statusOf(address(adManager), h)), uint256(IEscrow.Status.Cancelled));
    }

    /// The margin is at most half the buffer, so the bridger always keeps half the window.
    function test_setRouteTiming_marginCappedAtHalfTheBuffer() public {
        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSelector(RouteTiming.RouteTiming__Invalid.selector, uint8(2)));
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(1 hours, 1 hours, 30 minutes + 1, 0));
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(1 hours, 1 hours, 30 minutes, 0));
        // An odd buffer rounds the cap down.
        vm.expectRevert(abi.encodeWithSelector(RouteTiming.RouteTiming__Invalid.selector, uint8(2)));
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(1 hours, 1 hours + 1, 30 minutes + 1, 0));
        vm.stopPrank();
    }

    /*//////////////////////////// T-54 / D3: presentSettled ////////////////////////////*/

    function test_T54_presentSettled_settlesAClaimedOrder_noNullifier() public {
        _wireAnchor();
        (IAdManager.OrderParams memory p, bytes32 h) = _lock(9);
        _claim(p);
        uint256 leaves = adManager.getMerkleLeafCount();
        uint256 balanceBefore = _balance();
        bytes32 root = bytes32(uint256(0xf00d));
        _anchorRoot(root);

        vm.warp(p.deadline + 29 minutes);
        vm.expectEmit(true, true, true, true);
        emit IEscrow.OrderSettled(h, true);
        adManager.presentSettled(p, root, hex"");

        assertEq(uint256(statusOf(address(adManager), h)), uint256(IEscrow.Status.Filled));
        assertEq(adToken.balanceOf(recipient), 60 ether, "the bridger's recipient is paid");
        assertEq(_balance(), balanceBefore - 60 ether);
        assertEq(_locked(), 0);
        adManager.recordSettled(p);
        assertEq(adManager.getMerkleLeafCount(), leaves + 1, "T-59: SETTLED appended");
        assertEq(adManager.inFlightOf(p.adSettlementSigner), 0, "T-44");
        assertFalse(adManager.nullifierUsed(bytes32(0)), "no nullifier consumed");

        vm.warp(p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimed.selector, h));
        adManager.finalizeCancel(p);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimable.selector, h, IEscrow.Status.Filled));
        adManager.presentSettled(p, root, hex"");
    }

    /// D3: not window-gated — accepted on an Open order before the deadline.
    function test_presentSettled_onOpen_beforeDeadline() public {
        _wireAnchor();
        (IAdManager.OrderParams memory p, bytes32 h) = _lock(10);
        _anchorRoot(bytes32(uint256(2)));
        adManager.presentSettled(p, bytes32(uint256(2)), hex"");
        assertEq(uint256(statusOf(address(adManager), h)), uint256(IEscrow.Status.Filled));
    }

    function test_presentSettled_rootNotAnchored_orInsideDelay_reverts() public {
        _wireAnchor();
        (IAdManager.OrderParams memory p,) = _lock(11);
        bytes32 root = bytes32(uint256(3));
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__RootNotAnchored.selector, orderChainId, root));
        adManager.presentSettled(p, root, hex"");

        vm.prank(admin);
        anchor.setAnchorDelay(orderChainId, 3600);
        _anchorRoot(root);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__RootNotAnchored.selector, orderChainId, root));
        adManager.presentSettled(p, root, hex"");

        vm.warp(block.timestamp + 3600);
        adManager.presentSettled(p, root, hex"");
    }

    function test_presentSettled_badProof_reverts() public {
        _wireAnchor();
        (IAdManager.OrderParams memory p,) = _lock(12);
        _anchorRoot(bytes32(uint256(4)));
        verifier.setResult(false);
        vm.expectRevert(IEscrow.Escrow__InvalidProof.selector);
        adManager.presentSettled(p, bytes32(uint256(4)), hex"");
    }

    /*//////////////////////////// T-41: a filled primary can never grow a cancel leaf ////////////////////////////*/

    function test_T41_filledPrimary_noCancelLeafIsReachable() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lock(13);
        adManager.unlock(p, TestField.fe("F1"), bytes32(0), hex"", hex"");
        adManager.recordSettled(p);
        uint256 leaves = adManager.getMerkleLeafCount();
        assertEq(leaves, 2, "ORDER + SETTLED");

        vm.warp(p.deadline + 10 days);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimable.selector, h, IEscrow.Status.Filled));
        adManager.claimCancel(p);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimed.selector, h));
        adManager.finalizeCancel(p);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimable.selector, h, IEscrow.Status.Filled));
        adManager.cancelNeverLocked(p);
        assertEq(adManager.getMerkleLeafCount(), leaves, "no cancel leaf");
    }

    /*//////////////////////////// pause: entries only ////////////////////////////*/

    /// Each entry refuses while paused.
    function test_pause_refusesEveryEntry() public {
        test_fundAd_makerOnly();
        IAdManager.OrderParams memory p = _defaultParams(lastAdId);
        vm.prank(admin);
        adManager.pause();

        vm.startPrank(maker);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        adManager.createAd("paused", address(adToken), 1 ether, orderChainId, _b32(adRecipient), _b32(maker));
        vm.expectRevert(Pausable.EnforcedPause.selector);
        adManager.fundAd(lastAdId, 1 ether);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        adManager.lockForOrder(p);
        vm.stopPrank();

        vm.prank(admin);
        adManager.unpause();
        vm.prank(maker);
        adManager.lockForOrder(p);
    }

    /// Every exit works while paused, the maker's free liquidity included.
    function test_pause_leavesEveryExitOpen() public {
        _wireAnchor();
        (IAdManager.OrderParams memory a, bytes32 ha) = _lock(30);
        (IAdManager.OrderParams memory b, bytes32 hb) =
            _openOrder(lastAdId, address(adToken), 60 ether, 31, bridger, recipient);
        (IAdManager.OrderParams memory c, bytes32 hc) =
            _openOrder(lastAdId, address(adToken), 60 ether, 32, bridger, recipient);
        IAdManager.OrderParams memory d = _defaultParams(lastAdId);
        d.salt = 33;
        bytes32 root = bytes32(uint256(0xbeef));
        _anchorRoot(root);
        vm.prank(admin);
        adManager.pause();

        adManager.unlock(a, TestField.fe("X1"), bytes32(uint256(1)), hex"", hex"");
        adManager.recordSettled(a);
        adManager.presentSettled(b, root, hex"");
        vm.warp(c.deadline);
        adManager.claimCancel(c);
        adManager.cancelNeverLocked(d);
        vm.warp(c.deadline + 30 minutes);
        adManager.finalizeCancel(c);
        assertEq(uint256(statusOf(address(adManager), ha)), uint256(IEscrow.Status.Filled));
        assertEq(uint256(statusOf(address(adManager), hb)), uint256(IEscrow.Status.Filled));
        assertEq(uint256(statusOf(address(adManager), hc)), uint256(IEscrow.Status.Cancelled));
        assertEq(uint256(statusOf(address(adManager), adManager.hashOrderPublic(d))), uint256(IEscrow.Status.Cancelled));

        // No trade holds the maker's free liquidity, so it leaves during a pause too.
        vm.startPrank(maker);
        adManager.withdrawFromAd(lastAdId, 1 ether, maker);
        adManager.closeAd(lastAdId, maker);
        vm.stopPrank();
        assertEq(_balance(), 0);
    }

    /// A pause across the deadline moves no window: the co-signed unlock cutoff and the cancel window
    /// read the same before, during and after it.
    function test_pause_acrossTheDeadline_movesNoWindow() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lock(34);
        (IAdManager.OrderParams memory q, bytes32 hq) =
            _openOrder(lastAdId, address(adToken), 60 ether, 35, bridger, recipient);
        uint256 end = p.deadline + 30 minutes;

        vm.warp(p.deadline - 5 minutes);
        vm.prank(admin);
        adManager.pause();
        vm.warp(p.deadline);
        adManager.claimCancel(p);
        (, uint64 finalizeAt) = adManager.claims(h);
        assertEq(finalizeAt, end, "during the pause");
        // The unlock is accepted before the cutoff, and not at it, while paused.
        vm.warp(end);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderExpired.selector, end));
        adManager.unlock(q, TestField.fe("W1"), bytes32(0), hex"", hex"");
        vm.warp(end - 1);
        adManager.unlock(q, TestField.fe("W1"), bytes32(0), hex"", hex"");
        assertEq(uint256(statusOf(address(adManager), hq)), uint256(IEscrow.Status.Filled));

        vm.warp(end + 1 hours);
        vm.prank(admin);
        adManager.unpause();
        assertEq(adManager.cancelFinalizesAt(p), end, "after the pause");
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderExpired.selector, end));
        adManager.unlock(p, TestField.fe("W2"), bytes32(0), hex"", hex"");
        adManager.finalizeCancel(p);
    }

    /// T-59: the SETTLED leaf is recordable exactly once, only for `Filled`, never after a cancel.
    function test_T59_recordSettled_singleShot_onlyWhenFilled() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lock(17);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotFilled.selector, h));
        adManager.recordSettled(p);

        adManager.unlock(p, TestField.fe("R2"), bytes32(0), hex"", hex"");
        assertFalse(adManager.settledRecorded(h));
        vm.expectEmit(true, true, true, true);
        emit IEscrow.SettledRecorded(h);
        adManager.recordSettled(p);
        assertTrue(adManager.settledRecorded(h));
        assertEq(adManager.getMerkleLeafCount(), 2, "ORDER + SETTLED");
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__SettledRecorded.selector, h));
        adManager.recordSettled(p);
        assertEq(adManager.getMerkleLeafCount(), 2);

        // A cancelled order never gets one.
        IAdManager.OrderParams memory q = _defaultParams(lastAdId);
        q.salt = 18;
        bytes32 hq = adManager.hashOrderPublic(q);
        vm.warp(q.deadline);
        adManager.cancelNeverLocked(q);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotFilled.selector, hq));
        adManager.recordSettled(q);
        assertEq(adManager.getMerkleLeafCount(), 3, "the CANCEL leaf only");
    }

    /// A retiming moves no locked order: buffer, margin and stagger change together, and the order
    /// keeps its own version's cutoff and window; a lock after the retiming reads the new version.
    function test_retiming_movesNoLockedOrder() public {
        _setTiming(RouteTiming.Timing(1 hours, 30 minutes, 5 minutes, 30 minutes));
        (IAdManager.OrderParams memory p, bytes32 h) = _lock(40);
        (, uint32 v) = adManager.orders(h);
        assertEq(v, adManager.timingVersion(orderChainId), "the lock keeps the current version");
        _setTiming(RouteTiming.Timing(1 hours, 2 hours, 1 hours, 50 minutes));

        uint256 cutoff = p.deadline + 30 minutes - 5 minutes;
        vm.warp(cutoff);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderExpired.selector, cutoff));
        adManager.unlock(p, TestField.fe("G3"), bytes32(0), hex"", hex"");
        adManager.claimCancel(p);
        (, uint64 finalizeAt) = adManager.claims(h);
        assertEq(finalizeAt, p.deadline + 30 minutes, "the window is the order's own");
        vm.warp(p.deadline + 30 minutes);
        adManager.finalizeCancel(p);

        // A lock after the retiming reads the new version: a 2-hour window, a 1-hour margin.
        (IAdManager.OrderParams memory q, bytes32 hq) =
            _openOrder(lastAdId, address(adToken), 60 ether, 41, bridger, recipient);
        (, uint32 vq) = adManager.orders(hq);
        assertEq(vq, v + 1);
        uint256 cutoffQ = q.deadline + 2 hours - 1 hours;
        vm.warp(cutoffQ);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderExpired.selector, cutoffQ));
        adManager.unlock(q, TestField.fe("G3b"), bytes32(0), hex"", hex"");
        vm.warp(cutoffQ - 1);
        adManager.unlock(q, TestField.fe("G3b"), bytes32(0), hex"", hex"");
    }

    /*//////////////////////////// T-59 with the real verifier ////////////////////////////*/

    /// A domain-3 proof of the order leg's settled leaf flips a Claimed primary to Filled.
    function test_T59_realProof_settledLeafOfTheOtherLeg_settlesTheWindow() public {
        _wireAnchor();
        (IAdManager.OrderParams memory p, bytes32 h) = _lock(15);
        _claim(p);
        _useRealVerifier();

        (bytes memory proof, bytes32 root) = _eventProof(LeafDomain.SETTLED, h);
        _anchorRoot(root);
        vm.warp(p.deadline + 10 minutes);
        adManager.presentSettled(p, root, proof);
        assertEq(uint256(statusOf(address(adManager), h)), uint256(IEscrow.Status.Filled));
        assertEq(adToken.balanceOf(recipient), 60 ether);
    }

    /// A cancel leaf is not a settled leaf: the domain is a contract constant, never calldata.
    function test_T59_realProof_cancelLeafCannotPresentAsSettled() public {
        _wireAnchor();
        (IAdManager.OrderParams memory p, bytes32 h) = _lock(16);
        _useRealVerifier();

        (bytes memory proof, bytes32 root) = _eventProof(LeafDomain.CANCEL, h);
        _anchorRoot(root);
        vm.expectRevert();
        adManager.presentSettled(p, root, proof);
        assertEq(uint256(statusOf(address(adManager), h)), uint256(IEscrow.Status.Open), "the unwind stands");
    }
}

/*//////////////////////////////////////////////////////////////
                       THE FOLLOWER (OrderPortal)
//////////////////////////////////////////////////////////////*/

contract OrderPortalCancellationTest is OrderPortalTest, CancellationHarness {
    RootAnchor internal anchor;

    function setUp() public virtual override {
        super.setUp();
        anchor = _anchorOf(admin, address(this));
    }

    /*//////////////////////////// helpers ////////////////////////////*/

    function _wireAnchor() internal {
        vm.prank(admin);
        portal.setRootAnchor(IRootAnchor(address(anchor)));
    }

    function _anchorRoot(bytes32 root) internal {
        anchor.anchor(adChainId, root, nextSeq++);
    }

    function _setTiming(RouteTiming.Timing memory t) internal {
        vm.prank(admin);
        portal.setRouteTiming(adChainId, t);
    }

    /// Wire the peer + route lazily: the inherited suite has tests that need them absent.
    function _wireRoute() internal {
        if (portal.peerEscrow(adChainId) != bytes32(0)) return;
        vm.startPrank(admin);
        portal.setPeerEscrow(adChainId, _b32(adManager));
        portal.setTokenRoute(address(orderToken), adChainId, adToken);
        vm.stopPrank();
    }

    function _create(uint256 salt) internal returns (IOrderPortal.OrderParams memory p, bytes32 h) {
        _wireRoute();
        p = _defaultParams();
        p.salt = salt;
        vm.startPrank(bridger);
        orderToken.approve(address(portal), p.amount);
        h = portal.createOrder(p);
        vm.stopPrank();
    }

    function _useRealVerifier() internal {
        vm.etch(address(verifier), address(new HonkVerifier()).code);
    }

    function _eventProof(uint256 domain, bytes32 subject) internal returns (bytes memory proof, bytes32 root) {
        string[] memory a = new string[](5);
        a[0] = "npx";
        a[1] = "tsx";
        a[2] = "js-scripts/deposits/generateEventClaim.ts";
        a[3] = vm.toString(domain);
        a[4] = vm.toString(subject);
        bytes32[] memory pub;
        (proof, pub) = abi.decode(vm.ffi(a), (bytes, bytes32[]));
        root = pub[2];
    }

    /*//////////////////////////// T-45 / T-45b: the bounds on this leg ////////////////////////////*/

    function test_T45_create_refusesDeadlineInsideMinWindow() public {
        _setTiming(RouteTiming.Timing(1 hours, 30 minutes, 0, 0));
        _wireRoute();
        IOrderPortal.OrderParams memory p = _defaultParams();
        p.deadline = block.timestamp + 30 minutes;
        vm.startPrank(bridger);
        orderToken.approve(address(portal), p.amount);
        vm.expectRevert(
            abi.encodeWithSelector(IEscrow.Escrow__DeadlineTooSoon.selector, p.deadline, block.timestamp + 1 hours)
        );
        portal.createOrder(p);
        vm.stopPrank();
    }

    /// #453: the order chain caps the same way, so a bridger cannot create an order the maker can
    ///      never lock.
    function test_453_create_refusesDeadlinePastTheOrderWindow() public {
        _wireRoute();
        IOrderPortal.OrderParams memory p = _defaultParams();
        uint256 maxAllowed = block.timestamp + RouteTiming.MAX_ORDER_WINDOW;
        p.deadline = maxAllowed + 1;
        vm.startPrank(bridger);
        orderToken.approve(address(portal), p.amount);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__DeadlineTooFar.selector, p.deadline, maxAllowed));
        portal.createOrder(p);
        p.deadline = maxAllowed;
        portal.createOrder(p);
        vm.stopPrank();
    }

    function test_T45b_followerUnlock_stopsAtDeadlineMinusStagger() public {
        _setTiming(RouteTiming.Timing(1 hours, 30 minutes, 0, 30 minutes));
        (IOrderPortal.OrderParams memory p,) = _create(1);
        uint256 cutoff = p.deadline - 30 minutes;

        vm.warp(cutoff + 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderExpired.selector, cutoff));
        portal.unlock(p, TestField.fe("S1"), bytes32(0), hex"", hex"");
        vm.warp(cutoff);
        portal.unlock(p, TestField.fe("S1"), bytes32(0), hex"", hex"");
    }

    function test_T45b_zeroStagger_restoresThePlainDeadline() public {
        (IOrderPortal.OrderParams memory p,) = _create(2);
        vm.warp(p.deadline + 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderExpired.selector, p.deadline));
        portal.unlock(p, TestField.fe("S2"), bytes32(0), hex"", hex"");
        vm.warp(p.deadline);
        portal.unlock(p, TestField.fe("S2"), bytes32(0), hex"", hex"");
    }

    /*//////////////////////////// T-40 / T-41 / T-44: refund by cancel proof ////////////////////////////*/

    function test_T41_refundByCancel_readsNoClock() public {
        _wireAnchor();
        bytes32 root = bytes32(uint256(0xc0ffee));
        _anchorRoot(root);

        // Long before the deadline.
        (IOrderPortal.OrderParams memory a, bytes32 ha) = _create(3);
        uint256 before = orderToken.balanceOf(bridger);
        vm.warp(a.deadline - 20 hours);
        vm.expectEmit(true, true, true, true);
        emit IEscrow.OrderCancelled(ha, true);
        vm.expectEmit(true, true, true, true);
        emit IOrderPortal.OrderRefunded(ha, a.bridger, a.amount);
        portal.refundByCancel(a, root, hex"");
        assertEq(uint256(statusOf(address(portal), ha)), uint256(IEscrow.Status.Cancelled));
        assertEq(orderToken.balanceOf(bridger), before + a.amount, "deposit back");
        assertEq(portal.inFlightOf(a.bridger), 0, "T-44");

        // Long after it: identical.
        (IOrderPortal.OrderParams memory b, bytes32 hb) = _create(4);
        vm.warp(b.deadline + 30 days);
        portal.refundByCancel(b, root, hex"");
        assertEq(uint256(statusOf(address(portal), hb)), uint256(IEscrow.Status.Cancelled));

        // Terminal.
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimable.selector, ha, IEscrow.Status.Cancelled));
        portal.refundByCancel(a, root, hex"");
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderNotOpen.selector, ha));
        portal.unlock(a, TestField.fe("X"), bytes32(0), hex"", hex"");
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimable.selector, ha, IEscrow.Status.Cancelled));
        portal.presentSettled(a, root, hex"");
        assertEq(portal.getMerkleLeafCount(), 2, "the follower appends no leaf of its own on cancel");
    }

    function test_refundByCancel_anchorGates() public {
        (IOrderPortal.OrderParams memory p,) = _create(6);
        bytes32 root = bytes32(uint256(7));
        vm.expectRevert(IEscrow.Escrow__NoRootAnchor.selector);
        portal.refundByCancel(p, root, hex"");

        _wireAnchor();
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__RootNotAnchored.selector, adChainId, root));
        portal.refundByCancel(p, root, hex"");

        vm.prank(admin);
        anchor.setAnchorDelay(adChainId, 3600);
        _anchorRoot(root);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__RootNotAnchored.selector, adChainId, root));
        portal.refundByCancel(p, root, hex"");

        vm.warp(block.timestamp + 3600);
        portal.refundByCancel(p, root, hex"");
    }

    /*//////////////////////////// the follower only follows ////////////////////////////*/

    /// No clock on this leg runs after the deadline: long past it nothing refunds, the backstop doors
    /// are gone from the ABI, and the leader's leaf still decides the leg whenever it arrives.
    function test_follower_hasNoClockOfItsOwn() public {
        _wireAnchor();
        (IOrderPortal.OrderParams memory p, bytes32 h) = _create(7);
        uint256 before = orderToken.balanceOf(bridger);
        vm.warp(p.deadline + 30 days);

        bytes memory args = abi.encode(p);
        (bool ok,) = address(portal)
            .call(
                abi.encodePacked(
                    bytes4(
                        keccak256(
                            "claimBackstop((bytes32,bytes32,uint256,bytes32,bytes32,uint256,bytes32,string,bytes32,bytes32,uint256,uint8,uint8,uint256,bytes32))"
                        )
                    ),
                    args
                )
            );
        assertFalse(ok, "no backstop claim");
        (ok,) = address(portal)
            .call(
                abi.encodePacked(
                    bytes4(
                        keccak256(
                            "finalizeBackstop((bytes32,bytes32,uint256,bytes32,bytes32,uint256,bytes32,string,bytes32,bytes32,uint256,uint8,uint8,uint256,bytes32))"
                        )
                    ),
                    args
                )
            );
        assertFalse(ok, "no backstop finalize");
        assertEq(uint256(statusOf(address(portal), h)), uint256(IEscrow.Status.Open), "silence refunds nothing");
        assertEq(orderToken.balanceOf(bridger), before);
        assertEq(portal.inFlightOf(p.bridger), 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderExpired.selector, p.deadline));
        portal.unlock(p, TestField.fe("B1"), bytes32(0), hex"", hex"");

        // A late SETTLED root still settles it to the maker.
        _anchorRoot(bytes32(uint256(8)));
        portal.presentSettled(p, bytes32(uint256(8)), hex"");
        assertEq(uint256(statusOf(address(portal), h)), uint256(IEscrow.Status.Filled));
        assertEq(orderToken.balanceOf(adRecipient), p.amount, "the maker's recipient is paid");
    }

    /// The bridger's refund on silence is the leader's CANCEL leaf, however late it is anchored.
    function test_follower_refundWaitsForTheCancelLeaf() public {
        _wireAnchor();
        (IOrderPortal.OrderParams memory p, bytes32 h) = _create(9);
        uint256 before = orderToken.balanceOf(bridger);
        vm.warp(p.deadline + 10 days);
        assertEq(uint256(statusOf(address(portal), h)), uint256(IEscrow.Status.Open));
        _anchorRoot(bytes32(uint256(9)));
        portal.refundByCancel(p, bytes32(uint256(9)), hex"");
        assertEq(uint256(statusOf(address(portal), h)), uint256(IEscrow.Status.Cancelled));
        assertEq(orderToken.balanceOf(bridger), before + p.amount);
        assertEq(portal.inFlightOf(p.bridger), 0, "T-44");
        assertEq(portal.getMerkleLeafCount(), 1, "no leaf on a follower cancel");
    }

    /// A retiming moves no created order: the maker's unlock keeps the order's own stagger.
    function test_retiming_movesNoCreatedOrder() public {
        _setTiming(RouteTiming.Timing(1 hours, 30 minutes, 0, 30 minutes));
        (IOrderPortal.OrderParams memory p, bytes32 h) = _create(10);
        (, uint32 v) = portal.orders(h);
        assertEq(v, portal.timingVersion(adChainId));
        _setTiming(RouteTiming.Timing(2 hours, 2 hours, 1 hours, 90 minutes));

        uint256 cutoff = p.deadline - 30 minutes;
        vm.warp(cutoff + 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderExpired.selector, cutoff));
        portal.unlock(p, TestField.fe("RT1"), bytes32(0), hex"", hex"");

        // An order created after the retiming reads the new stagger.
        (IOrderPortal.OrderParams memory q, bytes32 hq) = _create(15);
        (, uint32 vq) = portal.orders(hq);
        assertEq(vq, v + 1);
        uint256 cutoffQ = q.deadline - 90 minutes;
        vm.warp(cutoffQ + 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderExpired.selector, cutoffQ));
        portal.unlock(q, TestField.fe("RT2"), bytes32(0), hex"", hex"");
        vm.warp(cutoffQ);
        portal.unlock(q, TestField.fe("RT2"), bytes32(0), hex"", hex"");
    }

    /*//////////////////////////// T-59: the settled leaf on this leg ////////////////////////////*/

    function test_T59_cosignedUnlock_appendsSettled_thenNothingCancels() public {
        _wireAnchor();
        (IOrderPortal.OrderParams memory p, bytes32 h) = _create(11);
        assertEq(portal.getMerkleLeafCount(), 1, "the AD leaf");
        vm.expectEmit(true, true, true, true);
        emit IEscrow.OrderSettled(h, false);
        portal.unlock(p, TestField.fe("U1"), bytes32(0), hex"", hex"");
        assertEq(portal.getMerkleLeafCount(), 1, "the fill itself appends nothing");
        portal.recordSettled(p);
        assertEq(portal.getMerkleLeafCount(), 2, "AD + SETTLED");
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__SettledRecorded.selector, h));
        portal.recordSettled(p);

        _anchorRoot(bytes32(uint256(11)));
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimable.selector, h, IEscrow.Status.Filled));
        portal.refundByCancel(p, bytes32(uint256(11)), hex"");
    }

    function test_T59_noSettledProof_theUnwindStands() public {
        _wireAnchor();
        (IOrderPortal.OrderParams memory p, bytes32 h) = _create(12);
        _anchorRoot(bytes32(uint256(12)));
        verifier.setResult(false);
        vm.expectRevert(IEscrow.Escrow__InvalidProof.selector);
        portal.presentSettled(p, bytes32(uint256(12)), hex"");
        assertEq(uint256(statusOf(address(portal), h)), uint256(IEscrow.Status.Open));
    }

    /*//////////////////////////// pause: entries only ////////////////////////////*/

    /// The deposit refuses while paused; every exit on this leg works while paused.
    function test_pause_refusesTheEntry_leavesEveryExitOpen() public {
        _wireAnchor();
        (IOrderPortal.OrderParams memory a, bytes32 ha) = _create(13);
        (IOrderPortal.OrderParams memory b, bytes32 hb) = _create(16);
        (IOrderPortal.OrderParams memory c, bytes32 hc) = _create(17);
        (IOrderPortal.OrderParams memory d, bytes32 hd) = _create(21);
        bytes32 root = bytes32(uint256(0xbeef));
        _anchorRoot(root);
        vm.prank(admin);
        portal.pause();

        IOrderPortal.OrderParams memory e = _defaultParams();
        e.salt = 22;
        vm.startPrank(bridger);
        orderToken.approve(address(portal), e.amount);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        portal.createOrder(e);
        vm.stopPrank();

        portal.unlock(a, TestField.fe("PX"), bytes32(0), hex"", hex"");
        portal.recordSettled(a);
        portal.presentSettled(b, root, hex"");
        portal.refundByCancel(c, root, hex"");
        portal.payMakerByForfeit(d, root, hex"");
        assertEq(uint256(statusOf(address(portal), ha)), uint256(IEscrow.Status.Filled));
        assertEq(uint256(statusOf(address(portal), hb)), uint256(IEscrow.Status.Filled));
        assertEq(uint256(statusOf(address(portal), hc)), uint256(IEscrow.Status.Cancelled));
        assertEq(uint256(statusOf(address(portal), hd)), uint256(IEscrow.Status.Filled));
    }

    /*//////////////////////////// T-40 with the real verifier ////////////////////////////*/

    function test_T40_realProof_cancelLeaf_refunds() public {
        _wireAnchor();
        (IOrderPortal.OrderParams memory p, bytes32 h) = _create(14);
        _useRealVerifier();
        (bytes memory proof, bytes32 root) = _eventProof(LeafDomain.CANCEL, h);

        // Un-anchored, then inside the delay, then usable.
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__RootNotAnchored.selector, adChainId, root));
        portal.refundByCancel(p, root, proof);
        vm.prank(admin);
        anchor.setAnchorDelay(adChainId, 600);
        _anchorRoot(root);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__RootNotAnchored.selector, adChainId, root));
        portal.refundByCancel(p, root, proof);

        vm.warp(block.timestamp + 600);
        uint256 before = orderToken.balanceOf(bridger);
        portal.refundByCancel(p, root, proof);
        assertEq(uint256(statusOf(address(portal), h)), uint256(IEscrow.Status.Cancelled));
        assertEq(orderToken.balanceOf(bridger), before + p.amount);
    }

    /*//////////// 2.3g: the follower's whole part in a dispute ////////////*/

    /// A `BridgerForfeit` ruled on the ad chain arrives here as a proof of the primary's FORFEIT
    /// leaf, and pays the maker. This is the follower's entire dispute surface: proof-only, with no
    /// dispute, no arbiter and no clock of its own.
    function test_2_3g_forfeitLeafPaysTheMaker() public {
        _wireAnchor();
        (IOrderPortal.OrderParams memory p, bytes32 h) = _create(40);
        _useRealVerifier();
        (bytes memory proof, bytes32 root) = _eventProof(LeafDomain.FORFEIT, h);
        _anchorRoot(root);

        uint256 before = orderToken.balanceOf(adRecipient);
        // C-14: the forfeit is named, beside the evidence settle event.
        vm.expectEmit(true, false, false, true, address(portal));
        emit IEscrow.OrderSettled(h, true);
        vm.expectEmit(true, false, false, true, address(portal));
        emit IOrderPortal.OrderForfeited(h);
        portal.payMakerByForfeit(p, root, proof);

        assertEq(uint256(statusOf(address(portal), h)), uint256(IEscrow.Status.Filled), "the deposit was paid out");
        assertEq(orderToken.balanceOf(adRecipient), before + p.amount, "and it went to the maker");
    }

    /// The domains must not be interchangeable: a CANCEL leaf means "refund the bridger" and can
    /// never be replayed to pay the maker instead. This is the separation the whole revision rests
    /// on — one domain per follower action.
    function test_2_3g_cancelLeafCannotPayTheMaker() public {
        _wireAnchor();
        (IOrderPortal.OrderParams memory p, bytes32 h) = _create(41);
        _useRealVerifier();
        (bytes memory proof, bytes32 root) = _eventProof(LeafDomain.CANCEL, h);
        _anchorRoot(root);

        vm.expectRevert();
        portal.payMakerByForfeit(p, root, proof);
    }

    /// ...and the converse: a FORFEIT leaf cannot be replayed to refund the bridger.
    function test_2_3g_forfeitLeafCannotRefundTheBridger() public {
        _wireAnchor();
        (IOrderPortal.OrderParams memory p, bytes32 h) = _create(42);
        _useRealVerifier();
        (bytes memory proof, bytes32 root) = _eventProof(LeafDomain.FORFEIT, h);
        _anchorRoot(root);

        vm.expectRevert();
        portal.refundByCancel(p, root, proof);
    }

    /// The follower originates nothing. It held `dispute`, `respondToDispute` and `finalizeDispute`
    /// in the first build — with no test on any of them, which is why it shipped — and every one of
    /// them moved funds reading only a local module, with no proof from the ad chain at all.
    function test_2_3g_followerExposesNoDisputeEntryPoint() public {
        string[4] memory gone = [
            "dispute((bytes32,bytes32,uint256,bytes32,bytes32,uint256,bytes32,string,bytes32,bytes32,uint256,uint8,uint8,uint256,bytes32),bytes32)",
            "finalizeDispute((bytes32,bytes32,uint256,bytes32,bytes32,uint256,bytes32,string,bytes32,bytes32,uint256,uint8,uint8,uint256,bytes32))",
            "respondToDispute((bytes32,bytes32,uint256,bytes32,bytes32,uint256,bytes32,string,bytes32,bytes32,uint256,uint8,uint8,uint256,bytes32),bytes32)",
            "setDisputeManager(address)"
        ];
        for (uint256 i = 0; i < gone.length; i++) {
            (bool ok,) = address(portal).call(abi.encodeWithSelector(bytes4(keccak256(bytes(gone[i])))));
            assertFalse(ok, "the follower must expose no dispute entry point");
        }
    }

    function test_T40_realProof_settledLeafCannotRefund() public {
        _wireAnchor();
        (IOrderPortal.OrderParams memory p, bytes32 h) = _create(15);
        _useRealVerifier();
        (bytes memory proof, bytes32 root) = _eventProof(LeafDomain.SETTLED, h);
        _anchorRoot(root);
        vm.expectRevert();
        portal.refundByCancel(p, root, proof);
        assertEq(uint256(statusOf(address(portal), h)), uint256(IEscrow.Status.Open));
        // ...but it does settle this leg (T-59): the maker is paid.
        portal.presentSettled(p, root, proof);
        assertEq(uint256(statusOf(address(portal), h)), uint256(IEscrow.Status.Filled));
        assertEq(orderToken.balanceOf(adRecipient), p.amount);
    }

    function test_T40_realProof_anotherOrdersLeafCannotRefund() public {
        _wireAnchor();
        (IOrderPortal.OrderParams memory a, bytes32 ha) = _create(16);
        (IOrderPortal.OrderParams memory b,) = _create(17);
        _useRealVerifier();
        (bytes memory proof, bytes32 root) = _eventProof(LeafDomain.CANCEL, ha);
        _anchorRoot(root);
        vm.expectRevert();
        portal.refundByCancel(b, root, proof);
        portal.refundByCancel(a, root, proof);
    }
}
