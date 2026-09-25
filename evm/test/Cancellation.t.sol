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
import {Termination} from "src/libraries/Termination.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {AdManagerTest, MockAdManager} from "./Admanager.t.sol";
import {OrderPortalTest} from "./OrderPortal.t.sol";

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
    RouteTiming.Timing internal baseTiming = RouteTiming.Timing(0, 30 minutes, 0, 1 days, 0);

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
        vm.expectRevert(abi.encodeWithSelector(RouteTiming.RouteTiming__Invalid.selector, uint8(1)));
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(0, 29 minutes, 0, 1 days, 0));
        vm.expectRevert(abi.encodeWithSelector(RouteTiming.RouteTiming__Invalid.selector, uint8(2)));
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(1 hours, 1 hours, 1 hours, 1 days, 0));
        vm.expectRevert(abi.encodeWithSelector(RouteTiming.RouteTiming__Invalid.selector, uint8(3)));
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(0, 2 hours, 0, 1 hours, 0));
        vm.expectRevert(abi.encodeWithSelector(RouteTiming.RouteTiming__Invalid.selector, uint8(4)));
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(30 minutes, 1 hours, 0, 1 days, 30 minutes));
        vm.expectRevert(abi.encodeWithSelector(RouteTiming.RouteTiming__Invalid.selector, uint8(5)));
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(1 minutes, 1 hours, 2 minutes, 1 days, 0));

        // The D6 defaults, and the stagger switched off with a zero window.
        RouteTiming.Timing memory live = RouteTiming.Timing(1 hours, 2 hours, 120, 3 days, 30 minutes);
        vm.expectEmit(true, true, true, true);
        emit IEscrow.RouteTimingSet(orderChainId, live);
        adManager.setRouteTiming(orderChainId, live);
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(0, 30 minutes, 0, 30 minutes, 0));
        vm.stopPrank();

        (uint64 minWindow, uint64 buffer, uint64 margin, uint64 longBackstop, uint64 stagger) =
            adManager.routeTiming(orderChainId);
        assertEq(minWindow, 0);
        assertEq(buffer, 30 minutes);
        assertEq(margin, 0);
        assertEq(longBackstop, 30 minutes);
        assertEq(stagger, 0);

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
        merkleManager.grantRole(merkleManager.MANAGER_ROLE(), address(bare));
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
        _setTiming(RouteTiming.Timing(1 hours, 30 minutes, 0, 1 days, 0));
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
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(0, maxBuffer + 1, 0, maxBuffer + 1, 0));
        vm.expectRevert(abi.encodeWithSelector(RouteTiming.RouteTiming__Invalid.selector, uint8(5)));
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(maxWindow + 1, 1 hours, 0, 1 days, 0));
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(0, maxBuffer, 0, maxBuffer, 0));
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(maxWindow, 1 hours, 0, 1 days, 0));
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
        assertEq(uint256(adManager.orders(h)), uint256(IEscrow.Status.Cancelled));
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
        emit IEscrow.ClaimOpened(h, Termination.ClaimEntry.Deadline, uint64(p.deadline + 30 minutes));
        adManager.claimCancel(p);

        (uint64 openedAt, uint64 finalizeAt,, Termination.ClaimEntry entry) = adManager.claims(h);
        assertEq(openedAt, p.deadline);
        assertEq(finalizeAt, p.deadline + 30 minutes, "deadline-anchored");
        assertEq(uint256(entry), uint256(Termination.ClaimEntry.Deadline));
        assertEq(uint256(adManager.orders(h)), uint256(IEscrow.Status.Claimed));
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
        (, uint64 finalizeAt,,) = adManager.claims(h);
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

        assertEq(uint256(adManager.orders(h)), uint256(IEscrow.Status.Cancelled));
        assertEq(_locked(), 0, "lock released");
        assertEq(_balance(), balanceBefore, "the ad keeps its funds");
        assertEq(adManager.getMerkleLeafCount(), leaves + 1, "the CANCEL leaf");
        assertEq(adManager.inFlightOf(p.adSettlementSigner), 0, "T-44");
        (, uint64 finalizeAt,,) = adManager.claims(h);
        assertEq(finalizeAt, 0, "claim record cleared");

        // Terminal: nothing else appends or moves.
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimed.selector, h));
        adManager.finalizeCancel(p);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimable.selector, h, IEscrow.Status.Cancelled));
        adManager.claimCancel(p);
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

        assertEq(uint256(adManager.orders(h)), uint256(IEscrow.Status.Filled));
        assertEq(adManager.getMerkleLeafCount(), leaves, "the fill itself appends nothing");
        adManager.recordSettled(p);
        assertEq(adManager.getMerkleLeafCount(), leaves + 1, "T-59: the SETTLED leaf, no cancel leaf");
        (, uint64 finalizeAt,,) = adManager.claims(h);
        assertEq(finalizeAt, 0, "window closed");
        assertEq(adManager.inFlightOf(p.adSettlementSigner), 0);

        vm.warp(p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimed.selector, h));
        adManager.finalizeCancel(p);
    }

    function test_T45b_primaryUnlock_validToBufferMinusMargin() public {
        _setTiming(RouteTiming.Timing(120, 30 minutes, 120, 1 days, 0));
        (IAdManager.OrderParams memory p,) = _lock(8);
        uint256 cutoff = p.deadline + 30 minutes - 120;

        vm.warp(cutoff + 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderExpired.selector, cutoff));
        adManager.unlock(p, TestField.fe("M1"), bytes32(0), hex"", hex"");

        vm.warp(cutoff);
        adManager.unlock(p, TestField.fe("M1"), bytes32(0), hex"", hex"");
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

        assertEq(uint256(adManager.orders(h)), uint256(IEscrow.Status.Filled));
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
        assertEq(uint256(adManager.orders(h)), uint256(IEscrow.Status.Filled));
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

    /*//////////////////////////// D10: pause ////////////////////////////*/

    function test_pause_gatesEveryTerminationPath() public {
        _wireAnchor();
        (IAdManager.OrderParams memory p,) = _lock(14);
        vm.warp(p.deadline);
        vm.prank(admin);
        adManager.pause();

        vm.expectRevert(Pausable.EnforcedPause.selector);
        adManager.claimCancel(p);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        adManager.finalizeCancel(p);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        adManager.cancelNeverLocked(p);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        adManager.presentSettled(p, bytes32(0), hex"");
        vm.expectRevert(Pausable.EnforcedPause.selector);
        adManager.recordSettled(p);
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

    /// G2: a pause freezes evidence, so it stops the clocks. A window open when the pause began ends
    /// later by exactly the pause; the unlock is valid again for what was left of it.
    function test_pause_acrossTheWindow_evidenceGetsTheRestOfItsWindowAfterUnpause() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lock(19);
        _claim(p);
        vm.warp(p.deadline + 10 minutes);
        vm.prank(admin);
        adManager.pause();
        vm.warp(p.deadline + 30 minutes + 1 hours);
        vm.prank(admin);
        adManager.unpause();
        // 20 minutes were left when the pause began; 20 minutes remain after it.
        uint256 reopened = block.timestamp + 20 minutes;
        assertEq(adManager.pausedSeconds(), 1 hours + 20 minutes);

        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, reopened));
        adManager.finalizeCancel(p);
        vm.warp(reopened - 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, reopened));
        adManager.finalizeCancel(p);
        // The bridger's co-signed unlock is valid through the reopened window.
        adManager.unlock(p, TestField.fe("P1"), bytes32(0), hex"", hex"");
        assertEq(uint256(adManager.orders(h)), uint256(IEscrow.Status.Filled));
    }

    function test_pause_acrossTheWindow_thenSilence_finalizesAtTheReopenedEnd() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lock(20);
        // Paused while still Open, from 5 minutes before the deadline across the whole buffer:
        // the clock is measured from the lock, so all 1h35 count.
        vm.warp(p.deadline - 5 minutes);
        vm.prank(admin);
        adManager.pause();
        vm.warp(p.deadline + 30 minutes + 1 hours);
        vm.prank(admin);
        adManager.unpause();
        uint256 reopened = block.timestamp + 35 minutes;

        adManager.claimCancel(p);
        (, uint64 finalizeAt,,) = adManager.claims(h);
        assertEq(finalizeAt, reopened, "the record carries the pause that fell inside the window");
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, reopened));
        adManager.finalizeCancel(p);
        vm.warp(reopened + 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderExpired.selector, reopened));
        adManager.unlock(p, TestField.fe("P2"), bytes32(0), hex"", hex"");
        adManager.finalizeCancel(p);
        assertEq(uint256(adManager.orders(h)), uint256(IEscrow.Status.Cancelled));
    }

    /// P1: a pause never reopens a window that had already closed — claimed or not — and a pause
    /// that ended before the deadline touches nothing.
    function test_pause_afterTheWindowClosed_doesNotReopenIt() public {
        // Claimed, closed ten days ago, never finalized.
        (IAdManager.OrderParams memory p,) = _lock(23);
        _claim(p);
        vm.warp(p.deadline + 30 minutes + 10 days);
        vm.prank(admin);
        adManager.pause();
        vm.warp(block.timestamp + 1 hours);
        vm.prank(admin);
        adManager.unpause();
        vm.expectRevert(
            abi.encodeWithSelector(IEscrow.Escrow__OrderExpired.selector, p.deadline + 30 minutes + 1 hours)
        );
        adManager.unlock(p, TestField.fe("P3"), bytes32(0), hex"", hex"");
        adManager.finalizeCancel(p);

        // Never claimed, closed ten days ago: the claim lands and finalizes at once.
        (IAdManager.OrderParams memory q, bytes32 hq) =
            _openOrder(lastAdId, address(adToken), 60 ether, 24, bridger, recipient);
        vm.warp(q.deadline + 30 minutes + 10 days);
        vm.prank(admin);
        adManager.pause();
        vm.warp(block.timestamp + 1 hours);
        vm.prank(admin);
        adManager.unpause();
        vm.expectRevert(
            abi.encodeWithSelector(IEscrow.Escrow__OrderExpired.selector, q.deadline + 30 minutes + 1 hours)
        );
        adManager.unlock(q, TestField.fe("P4"), bytes32(0), hex"", hex"");
        adManager.claimCancel(q);
        (, uint64 finalizeAt,,) = adManager.claims(hq);
        assertEq(finalizeAt, q.deadline + 30 minutes + 1 hours);
        adManager.finalizeCancel(q);

        // A pause between the lock and the deadline extends the window too (the chosen behaviour:
        // the clock runs from the lock, and that pause froze both unlocks).
        (IAdManager.OrderParams memory r,) = _openOrder(lastAdId, address(adToken), 60 ether, 25, bridger, recipient);
        vm.prank(admin);
        adManager.pause();
        vm.warp(block.timestamp + 1 hours);
        vm.prank(admin);
        adManager.unpause();
        vm.warp(r.deadline + 30 minutes + 1 hours + 1);
        vm.expectRevert(
            abi.encodeWithSelector(IEscrow.Escrow__OrderExpired.selector, r.deadline + 30 minutes + 1 hours)
        );
        adManager.unlock(r, TestField.fe("P5"), bytes32(0), hex"", hex"");
        vm.warp(r.deadline + 30 minutes + 1 hours);
        adManager.unlock(r, TestField.fe("P5"), bytes32(0), hex"", hex"");
    }

    /// Two pauses on one still-unclaimed lock, a long one then a short one, both count: the window
    /// is measured from the lock's pause-counter snapshot, exact over any number of pauses. A lock
    /// taken after a pause does not inherit it.
    function test_pause_everyPauseSinceTheLockCounts() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lock(26);
        vm.warp(p.deadline + 1 minutes);
        vm.prank(admin);
        adManager.pause();
        vm.warp(p.deadline + 11 minutes);
        vm.prank(admin);
        adManager.unpause();
        vm.warp(p.deadline + 15 minutes);
        vm.prank(admin);
        adManager.pause();
        vm.warp(p.deadline + 20 minutes);
        vm.prank(admin);
        adManager.unpause();
        uint256 end = p.deadline + 30 minutes + 15 minutes;

        vm.warp(end + 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderExpired.selector, end));
        adManager.unlock(p, TestField.fe("H1"), bytes32(0), hex"", hex"");
        adManager.claimCancel(p);
        (, uint64 finalizeAt,,) = adManager.claims(h);
        assertEq(finalizeAt, end, "the claim materializes every pause");
        adManager.finalizeCancel(p);

        assertEq(adManager.pausedSeconds(), 15 minutes);
        assertEq(adManager.orderPausedAtOpen(h), 0);

        // A lock taken now starts its clock at the current counter: those pauses are not its own.
        (IAdManager.OrderParams memory q, bytes32 hq) =
            _openOrder(lastAdId, address(adToken), 60 ether, 27, bridger, recipient);
        assertEq(adManager.orderPausedAtOpen(hq), 15 minutes);
        vm.warp(q.deadline + 30 minutes + 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderExpired.selector, q.deadline + 30 minutes));
        adManager.unlock(q, TestField.fe("H2"), bytes32(0), hex"", hex"");
    }

    /// G3: once claimed, the cutoff is the claim's frozen end; an admin retiming cannot move it.
    function test_G3_retimingDuringAClaimDoesNotMoveTheCutoff() public {
        (IAdManager.OrderParams memory p,) = _lock(21);
        _claim(p);
        _setTiming(RouteTiming.Timing(0, 2 hours, 0, 1 days, 0));
        vm.warp(p.deadline + 30 minutes + 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderExpired.selector, p.deadline + 30 minutes));
        adManager.unlock(p, TestField.fe("G3"), bytes32(0), hex"", hex"");
        adManager.finalizeCancel(p);

        // And lowered: the window stays open as long as the claim said.
        _setTiming(RouteTiming.Timing(0, 2 hours, 0, 1 days, 0));
        (IAdManager.OrderParams memory q,) = _openOrder(lastAdId, address(adToken), 60 ether, 22, bridger, recipient);
        _claim(q);
        _setTiming(RouteTiming.Timing(0, 30 minutes, 0, 1 days, 0));
        vm.warp(q.deadline + 1 hours);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, q.deadline + 2 hours));
        adManager.finalizeCancel(q);
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
        assertEq(uint256(adManager.orders(h)), uint256(IEscrow.Status.Filled));
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
        assertEq(uint256(adManager.orders(h)), uint256(IEscrow.Status.Open), "the unwind stands");
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
        _setTiming(RouteTiming.Timing(1 hours, 30 minutes, 0, 1 days, 0));
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
        _setTiming(RouteTiming.Timing(1 hours, 30 minutes, 0, 1 days, 30 minutes));
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
        assertEq(uint256(portal.orders(ha)), uint256(IEscrow.Status.Cancelled));
        assertEq(orderToken.balanceOf(bridger), before + a.amount, "deposit back");
        assertEq(portal.inFlightOf(a.bridger), 0, "T-44");

        // Long after it: identical.
        (IOrderPortal.OrderParams memory b, bytes32 hb) = _create(4);
        vm.warp(b.deadline + 30 days);
        portal.refundByCancel(b, root, hex"");
        assertEq(uint256(portal.orders(hb)), uint256(IEscrow.Status.Cancelled));

        // Terminal.
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimable.selector, ha, IEscrow.Status.Cancelled));
        portal.refundByCancel(a, root, hex"");
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderNotOpen.selector, ha));
        portal.unlock(a, TestField.fe("X"), bytes32(0), hex"", hex"");
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimable.selector, ha, IEscrow.Status.Cancelled));
        portal.presentSettled(a, root, hex"");
        assertEq(portal.getMerkleLeafCount(), 2, "the follower appends no leaf of its own on cancel");
    }

    /// A cancel proof beats an open backstop window (recorded decision: both Open and Claimed accepted).
    function test_refundByCancel_fromABackstopWindow() public {
        _wireAnchor();
        (IOrderPortal.OrderParams memory p, bytes32 h) = _create(5);
        vm.warp(p.deadline + 1 days);
        portal.claimBackstop(p);
        _anchorRoot(bytes32(uint256(6)));
        portal.refundByCancel(p, bytes32(uint256(6)), hex"");
        assertEq(uint256(portal.orders(h)), uint256(IEscrow.Status.Cancelled));
        (, uint64 finalizeAt,,) = portal.claims(h);
        assertEq(finalizeAt, 0);
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

    /*//////////////////////////// T-43: the backstop ////////////////////////////*/

    function test_T43_claimBackstop_onlyAfterLongBackstop_opensClaimAnchoredWindow() public {
        (IOrderPortal.OrderParams memory p, bytes32 h) = _create(7);
        uint256 before = orderToken.balanceOf(bridger);

        vm.warp(p.deadline + 1 days - 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 1 days));
        portal.claimBackstop(p);

        vm.warp(p.deadline + 1 days + 5 hours);
        uint64 finalizeAt = uint64(block.timestamp + 30 minutes);
        vm.expectEmit(true, true, true, true);
        emit IEscrow.ClaimOpened(h, Termination.ClaimEntry.Backstop, finalizeAt);
        portal.claimBackstop(p);

        (uint64 openedAt, uint64 fAt,, Termination.ClaimEntry entry) = portal.claims(h);
        assertEq(openedAt, block.timestamp);
        assertEq(fAt, finalizeAt, "claim-anchored");
        assertEq(uint256(entry), uint256(Termination.ClaimEntry.Backstop));
        assertEq(orderToken.balanceOf(bridger), before, "no funds move on a claim");
        assertEq(portal.inFlightOf(p.bridger), 1);

        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimable.selector, h, IEscrow.Status.Claimed));
        portal.claimBackstop(p);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, finalizeAt));
        portal.finalizeBackstop(p);
    }

    function test_T43_presentSettled_insideTheBackstopWindow_paysTheMaker() public {
        _wireAnchor();
        (IOrderPortal.OrderParams memory p, bytes32 h) = _create(8);
        vm.warp(p.deadline + 1 days);
        portal.claimBackstop(p);
        uint256 leaves = portal.getMerkleLeafCount();
        _anchorRoot(bytes32(uint256(8)));

        vm.warp(block.timestamp + 29 minutes);
        vm.expectEmit(true, true, true, true);
        emit IEscrow.OrderSettled(h, true);
        portal.presentSettled(p, bytes32(uint256(8)), hex"");

        assertEq(uint256(portal.orders(h)), uint256(IEscrow.Status.Filled));
        assertEq(orderToken.balanceOf(adRecipient), p.amount, "the maker's recipient is paid");
        portal.recordSettled(p);
        assertEq(portal.getMerkleLeafCount(), leaves + 1, "T-59: SETTLED appended");
        assertEq(portal.inFlightOf(p.bridger), 0, "T-44");

        vm.warp(block.timestamp + 1 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimed.selector, h));
        portal.finalizeBackstop(p);
    }

    /// The documented residual: only silence through claim + window reaches the refund.
    function test_T43_unchallengedBackstop_refundsAfterTheWindow() public {
        (IOrderPortal.OrderParams memory p, bytes32 h) = _create(9);
        uint256 before = orderToken.balanceOf(bridger);
        vm.warp(p.deadline + 1 days);
        portal.claimBackstop(p);

        vm.warp(block.timestamp + 30 minutes - 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, block.timestamp + 1));
        portal.finalizeBackstop(p);

        vm.warp(block.timestamp + 1);
        vm.expectEmit(true, true, true, true);
        emit IEscrow.OrderCancelled(h, false);
        portal.finalizeBackstop(p);
        assertEq(uint256(portal.orders(h)), uint256(IEscrow.Status.Cancelled));
        assertEq(orderToken.balanceOf(bridger), before + p.amount);
        assertEq(portal.inFlightOf(p.bridger), 0, "T-44");
        assertEq(portal.getMerkleLeafCount(), 1, "no leaf on a follower cancel");

        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimed.selector, h));
        portal.finalizeBackstop(p);
    }

    /// The co-signed unlock is refused inside a backstop window: the package proves the lock, not
    /// the ad leg's outcome. Only outcome evidence settles or refunds there.
    function test_unlock_refusedInsideBackstopWindow() public {
        _wireAnchor();
        (IOrderPortal.OrderParams memory p, bytes32 h) = _create(10);
        vm.warp(p.deadline + 1 days);
        portal.claimBackstop(p);

        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderNotOpen.selector, h));
        portal.unlock(p, TestField.fe("B1"), bytes32(0), hex"", hex"");
        assertEq(uint256(portal.orders(h)), uint256(IEscrow.Status.Claimed));
        // A settled-leaf proof does settle it.
        _anchorRoot(bytes32(uint256(10)));
        portal.presentSettled(p, bytes32(uint256(10)), hex"");
        assertEq(uint256(portal.orders(h)), uint256(IEscrow.Status.Filled));
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
        vm.warp(p.deadline + 2 days);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimable.selector, h, IEscrow.Status.Filled));
        portal.claimBackstop(p);
    }

    function test_T59_noSettledProof_theUnwindStands() public {
        _wireAnchor();
        (IOrderPortal.OrderParams memory p, bytes32 h) = _create(12);
        _anchorRoot(bytes32(uint256(12)));
        verifier.setResult(false);
        vm.expectRevert(IEscrow.Escrow__InvalidProof.selector);
        portal.presentSettled(p, bytes32(uint256(12)), hex"");
        assertEq(uint256(portal.orders(h)), uint256(IEscrow.Status.Open));
    }

    /*//////////////////////////// D10: pause ////////////////////////////*/

    function test_pause_gatesEveryTerminationPath() public {
        _wireAnchor();
        (IOrderPortal.OrderParams memory p,) = _create(13);
        vm.prank(admin);
        portal.pause();
        vm.expectRevert(Pausable.EnforcedPause.selector);
        portal.refundByCancel(p, bytes32(0), hex"");
        vm.expectRevert(Pausable.EnforcedPause.selector);
        portal.presentSettled(p, bytes32(0), hex"");
        vm.expectRevert(Pausable.EnforcedPause.selector);
        portal.claimBackstop(p);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        portal.finalizeBackstop(p);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        portal.recordSettled(p);
    }

    /// G2 on the follower: a pause inside a backstop window moves its end by the pause; a pause
    /// after it closed does not reopen it.
    function test_pause_acrossBackstopWindow_evidenceGetsTheRestOfItsWindowAfterUnpause() public {
        _wireAnchor();
        (IOrderPortal.OrderParams memory p, bytes32 h) = _create(18);
        vm.warp(p.deadline + 1 days);
        portal.claimBackstop(p);
        vm.prank(admin);
        portal.pause();
        vm.warp(block.timestamp + 30 minutes + 1 hours);
        vm.prank(admin);
        portal.unpause();
        uint256 reopened = block.timestamp + 30 minutes;

        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, reopened));
        portal.finalizeBackstop(p);
        _anchorRoot(bytes32(uint256(18)));
        portal.presentSettled(p, bytes32(uint256(18)), hex"");
        assertEq(uint256(portal.orders(h)), uint256(IEscrow.Status.Filled));

        (IOrderPortal.OrderParams memory q, bytes32 hq) = _create(19);
        vm.warp(q.deadline + 1 days);
        portal.claimBackstop(q);
        vm.prank(admin);
        portal.pause();
        vm.warp(block.timestamp + 2 hours);
        vm.prank(admin);
        portal.unpause();
        uint256 reopened2 = block.timestamp + 30 minutes;
        vm.warp(reopened2 - 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, reopened2));
        portal.finalizeBackstop(q);
        _anchorRoot(bytes32(uint256(19)));
        portal.presentSettled(q, bytes32(uint256(19)), hex"");
        assertEq(uint256(portal.orders(hq)), uint256(IEscrow.Status.Filled));

        // Closed ten days ago: a later pause reopens nothing (P1).
        (IOrderPortal.OrderParams memory r, bytes32 hr) = _create(20);
        vm.warp(r.deadline + 1 days);
        portal.claimBackstop(r);
        vm.warp(block.timestamp + 30 minutes + 10 days);
        vm.prank(admin);
        portal.pause();
        vm.warp(block.timestamp + 1 hours);
        vm.prank(admin);
        portal.unpause();
        _anchorRoot(bytes32(uint256(20)));
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderNotOpen.selector, hr));
        portal.unlock(r, TestField.fe("PC"), bytes32(0), hex"", hex"");
        portal.finalizeBackstop(r);
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
        assertEq(uint256(portal.orders(h)), uint256(IEscrow.Status.Cancelled));
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
        portal.payMakerByForfeit(p, root, proof);

        assertEq(uint256(portal.orders(h)), uint256(IEscrow.Status.Filled), "the deposit was paid out");
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
        assertEq(uint256(portal.orders(h)), uint256(IEscrow.Status.Open));
        // ...but it does settle this leg (T-59): the maker is paid.
        portal.presentSettled(p, root, proof);
        assertEq(uint256(portal.orders(h)), uint256(IEscrow.Status.Filled));
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
