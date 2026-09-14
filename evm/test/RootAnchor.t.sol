// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {RootAnchor} from "src/RootAnchor.sol";
import {IRootAnchor} from "src/interfaces/IRootAnchor.sol";
import {TwoStepAdmin} from "src/libraries/TwoStepAdmin.sol";
import {MockAnchorConsumer} from "./mocks/MockAnchorConsumer.sol";

/// 2.3f (#343): the RootAnchor module. T-42 (forged extension / rollback never anchors), T-63 (the
/// delay, and the writer swap as a config change), the pending-state rules that make the quorum rung
/// safe (A1, A2, A6), the incident levers (A3), and the consumer seam 2.3e will call through.
contract RootAnchorTest is Test {
    RootAnchor internal ra;
    MockAnchorConsumer internal consumer;

    address internal admin = makeAddr("admin");
    address internal s1 = makeAddr("signer1");
    address internal s2 = makeAddr("signer2");
    address internal s3 = makeAddr("signer3");
    address internal stranger = makeAddr("stranger");

    uint256 internal constant CHAIN = 1_000_001;
    uint256 internal constant OTHER_CHAIN = 1_000_002;
    bytes32 internal constant ROOT_A = bytes32(uint256(0xA1));
    bytes32 internal constant ROOT_B = bytes32(uint256(0xB2));

    function setUp() public {
        vm.warp(1_700_000_000);
        address[] memory one = new address[](1);
        one[0] = s1;
        ra = new RootAnchor(admin, one, 1);
        consumer = new MockAnchorConsumer(IRootAnchor(address(ra)));
    }

    function _set(address[] memory set, uint32 threshold) internal {
        vm.prank(admin);
        ra.setSigners(set, threshold);
    }

    function _three(uint32 threshold) internal {
        address[] memory three = new address[](3);
        three[0] = s1;
        three[1] = s2;
        three[2] = s3;
        _set(three, threshold);
    }

    function _one(address who) internal pure returns (address[] memory set) {
        set = new address[](1);
        set[0] = who;
    }

    function _unauthorized(address who) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, who, bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                    T-42 — only what was notarized is anchored
    //////////////////////////////////////////////////////////////*/

    function test_unanchoredRoot_isFalse() public view {
        assertFalse(ra.isAnchored(CHAIN, ROOT_A));
        assertEq(ra.anchoredAt(CHAIN, ROOT_A), 0);
    }

    function test_anchor_isTrueWithZeroDelay() public {
        vm.prank(s1);
        vm.expectEmit(true, true, false, true);
        emit IRootAnchor.Anchored(CHAIN, ROOT_A, 10, uint64(block.timestamp));
        ra.anchor(CHAIN, ROOT_A, 10);
        assertTrue(ra.isAnchored(CHAIN, ROOT_A));
        assertEq(ra.anchoredAt(CHAIN, ROOT_A), uint64(block.timestamp));
    }

    function test_onlyTheExactRootIsAnchored() public {
        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, 10);
        // A forged extension is a different root; the same root on another chain is a different key.
        assertFalse(ra.isAnchored(CHAIN, ROOT_B));
        assertFalse(ra.isAnchored(OTHER_CHAIN, ROOT_A));
    }

    function test_lowerSeq_reverts_whenMonotonic() public {
        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, 10);
        vm.prank(s1);
        vm.expectRevert(abi.encodeWithSelector(IRootAnchor.RootAnchor__SeqNotMonotonic.selector, 10, 9));
        ra.anchor(CHAIN, ROOT_B, 9);
    }

    function test_equalSeq_reverts_whenMonotonic() public {
        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, 10);
        vm.prank(s1);
        vm.expectRevert(abi.encodeWithSelector(IRootAnchor.RootAnchor__SeqNotMonotonic.selector, 10, 10));
        ra.anchor(CHAIN, ROOT_B, 10);
    }

    function test_monotonicityIsPerChain() public {
        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, 10);
        vm.prank(s1);
        ra.anchor(OTHER_CHAIN, ROOT_B, 3);
        assertTrue(ra.isAnchored(OTHER_CHAIN, ROOT_B));
    }

    function test_lowerSeq_allowed_whenMonotonicOff() public {
        vm.prank(admin);
        ra.setMonotonic(false);
        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, 10);
        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_B, 9);
        assertTrue(ra.isAnchored(CHAIN, ROOT_B));
        assertEq(ra.latestSeq(CHAIN), 10, "latestSeq never decreases on its own");
    }

    function test_nonSigner_reverts() public {
        vm.prank(stranger);
        vm.expectRevert(IRootAnchor.RootAnchor__NotSigner.selector);
        ra.anchor(CHAIN, ROOT_A, 10);
    }

    function test_reanchor_isNoop() public {
        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, 10);
        IRootAnchor.Anchor memory before = ra.anchorOf(CHAIN, ROOT_A);

        vm.warp(block.timestamp + 100);
        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, 10);
        IRootAnchor.Anchor memory after_ = ra.anchorOf(CHAIN, ROOT_A);

        assertEq(after_.anchoredAt, before.anchoredAt);
        assertEq(after_.approvals, before.approvals);
    }

    /*//////////////////////////////////////////////////////////////
                  T-63 — the delay, and the writer as config
    //////////////////////////////////////////////////////////////*/

    function test_insideDelay_false_afterDelay_true() public {
        vm.prank(admin);
        ra.setAnchorDelay(CHAIN, 600);

        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, 10);
        assertFalse(ra.isAnchored(CHAIN, ROOT_A), "usable only after the delay");

        vm.warp(block.timestamp + 599);
        assertFalse(ra.isAnchored(CHAIN, ROOT_A));
        vm.warp(block.timestamp + 1);
        assertTrue(ra.isAnchored(CHAIN, ROOT_A));
    }

    function test_delayIsPerChain() public {
        vm.prank(admin);
        ra.setAnchorDelay(CHAIN, 600);
        vm.startPrank(s1);
        ra.anchor(CHAIN, ROOT_A, 10);
        ra.anchor(OTHER_CHAIN, ROOT_B, 10);
        vm.stopPrank();
        assertFalse(ra.isAnchored(CHAIN, ROOT_A));
        assertTrue(ra.isAnchored(OTHER_CHAIN, ROOT_B));
    }

    function test_delayIsBounded_andIsAnchoredNeverReverts() public {
        // Resolve the constant first: a call inside the argument list would be expectRevert's target.
        uint64 max = ra.MAX_ANCHOR_DELAY();
        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSelector(IRootAnchor.RootAnchor__DelayTooLong.selector, max, max + 1));
        ra.setAnchorDelay(CHAIN, max + 1);
        ra.setAnchorDelay(CHAIN, max);
        vm.stopPrank();

        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, 10);
        assertFalse(ra.isAnchored(CHAIN, ROOT_A), "max delay: not yet, and no revert");
        vm.warp(block.timestamp + max);
        assertTrue(ra.isAnchored(CHAIN, ROOT_A));
    }

    function test_setSigners_rotatesTheWriter_withoutRedeploy() public {
        _set(_one(s2), 1);

        vm.prank(s1);
        vm.expectRevert(IRootAnchor.RootAnchor__NotSigner.selector);
        ra.anchor(CHAIN, ROOT_A, 10);

        vm.prank(s2);
        ra.anchor(CHAIN, ROOT_A, 10);
        assertTrue(ra.isAnchored(CHAIN, ROOT_A));
        assertEq(ra.signers().length, 1);
        assertEq(ra.signers()[0], s2);
    }

    function test_threshold2of3_needsTwoDistinctSigners() public {
        _three(2);

        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, 10);
        assertFalse(ra.isAnchored(CHAIN, ROOT_A));
        assertEq(ra.anchorOf(CHAIN, ROOT_A).approvals, 1);

        // The same signer again counts once.
        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, 10);
        assertEq(ra.anchorOf(CHAIN, ROOT_A).approvals, 1);
        assertFalse(ra.isAnchored(CHAIN, ROOT_A));

        vm.prank(s2);
        ra.anchor(CHAIN, ROOT_A, 10);
        assertTrue(ra.isAnchored(CHAIN, ROOT_A));
        assertEq(ra.anchorOf(CHAIN, ROOT_A).approvals, 2);
    }

    /*//////////////////////////////////////////////////////////////
              the pending state under a quorum (A1, A2, A6)
    //////////////////////////////////////////////////////////////*/

    /// A6: two honest publishers read the same root of a quiet chain at different ledgers.
    function test_pendingRoot_acceptsAnySeq_recordsTheMax() public {
        _three(2);
        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, 100);
        vm.prank(s2);
        ra.anchor(CHAIN, ROOT_A, 150);
        assertTrue(ra.isAnchored(CHAIN, ROOT_A));
        assertEq(ra.anchorOf(CHAIN, ROOT_A).ledgerSeq, 150);
        assertEq(ra.latestSeq(CHAIN), 150);

        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_B, 200);
        vm.prank(s3);
        ra.anchor(CHAIN, ROOT_B, 180); // lower than pending: accepted, max kept
        assertTrue(ra.isAnchored(CHAIN, ROOT_B));
        assertEq(ra.anchorOf(CHAIN, ROOT_B).ledgerSeq, 200);
    }

    /// A1: a rotated-out notary's approvals stop counting.
    function test_removedSigner_approvalsStopCounting() public {
        _three(2);
        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, 10); // s1 pre-approves, then is rotated out

        address[] memory two = new address[](2);
        two[0] = s2;
        two[1] = s3;
        _set(two, 2);

        vm.prank(s2);
        ra.anchor(CHAIN, ROOT_A, 10);
        assertFalse(ra.isAnchored(CHAIN, ROOT_A), "s1's approval must not count under the new set");
        assertEq(ra.anchorOf(CHAIN, ROOT_A).approvals, 1);

        vm.prank(s3);
        ra.anchor(CHAIN, ROOT_A, 10);
        assertTrue(ra.isAnchored(CHAIN, ROOT_A));
    }

    /// A1 (second case): a lowered threshold can complete a pending root.
    function test_loweredThreshold_completesPendingRoot() public {
        _three(2);
        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, 10);
        assertFalse(ra.isAnchored(CHAIN, ROOT_A));

        _set(_one(s1), 1);
        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, 10);
        assertTrue(ra.isAnchored(CHAIN, ROOT_A));
    }

    /// A2: a pending root cannot complete below a root that anchored meanwhile.
    function test_pendingRoot_cannotCompleteBelowLatest() public {
        _three(2);
        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, 10); // pending at 10

        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_B, 20);
        vm.prank(s2);
        ra.anchor(CHAIN, ROOT_B, 20); // B anchors at 20

        vm.prank(s2);
        vm.expectRevert(abi.encodeWithSelector(IRootAnchor.RootAnchor__SeqNotMonotonic.selector, 20, 10));
        ra.anchor(CHAIN, ROOT_A, 10);
    }

    /*//////////////////////////////////////////////////////////////
                       the incident levers (A3)
    //////////////////////////////////////////////////////////////*/

    function test_revokeAnchor_duringDelay_andAfter() public {
        vm.prank(admin);
        ra.setAnchorDelay(CHAIN, 600);
        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, 10);

        // Caught inside the delay: revoked before it ever becomes usable.
        vm.prank(admin);
        vm.expectEmit(true, true, false, true);
        emit IRootAnchor.AnchorRevoked(CHAIN, ROOT_A, 1);
        ra.revokeAnchor(CHAIN, ROOT_A);
        vm.warp(block.timestamp + 600);
        assertFalse(ra.isAnchored(CHAIN, ROOT_A));
        assertEq(ra.anchoredAt(CHAIN, ROOT_A), 0);

        // Caught after: an anchored root can be pulled too.
        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_B, 11);
        vm.warp(block.timestamp + 600);
        assertTrue(ra.isAnchored(CHAIN, ROOT_B));
        vm.prank(admin);
        ra.revokeAnchor(CHAIN, ROOT_B);
        assertFalse(ra.isAnchored(CHAIN, ROOT_B));
    }

    function test_revokeAnchor_discardsPendingApprovals() public {
        _three(2);
        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, 10);
        vm.prank(admin);
        ra.revokeAnchor(CHAIN, ROOT_A);

        // s1's earlier approval is gone; it takes two fresh ones.
        vm.prank(s2);
        ra.anchor(CHAIN, ROOT_A, 10);
        assertFalse(ra.isAnchored(CHAIN, ROOT_A));
        assertEq(ra.anchorOf(CHAIN, ROOT_A).approvals, 1);
        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, 10);
        assertTrue(ra.isAnchored(CHAIN, ROOT_A));
    }

    function test_revokeAnchor_unknownRoot_reverts() public {
        vm.prank(admin);
        vm.expectRevert(IRootAnchor.RootAnchor__NoSuchAnchor.selector);
        ra.revokeAnchor(CHAIN, ROOT_A);
    }

    function test_resetLatestSeq_recoversABrickedRoute() public {
        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, type(uint64).max); // a buggy publisher pins the route
        vm.prank(s1);
        vm.expectRevert(abi.encodeWithSelector(IRootAnchor.RootAnchor__SeqNotMonotonic.selector, type(uint64).max, 11));
        ra.anchor(CHAIN, ROOT_B, 11);

        vm.startPrank(admin);
        ra.revokeAnchor(CHAIN, ROOT_A);
        ra.resetLatestSeq(CHAIN, 0);
        vm.stopPrank();

        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_B, 11);
        assertTrue(ra.isAnchored(CHAIN, ROOT_B));
    }

    /*//////////////////////////////////////////////////////////////
                         signer-set validation
    //////////////////////////////////////////////////////////////*/

    function test_setSigners_badThreshold_reverts() public {
        address[] memory two = new address[](2);
        two[0] = s1;
        two[1] = s2;
        vm.startPrank(admin);
        vm.expectRevert(IRootAnchor.RootAnchor__BadThreshold.selector);
        ra.setSigners(two, 0);
        vm.expectRevert(IRootAnchor.RootAnchor__BadThreshold.selector);
        ra.setSigners(two, 3);
        vm.stopPrank();
    }

    function test_setSigners_duplicate_reverts() public {
        address[] memory dup = new address[](2);
        dup[0] = s1;
        dup[1] = s1;
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(IRootAnchor.RootAnchor__DuplicateSigner.selector, s1));
        ra.setSigners(dup, 1);
    }

    function test_setSigners_zeroAddress_reverts() public {
        vm.prank(admin);
        vm.expectRevert(IRootAnchor.RootAnchor__ZeroAddress.selector);
        ra.setSigners(_one(address(0)), 1);
    }

    /*//////////////////////////////////////////////////////////////
                         pause + admin discipline
    //////////////////////////////////////////////////////////////*/

    function test_pause_blocksAnchor_neverIsAnchored() public {
        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, 10);

        vm.prank(admin);
        ra.pause();

        vm.prank(s1);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        ra.anchor(CHAIN, ROOT_B, 11);

        // The read on the refund path keeps answering under pause (D4).
        assertTrue(ra.isAnchored(CHAIN, ROOT_A));

        vm.prank(admin);
        ra.unpause();
        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_B, 11);
        assertTrue(ra.isAnchored(CHAIN, ROOT_B));
    }

    function test_adminOnly_setters() public {
        vm.startPrank(stranger);
        vm.expectRevert(_unauthorized(stranger));
        ra.setSigners(_one(s2), 1);
        vm.expectRevert(_unauthorized(stranger));
        ra.setAnchorDelay(CHAIN, 1);
        vm.expectRevert(_unauthorized(stranger));
        ra.setMonotonic(false);
        vm.expectRevert(_unauthorized(stranger));
        ra.pause();
        vm.expectRevert(_unauthorized(stranger));
        ra.revokeAnchor(CHAIN, ROOT_A);
        vm.expectRevert(_unauthorized(stranger));
        ra.resetLatestSeq(CHAIN, 0);
        vm.stopPrank();
    }

    function test_twoStepAdmin() public {
        address next = makeAddr("nextAdmin");
        vm.prank(admin);
        ra.transferAdmin(next);

        vm.prank(stranger);
        vm.expectRevert(TwoStepAdmin.NotPendingAdmin.selector);
        ra.acceptAdmin();

        vm.prank(next);
        ra.acceptAdmin();
        assertEq(ra.admin(), next);

        vm.prank(admin);
        vm.expectRevert(_unauthorized(admin));
        ra.setAnchorDelay(CHAIN, 1);
        vm.prank(next);
        ra.setAnchorDelay(CHAIN, 1);
    }

    /*//////////////////////////////////////////////////////////////
                    the seam 2.3e's cancel_order calls
    //////////////////////////////////////////////////////////////*/

    function test_consumer_revertsUnanchored_passesAnchored() public {
        vm.expectRevert(abi.encodeWithSelector(MockAnchorConsumer.NotAnchored.selector, CHAIN, ROOT_A));
        consumer.refund(CHAIN, ROOT_A);

        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, 10);
        assertTrue(consumer.refund(CHAIN, ROOT_A));
    }

    function test_consumer_respectsTheDelay() public {
        vm.prank(admin);
        ra.setAnchorDelay(CHAIN, 300);
        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, 10);

        vm.expectRevert(abi.encodeWithSelector(MockAnchorConsumer.NotAnchored.selector, CHAIN, ROOT_A));
        consumer.refund(CHAIN, ROOT_A);

        vm.warp(block.timestamp + 300);
        assertTrue(consumer.refund(CHAIN, ROOT_A));
    }
}
