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
/// delay, and the writer swap as a config change), plus the consumer seam 2.3e will call through.
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

    function _three(uint32 threshold) internal {
        address[] memory three = new address[](3);
        three[0] = s1;
        three[1] = s2;
        three[2] = s3;
        vm.prank(admin);
        ra.setSigners(three, threshold);
    }

    function _unauthorized(address who) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, who, bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                    T-42 — only what was notarized is anchored
    //////////////////////////////////////////////////////////////*/

    function test_unanchoredRoot_isFalse() public view {
        assertFalse(ra.isAnchored(CHAIN, ROOT_A));
    }

    function test_anchor_isTrueWithZeroDelay() public {
        vm.prank(s1);
        vm.expectEmit(true, true, false, true);
        emit RootAnchor.Anchored(CHAIN, ROOT_A, 10, uint64(block.timestamp));
        ra.anchor(CHAIN, ROOT_A, 10);
        assertTrue(ra.isAnchored(CHAIN, ROOT_A));
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
        vm.expectRevert(abi.encodeWithSelector(RootAnchor.RootAnchor__SeqNotMonotonic.selector, 10, 9));
        ra.anchor(CHAIN, ROOT_B, 9);
    }

    function test_equalSeq_reverts_whenMonotonic() public {
        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, 10);
        vm.prank(s1);
        vm.expectRevert(abi.encodeWithSelector(RootAnchor.RootAnchor__SeqNotMonotonic.selector, 10, 10));
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
        assertEq(ra.latestSeq(CHAIN), 10, "latestSeq never decreases");
    }

    function test_nonSigner_reverts() public {
        vm.prank(stranger);
        vm.expectRevert(RootAnchor.RootAnchor__NotSigner.selector);
        ra.anchor(CHAIN, ROOT_A, 10);
    }

    function test_reanchor_isNoop() public {
        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, 10);
        RootAnchor.Anchor memory before = ra.anchorOf(CHAIN, ROOT_A);

        vm.warp(block.timestamp + 100);
        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, 10);
        RootAnchor.Anchor memory after_ = ra.anchorOf(CHAIN, ROOT_A);

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

    function test_setSigners_rotatesTheWriter_withoutRedeploy() public {
        address[] memory next = new address[](1);
        next[0] = s2;
        vm.prank(admin);
        ra.setSigners(next, 1);

        vm.prank(s1);
        vm.expectRevert(RootAnchor.RootAnchor__NotSigner.selector);
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

    function test_seqMismatch_onPendingRoot_reverts() public {
        _three(2);
        vm.prank(s1);
        ra.anchor(CHAIN, ROOT_A, 10);
        vm.prank(s2);
        vm.expectRevert(abi.encodeWithSelector(RootAnchor.RootAnchor__SeqMismatch.selector, 10, 11));
        ra.anchor(CHAIN, ROOT_A, 11);
    }

    function test_setSigners_badThreshold_reverts() public {
        address[] memory two = new address[](2);
        two[0] = s1;
        two[1] = s2;
        vm.startPrank(admin);
        vm.expectRevert(RootAnchor.RootAnchor__BadThreshold.selector);
        ra.setSigners(two, 0);
        vm.expectRevert(RootAnchor.RootAnchor__BadThreshold.selector);
        ra.setSigners(two, 3);
        vm.stopPrank();
    }

    function test_setSigners_duplicate_reverts() public {
        address[] memory dup = new address[](2);
        dup[0] = s1;
        dup[1] = s1;
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(RootAnchor.RootAnchor__DuplicateSigner.selector, s1));
        ra.setSigners(dup, 1);
    }

    function test_setSigners_zeroAddress_reverts() public {
        address[] memory z = new address[](1);
        z[0] = address(0);
        vm.prank(admin);
        vm.expectRevert(RootAnchor.RootAnchor__ZeroAddress.selector);
        ra.setSigners(z, 1);
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
        address[] memory one = new address[](1);
        one[0] = s2;
        vm.startPrank(stranger);
        vm.expectRevert(_unauthorized(stranger));
        ra.setSigners(one, 1);
        vm.expectRevert(_unauthorized(stranger));
        ra.setAnchorDelay(CHAIN, 1);
        vm.expectRevert(_unauthorized(stranger));
        ra.setMonotonic(false);
        vm.expectRevert(_unauthorized(stranger));
        ra.pause();
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
