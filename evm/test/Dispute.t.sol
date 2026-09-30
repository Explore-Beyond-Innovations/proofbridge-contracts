// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Vm} from "forge-std/Vm.sol";
import {IEscrow} from "src/interfaces/IEscrow.sol";
import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IDisputeManager} from "src/interfaces/IDisputeManager.sol";
import {IwNativeToken} from "src/wNativeToken.sol";
import {DisputeManager} from "src/DisputeManager.sol";
import {Dispute} from "src/libraries/Dispute.sol";
import {RouteTiming} from "src/libraries/RouteTiming.sol";
import {AdManagerTest} from "./Admanager.t.sol";
import {CancellationHarness} from "./Cancellation.t.sol";
import {IRootAnchor} from "src/interfaces/IRootAnchor.sol";
import {RootAnchor} from "src/RootAnchor.sol";

/*//////////////////////////////////////////////////////////////
       2.3g — disputes, with the lifecycle in its own contract
//////////////////////////////////////////////////////////////*/

/// A recipient that refuses native value, to prove a resolution cannot be bricked by one.
contract RefusingRecipient {
    receive() external payable {
        revert("no");
    }
}

/// Refuses native value until opened.
contract ToggleRecipient {
    bool internal accepting;

    function open() external {
        accepting = true;
    }

    receive() external payable {
        require(accepting, "closed");
    }
}

contract DisputeTest is AdManagerTest, CancellationHarness {
    DisputeManager internal dm;
    address internal arbiter = makeAddr("arbiter");
    address internal feePool = makeAddr("feePool");
    /// The bridger-side party as the *ad* leg knows them: `orderRecipient`, the address this chain
    /// would pay. Only the order's two parties may file (D11), so a dispute fixture that files as a
    /// bystander is testing a path that no longer exists.
    address internal filer;
    address internal stranger = makeAddr("stranger");

    uint64 internal constant CHALLENGE = 2 hours;
    uint128 internal constant BOND_FLOOR = 1 ether;
    uint16 internal constant BOND_BPS = 100; // 1%

    function setUp() public virtual override {
        super.setUp();
        dm = new DisputeManager(admin, IwNativeToken(address(_wNativeToken)));
        vm.startPrank(admin);
        dm.setEscrow(address(adManager), true);
        dm.setArbiter(arbiter);
        dm.setProtocolFeePool(feePool);
        dm.setDisputeParams(orderChainId, Dispute.Params(CHALLENGE, BOND_FLOOR, BOND_BPS));
        adManager.setDisputeManager(IDisputeManager(address(dm)));
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(0, 30 minutes, 0, 1 days, 0));
        vm.stopPrank();
        filer = recipient;
        anchor = _anchorOf(admin, address(this));
        vm.prank(admin);
        adManager.setRootAnchor(IRootAnchor(address(anchor)));
    }

    RootAnchor internal anchor;

    /// Terminate `p` by presenting the counterparty's SETTLED leaf — the evidence path that must
    /// close any open dispute along with the order.
    function _presentSettledOn(IAdManager.OrderParams memory p, bytes32) internal {
        bytes32 root = bytes32(uint256(0xf00d) + nextSeq);
        anchor.anchor(orderChainId, root, nextSeq++);
        adManager.presentSettled(p, root, hex"");
    }

    /*//////////////////////////// helpers ////////////////////////////*/

    function _lockedOrder(uint256 salt) internal returns (IAdManager.OrderParams memory p, bytes32 h) {
        test_fundAd_makerOnly();
        (p, h) = _openOrder(lastAdId, address(adToken), 60 ether, salt, bridger, recipient);
    }

    function _lockedOrderTo(uint256 salt, address orderRecipient)
        internal
        returns (IAdManager.OrderParams memory p, bytes32 h)
    {
        test_fundAd_makerOnly();
        (p, h) = _openOrder(lastAdId, address(adToken), 60 ether, salt, bridger, orderRecipient);
    }

    /// Past the window the module actually enforces, rather than past the challenge period alone.
    /// Those are different numbers whenever the order's deadline is further out than the challenge
    /// period — which is the normal case, and was the hole that let a dispute finalize early.
    function _warpPastWindow(bytes32 h) internal {
        vm.warp(dm.effectiveChallengeDeadline(h) + 1);
    }

    function _file(IAdManager.OrderParams memory p, address who) internal returns (uint256 bond) {
        bond = Dispute.bondFor(60 ether, Dispute.Params(CHALLENGE, BOND_FLOOR, BOND_BPS));
        vm.deal(who, bond);
        vm.prank(who);
        adManager.dispute{value: bond}(p, bytes32("evidence"));
    }

    /*//////////////////////// the boundary ////////////////////////*/

    /// The property I most wanted to be wrong about: the escrow and the module must agree, and a
    /// failure on either side of the call must leave neither half-updated.
    function test_boundary_filingIsAtomicAcrossBothContracts() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(1);
        uint256 bond = Dispute.bondFor(60 ether, Dispute.Params(CHALLENGE, BOND_FLOOR, BOND_BPS));

        // Under-funding fails inside the *module*, after the escrow has already written Disputed.
        vm.deal(filer, bond);
        vm.prank(filer);
        vm.expectRevert(
            abi.encodeWithSelector(DisputeManager.DisputeManager__NativeAmountMismatch.selector, bond - 1, bond)
        );
        adManager.dispute{value: bond - 1}(p, bytes32(0));

        // Neither side kept anything: the escrow's status rolled back with the module's record.
        assertEq(uint8(adManager.orders(h)), uint8(IEscrow.Status.Open), "escrow rolled back");
        assertFalse(dm.isDisputed(h), "module rolled back");
    }

    /// The module holds the bond; the escrow never does. That is what keeps "the escrow's balance
    /// is its order escrow" a single-contract invariant for 2.3h.
    function test_boundary_bondNeverRestsInTheEscrow() public {
        (IAdManager.OrderParams memory p,) = _lockedOrder(2);
        uint256 before = address(adManager).balance;
        uint256 bond = _file(p, filer);
        assertEq(address(adManager).balance, before, "escrow took no native value");
        assertEq(_wNativeToken.balanceOf(address(dm)), bond, "the module holds it, wrapped");
    }

    /// The module cannot write escrow state: there is no function for it to call.
    function test_boundary_moduleHasNoWriteAccessToTheEscrow() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(3);
        _file(p, filer);
        assertEq(uint8(adManager.orders(h)), uint8(IEscrow.Status.Disputed));
        // The escrow exposes no dispute-status setter at all, to the module or anyone else.
        (bool ok,) = address(adManager).call(abi.encodeWithSignature("setDisputeOpen(bytes32,bool)", h, false));
        assertFalse(ok, "no such entry point exists");
    }

    /*//////////////////////// the rules ////////////////////////*/

    /// T-51: the arbiter can never rule that the trade went through — evidence alone reaches that.
    function test_t51_arbiterCannotSettle() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(4);
        _file(p, filer);
        vm.prank(arbiter);
        vm.expectRevert(DisputeManager.DisputeManager__ArbiterCannotSettle.selector);
        dm.resolveDispute(h, Dispute.Outcome.TradeProceeds);

        vm.prank(arbiter);
        vm.expectRevert(DisputeManager.DisputeManager__ArbiterCannotSettle.selector);
        dm.resolveDispute(h, Dispute.Outcome.None);
    }

    /// Only the arbiter rules, and the arbiter is not the admin.
    function test_onlyArbiterRules_andAdminIsNotArbiter() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(5);
        _file(p, filer);
        vm.prank(admin);
        vm.expectRevert(DisputeManager.DisputeManager__NotArbiter.selector);
        dm.resolveDispute(h, Dispute.Outcome.MutualRefund);
    }

    /// T-23: the bond is `max(floor, bps x amount)`, and both terms are per route.
    function test_t23_bondScalesWithTheOrder() public pure {
        Dispute.Params memory p = Dispute.Params(2 hours, 1 ether, 100); // 1%
        // Floor dominates a small order.
        assertEq(Dispute.bondFor(10 ether, p), 1 ether);
        // The percentage dominates a large one.
        assertEq(Dispute.bondFor(1000 ether, p), 10 ether);
        // Exactly at the crossover the floor still wins (>= keeps it non-zero).
        assertEq(Dispute.bondFor(100 ether, p), 1 ether);
    }

    /// The parameters fail closed: an unconfigured route cannot be disputed for free.
    function test_unconfiguredRouteCannotBeDisputed() public {
        (IAdManager.OrderParams memory p,) = _lockedOrder(6);
        vm.prank(admin);
        // A different peer chain has no params.
        dm.setDisputeParams(orderChainId + 1, Dispute.Params(CHALLENGE, BOND_FLOOR, BOND_BPS));
        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSelector(Dispute.Dispute__InvalidParams.selector, 1));
        dm.setDisputeParams(orderChainId, Dispute.Params(1 minutes, BOND_FLOOR, BOND_BPS));
        vm.stopPrank();
        // And the validated one is still in force.
        _file(p, filer);
    }

    /// T-50 (disputed half): the fallback cannot open before the challenge period is really over,
    /// and "really" counts paused seconds.
    function test_t50_fallbackWaitsOutTheChallengePeriod() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(7);
        _file(p, filer);

        uint256 until_ = dm.effectiveChallengeDeadline(h);
        vm.expectRevert(abi.encodeWithSelector(DisputeManager.DisputeManager__ChallengeOpen.selector, until_));
        dm.claimDispute(h);

        // The challenge period alone is NOT enough: the order still has time on its own clock, and
        // no dispute path may complete before `deadline + buffer` (D3, T-50). This is the bug that
        // let any filer cancel a week-long order an hour after filing.
        vm.warp(block.timestamp + CHALLENGE + 1);
        vm.expectRevert(abi.encodeWithSelector(DisputeManager.DisputeManager__ChallengeOpen.selector, until_));
        dm.claimDispute(h);

        _warpPastWindow(h);
        dm.claimDispute(h); // now allowed
    }

    /// #452: once the arbiter rules, the no-ruling fallback is refused with its own error, even
    /// after the ruling's window has passed.
    function test_claimAfterARulingIsAlreadyRuled() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(31);
        _file(p, filer);
        vm.prank(arbiter);
        dm.resolveDispute(h, Dispute.Outcome.MutualRefund);

        vm.expectRevert(abi.encodeWithSelector(DisputeManager.DisputeManager__AlreadyRuled.selector, h));
        dm.claimDispute(h);

        _warpPastWindow(h);
        vm.expectRevert(abi.encodeWithSelector(DisputeManager.DisputeManager__AlreadyRuled.selector, h));
        dm.claimDispute(h);
    }

    /// c41-J: a pause between the lock and the filing extends the bridger's unlock on this leg; the
    /// dispute's floor must carry it too, or the fallback ends the order while the payout is valid.
    function test_j_fallbackCarriesAPauseBeforeTheFiling() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(30);
        vm.prank(admin);
        adManager.pause();
        vm.warp(block.timestamp + 3 hours);
        vm.prank(admin);
        adManager.unpause();
        _file(p, filer);
        uint256 until_ = dm.effectiveChallengeDeadline(h);
        assertEq(until_, p.deadline + 30 minutes + 3 hours, "the floor carries the pause since the lock");

        vm.warp(p.deadline + 30 minutes + 1); // the old floor: the unlock is still open here
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__DisputeNotResolved.selector, h));
        adManager.finalizeDispute(p);
        vm.warp(until_ + 1);
        adManager.finalizeDispute(p);
        assertEq(uint256(adManager.orders(h)), uint256(IEscrow.Status.Resolved));
    }

    /// T-13: `inFlightOf` returns to zero on `Resolved`, as on every other terminal.
    function test_t13_inFlightClearsOnResolved() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(8);
        _file(p, filer);
        assertEq(adManager.inFlightOf(p.adSettlementSigner), 1);

        vm.prank(arbiter);
        dm.resolveDispute(h, Dispute.Outcome.MutualRefund);
        _warpPastWindow(h);
        adManager.finalizeDispute(p);

        assertEq(uint8(adManager.orders(h)), uint8(IEscrow.Status.Resolved));
        assertEq(adManager.inFlightOf(p.adSettlementSigner), 0);
    }

    /// D7: a mutual refund returns the bond to whoever filed.
    function test_d7_mutualRefundReturnsTheBond() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(9);
        uint256 bond = _file(p, filer);

        vm.prank(arbiter);
        dm.resolveDispute(h, Dispute.Outcome.MutualRefund);
        _warpPastWindow(h);
        adManager.finalizeDispute(p);

        assertEq(filer.balance, bond, "bond came back");
        assertFalse(dm.isDisputed(h), "record closed");
    }

    /// T-18: a filer that refuses native value cannot brick the resolution — the bond lands as a
    /// credit and is claimable afterwards.
    function test_t18_refusingFilerCannotBrickTheResolution() public {
        // The refuser has to be a party to file at all, so it is the order's recipient here.
        address refuser = address(new RefusingRecipient());
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrderTo(10, refuser);
        _file(p, refuser);

        vm.prank(arbiter);
        dm.resolveDispute(h, Dispute.Outcome.MutualRefund);
        _warpPastWindow(h);
        adManager.finalizeDispute(p); // must not revert

        assertEq(uint8(adManager.orders(h)), uint8(IEscrow.Status.Resolved));
        assertGt(dm.claimable(refuser), 0, "credited instead of pushed");
    }

    /// The escrow refuses to finalize while the module's window is still open.
    function test_finalizeWaitsForTheModulesWindow() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(11);
        _file(p, filer);
        vm.prank(arbiter);
        dm.resolveDispute(h, Dispute.Outcome.MutualRefund);

        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__DisputeNotResolved.selector, h));
        adManager.finalizeDispute(p);
    }

    /*//////////////////// review pass 1 — the holes ////////////////////*/

    /// B1: a bystander could file on anybody's live order, and one short challenge period later
    /// cancel it. Filing is restricted to the order's two parties.
    function test_onlyAPartyMayFile() public {
        (IAdManager.OrderParams memory p,) = _lockedOrder(20);
        uint256 bond = Dispute.bondFor(60 ether, Dispute.Params(CHALLENGE, BOND_FLOOR, BOND_BPS));
        vm.deal(stranger, bond);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotAParty.selector, stranger));
        adManager.dispute{value: bond}(p, bytes32("evidence"));

        // Both parties may, and only they.
        vm.deal(maker, bond);
        vm.prank(maker);
        adManager.dispute{value: bond}(p, bytes32("evidence"));
    }

    /// B1, the half that matters most: a dispute filed on an order with a week still to run cannot
    /// finalize after the challenge period. The window floors at `deadline + buffer`.
    function test_b1_disputeCannotFinalizeBeforeTheOrdersOwnDeadline() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(21);
        _file(p, filer);
        assertGe(dm.effectiveChallengeDeadline(h), p.deadline + 30 minutes, "window floors at deadline + buffer");

        vm.warp(block.timestamp + CHALLENGE + 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__DisputeNotResolved.selector, h));
        adManager.finalizeDispute(p);
    }

    /// B2: evidence terminates a disputed order, and the dispute has to end with it — otherwise the
    /// status leaves `Disputed`, `finalizeDispute` can never run, and the bond is stranded forever.
    function test_b2_evidenceClosesTheDisputeAndReleasesTheBond() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(22);
        _file(p, filer);
        assertTrue(dm.isDisputed(h), "filed");

        _presentSettledOn(p, h);

        assertEq(uint8(adManager.orders(h)), uint8(IEscrow.Status.Filled), "evidence terminated it");
        assertFalse(dm.isDisputed(h), "and closed the dispute with it");
        assertEq(_wNativeToken.balanceOf(address(dm)), 0, "no bond left stranded in the module");
    }

    /// S2: the bond on an evidence path settles on what the proof shows, not on a ruling the
    /// evidence has just overridden. `TradeProceeds` never returns the bond to the filer.
    function test_s2_evidenceOverridesTheRulingForTheBondToo() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(23);
        uint256 bond = _file(p, filer);
        // The arbiter rules the filer's way; evidence then proves the trade settled anyway.
        vm.prank(arbiter);
        dm.resolveDispute(h, Dispute.Outcome.MakerForfeit);

        _presentSettledOn(p, h);

        assertEq(filer.balance, 0, "a disproved filer does not get the bond back");
        assertEq(_wNativeToken.balanceOf(feePool) + feePool.balance, bond, "it went to the fee pool");
    }

    /// B3: a ruling opens a window rather than paying. One issued a second before the deadline must
    /// not become payable a second after it — that is the room the forfeited party presents in.
    function test_b3_aRulingOpensARealWindow() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(24);
        _file(p, filer);
        vm.warp(p.deadline - 1);
        vm.prank(arbiter);
        dm.resolveDispute(h, Dispute.Outcome.MakerForfeit);

        assertGe(dm.effectiveChallengeDeadline(h), p.deadline + 30 minutes, "the ruling opened a buffer");
        vm.warp(p.deadline + 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__DisputeNotResolved.selector, h));
        adManager.finalizeDispute(p);
    }

    /// S3: the responder slot is single, so anyone able to write it could overwrite the genuine
    /// counterparty's evidence hash. Only the other party may respond.
    function test_s3_onlyTheOtherPartyMayRespond() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(25);
        _file(p, filer);

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotAParty.selector, stranger));
        adManager.respondToDispute(p, bytes32("response"));

        vm.prank(maker);
        adManager.respondToDispute(p, bytes32("response"));
        (,,,,, bytes32 responderEvidence,,,) = dm.disputes(h);
        assertEq(responderEvidence, bytes32("response"), "the counterparty's hash is recorded");
    }

    /// S4, tightened by C-17: the bond is paid exactly. An overpaid or underpaid bond is refused,
    /// so no surplus is ever wrapped and nothing needs refunding.
    /// 49E-2: the bond is exact, so the amount is quoted by the contract, not re-derived by clients.
    function test_49e2_bondForQuotesWhatTheFilingRequires() public {
        assertEq(
            dm.bondFor(60 ether, orderChainId),
            Dispute.bondFor(60 ether, Dispute.Params(CHALLENGE, BOND_FLOOR, BOND_BPS))
        );
        assertEq(dm.bondFor(1, orderChainId), BOND_FLOOR, "the floor dominates a tiny amount");
        vm.expectRevert();
        dm.bondFor(60 ether, orderChainId + 7);
    }

    /// 49E-2: above the floor the bond is BOND_BPS of the amount; the literals are 1% of each amount.
    function test_49e2_bondForScalesAboveTheFloor() public view {
        assertEq(dm.bondFor(500 ether, orderChainId), 5 ether, "1% of 500 is above the 1-ether floor");
        assertEq(dm.bondFor(1000 ether, orderChainId), 10 ether, "and follows the amount");
        assertEq(dm.bondFor(1000 ether + 12_300, orderChainId), 10 ether + 123, "to the wei");
    }

    /// 49E-2: at the boundary 1% of the amount equals the floor; one step past it the percentage wins.
    function test_49e2_bondForAtTheFloorBoundary() public view {
        assertEq(dm.bondFor(100 ether, orderChainId), 1 ether, "1% of 100 is exactly the floor");
        assertEq(dm.bondFor(100 ether + 99, orderChainId), 1 ether, "rounds down onto the floor");
        assertEq(dm.bondFor(100 ether + 100, orderChainId), 1 ether + 1, "one wei of bond past the floor");
        assertEq(dm.bondFor(100 ether - 100, orderChainId), 1 ether, "just below: the floor");
    }

    function test_c17_bondMustBeExact() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(26);
        uint256 bond = Dispute.bondFor(60 ether, Dispute.Params(CHALLENGE, BOND_FLOOR, BOND_BPS));
        vm.deal(filer, bond * 2);

        vm.prank(filer);
        vm.expectRevert(
            abi.encodeWithSelector(DisputeManager.DisputeManager__NativeAmountMismatch.selector, bond + 1, bond)
        );
        adManager.dispute{value: bond + 1}(p, bytes32("evidence"));

        vm.prank(filer);
        vm.expectRevert(
            abi.encodeWithSelector(DisputeManager.DisputeManager__NativeAmountMismatch.selector, bond - 1, bond)
        );
        adManager.dispute{value: bond - 1}(p, bytes32("evidence"));

        vm.prank(filer);
        adManager.dispute{value: bond}(p, bytes32("evidence"));
        assertTrue(dm.isDisputed(h), "the exact bond files");
        assertEq(_wNativeToken.balanceOf(address(dm)), bond, "the module holds exactly the bond");
    }

    /// S5: `Claimed → Disputed → Resolved` used to leave a live claim with a past `finalizeAt`,
    /// breaking "terminal implies no open claim" for #345's sweep and the relayer's projections.
    function test_s5_resolvingClearsTheClaim() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(27);
        vm.warp(p.deadline);
        adManager.claimCancel(p);
        _file(p, filer);
        vm.prank(arbiter);
        dm.resolveDispute(h, Dispute.Outcome.MutualRefund);
        _warpPastWindow(h);
        adManager.finalizeDispute(p);

        (, uint64 finalizeAt,,) = adManager.claims(h);
        assertEq(finalizeAt, 0, "the claim record is cleared on the dispute terminal too");
    }

    /// S6: de-authorising an escrow mid-incident must not strand the bonds it already opened.
    function test_s6_deauthorisedEscrowCanStillCloseItsDisputes() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(28);
        uint256 bond = _file(p, filer);
        vm.prank(admin);
        dm.setEscrow(address(adManager), false);

        vm.prank(arbiter);
        dm.resolveDispute(h, Dispute.Outcome.MutualRefund);
        _warpPastWindow(h);
        adManager.finalizeDispute(p); // must not revert

        assertEq(filer.balance, bond, "the bond still found its way out");
    }

    /*//////////////// the head/follower rule (review pass 1) ////////////////*/

    /// The domain the primary appended for this order, read off the MerkleManager's event.
    function _appendedDomain(IAdManager.OrderParams memory p) internal returns (uint256 domain, uint256 count) {
        vm.recordLogs();
        adManager.finalizeDispute(p);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 topic = keccak256("DepositHashAppended(uint256,bytes32,uint256,bytes32)");
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == topic) {
                count++;
                (domain,) = abi.decode(logs[i].data, (uint256, bytes32));
            }
        }
    }

    /// The primary broadcasts the outcome, and it must broadcast the *right* one. Appending CANCEL
    /// for a forfeit — which the first build did for every outcome — hands the follower a proof of
    /// the opposite ruling, so it would refund the very party that just lost.
    function test_primaryBroadcastsForfeitUnderItsOwnDomain() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(40);
        _file(p, filer);
        vm.prank(arbiter);
        dm.resolveDispute(h, Dispute.Outcome.BridgerForfeit);
        _warpPastWindow(h);

        (uint256 domain, uint256 count) = _appendedDomain(p);
        assertEq(count, 1, "exactly one leaf");
        assertEq(domain, 5, "FORFEIT, not CANCEL");
    }

    /// Every other outcome still means "refund the bridger", which is what CANCEL has always meant,
    /// so the follower needs no new path for them.
    function test_primaryBroadcastsCancelForTheRefundingOutcomes() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(41);
        _file(p, filer);
        vm.prank(arbiter);
        dm.resolveDispute(h, Dispute.Outcome.MakerForfeit);
        _warpPastWindow(h);

        (uint256 domain, uint256 count) = _appendedDomain(p);
        assertEq(count, 1, "exactly one leaf");
        assertEq(domain, 2, "CANCEL, not FORFEIT");
    }

    /// And the unresolved fallback is a mutual refund, so it too is a CANCEL.
    function test_theFallbackBroadcastsCancel() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(42);
        _file(p, filer);
        _warpPastWindow(h);

        (uint256 domain, uint256 count) = _appendedDomain(p);
        assertEq(count, 1, "exactly one leaf");
        assertEq(domain, 2, "CANCEL");
    }

    /// The outcome table, read from the shared vector rather than restated here.
    ///
    /// This is the point of that file. The routing was implemented twice, once per chain, and the
    /// two agreed on the ad leg and disagreed on the order leg — a hand-written table on each side
    /// cannot catch that, because each side writes the table it already believes.
    function test_bondRoutingMatchesTheSharedVector() public view {
        string memory v = vm.readFile("../test-vectors/dispute.json");
        uint256 n = vm.parseJsonUint(v, ".counts.bondRouting");
        assertEq(n, 10, "5 outcomes x both arms of the flag");

        for (uint256 i = 0; i < n; i++) {
            string memory at = string.concat(".bondRouting[", vm.toString(i), "]");
            uint256 outcomeValue = vm.parseJsonUint(v, string.concat(at, ".outcomeValue"));
            bool filerIsBridger = vm.parseJsonBool(v, string.concat(at, ".filerIsBridger"));
            bool expected = vm.parseJsonBool(v, string.concat(at, ".bondReturnsToFiler"));
            assertEq(
                Dispute.bondReturnsToFiler(Dispute.Outcome(outcomeValue), filerIsBridger),
                expected,
                "routing disagrees with the shared vector"
            );
        }
    }

    /// The leaf each outcome broadcasts, read from the shared vector rather than restated here.
    ///
    /// This is a two-sided rule implemented on two chains — the primary picks the domain, the
    /// follower reads it — which is the exact shape that drifted last time with the bond flag. The
    /// primary is driven for real here, per row; the follower's half is asserted in Cancellation.t.
    function test_primaryLeafPerOutcomeMatchesTheSharedVector() public {
        string memory v = vm.readFile("../test-vectors/dispute.json");
        uint256 n = vm.parseJsonUint(v, ".counts.legActions");
        uint256 driven;
        // Fund once, outside the loop: `_lockedOrder` runs a *test* whose `expectEmit` is armed for
        // the first ad, so calling it per row fails on the second with a stale expectation.
        test_fundAd_makerOnly();

        for (uint256 i = 0; i < n; i++) {
            string memory at = string.concat(".legActions[", vm.toString(i), "]");
            string memory name = vm.parseJsonString(v, string.concat(at, ".outcome"));
            uint256 expected = vm.parseJsonUint(v, string.concat(at, ".primaryLeaf"));
            // TradeProceeds is reached by evidence, never by a ruling, so it has no finalize to drive.
            if (keccak256(bytes(name)) == keccak256("TradeProceeds")) continue;

            (IAdManager.OrderParams memory p, bytes32 h) =
                _openOrder(lastAdId, address(adToken), 60 ether, 100 + i, bridger, recipient);
            _file(p, filer);
            vm.prank(arbiter);
            dm.resolveDispute(h, _outcomeNamed(name));
            _warpPastWindow(h);
            (uint256 domain, uint256 count) = _appendedDomain(p);
            assertEq(count, 1, "exactly one leaf per resolution");
            assertEq(domain, expected, string.concat("wrong leaf domain for ", name));
            driven++;
        }
        assertEq(driven, 3, "every ruled outcome was actually driven");
    }

    function _outcomeNamed(string memory name) internal pure returns (Dispute.Outcome) {
        bytes32 k = keccak256(bytes(name));
        if (k == keccak256("MutualRefund")) return Dispute.Outcome.MutualRefund;
        if (k == keccak256("BridgerForfeit")) return Dispute.Outcome.BridgerForfeit;
        if (k == keccak256("MakerForfeit")) return Dispute.Outcome.MakerForfeit;
        revert("unknown outcome in the shared vector");
    }

    /// The enum discriminants are ABI and are pinned by the same file.
    function test_outcomeDiscriminantsMatchTheSharedVector() public view {
        string memory v = vm.readFile("../test-vectors/dispute.json");
        assertEq(vm.parseJsonUint(v, ".outcomes[0].value"), uint256(Dispute.Outcome.None));
        assertEq(vm.parseJsonUint(v, ".outcomes[1].value"), uint256(Dispute.Outcome.MutualRefund));
        assertEq(vm.parseJsonUint(v, ".outcomes[2].value"), uint256(Dispute.Outcome.TradeProceeds));
        assertEq(vm.parseJsonUint(v, ".outcomes[3].value"), uint256(Dispute.Outcome.BridgerForfeit));
        assertEq(vm.parseJsonUint(v, ".outcomes[4].value"), uint256(Dispute.Outcome.MakerForfeit));
    }

    /// Bond sizing, likewise: the cases live in the vector, not in each chain's head.
    function test_bondSizingMatchesTheSharedVector() public view {
        string memory v = vm.readFile("../test-vectors/dispute.json");
        uint256 n = vm.parseJsonUint(v, ".counts.bondSizing");
        for (uint256 i = 0; i < n; i++) {
            string memory at = string.concat(".bondSizing[", vm.toString(i), "]");
            Dispute.Params memory p = Dispute.Params({
                challengePeriod: CHALLENGE,
                bondFloor: uint128(vm.parseJsonUint(v, string.concat(at, ".bondFloor"))),
                bondBps: uint16(vm.parseJsonUint(v, string.concat(at, ".bondBps")))
            });
            assertEq(
                Dispute.bondFor(vm.parseJsonUint(v, string.concat(at, ".amount")), p),
                vm.parseJsonUint(v, string.concat(at, ".bond")),
                "bond sizing disagrees with the shared vector"
            );
        }
    }

    /// A second dispute on the same order is refused: the escrow sees `Disputed` before the module.
    function test_oneDisputePerOrder() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(12);
        _file(p, filer);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotDisputable.selector, h, IEscrow.Status.Disputed));
        _file(p, filer);
    }

    /*//////////////// batch B (soak): filing window, module pinning, events ////////////////*/

    /// C-10: filing is allowed up to and including the primary's window end.
    function test_c10_filingAtTheWindowEndIsAllowed() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(60);
        vm.warp(p.deadline + 30 minutes);
        _file(p, filer);
        assertTrue(dm.isDisputed(h));
    }

    /// C-10: one second past the window end, filing is refused. A later dispute would run past the
    /// point the follower's backstop may already have refunded the bridger.
    function test_c10_filingPastTheWindowEndIsRefused() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(61);
        uint256 windowEnd = p.deadline + 30 minutes;
        vm.warp(windowEnd + 1);
        uint256 bond = Dispute.bondFor(60 ether, Dispute.Params(CHALLENGE, BOND_FLOOR, BOND_BPS));
        vm.deal(filer, bond);
        vm.prank(filer);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__DisputeWindowClosed.selector, h, windowEnd));
        adManager.dispute{value: bond}(p, bytes32("evidence"));
    }

    /// C-10: a pause after the lock moves the window end by the pause, so filing still fits.
    function test_c10_aPauseExtendsTheFilingWindow() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(62);
        vm.prank(admin);
        adManager.pause();
        vm.warp(block.timestamp + 1 hours);
        vm.prank(admin);
        adManager.unpause();
        vm.warp(p.deadline + 30 minutes + 1 hours);
        _file(p, filer);
        assertTrue(dm.isDisputed(h));
    }

    /// C-10: a `Claimed` order uses its frozen claimed window end, not one rebuilt from the route's
    /// current buffer. A retiming after the claim must not reopen filing.
    function test_c10_aClaimedOrderUsesItsClaimedWindowEnd() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(63);
        vm.warp(p.deadline);
        adManager.claimCancel(p);
        uint256 claimedEnd = p.deadline + 30 minutes;
        // The route's buffer grows after the claim; the claim's own end does not move.
        vm.prank(admin);
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(0, 2 hours, 0, 1 days, 0));

        vm.warp(claimedEnd + 1);
        uint256 bond = Dispute.bondFor(60 ether, Dispute.Params(CHALLENGE, BOND_FLOOR, BOND_BPS));
        vm.deal(filer, bond);
        vm.prank(filer);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__DisputeWindowClosed.selector, h, claimedEnd));
        adManager.dispute{value: bond}(p, bytes32("evidence"));

        // At the claimed end itself, filing still goes through.
        vm.warp(claimedEnd);
        vm.prank(filer);
        adManager.dispute{value: bond}(p, bytes32("evidence"));
        assertTrue(dm.isDisputed(h));
    }

    /// C-36: the challenge period has a ceiling of 7 days.
    function test_c36_challengePeriodCeiling() public {
        vm.startPrank(admin);
        dm.setDisputeParams(orderChainId, Dispute.Params(7 days, BOND_FLOOR, BOND_BPS));
        vm.expectRevert(abi.encodeWithSelector(Dispute.Dispute__InvalidParams.selector, 1));
        dm.setDisputeParams(orderChainId, Dispute.Params(7 days + 1, BOND_FLOOR, BOND_BPS));
        vm.stopPrank();
        (uint64 period,,) = dm.disputeParams(orderChainId);
        assertEq(period, 7 days, "the refused write left the accepted one in force");
    }

    /// Parameter validation, from the shared vector both chains loop over: every row either writes or
    /// fails naming the field the vector expects (C-36 put the challenge-period ceiling there).
    function test_paramValidationMatchesTheSharedVector() public {
        string memory v = vm.readFile("../test-vectors/dispute.json");
        uint256 n = vm.parseJsonUint(v, ".counts.paramValidation");
        assertGt(n, 0, "the vector holds no validation rows");
        vm.startPrank(admin);
        for (uint256 i = 0; i < n; i++) {
            string memory at = string.concat(".paramValidation[", vm.toString(i), "]");
            Dispute.Params memory p = Dispute.Params({
                challengePeriod: uint64(vm.parseJsonUint(v, string.concat(at, ".challengePeriod"))),
                bondFloor: uint128(vm.parseUint(vm.parseJsonString(v, string.concat(at, ".bondFloor")))),
                bondBps: uint16(vm.parseJsonUint(v, string.concat(at, ".bondBps")))
            });
            uint256 field = vm.parseJsonUint(v, string.concat(at, ".validField"));
            if (field != 0) {
                vm.expectRevert(abi.encodeWithSelector(Dispute.Dispute__InvalidParams.selector, uint8(field)));
            }
            dm.setDisputeParams(orderChainId, p);
        }
        vm.stopPrank();
    }

    /// A second module, wired for this escrow like the first.
    function _secondModule() internal returns (DisputeManager b) {
        b = new DisputeManager(admin, IwNativeToken(address(_wNativeToken)));
        vm.startPrank(admin);
        b.setEscrow(address(adManager), true);
        b.setArbiter(arbiter);
        b.setProtocolFeePool(feePool);
        b.setDisputeParams(orderChainId, Dispute.Params(CHALLENGE, BOND_FLOOR, BOND_BPS));
        adManager.setDisputeManager(IDisputeManager(address(b)));
        vm.stopPrank();
    }

    /// C-11: a dispute filed under module A is responded to, finalized and bond-settled in A after
    /// the escrow is repointed at B; a new filing then goes to B.
    function test_c11_aSwappedModuleDoesNotStrandOpenDisputes() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(64);
        uint256 bond = _file(p, filer);
        assertEq(address(adManager.disputeModuleOf(h)), address(dm), "pinned to A at filing");

        DisputeManager b = _secondModule();

        vm.prank(maker);
        adManager.respondToDispute(p, bytes32("response"));
        (,,,,, bytes32 responderEvidence,,,) = dm.disputes(h);
        assertEq(responderEvidence, bytes32("response"), "the response landed in A");

        vm.prank(arbiter);
        dm.resolveDispute(h, Dispute.Outcome.MutualRefund);
        _warpPastWindow(h);
        adManager.finalizeDispute(p);

        assertEq(uint8(adManager.orders(h)), uint8(IEscrow.Status.Resolved));
        assertFalse(dm.isDisputed(h), "A's record closed");
        assertEq(filer.balance, bond, "and A paid the bond back");

        // A fresh filing goes to the module wired now.
        (IAdManager.OrderParams memory p2, bytes32 h2) =
            _openOrder(lastAdId, address(adToken), 60 ether, 65, bridger, recipient);
        _file(p2, filer);
        assertEq(address(adManager.disputeModuleOf(h2)), address(b), "the new filing pins B");
        assertTrue(b.isDisputed(h2));
        assertFalse(dm.isDisputed(h2));
    }

    /// C-11: the evidence path closes the dispute in the module it was filed under, after a swap.
    function test_c11_evidenceClosesTheDisputeInItsOwnModule() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(66);
        uint256 bond = _file(p, filer);
        _secondModule();

        _presentSettledOn(p, h);

        assertEq(uint8(adManager.orders(h)), uint8(IEscrow.Status.Filled));
        assertFalse(dm.isDisputed(h), "A's record closed by the evidence");
        assertEq(_wNativeToken.balanceOf(address(dm)), 0, "no bond stranded in A");
        assertEq(_wNativeToken.balanceOf(feePool) + feePool.balance, bond, "TradeProceeds routed it to the pool");
    }

    /// C-11: a never-disputed order has no module.
    function test_c11_neverDisputedHasNoModule() public {
        (, bytes32 h) = _lockedOrder(67);
        assertEq(address(adManager.disputeModuleOf(h)), address(0));
    }

    /// C-14: `finalizeDispute` emits the settled outcome, per outcome class.
    function test_c14_finalizeEmitsTheOutcome() public {
        test_fundAd_makerOnly();
        Dispute.Outcome[3] memory rulings =
            [Dispute.Outcome.MutualRefund, Dispute.Outcome.MakerForfeit, Dispute.Outcome.BridgerForfeit];
        for (uint256 i = 0; i < 3; i++) {
            (IAdManager.OrderParams memory p, bytes32 h) =
                _openOrder(lastAdId, address(adToken), 60 ether, 70 + i, bridger, recipient);
            _file(p, filer);
            vm.prank(arbiter);
            dm.resolveDispute(h, rulings[i]);
            _warpPastWindow(h);
            vm.expectEmit(true, false, false, true, address(adManager));
            emit IAdManager.DisputeFinalized(h, rulings[i]);
            adManager.finalizeDispute(p);
        }
    }

    /// C-14: no ruling finalizes as the fallback, and the event says `MutualRefund`, not `None`.
    function test_c14_theFallbackEmitsMutualRefund() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(75);
        _file(p, filer);
        _warpPastWindow(h);
        vm.expectEmit(true, false, false, true, address(adManager));
        emit IAdManager.DisputeFinalized(h, Dispute.Outcome.MutualRefund);
        adManager.finalizeDispute(p);
    }

    /// C-14: the filing event carries the filer's evidence hash.
    function test_c14_filingEventCarriesTheEvidence() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(76);
        uint256 bond = Dispute.bondFor(60 ether, Dispute.Params(CHALLENGE, BOND_FLOOR, BOND_BPS));
        uint64 challengeDeadline = uint64(block.timestamp) + CHALLENGE;
        if (p.deadline + 30 minutes > challengeDeadline) challengeDeadline = uint64(p.deadline + 30 minutes);
        vm.deal(filer, bond);
        vm.expectEmit(true, true, false, true, address(dm));
        emit DisputeManager.DisputeFiled(h, filer, uint128(bond), challengeDeadline, bytes32("the evidence"));
        vm.prank(filer);
        adManager.dispute{value: bond}(p, bytes32("the evidence"));
    }

    /// C-16 + C-34: a filer that refuses native is credited; `claimTo` sends its own credit
    /// elsewhere, and both claims emit `BondClaimed` (its own topic, apart from the escrows' PayoutClaimed).
    function test_c16_claimToRedirectsARefusedCredit() public {
        address refuser = address(new RefusingRecipient());
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrderTo(77, refuser);
        uint256 bond = _file(p, refuser);
        vm.prank(arbiter);
        dm.resolveDispute(h, Dispute.Outcome.MutualRefund);
        _warpPastWindow(h);
        adManager.finalizeDispute(p);
        assertEq(dm.claimable(refuser), bond, "credited");

        // `claim` to the refuser still fails; the credit stays put.
        vm.expectRevert(bytes("no"));
        dm.claim(refuser);

        vm.prank(refuser);
        vm.expectRevert(DisputeManager.DisputeManager__ZeroAddress.selector);
        dm.claimTo(address(0));

        address wallet = makeAddr("wallet");
        vm.expectEmit(true, true, false, true, address(dm));
        emit DisputeManager.BondClaimed(refuser, wallet, bond);
        vm.prank(refuser);
        dm.claimTo(wallet);
        assertEq(wallet.balance, bond, "paid to the address the recipient chose");
        assertEq(dm.claimable(refuser), 0);

        // Only the credited account's own credit moves: a stranger has nothing to claim.
        vm.prank(stranger);
        vm.expectRevert(DisputeManager.DisputeManager__NothingToClaim.selector);
        dm.claimTo(wallet);
    }

    /// C-34: the permissionless `claim` emits too.
    function test_c34_claimEmits() public {
        ToggleRecipient r = new ToggleRecipient();
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrderTo(78, address(r));
        uint256 bond = _file(p, address(r));
        vm.prank(arbiter);
        dm.resolveDispute(h, Dispute.Outcome.MutualRefund);
        _warpPastWindow(h);
        adManager.finalizeDispute(p);
        assertEq(dm.claimable(address(r)), bond, "credited");

        r.open();
        vm.expectEmit(true, true, false, true, address(dm));
        emit DisputeManager.BondClaimed(address(r), address(r), bond);
        dm.claim(address(r));
        assertEq(address(r).balance, bond);
    }

    /// C-17: a plain native send to the module is refused; unwraps from the wrapper still land.
    function test_c17_moduleRefusesStrayNative() public {
        vm.deal(stranger, 1 ether);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(DisputeManager.DisputeManager__NativeNotAccepted.selector, stranger));
        (bool ok,) = address(dm).call{value: 1 ether}("");
        assertTrue(ok, "expectRevert consumed the revert");
        assertEq(address(dm).balance, 0);
        // The bond exits unwrap through this contract's `receive`, so a bond round trip proves it.
        test_d7_mutualRefundReturnsTheBond();
    }

    /*//////////////// C-19: every module error named ////////////////*/

    /// C-19: the filer cannot answer its own dispute; only the other party's evidence lands.
    function test_c19_theFilerCannotRespond() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(70);
        _file(p, filer);
        vm.prank(filer);
        vm.expectRevert(DisputeManager.DisputeManager__NotResponder.selector);
        adManager.respondToDispute(p, bytes32("mine too"));
        vm.prank(maker);
        adManager.respondToDispute(p, bytes32("theirs"));
        (,,,,, bytes32 responderEvidence,,,) = dm.disputes(h);
        assertEq(responderEvidence, bytes32("theirs"));
    }

    /// C-19: the arbiter cannot rule once the challenge window has closed.
    function test_c19_noRulingAfterTheWindow() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(71);
        _file(p, filer);
        uint256 until = dm.effectiveChallengeDeadline(h);
        vm.warp(until);
        vm.prank(arbiter);
        vm.expectRevert(abi.encodeWithSelector(DisputeManager.DisputeManager__ChallengeClosed.selector, until));
        dm.resolveDispute(h, Dispute.Outcome.MutualRefund);
        // One second earlier it would have landed.
        vm.warp(until - 1);
        vm.prank(arbiter);
        dm.resolveDispute(h, Dispute.Outcome.MutualRefund);
    }

    /// C-19: ruling, claiming or answering an order that holds no dispute names the order.
    function test_c19_noDisputeNoRecord() public {
        bytes32 none = keccak256("never filed");
        vm.prank(arbiter);
        vm.expectRevert(abi.encodeWithSelector(DisputeManager.DisputeManager__NotDisputed.selector, none));
        dm.resolveDispute(none, Dispute.Outcome.MutualRefund);
        vm.expectRevert(abi.encodeWithSelector(DisputeManager.DisputeManager__NotDisputed.selector, none));
        dm.claimDispute(none);
    }

    /// C-19: only an allowed escrow opens a dispute, and the module holds one per order even if an
    /// escrow asks twice.
    function test_c19_moduleEdgeRefusesStrangersAndDoubles() public {
        bytes32 h = keccak256("direct");
        uint256 bond = Dispute.bondFor(60 ether, Dispute.Params(CHALLENGE, BOND_FLOOR, BOND_BPS));
        vm.deal(stranger, 2 * bond);
        vm.prank(stranger);
        vm.expectRevert(DisputeManager.DisputeManager__NotEscrow.selector);
        dm.openDispute{value: bond}(h, 60 ether, orderChainId, stranger, bytes32(0), 0, 0, 0);

        vm.prank(admin);
        dm.setEscrow(stranger, true);
        vm.prank(stranger);
        dm.openDispute{value: bond}(h, 60 ether, orderChainId, filer, bytes32(0), 0, 0, 0);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(DisputeManager.DisputeManager__DisputeExists.selector, h));
        dm.openDispute{value: bond}(h, 60 ether, orderChainId, filer, bytes32(0), 0, 0, 0);

        // Settling a bond or recording a response is for the escrow that opened it, nobody else.
        vm.expectRevert(DisputeManager.DisputeManager__NotEscrow.selector);
        dm.settleBond(h, Dispute.Outcome.MutualRefund, false);
        vm.expectRevert(DisputeManager.DisputeManager__NotEscrow.selector);
        dm.recordResponse(h, maker, bytes32(0));
    }

    /// C-19: a module with no parameters for the route refuses the filing and names the chain.
    function test_c19_aRouteWithNoParamsCannotBeFiled() public {
        DisputeManager bare = new DisputeManager(admin, IwNativeToken(address(_wNativeToken)));
        vm.startPrank(admin);
        bare.setEscrow(address(adManager), true);
        adManager.setDisputeManager(IDisputeManager(address(bare)));
        vm.stopPrank();
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(72);
        vm.deal(filer, 1 ether);
        vm.prank(filer);
        vm.expectRevert(abi.encodeWithSelector(Dispute.Dispute__NoParams.selector, orderChainId));
        adManager.dispute{value: 1 ether}(p, bytes32("evidence"));
        assertEq(uint8(adManager.orders(h)), uint8(IEscrow.Status.Open), "nothing changed");
    }
}

/*//////////////////////////////////////////////////////////////
        The correspondence, over arbitrary call sequences
//////////////////////////////////////////////////////////////*/

/// Drives the dispute surface with whatever the fuzzer picks, swallowing reverts so that only
/// *successful* paths shape the state. Anything that gets through here has to leave the two
/// contracts agreeing.
