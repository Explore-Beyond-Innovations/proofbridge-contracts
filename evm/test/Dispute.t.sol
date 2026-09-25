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
        vm.expectRevert();
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

        vm.expectRevert();
        dm.claimDispute(h);

        // The challenge period alone is NOT enough: the order still has time on its own clock, and
        // no dispute path may complete before `deadline + buffer` (D3, T-50). This is the bug that
        // let any filer cancel a week-long order an hour after filing.
        vm.warp(block.timestamp + CHALLENGE + 1);
        vm.expectRevert();
        dm.claimDispute(h);

        _warpPastWindow(h);
        dm.claimDispute(h); // now allowed
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
        vm.expectRevert();
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
        vm.expectRevert();
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

    /// S4: everything above the bond was wrapped and then unreachable, since every exit withdraws
    /// through the wrapper. The surplus goes back to the filer.
    function test_s4_anOverpaidBondIsRefunded() public {
        (IAdManager.OrderParams memory p,) = _lockedOrder(26);
        uint256 bond = Dispute.bondFor(60 ether, Dispute.Params(CHALLENGE, BOND_FLOOR, BOND_BPS));
        vm.deal(filer, bond * 2);
        vm.prank(filer);
        adManager.dispute{value: bond * 2}(p, bytes32("evidence"));
        assertEq(filer.balance, bond, "the surplus came straight back");
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

    /// A second dispute on the same order is refused by the module.
    function test_oneDisputePerOrder() public {
        (IAdManager.OrderParams memory p,) = _lockedOrder(12);
        _file(p, filer);
        vm.expectRevert();
        _file(p, filer);
    }
}

/*//////////////////////////////////////////////////////////////
        The correspondence, over arbitrary call sequences
//////////////////////////////////////////////////////////////*/

/// Drives the dispute surface with whatever the fuzzer picks, swallowing reverts so that only
/// *successful* paths shape the state. Anything that gets through here has to leave the two
/// contracts agreeing.
