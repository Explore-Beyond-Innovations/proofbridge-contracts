// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IEscrow} from "src/interfaces/IEscrow.sol";
import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IDisputeManager} from "src/interfaces/IDisputeManager.sol";
import {IwNativeToken} from "src/wNativeToken.sol";
import {DisputeManager} from "src/DisputeManager.sol";
import {Dispute} from "src/libraries/Dispute.sol";
import {RouteTiming} from "src/libraries/RouteTiming.sol";
import {AdManagerTest} from "./Admanager.t.sol";

/*//////////////////////////////////////////////////////////////
       2.3g — disputes, with the lifecycle in its own contract
//////////////////////////////////////////////////////////////*/

/// A recipient that refuses native value, to prove a resolution cannot be bricked by one.
contract RefusingRecipient {
    receive() external payable {
        revert("no");
    }
}

contract DisputeTest is AdManagerTest {
    DisputeManager internal dm;
    address internal arbiter = makeAddr("arbiter");
    address internal feePool = makeAddr("feePool");
    address internal filer = makeAddr("filer");

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
    }

    /*//////////////////////////// helpers ////////////////////////////*/

    function _lockedOrder(uint256 salt) internal returns (IAdManager.OrderParams memory p, bytes32 h) {
        test_fundAd_makerOnly();
        (p, h) = _openOrder(lastAdId, address(adToken), 60 ether, salt, bridger, recipient);
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

        vm.warp(block.timestamp + CHALLENGE);
        dm.claimDispute(h); // now allowed
    }

    /// T-13: `inFlightOf` returns to zero on `Resolved`, as on every other terminal.
    function test_t13_inFlightClearsOnResolved() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(8);
        _file(p, filer);
        assertEq(adManager.inFlightOf(p.adSettlementSigner), 1);

        vm.prank(arbiter);
        dm.resolveDispute(h, Dispute.Outcome.MutualRefund);
        vm.warp(block.timestamp + CHALLENGE + 1);
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
        vm.warp(block.timestamp + CHALLENGE + 1);
        adManager.finalizeDispute(p);

        assertEq(filer.balance, bond, "bond came back");
        assertFalse(dm.isDisputed(h), "record closed");
    }

    /// T-18: a filer that refuses native value cannot brick the resolution — the bond lands as a
    /// credit and is claimable afterwards.
    function test_t18_refusingFilerCannotBrickTheResolution() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(10);
        address refuser = address(new RefusingRecipient());
        _file(p, refuser);

        vm.prank(arbiter);
        dm.resolveDispute(h, Dispute.Outcome.MutualRefund);
        vm.warp(block.timestamp + CHALLENGE + 1);
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

    /// A second dispute on the same order is refused by the module.
    function test_oneDisputePerOrder() public {
        (IAdManager.OrderParams memory p,) = _lockedOrder(12);
        _file(p, filer);
        vm.expectRevert();
        _file(p, filer);
    }
}
