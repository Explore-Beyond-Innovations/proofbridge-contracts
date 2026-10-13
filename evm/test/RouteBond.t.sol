// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IAdManager} from "src/interfaces/IAdManager.sol";
import {DisputeManager} from "src/DisputeManager.sol";
import {Dispute} from "src/libraries/Dispute.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {Phase3Base} from "./utils/Phase3Base.sol";

/// #586 (plan 2.6 doc 24, D9–D10): per-route dispute bonds in the order's own token.
contract RouteBondTest is Phase3Base {
    function setUp() public override {
        super.setUp();
        vm.warp(1 days);
        adToken.mint(maker, 1e30);
        adToken.mint(recipient, 1e30);
        vm.prank(maker);
        adToken.approve(address(dm), type(uint256).max);
        vm.prank(recipient);
        adToken.approve(address(dm), type(uint256).max);
    }

    function _config(address token, uint128 minBond, uint16 bps) internal {
        vm.prank(admin);
        dm.setBondConfig(token, ORDER_CHAIN, Dispute.BondConfig(minBond, bps));
    }

    function _recordBond(bytes32 h) internal view returns (uint128 bond, address bondToken) {
        (, bond,,,,,,, bondToken) = dm.disputes(h);
    }

    struct BondRow {
        uint128 minBond;
        uint16 bps;
        uint256 amount;
        uint256 bond;
    }

    function _bondRow(string memory v, uint256 i) internal pure returns (BondRow memory r) {
        string memory at = string.concat(".routeBond[", vm.toString(i), "]");
        r.minBond = uint128(vm.parseJsonUint(v, string.concat(at, ".minBond")));
        r.bps = uint16(vm.parseJsonUint(v, string.concat(at, ".bondBps")));
        r.amount = vm.parseJsonUint(v, string.concat(at, ".amount"));
        r.bond = vm.parseJsonUint(v, string.concat(at, ".bond"));
    }

    /// Each row: the library, the module's quote, and a real filing through the AdManager pull
    /// exactly the vector's bond in the ad token.
    function test_routeBondMatchesTheSharedVector() public {
        string memory v = vm.readFile("../test-vectors/fees-bonds.json");
        uint256 n = vm.parseJsonUint(v, ".counts.routeBond");
        assertGt(n, 0);
        for (uint256 i = 0; i < n; i++) {
            BondRow memory r = _bondRow(v, i);
            assertEq(Dispute.routeBond(Dispute.BondConfig(r.minBond, r.bps), r.amount), r.bond, "library");
            _config(address(adToken), r.minBond, r.bps);
            (address quotedToken, uint256 quoted) = dm.routeBond(ORDER_CHAIN, address(adToken), r.amount);
            assertEq(quotedToken, address(adToken), "quoted token");
            assertEq(quoted, r.bond, "quote");

            IAdManager.OrderParams memory p = _params(false, r.amount, 100 + i);
            p.deadline = block.timestamp + 7 days;
            bytes32 h = _lock(p);
            uint256 before = adToken.balanceOf(address(dm));
            vm.prank(maker);
            adManager.dispute(p, bytes32("e"));
            assertEq(adToken.balanceOf(address(dm)) - before, r.bond, "filing took other than the vector's bond");
            (uint128 bond, address bondToken) = _recordBond(h);
            assertEq(bond, r.bond);
            assertEq(bondToken, address(adToken));
        }
    }

    function test_bondConfigValidationMatchesTheSharedVector() public {
        string memory v = vm.readFile("../test-vectors/fees-bonds.json");
        uint256 n = vm.parseJsonUint(v, ".counts.bondConfigValidation");
        for (uint256 i = 0; i < n; i++) {
            string memory at = string.concat(".bondConfigValidation[", vm.toString(i), "]");
            uint128 minBond = uint128(vm.parseJsonUint(v, string.concat(at, ".minBond")));
            uint16 bps = uint16(vm.parseJsonUint(v, string.concat(at, ".bondBps")));
            bool valid = vm.parseJsonBool(v, string.concat(at, ".valid"));
            vm.prank(admin);
            if (!valid) vm.expectRevert(Dispute.Dispute__InvalidBondConfig.selector);
            dm.setBondConfig(address(adToken), ORDER_CHAIN, Dispute.BondConfig(minBond, bps));
        }
        vm.prank(admin);
        vm.expectRevert(DisputeManager.DisputeManager__ZeroAddress.selector);
        dm.setBondConfig(address(0), ORDER_CHAIN, Dispute.BondConfig(1, 0));
    }

    /// A route with no config posts plan 09's flat floor in native, whatever the order.
    function test_anUnconfiguredRouteKeepsTheNativeFloor() public {
        (address t, uint256 b) = dm.routeBond(ORDER_CHAIN, address(adToken), 1e24);
        assertEq(t, address(0));
        assertEq(b, BOND_FLOOR);
        IAdManager.OrderParams memory p = _params(false, 1e24, 1);
        bytes32 h = _lock(p);
        vm.deal(maker, BOND_FLOOR);
        vm.prank(maker);
        adManager.dispute{value: BOND_FLOOR}(p, bytes32("e"));
        (uint128 bond, address bondToken) = _recordBond(h);
        assertEq(bond, BOND_FLOOR);
        assertEq(bondToken, address(0));
    }

    /// Clearing a config (`{0, 0}`) puts the route back on the floor.
    function test_clearingAConfigRestoresTheFloor() public {
        _config(address(adToken), 1_000_000, 50);
        _config(address(adToken), 0, 0);
        (address t, uint256 b) = dm.routeBond(ORDER_CHAIN, address(adToken), 1e24);
        assertEq(t, address(0));
        assertEq(b, BOND_FLOOR);
    }

    /// A token bond carries no value: value sent with it is refused, not kept.
    function test_aTokenBondRefusesValue() public {
        _config(address(adToken), 1_000_000, 50);
        IAdManager.OrderParams memory p = _params(false, 1_000_000_000, 2);
        _lock(p);
        vm.deal(maker, 1);
        vm.prank(maker);
        vm.expectRevert(abi.encodeWithSelector(DisputeManager.DisputeManager__NativeAmountMismatch.selector, 1, 0));
        adManager.dispute{value: 1}(p, bytes32("e"));
    }

    /// A native-token route scales its bond in native, posted as value, exactly.
    function test_aNativeRouteScalesItsBondInNative() public {
        _config(NATIVE, 0.01 ether, 50);
        IAdManager.OrderParams memory p = _params(true, 100 ether, 3);
        bytes32 h = _lock(p);
        (address t, uint256 b) = dm.routeBond(ORDER_CHAIN, NATIVE, 100 ether);
        assertEq(t, address(0));
        assertEq(b, 0.5 ether);
        vm.deal(maker, 1 ether);
        vm.prank(maker);
        vm.expectRevert(
            abi.encodeWithSelector(DisputeManager.DisputeManager__NativeAmountMismatch.selector, BOND_FLOOR, 0.5 ether)
        );
        adManager.dispute{value: BOND_FLOOR}(p, bytes32("e"));
        vm.prank(maker);
        adManager.dispute{value: 0.5 ether}(p, bytes32("e"));
        (uint128 bond, address bondToken) = _recordBond(h);
        assertEq(bond, 0.5 ether);
        assertEq(bondToken, address(0));
    }

    /// The bond comes back, or goes to the pool, in the token it was posted in.
    function test_aTokenBondPaysOutInItsToken() public {
        _config(address(adToken), 1_000_000, 50);
        // Unruled: MutualRefund returns the bond to the filer.
        IAdManager.OrderParams memory p = _params(false, 1_000_000_000_000, 4);
        p.deadline = block.timestamp + 7 days;
        _lock(p);
        uint256 makerBefore = adToken.balanceOf(maker);
        vm.prank(maker);
        adManager.dispute(p, bytes32("e"));
        assertEq(makerBefore - adToken.balanceOf(maker), 5_000_000_000);
        vm.warp(dm.effectiveChallengeDeadline(_hash(p)));
        adManager.finalizeDispute(p);
        assertEq(adToken.balanceOf(maker), makerBefore, "the refunded bond did not come back in its token");

        // MakerForfeit against a maker filer: the bond goes to the module's pool.
        IAdManager.OrderParams memory q = _params(false, 1_000_000_000_000, 5);
        q.deadline = block.timestamp + 7 days;
        bytes32 hq = _lock(q);
        vm.prank(maker);
        adManager.dispute(q, bytes32("e"));
        vm.prank(arbiter);
        dm.resolveDispute(hq, Dispute.Outcome.MakerForfeit);
        vm.warp(dm.effectiveChallengeDeadline(hq));
        adManager.finalizeDispute(q);
        assertEq(adToken.balanceOf(bondPool), 5_000_000_000, "the forfeited bond did not reach the pool in its token");
        assertEq(adToken.balanceOf(address(dm)), 0, "the module kept a bond");
    }

    /*//////////////////// the module alone (this test as an escrow) ////////////////////*/

    function _asEscrow() internal {
        vm.prank(admin);
        dm.setEscrow(address(this), true);
    }

    /// A short receipt (a fee-on-transfer token) is refused.
    function test_aShortTokenBondIsRefused() public {
        _asEscrow();
        FeeOnTransferERC20 fot = new FeeOnTransferERC20();
        fot.mint(maker, 1e24);
        vm.prank(maker);
        fot.approve(address(dm), type(uint256).max);
        _config(address(fot), 1_000_000, 0);
        vm.expectRevert(
            abi.encodeWithSelector(DisputeManager.DisputeManager__TransferShort.selector, 1_000_000, 990_000)
        );
        dm.openDispute(bytes32("o"), ORDER_CHAIN, maker, bytes32("e"), 0, 0, address(fot), 1);
    }

    /// A bond too large for the record's 128 bits is refused rather than truncated.
    function test_aBondPast128BitsIsRefused() public {
        _asEscrow();
        _config(address(adToken), 1, 500);
        uint256 amount = uint256(1) << 135;
        vm.expectRevert(abi.encodeWithSelector(SafeCast.SafeCastOverflowedUintDowncast.selector, 128, amount / 20));
        dm.openDispute(bytes32("o"), ORDER_CHAIN, maker, bytes32("e"), 0, 0, address(adToken), amount);
    }

    /// A recipient the token refuses is credited, and the credit claims out by `claimToken` /
    /// `claimTokenTo`.
    function test_aRefusedTokenBondIsCreditedAndClaimable() public {
        _asEscrow();
        BlockingERC20 blk = new BlockingERC20();
        blk.mint(maker, 1e24);
        vm.prank(maker);
        blk.approve(address(dm), type(uint256).max);
        _config(address(blk), 1_000_000, 0);
        dm.openDispute(bytes32("o"), ORDER_CHAIN, maker, bytes32("e"), 0, 0, address(blk), 1);
        blk.setBlocked(maker, true);
        dm.settleBond(bytes32("o"), Dispute.Outcome.MutualRefund, false, false);
        assertEq(dm.tokenClaimable(maker, address(blk)), 1_000_000, "the refused bond was not credited");

        vm.expectRevert(DisputeManager.DisputeManager__NothingToClaim.selector);
        dm.claimToken(recipient, address(blk));
        address wallet = makeAddr("wallet");
        vm.prank(maker);
        dm.claimTokenTo(address(blk), wallet);
        assertEq(blk.balanceOf(wallet), 1_000_000);
        assertEq(dm.tokenClaimable(maker, address(blk)), 0);

        // And `claimToken` pays a credit to its own recipient once it accepts again.
        dm.openDispute(bytes32("p"), ORDER_CHAIN, maker, bytes32("e"), 0, 0, address(blk), 1);
        dm.settleBond(bytes32("p"), Dispute.Outcome.MutualRefund, false, false);
        blk.setBlocked(maker, false);
        uint256 before = blk.balanceOf(maker);
        dm.claimToken(maker, address(blk));
        assertEq(blk.balanceOf(maker) - before, 1_000_000);
    }

    /// The self-call door is the module's own.
    function test_directTokenPayoutIsSelfCallOnly() public {
        vm.expectRevert(DisputeManager.DisputeManager__NotEscrow.selector);
        dm.directTokenPayout(maker, address(adToken), 1);
    }
}

/// Takes 1% of every transfer.
contract FeeOnTransferERC20 is ERC20Mock {
    function _update(address from, address to, uint256 value) internal override {
        if (from != address(0) && to != address(0)) {
            uint256 fee = value / 100;
            super._update(from, address(0), fee);
            value -= fee;
        }
        super._update(from, to, value);
    }
}

/// Refuses transfers to a blocked address (a blacklist).
contract BlockingERC20 is ERC20Mock {
    mapping(address => bool) public blocked;

    function setBlocked(address a, bool b) external {
        blocked[a] = b;
    }

    function _update(address from, address to, uint256 value) internal override {
        require(!blocked[to], "blocked");
        super._update(from, to, value);
    }
}
