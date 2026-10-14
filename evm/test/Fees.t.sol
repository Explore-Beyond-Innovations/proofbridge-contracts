// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IEscrow} from "src/interfaces/IEscrow.sol";
import {IVerifier} from "src/interfaces/IVerifier.sol";
import {IMerkleManager} from "src/interfaces/IMerkleManager.sol";
import {IwNativeToken} from "src/wNativeToken.sol";
import {AdManager} from "src/AdManager.sol";
import {Dispute} from "src/libraries/Dispute.sol";
import {ProofBridgeUtils} from "src/libraries/ProofBridgeUtils.sol";
import {Timelock} from "src/libraries/Timelock.sol";
import {Phase3Base} from "./utils/Phase3Base.sol";
import {statusOf} from "test/utils/OrderStatus.sol";

/// #586 (plan 2.6 doc 24, D5–D8): the bridge fee on the ad chain's payouts.
contract FeeTest is Phase3Base {
    function setUp() public override {
        super.setUp();
        vm.warp(1 days);
    }

    struct FeeRow {
        uint256 amount;
        uint16 lp;
        uint16 protocol;
        uint256 lpFee;
        uint256 protocolFee;
        uint256 net;
    }

    function _feeRow(string memory v, uint256 i) internal pure returns (FeeRow memory r) {
        string memory at = string.concat(".feeSplit[", vm.toString(i), "]");
        r.amount = vm.parseJsonUint(v, string.concat(at, ".amount"));
        r.lp = uint16(vm.parseJsonUint(v, string.concat(at, ".lpBps")));
        r.protocol = uint16(vm.parseJsonUint(v, string.concat(at, ".protocolBps")));
        r.lpFee = vm.parseJsonUint(v, string.concat(at, ".lpFee"));
        r.protocolFee = vm.parseJsonUint(v, string.concat(at, ".protocolFee"));
        r.net = vm.parseJsonUint(v, string.concat(at, ".net"));
    }

    /// The vector's arithmetic, through the library and through a real unlock per row.
    function test_feeSplitMatchesTheSharedVector() public {
        string memory v = vm.readFile("../test-vectors/fees-bonds.json");
        uint256 n = vm.parseJsonUint(v, ".counts.feeSplit");
        assertGt(n, 0);
        vm.prank(admin);
        adManager.setProtocolFeePool(pool);
        for (uint256 i = 0; i < n; i++) {
            _checkFeeRow(_feeRow(v, i), 1000 + i);
        }
    }

    function _checkFeeRow(FeeRow memory r, uint256 salt) internal {
        (uint256 l, uint256 pf) = ProofBridgeUtils.splitFee(r.amount, r.lp, r.protocol);
        assertEq(l, r.lpFee, "lpFee");
        assertEq(pf, r.protocolFee, "protocolFee");

        vm.prank(admin);
        adManager.setFeeBps(r.lp, r.protocol);
        IAdManager.OrderParams memory p = _params(false, r.amount, salt);
        bytes32 h = _lock(p);
        uint256 recipientBefore = adToken.balanceOf(recipient);
        uint256 poolBefore = adToken.balanceOf(pool);
        (uint256 balanceBefore,) = _adBalance(AD);

        vm.expectEmit(address(adManager));
        emit IAdManager.FeeCharged(h, r.lpFee, r.protocolFee);
        _unlock(p, salt);

        assertEq(adToken.balanceOf(recipient) - recipientBefore, r.net, "the recipient got other than the net");
        assertEq(adToken.balanceOf(pool) - poolBefore, r.protocolFee, "the pool got other than the protocol fee");
        (uint256 balanceAfter, uint256 locked) = _adBalance(AD);
        assertEq(balanceBefore - balanceAfter, r.amount - r.lpFee, "the ad kept other than the LP fee");
        assertEq(locked, 0);
    }

    /// Evidence settlement takes the same fee as the co-signed unlock.
    function test_presentSettledTakesTheFee() public {
        _fees(30, 20);
        IAdManager.OrderParams memory p = _params(false, 1_000_000_000, 1);
        _lock(p);
        adManager.presentSettled(p, EVIDENCE_ROOT, hex"");
        assertEq(adToken.balanceOf(recipient), 995_000_000);
        assertEq(adToken.balanceOf(pool), 2_000_000);
        (uint256 balance,) = _adBalance(AD);
        assertEq(balance, AD_START - 997_000_000);
    }

    /// D7: a MakerForfeit takes the protocol fee only; the 0.3% LP share goes to the bridger, so the
    /// maker found at fault keeps nothing.
    function test_makerForfeitTakesTheFee() public {
        _fees(30, 20);
        IAdManager.OrderParams memory p = _params(false, 1_000_000_000, 2);
        bytes32 h = _lock(p);
        vm.deal(recipient, BOND_FLOOR);
        vm.prank(recipient);
        adManager.dispute{value: BOND_FLOOR}(p, bytes32("e"));
        vm.prank(arbiter);
        dm.resolveDispute(h, Dispute.Outcome.MakerForfeit);
        vm.warp(dm.effectiveChallengeDeadline(h));
        vm.expectEmit(address(adManager));
        emit IAdManager.FeeCharged(h, 0, 2_000_000);
        adManager.finalizeDispute(p);
        assertEq(adToken.balanceOf(recipient), 998_000_000, "the bridger gets the LP share too");
        assertEq(adToken.balanceOf(pool), 2_000_000);
        (uint256 balance, uint256 locked) = _adBalance(AD);
        assertEq(balance, AD_START - 1_000_000_000, "the forfeiting maker keeps nothing");
        assertEq(locked, 0);
    }

    /// Must-fix 3: the fee is the one the bridger deposited against (in the order hash). A change
    /// between the deposit and the maker's lock refuses the lock instead of charging the new rate.
    function test_aFeeChangeBetweenDepositAndLockRefusesTheLock() public {
        _fees(30, 20);
        IAdManager.OrderParams memory p = _params(false, 1_000_000_000, 11); // deposited at 30 / 20
        vm.prank(admin);
        adManager.setFeeBps(100, 100);
        vm.prank(maker);
        vm.expectRevert(abi.encodeWithSelector(IAdManager.AdManager__FeeMismatch.selector, 100, 100));
        adManager.lockForOrder(p, 0);
    }

    /// The ad-chain half of a refused lock, end to end: the fee rises after the deposit, the lock is
    /// refused, and at the deadline the never-locked cancel writes the CANCEL leaf that refunds the
    /// bridger on the order chain (the refund itself: Soroban's joined test and the refundByCancel suites).
    function test_aFeeChangeBeforeTheLockEndsInTheNeverLockedCancel() public {
        _fees(30, 20);
        IAdManager.OrderParams memory p = _params(false, 1_000_000_000, 12);
        p.deadline = block.timestamp + 1 days;
        vm.prank(admin);
        adManager.setFeeBps(30, 25);
        vm.prank(maker);
        vm.expectRevert(abi.encodeWithSelector(IAdManager.AdManager__FeeMismatch.selector, 30, 25));
        adManager.lockForOrder(p, 0);

        (uint256 balanceBefore,) = _adBalance(AD);
        uint256 size = mmr.getSize();
        vm.warp(p.deadline);
        adManager.cancelNeverLocked(p, EVIDENCE_ROOT, bytes32(uint256(7)), hex"");
        assertEq(uint256(statusOf(address(adManager), _hash(p))), uint256(IEscrow.Status.Cancelled));
        assertGt(mmr.getSize(), size, "the CANCEL leaf");
        (uint256 balanceAfter, uint256 locked) = _adBalance(AD);
        assertEq(balanceAfter, balanceBefore, "the ad lost nothing");
        assertEq(locked, 0);
        assertEq(adToken.balanceOf(pool), 0, "no fee was taken");
    }

    /// The native ad pays its fee in native: the pool receives value.
    function test_theNativeAdPaysItsFeeInNative() public {
        _fees(30, 20);
        IAdManager.OrderParams memory p = _params(true, 1 ether, 3);
        _lock(p);
        _unlock(p, 3);
        assertEq(recipient.balance, 0.995 ether);
        assertEq(pool.balance, 0.002 ether);
        (uint256 balance,) = _adBalance(NATIVE_AD);
        assertEq(balance, 500 ether - 0.997 ether);
    }

    /// No fee on any cancel or refund: the lock goes back to the ad whole, the pool gets nothing.
    function test_cancelsAndRefundsTakeNoFee() public {
        _fees(30, 20);
        IAdManager.OrderParams memory c = _params(false, 1_000_000_000, 4);
        _lock(c);
        vm.warp(c.deadline);
        adManager.claimCancel(c);
        vm.warp(adManager.cancelFinalizesAt(c));
        adManager.finalizeCancel(c);

        IAdManager.OrderParams memory r = _params(false, 1_000_000_000, 5);
        r.deadline = block.timestamp + 7 days;
        _lock(r);
        _disputeTo(r, maker, Dispute.Outcome.None); // unruled: MutualRefund

        IAdManager.OrderParams memory f = _params(false, 1_000_000_000, 6);
        f.deadline = block.timestamp + 7 days;
        _lock(f);
        _disputeTo(f, maker, Dispute.Outcome.BridgerForfeit);

        (uint256 balance, uint256 locked) = _adBalance(AD);
        assertEq(balance, AD_START, "a cancel or refund took a fee");
        assertEq(locked, 0);
        assertEq(adToken.balanceOf(pool), 0);
        assertEq(adToken.balanceOf(recipient), 0);
    }

    /// D6: an order pays the fee it deposited and locked under; a later change applies to later orders only.
    function test_aFeeChangeDoesNotMoveALiveOrder() public {
        _fees(30, 20);
        IAdManager.OrderParams memory early = _params(false, 1_000_000_000, 7);
        _lock(early);
        vm.prank(admin);
        adManager.setFeeBps(100, 100);
        IAdManager.OrderParams memory late = _params(false, 1_000_000_000, 8);
        _lock(late);

        _unlock(early, 7);
        assertEq(adToken.balanceOf(recipient), 995_000_000, "the live order moved with the new fee");
        _unlock(late, 8);
        assertEq(adToken.balanceOf(recipient), 995_000_000 + 980_000_000, "a new order kept the old fee");
        assertEq(adToken.balanceOf(pool), 2_000_000 + 10_000_000);
    }

    /// Fees off (the deployed default) pays the whole amount and emits a zero fee.
    function test_aContractNobodyConfiguredChargesNothing() public {
        (address p0, uint16 lp0, uint16 pr0) = adManager.feeConfig();
        assertEq(p0, address(0));
        assertEq(lp0, 0);
        assertEq(pr0, 0);
        IAdManager.OrderParams memory p = _params(false, 1_000_000_000, 9);
        bytes32 h = _lock(p);
        vm.expectEmit(address(adManager));
        emit IAdManager.FeeCharged(h, 0, 0);
        _unlock(p, 9);
        assertEq(adToken.balanceOf(recipient), 1_000_000_000);
    }

    /// The vector's validation rows: the 1% ceiling and the pool rule.
    function test_feeValidationMatchesTheSharedVector() public {
        string memory v = vm.readFile("../test-vectors/fees-bonds.json");
        uint256 n = vm.parseJsonUint(v, ".counts.feeValidation");
        for (uint256 i = 0; i < n; i++) {
            string memory at = string.concat(".feeValidation[", vm.toString(i), "]");
            uint16 lp = uint16(vm.parseJsonUint(v, string.concat(at, ".lpBps")));
            uint16 protocol = uint16(vm.parseJsonUint(v, string.concat(at, ".protocolBps")));
            bool poolSet = vm.parseJsonBool(v, string.concat(at, ".poolSet"));
            bool valid = vm.parseJsonBool(v, string.concat(at, ".valid"));
            AdManager fresh = new AdManager(admin, IVerifier(admin), IMerkleManager(admin), IwNativeToken(admin));
            vm.startPrank(admin);
            if (poolSet) fresh.setProtocolFeePool(pool);
            if (!valid) vm.expectRevert(IAdManager.AdManager__InvalidFee.selector);
            fresh.setFeeBps(lp, protocol);
            vm.stopPrank();
            if (valid) {
                (, uint16 l, uint16 pr) = fresh.feeConfig();
                assertEq(l, lp);
                assertEq(pr, protocol);
            }
        }
    }

    /// The ceilings both chains read from the vector.
    function test_theCeilingsMatchTheSharedVector() public view {
        string memory v = vm.readFile("../test-vectors/fees-bonds.json");
        assertEq(uint256(ProofBridgeUtils.MAX_FEE_BPS), vm.parseJsonUint(v, ".constants.maxFeeBps"));
        assertEq(uint256(Dispute.MAX_BOND_BPS), vm.parseJsonUint(v, ".constants.maxBondBps"));
        assertEq(Timelock.DELAY, vm.parseJsonUint(v, ".constants.timelockDelay"));
        assertEq(Timelock.GRACE, vm.parseJsonUint(v, ".constants.timelockGrace"));
    }

    /// D7: the pool can never be zero.
    function test_thePoolCannotBeZero() public {
        vm.prank(admin);
        vm.expectRevert(IEscrow.Escrow__ZeroAddress.selector);
        adManager.setProtocolFeePool(address(0));
    }

    /// A pool that refuses the push is credited instead, and settlement still lands.
    function test_aRefusingPoolIsCredited() public {
        RefusingPool refusing = new RefusingPool();
        vm.startPrank(admin);
        adManager.setProtocolFeePool(address(refusing));
        adManager.setFeeBps(30, 20);
        vm.stopPrank();
        IAdManager.OrderParams memory p = _params(true, 1 ether, 10);
        _lock(p);
        _unlock(p, 10);
        assertEq(recipient.balance, 0.995 ether);
        assertEq(adManager.claimable(address(refusing), NATIVE), 0.002 ether, "the pool's fee was not credited");
    }
}

contract RefusingPool {
    receive() external payable {
        revert("no");
    }
}
