// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IEscrow} from "src/interfaces/IEscrow.sol";
import {IOrderPortal} from "src/interfaces/IOrderPortal.sol";
import {AdManagerTest} from "./Admanager.t.sol";
import {OrderPortalTest} from "./OrderPortal.t.sol";
import {MockFeeOnTransferERC20} from "./mocks/MockFeeOnTransferERC20.sol";
import {statusOf} from "test/utils/OrderStatus.sol";

/// Every ERC20 pull must credit the escrow exactly the amount: a fee-on-transfer token is refused
/// at `createAd`, `fundAd` and `createOrder`, and nothing is recorded. A token that credits the
/// escrow more than the amount is refused the same way (the escrow records only what it asked
/// for, so an over-credit is an unaccounted balance). The same token with its fee or bonus off
/// goes through, and the native path is unchanged (its own suites).
contract AdManagerShortTransferTest is AdManagerTest {
    MockFeeOnTransferERC20 internal fee;

    /// Wired per test, not in `setUp`: the inherited suite's own tests expect an unwired escrow.
    function _wireFeeToken() internal {
        fee = new MockFeeOnTransferERC20(18);
        fee.mint(maker, minted);
        vm.startPrank(admin);
        adManager.setPeerEscrow(orderChainId, _b32(orderPortal));
        adManager.setTokenRoute(address(fee), orderChainId, _b32(orderToken));
        vm.stopPrank();
        vm.prank(maker);
        fee.approve(address(adManager), type(uint256).max);
    }

    function test_createAd_refusesAShortTransfer() public {
        _wireFeeToken();
        fee.setFee(1);
        vm.prank(maker);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TransferShort.selector, initAmt, initAmt - 1));
        adManager.createAd("fee", address(fee), initAmt, orderChainId, _b32(adRecipient), _b32(maker));
        (address owner,,,,,,,,) = adManager.ads("fee");
        assertEq(owner, address(0), "no ad recorded");
        assertEq(fee.balanceOf(address(adManager)), 0);
    }

    function test_fundAd_refusesAShortTransfer() public {
        _wireFeeToken();
        vm.prank(maker);
        adManager.createAd("fee", address(fee), initAmt, orderChainId, _b32(adRecipient), _b32(maker));
        fee.setFee(3);
        vm.prank(maker);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TransferShort.selector, fundAmt, fundAmt - 3));
        adManager.fundAd("fee", fundAmt);
        (,,,,,,, uint256 balance,) = adManager.ads("fee");
        assertEq(balance, initAmt, "the balance did not move");
        assertEq(fee.balanceOf(address(adManager)), initAmt);

        fee.setFee(0);
        vm.prank(maker);
        adManager.fundAd("fee", fundAmt);
        (,,,,,,, balance,) = adManager.ads("fee");
        assertEq(balance, initAmt + fundAmt, "the same token without a fee goes through");
    }

    function test_createAd_refusesAnOverCredit() public {
        _wireFeeToken();
        fee.setBonus(1);
        vm.prank(maker);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TransferShort.selector, initAmt, initAmt + 1));
        adManager.createAd("fee", address(fee), initAmt, orderChainId, _b32(adRecipient), _b32(maker));
        (address owner,,,,,,,,) = adManager.ads("fee");
        assertEq(owner, address(0), "no ad recorded");
        assertEq(fee.balanceOf(address(adManager)), 0);
    }

    function test_fundAd_refusesAnOverCredit() public {
        _wireFeeToken();
        vm.prank(maker);
        adManager.createAd("fee", address(fee), initAmt, orderChainId, _b32(adRecipient), _b32(maker));
        fee.setBonus(5);
        vm.prank(maker);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TransferShort.selector, fundAmt, fundAmt + 5));
        adManager.fundAd("fee", fundAmt);
        (,,,,,,, uint256 balance,) = adManager.ads("fee");
        assertEq(balance, initAmt, "the balance did not move");
        assertEq(fee.balanceOf(address(adManager)), initAmt);

        fee.setBonus(0);
        vm.prank(maker);
        adManager.fundAd("fee", fundAmt);
        (,,,,,,, balance,) = adManager.ads("fee");
        assertEq(balance, initAmt + fundAmt, "the same token without a bonus goes through");
    }
}

contract OrderPortalShortTransferTest is OrderPortalTest {
    MockFeeOnTransferERC20 internal fee;

    function _wireFeeToken() internal {
        fee = new MockFeeOnTransferERC20(18);
        fee.mint(bridger, minted);
        vm.startPrank(admin);
        portal.setPeerEscrow(adChainId, _b32(adManager));
        portal.setTokenRoute(address(fee), adChainId, adToken);
        vm.stopPrank();
        vm.prank(bridger);
        fee.approve(address(portal), type(uint256).max);
    }

    function test_createOrder_refusesAShortTransfer() public {
        _wireFeeToken();
        IOrderPortal.OrderParams memory p = _defaultParams();
        p.orderChainToken = _b32(address(fee));
        bytes32 h = portal.hashOrderPublic(p);
        fee.setFee(1);
        vm.prank(bridger);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TransferShort.selector, p.amount, p.amount - 1));
        portal.createOrder(p);
        assertEq(uint256(statusOf(address(portal), h)), uint256(IEscrow.Status.None), "no order recorded");

        fee.setFee(0);
        vm.prank(bridger);
        portal.createOrder(p);
        assertEq(fee.balanceOf(address(portal)), p.amount);
    }

    function test_createOrder_refusesAnOverCredit() public {
        _wireFeeToken();
        IOrderPortal.OrderParams memory p = _defaultParams();
        p.orderChainToken = _b32(address(fee));
        bytes32 h = portal.hashOrderPublic(p);
        fee.setBonus(2);
        vm.prank(bridger);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TransferShort.selector, p.amount, p.amount + 2));
        portal.createOrder(p);
        assertEq(uint256(statusOf(address(portal), h)), uint256(IEscrow.Status.None), "no order recorded");
        assertEq(fee.balanceOf(address(portal)), 0, "nothing stays in the escrow");

        fee.setBonus(0);
        vm.prank(bridger);
        portal.createOrder(p);
        assertEq(fee.balanceOf(address(portal)), p.amount);
    }
}
