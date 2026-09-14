// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {AdManagerTest} from "./Admanager.t.sol";
import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IOrderPortal} from "src/interfaces/IOrderPortal.sol";
import {IEscrow} from "src/interfaces/IEscrow.sol";
import {OrderPortalTest} from "./OrderPortal.t.sol";
import {AdManager} from "src/AdManager.sol";
import {OrderPortal} from "src/OrderPortal.sol";
import {OrderHash} from "src/libraries/OrderHash.sol";
import {RootVerifierRegistry} from "src/libraries/RootVerifierRegistry.sol";
import {Slot0RootVerifier} from "./mocks/Slot0RootVerifier.sol";

// 2.3b on the AdManager unlock path: the envelope's slot 0 is adSettlementSigner (the split case,
// custody != settlement identity, is the only shape where a wrong slot shows), deadline, widths.
contract AdManagerOrderV2Test is AdManagerTest {
    bytes32 constant SIGNER = bytes32(uint256(0x5161e7));
    bytes32 constant ROOT = bytes32(uint256(7));

    function _lock(bytes32 signer) internal returns (IAdManager.OrderParams memory p) {
        test_fundAd_makerOnly();
        // 2.3c: the ad must declare the signer the order names, so the split case re-points it first —
        // which also exercises the lever with a live ad.
        if (signer != _b32(maker)) {
            keyRegistry.set(signer, true);
            vm.prank(maker);
            adManager.setSettlementSigner(lastAdId, signer);
        }
        p = _defaultParams(lastAdId);
        p.adChainToken = _b32(address(adToken));
        p.amount = 60 ether;
        p.salt = 999;
        p.orderRecipient = _b32(recipient);
        p.adSettlementSigner = signer;
        vm.prank(maker);
        adManager.lockForOrder(p);
    }

    function _module(bytes32 expected) internal {
        address module = address(new Slot0RootVerifier(expected));
        vm.prank(admin);
        adManager.setRootVerifier(orderChainId, module);
    }

    function test_splitCase_slot0IsTheSettlementSigner() public {
        IAdManager.OrderParams memory p = _lock(SIGNER);
        assertTrue(p.adSettlementSigner != p.adCreator);
        _module(SIGNER);
        adManager.unlock(p, bytes32("S1"), ROOT, hex"", hex"");
        assertEq(uint256(adManager.orders(adManager.hashOrderPublic(p))), uint256(IEscrow.Status.Filled));
    }

    function test_splitCase_slot0IsNotTheCustodyAddress() public {
        IAdManager.OrderParams memory p = _lock(SIGNER);
        _module(p.adCreator);
        vm.expectRevert(abi.encodeWithSelector(RootVerifierRegistry.RootNotValid.selector, orderChainId, ROOT));
        adManager.unlock(p, bytes32("S2"), ROOT, hex"", hex"");
    }

    function test_unlock_revertsAfterDeadline_andPassesAtIt() public {
        IAdManager.OrderParams memory p = _lock(SIGNER);
        _module(SIGNER);
        vm.warp(p.deadline + 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderExpired.selector, p.deadline));
        adManager.unlock(p, bytes32("D1"), ROOT, hex"", hex"");
        vm.warp(p.deadline);
        adManager.unlock(p, bytes32("D1"), ROOT, hex"", hex"");
    }

    function test_deadlineIsHashed() public {
        test_fundAd_makerOnly();
        IAdManager.OrderParams memory p = _defaultParams(lastAdId);
        bytes32 h = adManager.hashOrderPublic(p);
        p.deadline += 1;
        assertTrue(adManager.hashOrderPublic(p) != h);
    }

    function test_lock_rejectsAWideAmount() public {
        test_fundAd_makerOnly();
        IAdManager.OrderParams memory p = _defaultParams(lastAdId);
        p.adChainToken = _b32(address(adToken));
        p.amount = uint256(type(uint128).max) + 1;
        vm.prank(maker);
        vm.expectRevert(OrderHash.OrderHash__AmountTooWide.selector);
        adManager.lockForOrder(p);
    }
}

// The same on the OrderPortal unlock path.
contract OrderPortalOrderV2Test is OrderPortalTest {
    bytes32 constant SIGNER = bytes32(uint256(0x5161e7));
    bytes32 constant ROOT = bytes32(uint256(7));

    function _create(bytes32 signer) internal returns (IOrderPortal.OrderParams memory p) {
        test_setTokenRoute_setsAndEmits_whenSupported();
        p = _defaultParams();
        p.adSettlementSigner = signer;
        orderToken.mint(bridger, p.amount);
        vm.startPrank(bridger);
        orderToken.approve(address(portal), p.amount);
        portal.createOrder(p);
        vm.stopPrank();
    }

    function _module(bytes32 expected) internal {
        address module = address(new Slot0RootVerifier(expected));
        vm.prank(admin);
        portal.setRootVerifier(adChainId, module);
    }

    function test_splitCase_slot0IsTheSettlementSigner() public {
        IOrderPortal.OrderParams memory p = _create(SIGNER);
        assertTrue(p.adSettlementSigner != p.adCreator);
        _module(SIGNER);
        portal.unlock(p, bytes32("S1"), ROOT, hex"", hex"");
        assertEq(uint256(portal.orders(portal.hashOrderPublic(p))), uint256(IEscrow.Status.Filled));
    }

    function test_splitCase_slot0IsNotTheCustodyAddress() public {
        IOrderPortal.OrderParams memory p = _create(SIGNER);
        _module(p.adCreator);
        vm.expectRevert(abi.encodeWithSelector(RootVerifierRegistry.RootNotValid.selector, adChainId, ROOT));
        portal.unlock(p, bytes32("S2"), ROOT, hex"", hex"");
    }

    function test_unlock_revertsAfterDeadline_andPassesAtIt() public {
        IOrderPortal.OrderParams memory p = _create(SIGNER);
        _module(SIGNER);
        vm.warp(p.deadline + 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderExpired.selector, p.deadline));
        portal.unlock(p, bytes32("D1"), ROOT, hex"", hex"");
        vm.warp(p.deadline);
        portal.unlock(p, bytes32("D1"), ROOT, hex"", hex"");
    }

    function test_create_rejectsAWideDeadline() public {
        test_setTokenRoute_setsAndEmits_whenSupported();
        IOrderPortal.OrderParams memory p = _defaultParams();
        p.deadline = uint256(type(uint64).max) + 1;
        orderToken.mint(bridger, p.amount);
        vm.startPrank(bridger);
        orderToken.approve(address(portal), p.amount);
        vm.expectRevert(OrderHash.OrderHash__DeadlineTooWide.selector);
        portal.createOrder(p);
        vm.stopPrank();
    }
}
