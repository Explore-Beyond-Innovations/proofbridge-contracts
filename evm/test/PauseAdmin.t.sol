// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {AdManagerTest} from "./Admanager.t.sol";
import {OrderPortalTest} from "./OrderPortal.t.sol";
import {AdManager} from "src/AdManager.sol";
import {OrderPortal} from "src/OrderPortal.sol";
import {BLSKeyRegistry} from "src/BLSKeyRegistry.sol";
import {TwoStepAdmin} from "src/libraries/TwoStepAdmin.sol";

contract AdManagerPauseTest is AdManagerTest {
    function test_pause_blocksAllEntryPoints() public {
        test_fundAd_makerOnly();
        string memory adId = lastAdId;

        vm.prank(admin);
        adManager.pause();

        vm.prank(maker);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        adManager.createAd("pausedAd", address(adToken), 0, orderChainId, _b32(adRecipient));

        vm.prank(maker);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        adManager.fundAd(adId, 1 ether);

        AdManager.OrderParams memory p = _defaultParams(adId);
        bytes32 orderHash = adManager.hashOrderPublic(p);
        vm.prank(maker);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        adManager.lockForOrder(p);

        vm.prank(bridger);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        adManager.unlock(p, bytes32("N"), bytes32(0), hex"", hex"");
    }

    function test_unpause_restores() public {
        vm.prank(admin);
        adManager.pause();
        vm.prank(admin);
        adManager.unpause();
        test_fundAd_makerOnly();
    }

    function test_pause_onlyAdmin() public {
        vm.prank(maker);
        vm.expectRevert();
        adManager.pause();
    }

    function test_twoStepAdmin_transferAndAccept() public {
        address next = makeAddr("nextAdmin");

        vm.prank(admin);
        adManager.transferAdmin(next);
        assertEq(adManager.pendingAdmin(), next);
        assertEq(adManager.admin(), admin);

        vm.prank(maker);
        vm.expectRevert(TwoStepAdmin.NotPendingAdmin.selector);
        adManager.acceptAdmin();

        vm.prank(next);
        adManager.acceptAdmin();
        assertEq(adManager.admin(), next);
        assertEq(adManager.pendingAdmin(), address(0));

        vm.prank(next);
        adManager.pause();

        vm.prank(admin);
        vm.expectRevert();
        adManager.pause();
    }
}

contract OrderPortalPauseTest is OrderPortalTest {
    function test_pause_blocksCreateAndUnlock() public {
        test_setTokenRoute_setsAndEmits_whenSupported();
        (OrderPortal.OrderParams memory p, bytes32 orderHash) = _openOrder(65 ether, 321);

        vm.prank(admin);
        portal.pause();

        OrderPortal.OrderParams memory p2 = _defaultParams();
        p2.salt = 322;
        bytes32 oh2 = portal.hashOrderPublic(p2);
        vm.prank(bridger);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        portal.createOrder(p2);

        vm.expectRevert(Pausable.EnforcedPause.selector);
        portal.unlock(p, bytes32("N"), bytes32(0), hex"", hex"");

        vm.prank(admin);
        portal.unpause();
        portal.unlock(p, bytes32("N"), bytes32(0), hex"", hex"");
    }

    function test_twoStepAdmin_transferAndAccept() public {
        address next = makeAddr("nextAdmin");
        vm.prank(admin);
        portal.transferAdmin(next);
        vm.prank(next);
        portal.acceptAdmin();
        assertEq(portal.admin(), next);
        vm.prank(next);
        portal.pause();
    }
}

contract RegistryPauseTest is Test {
    BLSKeyRegistry registry;

    function setUp() public {
        registry = new BLSKeyRegistry(address(this));
    }

    function test_pause_blocksRegisterAndRevoke() public {
        registry.pause();

        BLSKeyRegistry.OwnerAuth memory auth = BLSKeyRegistry.OwnerAuth(BLSKeyRegistry.Scheme.Eip712, new bytes(65));
        vm.expectRevert(BLSKeyRegistry.EnforcedPause.selector);
        registry.register(bytes32(uint256(1)), auth, new bytes(128), new bytes(256), 0);

        vm.expectRevert(BLSKeyRegistry.EnforcedPause.selector);
        registry.revoke(bytes32(uint256(1)), auth, 0);

        registry.unpause();
        vm.expectRevert(BLSKeyRegistry.IdentityKey.selector);
        registry.register(bytes32(uint256(1)), auth, new bytes(128), new bytes(256), 0);
    }

    function test_twoStepAdmin_transferAndAccept() public {
        address next = makeAddr("nextAdmin");
        registry.transferAdmin(next);
        assertEq(registry.pendingAdmin(), next);

        vm.prank(makeAddr("rando"));
        vm.expectRevert(BLSKeyRegistry.NotPendingAdmin.selector);
        registry.acceptAdmin();

        vm.prank(next);
        registry.acceptAdmin();
        assertEq(registry.admin(), next);

        vm.expectRevert(BLSKeyRegistry.NotAdmin.selector);
        registry.pause();
        vm.prank(next);
        registry.pause();
    }
}
