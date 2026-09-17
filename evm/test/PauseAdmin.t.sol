// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {TestField} from "test/utils/TestField.sol";

import {Test} from "forge-std/Test.sol";
import {IBLSKeyRegistry} from "src/interfaces/IBLSKeyRegistry.sol";
import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IOrderPortal} from "src/interfaces/IOrderPortal.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {AdManagerTest} from "./Admanager.t.sol";
import {OrderPortalTest} from "./OrderPortal.t.sol";
import {AdManager} from "src/AdManager.sol";
import {OrderPortal} from "src/OrderPortal.sol";
import {BLSKeyRegistry} from "src/BLSKeyRegistry.sol";
import {TwoStepAdmin} from "src/libraries/TwoStepAdmin.sol";
import {MerkleManager} from "src/MerkleManager.sol";
import {Poseidon2Yul_BN254 as Poseidon2Yul} from "@poseidon2/src/bn254/yul/Poseidon2Yul.sol";

contract AdManagerPauseTest is AdManagerTest {
    function test_pause_blocksAllEntryPoints() public {
        test_fundAd_makerOnly();
        string memory adId = lastAdId;

        vm.prank(admin);
        adManager.pause();

        vm.prank(maker);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        adManager.createAd("pausedAd", address(adToken), 0, orderChainId, _b32(adRecipient), _b32(maker));

        vm.prank(maker);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        adManager.fundAd(adId, 1 ether);

        IAdManager.OrderParams memory p = _defaultParams(adId);
        bytes32 orderHash = adManager.hashOrderPublic(p);
        vm.prank(maker);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        adManager.lockForOrder(p);

        vm.prank(bridger);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        adManager.unlock(p, TestField.fe("N"), bytes32(0), hex"", hex"");
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

    /// A self-nomination would strip the only admin at accept; a zero nomination is the cancel.
    function test_twoStepAdmin_refusesSelf_zeroWithdrawsNomination() public {
        address next = makeAddr("nextAdmin");
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(TwoStepAdmin.InvalidAdmin.selector, admin));
        adManager.transferAdmin(admin);

        vm.prank(admin);
        adManager.transferAdmin(next);
        vm.prank(admin);
        vm.expectEmit(true, true, true, true);
        emit TwoStepAdmin.AdminTransferStarted(admin, address(0));
        adManager.transferAdmin(address(0));
        assertEq(adManager.pendingAdmin(), address(0));

        vm.prank(next);
        vm.expectRevert(TwoStepAdmin.NotPendingAdmin.selector);
        adManager.acceptAdmin();
        assertEq(adManager.admin(), admin);
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
        (IOrderPortal.OrderParams memory p, bytes32 orderHash) = _openOrder(65 ether, 321);

        vm.prank(admin);
        portal.pause();

        IOrderPortal.OrderParams memory p2 = _defaultParams();
        p2.salt = 322;
        bytes32 oh2 = portal.hashOrderPublic(p2);
        vm.prank(bridger);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        portal.createOrder(p2);

        vm.expectRevert(Pausable.EnforcedPause.selector);
        portal.unlock(p, TestField.fe("N"), bytes32(0), hex"", hex"");

        vm.prank(admin);
        portal.unpause();
        portal.unlock(p, TestField.fe("N"), bytes32(0), hex"", hex"");
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

        IBLSKeyRegistry.OwnerAuth memory auth = IBLSKeyRegistry.OwnerAuth(IBLSKeyRegistry.Scheme.Eip712, new bytes(65));
        vm.expectRevert(IBLSKeyRegistry.EnforcedPause.selector);
        registry.register(bytes32(uint256(1)), auth, new bytes(128), new bytes(256), 0);

        vm.expectRevert(IBLSKeyRegistry.EnforcedPause.selector);
        registry.revoke(bytes32(uint256(1)), auth, 0);

        registry.unpause();
        vm.expectRevert(IBLSKeyRegistry.IdentityKey.selector);
        registry.register(bytes32(uint256(1)), auth, new bytes(128), new bytes(256), 0);
    }

    function test_twoStepAdmin_transferAndAccept() public {
        address next = makeAddr("nextAdmin");
        registry.transferAdmin(next);
        assertEq(registry.pendingAdmin(), next);

        vm.prank(makeAddr("rando"));
        vm.expectRevert(IBLSKeyRegistry.NotPendingAdmin.selector);
        registry.acceptAdmin();

        vm.prank(next);
        registry.acceptAdmin();
        assertEq(registry.admin(), next);

        vm.expectRevert(IBLSKeyRegistry.NotAdmin.selector);
        registry.pause();
        vm.prank(next);
        registry.pause();
    }
}

/// MerkleManager is the one contract that still runs OZ roles (`MANAGER_ROLE` for the escrows), so its
/// admin handover has to carry `DEFAULT_ADMIN_ROLE` along or the next admin cannot grant an escrow.
contract MerkleManagerAdminRoleTest is Test {
    MerkleManager internal mm;
    address internal admin = address(0xA11CE);
    address internal next = address(0xB0B);
    address internal escrow = address(0xE5C0);

    function setUp() public {
        mm = new MerkleManager(admin, address(new Poseidon2Yul()));
    }

    function test_adminHandoverCarriesTheRoleAdmin() public {
        // Cached: an argument that is itself a call would eat the prank meant for the next line.
        bytes32 roleAdmin = mm.DEFAULT_ADMIN_ROLE();
        bytes32 manager = mm.MANAGER_ROLE();
        assertTrue(mm.hasRole(roleAdmin, admin));

        vm.prank(admin);
        mm.transferAdmin(next);
        vm.prank(next);
        mm.acceptAdmin();

        assertTrue(mm.hasRole(roleAdmin, next));
        assertFalse(mm.hasRole(roleAdmin, admin));

        vm.prank(next);
        mm.grantRole(manager, escrow);
        assertTrue(mm.hasRole(manager, escrow));

        vm.expectRevert();
        vm.prank(admin);
        mm.grantRole(manager, address(0xDEAD));
    }

    function test_pauseIsAdminOnly() public {
        vm.prank(next);
        vm.expectRevert(TwoStepAdmin.NotAdmin.selector);
        mm.pause();

        vm.prank(admin);
        mm.pause();
    }
}
