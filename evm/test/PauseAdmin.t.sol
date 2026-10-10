// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {TestField} from "test/utils/TestField.sol";

import {Test} from "forge-std/Test.sol";
import {IBLSKeyRegistry} from "src/interfaces/IBLSKeyRegistry.sol";
import {IRootAnchor} from "src/interfaces/IRootAnchor.sol";
import {IVerifier} from "src/interfaces/IVerifier.sol";
import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IOrderPortal} from "src/interfaces/IOrderPortal.sol";
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
        registry = new BLSKeyRegistry(address(this), "local");
    }

    function test_pause_blocksRegisterAndRevoke() public {
        registry.pause();

        IBLSKeyRegistry.OwnerAuth memory auth;
        auth.sig = new bytes(65);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        registry.register(bytes32(uint256(1)), auth, new bytes(128), new bytes(256), 0, uint64(block.timestamp));

        vm.expectRevert(Pausable.EnforcedPause.selector);
        registry.revoke(bytes32(uint256(1)), auth, 0);

        registry.unpause();
        vm.expectRevert(IBLSKeyRegistry.IdentityKey.selector);
        registry.register(bytes32(uint256(1)), auth, new bytes(128), new bytes(256), 0, uint64(block.timestamp));
    }

    function test_twoStepAdmin_transferAndAccept() public {
        address next = makeAddr("nextAdmin");
        vm.expectEmit(true, true, false, false, address(registry));
        emit TwoStepAdmin.AdminTransferStarted(address(this), next);
        registry.transferAdmin(next);
        assertEq(registry.pendingAdmin(), next);

        vm.prank(makeAddr("rando"));
        vm.expectRevert(TwoStepAdmin.NotPendingAdmin.selector);
        registry.acceptAdmin();

        vm.expectEmit(true, true, false, false, address(registry));
        emit TwoStepAdmin.AdminTransferred(address(this), next);
        vm.prank(next);
        registry.acceptAdmin();
        assertEq(registry.admin(), next);

        vm.expectRevert(TwoStepAdmin.NotAdmin.selector);
        registry.pause();
        vm.prank(next);
        registry.pause();
    }

    function test_pause_blocksRegisterByProofAndCancel() public {
        registry.pause();
        IBLSKeyRegistry.OwnerAuth memory auth;
        vm.expectRevert(Pausable.EnforcedPause.selector);
        registry.registerByProof(bytes32(uint256(1)), new bytes(128), new bytes(256), 0, 1, bytes32(0), "");
        vm.expectRevert(Pausable.EnforcedPause.selector);
        registry.cancel(bytes32(uint256(1)), auth, 0);
    }

    /// The registry runs the shared handover: nominating the sitting admin is refused.
    function test_twoStepAdmin_selfTransferRefused() public {
        vm.expectRevert(abi.encodeWithSelector(TwoStepAdmin.InvalidAdmin.selector, address(this)));
        registry.transferAdmin(address(this));
    }

    function test_twoStepAdmin_cancelByZero() public {
        address next = makeAddr("nextAdmin");
        registry.transferAdmin(next);
        registry.transferAdmin(address(0));
        assertEq(registry.pendingAdmin(), address(0));
        vm.prank(next);
        vm.expectRevert(TwoStepAdmin.NotPendingAdmin.selector);
        registry.acceptAdmin();
    }

    /// After the handover the old admin holds none of the admin calls.
    function test_twoStepAdmin_oldAdminLosesEveryAdminCall() public {
        address next = makeAddr("nextAdmin");
        registry.transferAdmin(next);
        vm.prank(next);
        registry.acceptAdmin();
        assertEq(registry.pendingAdmin(), address(0));

        vm.expectRevert(TwoStepAdmin.NotAdmin.selector);
        registry.pause();
        vm.expectRevert(TwoStepAdmin.NotAdmin.selector);
        registry.transferAdmin(address(1));
        vm.expectRevert(TwoStepAdmin.NotAdmin.selector);
        registry.setPositionGuards(new address[](0));
        vm.expectRevert(TwoStepAdmin.NotAdmin.selector);
        registry.setProofRegistration(IRootAnchor(address(0)), IVerifier(address(0)), new uint256[](0), false);
    }

    function test_adminCalls_strangerRefused() public {
        registry.pause();
        vm.startPrank(makeAddr("rando"));
        vm.expectRevert(TwoStepAdmin.NotAdmin.selector);
        registry.unpause();
        vm.expectRevert(TwoStepAdmin.NotAdmin.selector);
        registry.setPositionGuards(new address[](0));
        vm.stopPrank();
    }

    /// Pause and unpause are OZ's: repeating either reverts instead of re-emitting.
    function test_pause_notIdempotent() public {
        vm.expectRevert(Pausable.ExpectedPause.selector);
        registry.unpause();
        registry.pause();
        assertTrue(registry.paused());
        vm.expectRevert(Pausable.EnforcedPause.selector);
        registry.pause();
        registry.unpause();
        assertFalse(registry.paused());
    }
}

/// C-37: the BLS key registry refuses a zero admin at construction. (MerkleManager's manager list and
/// its admin handover are covered in `MerkleManager.t.sol`.)
contract BLSKeyRegistryZeroAdminTest is Test {
    function test_c37_blsRegistryRefusesZeroAdmin() public {
        vm.expectRevert(IBLSKeyRegistry.ZeroAdmin.selector);
        new BLSKeyRegistry(address(0), "local");
    }
}
