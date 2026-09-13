// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {AdManagerTest, MockAdManager} from "./Admanager.t.sol";
import {OrderPortalTest} from "./OrderPortal.t.sol";
import {AdManager} from "src/AdManager.sol";
import {OrderPortal} from "src/OrderPortal.sol";
import {IVerifier} from "src/Verifier.sol";
import {IMerkleManager} from "src/MerkleManager.sol";
import {IwNativeToken} from "src/wNativeToken.sol";
import {MockRootVerifier} from "./mocks/MockRootVerifier.sol";

/// 2.3c (#340): the escrow binding (design 01 §1.4), the re-pointing lever (§1.5), and
/// `inFlightOf` counted only for the party each escrow authenticated (D1). T-12, T-13, T-14.
contract EscrowBindingAdManagerTest is AdManagerTest {
    bytes32 internal other32;

    function setUp() public override {
        super.setUp();
        other32 = _b32(other);
    }

    function _routeAd() internal {
        vm.startPrank(admin);
        adManager.setChain(orderChainId, _b32(orderPortal), true);
        adManager.setTokenRoute(address(adToken), _b32(orderToken), orderChainId);
        vm.stopPrank();
    }

    function _signerOf(string memory adId) internal view returns (bytes32 s) {
        (,,,,,,,, s) = adManager.ads(adId);
    }

    function _assertNoPositions(bytes32 who) internal view {
        assertFalse(adManager.hasOpenPositions(who));
        assertEq(adManager.inFlightOf(who), 0);
    }

    /*//////////////////////////////////////////////////////////////
                T-12 — only the authenticated party is counted
    //////////////////////////////////////////////////////////////*/

    function test_lock_countsMakerOnly() public {
        test_fundAd_makerOnly();
        (AdManager.OrderParams memory p,) = _openOrder(lastAdId, address(adToken), 60 ether, 1, bridger, recipient);

        assertEq(adManager.inFlightOf(p.adCreator), 1);
        assertTrue(adManager.hasOpenPositions(p.adCreator));
        _assertNoPositions(p.bridger);
    }

    function test_lock_namingThirdPartyBridger_leavesTheirCounterAtZero() public {
        test_fundAd_makerOnly();
        _openOrder(lastAdId, address(adToken), 60 ether, 2, other, recipient);
        _assertNoPositions(other32);
    }

    /*//////////////////////////////////////////////////////////////
          T-13 — the counter clears on the terminal (unlock, today)
    //////////////////////////////////////////////////////////////*/

    function test_lockThenUnlock_clearsMaker() public {
        test_fundAd_makerOnly();
        (AdManager.OrderParams memory p,) = _openOrder(lastAdId, address(adToken), 60 ether, 3, bridger, recipient);

        vm.prank(bridger);
        adManager.unlock(p, bytes32("EB1"), bytes32(uint256(3)), hex"", hex"");

        _assertNoPositions(p.adCreator);
        _assertNoPositions(p.bridger);
    }

    /*//////////////////////////////////////////////////////////////
                    T-14 — the createAd gate (D2)
    //////////////////////////////////////////////////////////////*/

    function test_createAd_zeroSigner_reverts() public {
        _routeAd();
        vm.startPrank(maker);
        adToken.approve(address(adManager), initAmt);
        vm.expectRevert(AdManager.AdManager__SettlementSignerZero.selector);
        adManager.createAd("z", address(adToken), initAmt, orderChainId, _b32(adRecipient), bytes32(0));
        vm.stopPrank();
    }

    function test_createAd_unregisteredSigner_reverts() public {
        _routeAd();
        vm.startPrank(maker);
        adToken.approve(address(adManager), initAmt);
        vm.expectRevert(abi.encodeWithSelector(AdManager.AdManager__SignerNotRegistered.selector, other32));
        adManager.createAd("u", address(adToken), initAmt, orderChainId, _b32(adRecipient), other32);
        vm.stopPrank();
    }

    function test_createAd_noRegistry_reverts() public {
        // A fresh escrow with no registry set fails closed, whatever the signer.
        MockAdManager bare = new MockAdManager(
            admin,
            IVerifier(address(verifier)),
            IMerkleManager(address(merkleManager)),
            IwNativeToken(address(_wNativeToken))
        );
        vm.startPrank(admin);
        bare.setChain(orderChainId, _b32(orderPortal), true);
        bare.setTokenRoute(address(adToken), _b32(orderToken), orderChainId);
        vm.stopPrank();

        vm.startPrank(maker);
        adToken.approve(address(bare), initAmt);
        vm.expectRevert(AdManager.AdManager__NoKeyRegistry.selector);
        bare.createAd("n", address(adToken), initAmt, orderChainId, _b32(adRecipient), _b32(maker));
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
              T-14 — setSettlementSigner, the third lever (D3)
    //////////////////////////////////////////////////////////////*/

    function test_setSettlementSigner_withLocksInFlight_succeeds() public {
        test_fundAd_makerOnly();
        _openOrder(lastAdId, address(adToken), 60 ether, 4, bridger, recipient);
        keyRegistry.set(other32, true);

        vm.expectEmit(true, false, false, true);
        emit AdManager.SettlementSignerSet(lastAdId, _b32(maker), other32);
        vm.prank(maker);
        adManager.setSettlementSigner(lastAdId, other32);

        assertEq(_signerOf(lastAdId), other32);
    }

    function test_setSettlementSigner_notMaker_reverts() public {
        test_fundAd_makerOnly();
        keyRegistry.set(other32, true);
        vm.prank(nonMaker);
        vm.expectRevert(AdManager.AdManager__NotMaker.selector);
        adManager.setSettlementSigner(lastAdId, other32);
    }

    function test_setSettlementSigner_unregistered_reverts() public {
        test_fundAd_makerOnly();
        vm.prank(maker);
        vm.expectRevert(abi.encodeWithSelector(AdManager.AdManager__SignerNotRegistered.selector, other32));
        adManager.setSettlementSigner(lastAdId, other32);
    }

    function test_lockedOrder_stillSettlesUnderOldSigner_afterRepoint() public {
        test_fundAd_makerOnly();
        (AdManager.OrderParams memory p,) = _openOrder(lastAdId, address(adToken), 60 ether, 5, bridger, recipient);

        keyRegistry.set(other32, true);
        vm.prank(maker);
        adManager.setSettlementSigner(lastAdId, other32);

        // The order settles against the signer frozen in its hash, never the ad's current field.
        vm.prank(bridger);
        adManager.unlock(p, bytes32("EB5"), bytes32(uint256(3)), hex"", hex"");
        _assertNoPositions(p.adCreator);
    }

    /*//////////////////////////////////////////////////////////////
                  T-14 — the lock-time equality (§1.4)
    //////////////////////////////////////////////////////////////*/

    function test_lock_signerMismatch_reverts() public {
        test_fundAd_makerOnly();
        AdManager.OrderParams memory p = _defaultParams(lastAdId);
        p.salt = 6;
        p.adSettlementSigner = other32;

        vm.prank(maker);
        vm.expectRevert(
            abi.encodeWithSelector(AdManager.AdManager__SettlementSignerMismatch.selector, _b32(maker), other32)
        );
        adManager.lockForOrder(p);
    }

    function test_lock_afterRepoint_requiresTheNewSigner() public {
        test_fundAd_makerOnly();
        keyRegistry.set(other32, true);
        vm.prank(maker);
        adManager.setSettlementSigner(lastAdId, other32);

        AdManager.OrderParams memory p = _defaultParams(lastAdId);
        p.salt = 7;
        vm.prank(maker);
        vm.expectRevert(
            abi.encodeWithSelector(AdManager.AdManager__SettlementSignerMismatch.selector, other32, _b32(maker))
        );
        adManager.lockForOrder(p);

        p.adSettlementSigner = other32;
        vm.prank(maker);
        adManager.lockForOrder(p);
    }
}

contract EscrowBindingOrderPortalTest is OrderPortalTest {
    function _create(uint256 salt) internal returns (OrderPortal.OrderParams memory p) {
        test_setTokenRoute_setsAndEmits_whenSupported();
        p = _defaultParams();
        p.salt = salt;
        orderToken.mint(bridger, p.amount);
        vm.startPrank(bridger);
        orderToken.approve(address(portal), p.amount);
        portal.createOrder(p);
        vm.stopPrank();
    }

    /// T-12: the portal counts the bridger it authenticated, not the maker it only names.
    function test_createOrder_countsBridgerOnly() public {
        OrderPortal.OrderParams memory p = _create(9001);
        assertEq(portal.inFlightOf(p.bridger), 1);
        assertTrue(portal.hasOpenPositions(p.bridger));
        assertEq(portal.inFlightOf(p.adCreator), 0);
        assertFalse(portal.hasOpenPositions(p.adCreator));
    }

    /// T-13: unlock mirrors createOrder, so the bridger's counter returns to zero.
    function test_createThenUnlock_clearsBridger() public {
        OrderPortal.OrderParams memory p = _create(9002);
        // Deploy first: a `new` inside the argument list would consume the prank.
        address module = address(new MockRootVerifier(true));
        vm.prank(admin);
        portal.setRootVerifier(adChainId, module);

        portal.unlock(p, bytes32("EB9"), bytes32(uint256(3)), hex"", hex"");

        assertEq(portal.inFlightOf(p.bridger), 0);
        assertFalse(portal.hasOpenPositions(p.bridger));
        assertEq(portal.inFlightOf(p.adCreator), 0);
    }
}
