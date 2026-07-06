// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {AdManagerTest} from "./Admanager.t.sol";
import {AdManager} from "src/AdManager.sol";

/// An ad settles only on the route it committed to at creation.
contract RouteCommitmentTest is AdManagerTest {
    AdManager.OrderParams rp;

    function _prepareLock(string memory adId, bytes32 orderChainToken, uint256 salt) internal {
        AdManager.OrderParams memory p = _defaultParams(adId);
        p.orderChainToken = orderChainToken;
        p.salt = salt;
        rp = p;

        bytes32 orderHash = adManager.hashOrderPublic(p);
        (authToken, timeToLive, signature) = generateLockForOrderRequestHash(adId, orderHash);
        vm.prank(maker);
    }

    function _lockWithOrderToken(string memory adId, bytes32 orderChainToken, uint256 salt) internal {
        _prepareLock(adId, orderChainToken, salt);
        adManager.lockForOrder(signature, authToken, timeToLive, rp);
    }

    function test_adStoresCommittedRouteAtCreation() public {
        test_fundAd_makerOnly();
        (,,,,,,, bytes32 committed) = adManager.ads(lastAdId);
        assertEq(committed, _b32(orderToken), "route not committed");
    }

    function test_rerouteCannotRedirectExistingAd() public {
        test_fundAd_makerOnly();
        string memory adId = lastAdId;
        address newOrderToken = makeAddr("newOrderToken");

        vm.prank(admin);
        adManager.setTokenRoute(address(adToken), _b32(newOrderToken), orderChainId);

        // matches the new table, not the commitment
        _prepareLock(adId, _b32(newOrderToken), 41);
        vm.expectRevert(
            abi.encodeWithSelector(AdManager.AdManager__RouteMismatch.selector, _b32(orderToken), _b32(newOrderToken))
        );
        adManager.lockForOrder(signature, authToken, timeToLive, rp);

        // matches the commitment, not the table: frozen, not redirected
        _prepareLock(adId, _b32(orderToken), 42);
        vm.expectRevert(
            abi.encodeWithSelector(
                AdManager.AdManager__OrderTokenMismatch.selector, _b32(newOrderToken), _b32(orderToken)
            )
        );
        adManager.lockForOrder(signature, authToken, timeToLive, rp);

        vm.prank(admin);
        adManager.setTokenRoute(address(adToken), _b32(orderToken), orderChainId);
        _lockWithOrderToken(adId, _b32(orderToken), 43);
    }

    /// Lock succeeds only when the offer equals commitment AND live corridor.
    function testFuzz_orderCannotSettleOnWrongRoute(bytes32 offeredToken, bool reroute) public {
        vm.assume(offeredToken != bytes32(0));
        test_fundAd_makerOnly();
        string memory adId = lastAdId;
        bytes32 committed = _b32(orderToken);

        if (reroute) {
            vm.prank(admin);
            adManager.setTokenRoute(address(adToken), bytes32(uint256(uint160(makeAddr("other")))), orderChainId);
        }

        bool shouldSucceed = offeredToken == committed && !reroute;
        _prepareLock(adId, offeredToken, 4242);
        if (!shouldSucceed) {
            vm.expectRevert();
        }
        adManager.lockForOrder(signature, authToken, timeToLive, rp);

        if (shouldSucceed) {
            (,,,,, uint256 locked,,) = adManager.ads(adId);
            assertGt(locked, 0, "lock did not take");
        }
    }
}
