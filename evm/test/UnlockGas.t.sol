// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {OrderPortalGateTest, AdManagerGateTest} from "./UnlockGates.t.sol";
import {MockRootVerifier} from "./mocks/MockRootVerifier.sol";
import {console2} from "forge-std/console2.sol";

// 1.6c cost-measurement gate: gas for a single unlock external call, asserted
// against an in-source ceiling so a regression fails the build. Ceilings are the
// measured baseline plus ~10% headroom; keep headroom generous across toolchain bumps.

contract OrderPortalUnlockGas is OrderPortalGateTest {
    uint256 constant ORDER_PORTAL_UNLOCK_GAS_CEILING = 400_000;

    function test_orderPortalUnlockGas() public {
        _prepareUnlock(address(cVerifier), vOrderRoot);
        bytes memory cosig = _cosigData();

        uint256 g0 = gasleft();
        portal.unlock(gp, bytes32("NG"), vOrderRoot, hex"", cosig);
        uint256 used = g0 - gasleft();

        console2.log("OrderPortal.unlock gas:", used);
        assertLe(used, ORDER_PORTAL_UNLOCK_GAS_CEILING);
    }
}

contract AdManagerUnlockGas is AdManagerGateTest {
    uint256 constant AD_MANAGER_UNLOCK_GAS_CEILING = 82_000;

    function test_adManagerUnlockGas() public {
        _prepareUnlock(address(new MockRootVerifier(true)), bytes32(uint256(5)));

        uint256 g0 = gasleft();
        adManager.unlock(gp, bytes32("NG"), bytes32(uint256(5)), hex"", hex"");
        uint256 used = g0 - gasleft();

        console2.log("AdManager.unlock gas:", used);
        assertLe(used, AD_MANAGER_UNLOCK_GAS_CEILING);
    }
}
