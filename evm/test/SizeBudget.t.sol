// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {AdManager} from "src/AdManager.sol";
import {OrderPortal} from "src/OrderPortal.sol";
import {IVerifier} from "src/interfaces/IVerifier.sol";
import {IMerkleManager} from "src/interfaces/IMerkleManager.sol";
import {IwNativeToken} from "src/wNativeToken.sol";

/// EIP-170 tripwire. AdManager sat 135 bytes under the 24,576 limit before `ProofBridgeUtils` became
/// a linked library (23,936 after). This fails 376 bytes before the wall so the
/// next feature gets a red test here, not a red build, and the fix is decided with room to measure
/// (the measured candidates are in the size handoff; "many call sites x small interface" is what pays).
/// Metered on the deployed code, so the link placeholders are resolved the way they are on chain.
contract SizeBudgetTest is Test {
    uint256 internal constant EIP170_LIMIT = 24_576;
    uint256 internal constant AD_MANAGER_BUDGET = 24_200;

    address internal constant SOME = address(0x1111);

    function test_adManager_underSizeBudget() public {
        AdManager a = new AdManager(SOME, IVerifier(SOME), IMerkleManager(SOME), IwNativeToken(SOME));
        uint256 size = address(a).code.length;
        emit log_named_uint("AdManager deployed code bytes", size);
        assertLe(size, AD_MANAGER_BUDGET, "AdManager is within 376 B of EIP-170: measure before adding code");
    }

    /// OrderPortal has ~9.6 KB of room; pinned at the same budget only so a runaway change shows here too.
    function test_orderPortal_underSizeBudget() public {
        OrderPortal p = new OrderPortal(SOME, IVerifier(SOME), IMerkleManager(SOME), IwNativeToken(SOME));
        uint256 size = address(p).code.length;
        emit log_named_uint("OrderPortal deployed code bytes", size);
        assertLe(size, AD_MANAGER_BUDGET);
    }

    /// The budget is a warning line, not the limit: it must sit below EIP-170 or it guards nothing.
    function test_budgetIsBelowTheLimit() public pure {
        assertLt(AD_MANAGER_BUDGET, EIP170_LIMIT);
    }
}
