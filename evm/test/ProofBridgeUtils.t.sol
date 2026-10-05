// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {ProofBridgeUtils} from "src/libraries/ProofBridgeUtils.sol";
import {DecimalScaling} from "src/libraries/DecimalScaling.sol";
import {OrderHash} from "src/libraries/OrderHash.sol";
import {AddressCast} from "src/libraries/AddressCast.sol";
import {IEscrow} from "src/interfaces/IEscrow.sol";
import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IOrderPortal} from "src/interfaces/IOrderPortal.sol";
import {AdManagerTest} from "./Admanager.t.sol";
import {OrderPortalTest} from "./OrderPortal.t.sol";

/// A token with no `decimals()`: the call reverts inside the callee, which is what the typed
/// `DecimalsUnavailable` wraps.
contract NoDecimals {}

/*//////////////////////////////////////////////////////////////
    THE DOOR: every public entry point of the deployed library answers exactly as the internal
    library it fronts. These calls are real DELEGATECALLs into the linked copy — the path the
    escrows run through, and the struct-selector path the deploy probe depends on.
//////////////////////////////////////////////////////////////*/
contract ProofBridgeUtilsDoorTest is Test {
    using stdJson for string;

    string internal v;

    function setUp() public {
        v = vm.readFile("../test-vectors/order-hash-v2.json");
    }

    // ── scale ──
    function test_scale_matchesInternal() public pure {
        assertEq(ProofBridgeUtils.scale(1_000_000, 6, 18), DecimalScaling.scale(1_000_000, 6, 18));
        assertEq(ProofBridgeUtils.scale(1_000_000, 6, 18), 1e18);
        assertEq(ProofBridgeUtils.scale(5e18, 18, 6), DecimalScaling.scale(5e18, 18, 6));
        assertEq(ProofBridgeUtils.scale(7, 9, 9), 7);
    }

    function testFuzz_scale_matchesInternal(uint128 amount, uint8 fromDec, uint8 toDec) public pure {
        fromDec = uint8(bound(fromDec, 0, 30));
        toDec = uint8(bound(toDec, 0, 30));
        // Scale-down must be exact or both revert the same way; keep the fuzz on the agreeing path.
        if (toDec < fromDec) {
            amount = uint128((uint256(amount) / 10 ** uint256(fromDec - toDec)) * 10 ** uint256(fromDec - toDec));
        }
        assertEq(ProofBridgeUtils.scale(amount, fromDec, toDec), DecimalScaling.scale(amount, fromDec, toDec));
    }

    function test_scale_revertsAsInternal() public {
        vm.expectRevert(abi.encodeWithSelector(DecimalScaling.DecimalScaling__NonExactDownscale.selector, 1, 18, 6));
        ProofBridgeUtils.scale(1, 18, 6);
        vm.expectRevert(abi.encodeWithSelector(DecimalScaling.DecimalScaling__DecimalsOutOfRange.selector, 31));
        ProofBridgeUtils.scale(1, 31, 6);
    }

    // ── assertInRange ──
    function test_assertInRange_matchesInternal() public {
        for (uint8 d = 0; d <= DecimalScaling.MAX_DECIMALS; d++) {
            ProofBridgeUtils.assertInRange(d);
            DecimalScaling.assertInRange(d);
        }
        vm.expectRevert(abi.encodeWithSelector(DecimalScaling.DecimalScaling__DecimalsOutOfRange.selector, 31));
        ProofBridgeUtils.assertInRange(31);
    }

    // ── assertMatchesOnChain ──
    function test_assertMatchesOnChain_matchesInternal() public {
        address token = address(new ERC20Mock()); // 18 decimals
        ProofBridgeUtils.assertMatchesOnChain(token, 18);
        DecimalScaling.assertMatchesOnChain(token, 18);
        ProofBridgeUtils.assertMatchesOnChain(AddressCast.NATIVE_TOKEN_ADDRESS, DecimalScaling.NATIVE_DECIMALS);

        vm.expectRevert(abi.encodeWithSelector(DecimalScaling.DecimalScaling__DecimalsMismatch.selector, 18, 6));
        ProofBridgeUtils.assertMatchesOnChain(token, 6);
        vm.expectRevert(abi.encodeWithSelector(DecimalScaling.DecimalScaling__DecimalsMismatch.selector, 18, 6));
        ProofBridgeUtils.assertMatchesOnChain(AddressCast.NATIVE_TOKEN_ADDRESS, 6);
        address mute = address(new NoDecimals());
        vm.expectRevert(abi.encodeWithSelector(DecimalScaling.DecimalScaling__DecimalsUnavailable.selector, mute));
        ProofBridgeUtils.assertMatchesOnChain(mute, 18);
    }

    // ── checkWidths ──
    function test_checkWidths_matchesInternal() public {
        ProofBridgeUtils.checkWidths(type(uint128).max, type(uint128).max, type(uint128).max, type(uint64).max);
        vm.expectRevert(OrderHash.OrderHash__AmountTooWide.selector);
        ProofBridgeUtils.checkWidths(_uint(".rejects[0].value"), 1, 1, 0);
        vm.expectRevert(OrderHash.OrderHash__DeadlineTooWide.selector);
        ProofBridgeUtils.checkWidths(1, 1, 1, _uint(".rejects[1].value"));
        vm.expectRevert(OrderHash.OrderHash__ChainIdTooWide.selector);
        ProofBridgeUtils.checkWidths(1, uint256(type(uint128).max) + 1, 1, 0);
        vm.expectRevert(OrderHash.OrderHash__ChainIdTooWide.selector);
        ProofBridgeUtils.checkWidths(1, 1, uint256(type(uint128).max) + 1, 0);
    }

    // ── digest: every frozen vector, through the door, equals the internal hash and the fixture ──
    function test_digest_everyVectorThroughTheDoor() public view {
        uint256 count = v.readUint(".count");
        assertGe(count, 11, "vector set shrank");
        for (uint256 i = 0; i < count; i++) {
            string memory p = string.concat(".vectors[", vm.toString(i), "]");
            OrderHash.Order memory o = _order(p);
            string memory name = v.readString(string.concat(p, ".name"));
            bytes32 expected = v.readBytes32(string.concat(p, ".expected.orderHash"));
            assertEq(ProofBridgeUtils.digest(o), expected, name);
            assertEq(ProofBridgeUtils.digest(o), OrderHash.digest(o), name);
        }
    }

    function _uint(string memory key) internal view returns (uint256) {
        return vm.parseUint(v.readString(key));
    }

    /// Same parser as `OrderHashParity.t.sol` (one file, one layout; both read `.order`).
    function _order(string memory p) internal view returns (OrderHash.Order memory o) {
        o.orderChainToken = v.readBytes32(string.concat(p, ".order.orderChainToken"));
        o.adChainToken = v.readBytes32(string.concat(p, ".order.adChainToken"));
        o.amount = _uint(string.concat(p, ".order.amount"));
        o.bridger = v.readBytes32(string.concat(p, ".order.bridger"));
        o.orderChainId = _uint(string.concat(p, ".order.orderChainId"));
        o.orderPortal = v.readBytes32(string.concat(p, ".order.orderPortal"));
        o.orderRecipient = v.readBytes32(string.concat(p, ".order.orderRecipient"));
        o.adChainId = _uint(string.concat(p, ".order.adChainId"));
        o.adManager = v.readBytes32(string.concat(p, ".order.adManager"));
        o.adId = v.readString(string.concat(p, ".order.adId"));
        o.adCreator = v.readBytes32(string.concat(p, ".order.adCreator"));
        o.adRecipient = v.readBytes32(string.concat(p, ".order.adRecipient"));
        o.salt = _uint(string.concat(p, ".order.salt"));
        o.orderDecimals = uint8(v.readUint(string.concat(p, ".order.orderDecimals")));
        o.adDecimals = uint8(v.readUint(string.concat(p, ".order.adDecimals")));
        o.deadline = _uint(string.concat(p, ".order.deadline"));
        o.adSettlementSigner = v.readBytes32(string.concat(p, ".order.adSettlementSigner"));
    }
}

/*//////////////////////////////////////////////////////////////
    THE ESCROWS: each guard the library carries refuses a lock, and the revert decodes by the
    error `IEscrow` re-declares (the compiler no longer lists these on the escrow ABI itself).
//////////////////////////////////////////////////////////////*/
contract AdManagerLibraryGuards is AdManagerTest {
    function test_lock_rejects_adDecimalsNotTheTokens() public {
        test_fundAd_makerOnly();
        IAdManager.OrderParams memory p = _defaultParams(lastAdId);
        p.adDecimals = 6; // the ad token has 18
        vm.prank(maker);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.DecimalScaling__DecimalsMismatch.selector, 18, 6));
        adManager.lockForOrder(p);
    }

    function test_lock_rejects_decimalsOutOfRange() public {
        test_fundAd_makerOnly();
        IAdManager.OrderParams memory p = _defaultParams(lastAdId);
        p.orderDecimals = 31;
        vm.prank(maker);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.DecimalScaling__DecimalsOutOfRange.selector, 31));
        adManager.lockForOrder(p);
    }
}

contract OrderPortalLibraryGuards is OrderPortalTest {
    function test_createOrder_rejects_orderDecimalsNotTheTokens() public {
        test_setTokenRoute_setsAndEmits_whenSupported();
        IOrderPortal.OrderParams memory p = _defaultParams();
        p.orderDecimals = 6; // the order token has 18
        vm.prank(bridger);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.DecimalScaling__DecimalsMismatch.selector, 18, 6));
        portal.createOrder(p);
    }

    function test_createOrder_rejects_decimalsOutOfRange() public {
        test_setTokenRoute_setsAndEmits_whenSupported();
        IOrderPortal.OrderParams memory p = _defaultParams();
        p.adDecimals = 31;
        vm.prank(bridger);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.DecimalScaling__DecimalsOutOfRange.selector, 31));
        portal.createOrder(p);
    }

    function test_createOrder_rejects_amountTooWide() public {
        test_setTokenRoute_setsAndEmits_whenSupported();
        IOrderPortal.OrderParams memory p = _defaultParams();
        p.amount = uint256(type(uint128).max) + 1;
        vm.prank(bridger);
        vm.expectRevert(IEscrow.OrderHash__AmountTooWide.selector);
        portal.createOrder(p);
    }
}
