// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {OrderHash} from "../src/libraries/OrderHash.sol";

contract WidthHarness {
    function check(uint256 amount, uint256 orderChainId, uint256 adChainId, uint256 deadline) external pure {
        OrderHash.checkWidths(amount, orderChainId, adChainId, deadline);
    }
}

/// 17-field EIP-712 order-hash parity (T-19, T-66) against the frozen 2.5b fixture. The same file
/// drives the Soroban and relayer suites; each recomputes every vector's committed hashes.
contract OrderHashParityTest is Test {
    using stdJson for string;

    string internal v;

    function setUp() public {
        v = vm.readFile("../test-vectors/order-hash-v2.json");
    }

    function test_typehashIsTheFixtureString() public view {
        assertEq(OrderHash.ORDER_TYPEHASH, keccak256(bytes(v.readString("._meta.orderTypeString"))));
        assertEq(OrderHash.ORDER_TYPEHASH, v.readBytes32("._meta.orderTypehash"));
    }

    function test_domainSeparatorMatchesFixture() public view {
        assertEq(OrderHash.domainSeparator(), v.readBytes32("._meta.domainSeparator"));
    }

    function _uint(string memory key) internal view returns (uint256) {
        return vm.parseUint(v.readString(key));
    }

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

    function test_everyVectorHashesAsFrozen() public view {
        uint256 count = v.readUint(".count");
        assertGe(count, 11, "vector set shrank");
        for (uint256 i = 0; i < count; i++) {
            string memory p = string.concat(".vectors[", vm.toString(i), "]");
            OrderHash.Order memory o = _order(p);
            string memory name = v.readString(string.concat(p, ".name"));
            assertEq(OrderHash.structHash(o), v.readBytes32(string.concat(p, ".expected.structHash")), name);
            assertEq(OrderHash.digest(o), v.readBytes32(string.concat(p, ".expected.orderHash")), name);
        }
    }

    function test_rejectsAreRejectedNeverHashed() public {
        WidthHarness h = new WidthHarness();
        assertEq(v.readString(".rejects[0].field"), "amount");
        assertEq(v.readString(".rejects[1].field"), "deadline");

        vm.expectRevert(OrderHash.OrderHash__AmountTooWide.selector);
        h.check(_uint(".rejects[0].value"), 1, 1, 0);
        vm.expectRevert(OrderHash.OrderHash__DeadlineTooWide.selector);
        h.check(1, 1, 1, _uint(".rejects[1].value"));
        vm.expectRevert(OrderHash.OrderHash__ChainIdTooWide.selector);
        h.check(1, uint256(type(uint128).max) + 1, 1, 0);

        // the widest accepted values pass
        h.check(type(uint128).max, type(uint128).max, type(uint128).max, type(uint64).max);
    }
}
