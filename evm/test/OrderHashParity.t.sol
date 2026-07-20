// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test, console2} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {OrderHash} from "../src/libraries/OrderHash.sol";

/// Cross-language EIP-712 order-hash parity (issue #205 / 1.6b). The same
/// fixture drives the JS and Stellar suites; all three recompute the committed
/// `expected.orderHash`.
contract OrderHashParityTest is Test {
    using stdJson for string;

    function test_OrderHashMatchesFixture() public {
        string memory v = vm.readFile("../test-vectors/order-hash.json");

        OrderHash.Order memory o = OrderHash.Order({
            orderChainToken: v.readBytes32(".order.orderChainToken"),
            adChainToken: v.readBytes32(".order.adChainToken"),
            amount: vm.parseUint(v.readString(".order.amount")),
            bridger: v.readBytes32(".order.bridger"),
            orderChainId: vm.parseUint(v.readString(".order.orderChainId")),
            orderPortal: v.readBytes32(".order.orderPortal"),
            orderRecipient: v.readBytes32(".order.orderRecipient"),
            adChainId: vm.parseUint(v.readString(".order.adChainId")),
            adManager: v.readBytes32(".order.adManager"),
            adId: v.readString(".order.adId"),
            adCreator: v.readBytes32(".order.adCreator"),
            adRecipient: v.readBytes32(".order.adRecipient"),
            salt: vm.parseUint(v.readString(".order.salt")),
            orderDecimals: uint8(vm.parseUint(v.readString(".order.orderDecimals"))),
            adDecimals: uint8(vm.parseUint(v.readString(".order.adDecimals")))
        });

        bytes32 got = OrderHash.digest(o);
        console2.logBytes32(got);
        assertEq(got, v.readBytes32(".expected.orderHash"));
    }
}
