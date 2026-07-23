// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test, console2} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {OrderHash} from "../src/libraries/OrderHash.sol";

/// Cross-language EIP-712 order-hash parity (issue #205 / 1.6b). The same
/// fixture drives the JS and Stellar suites; all three recompute every
/// vector's committed `expected.orderHash`.
contract OrderHashParityTest is Test {
    using stdJson for string;

    function test_OrderHashMatchesFixture() public {
        string memory v = vm.readFile("../test-vectors/order-hash.json");
        uint256 count = v.readUint(".count");
        assertGt(count, 0, "fixture must carry vectors");

        for (uint256 i = 0; i < count; i++) {
            string memory p = string.concat(".vectors[", vm.toString(i), "]");
            OrderHash.Order memory o = OrderHash.Order({
                orderChainToken: v.readBytes32(string.concat(p, ".order.orderChainToken")),
                adChainToken: v.readBytes32(string.concat(p, ".order.adChainToken")),
                amount: vm.parseUint(v.readString(string.concat(p, ".order.amount"))),
                bridger: v.readBytes32(string.concat(p, ".order.bridger")),
                orderChainId: vm.parseUint(v.readString(string.concat(p, ".order.orderChainId"))),
                orderPortal: v.readBytes32(string.concat(p, ".order.orderPortal")),
                orderRecipient: v.readBytes32(string.concat(p, ".order.orderRecipient")),
                adChainId: vm.parseUint(v.readString(string.concat(p, ".order.adChainId"))),
                adManager: v.readBytes32(string.concat(p, ".order.adManager")),
                adId: v.readString(string.concat(p, ".order.adId")),
                adCreator: v.readBytes32(string.concat(p, ".order.adCreator")),
                adRecipient: v.readBytes32(string.concat(p, ".order.adRecipient")),
                salt: vm.parseUint(v.readString(string.concat(p, ".order.salt"))),
                orderDecimals: uint8(vm.parseUint(v.readString(string.concat(p, ".order.orderDecimals")))),
                adDecimals: uint8(vm.parseUint(v.readString(string.concat(p, ".order.adDecimals"))))
            });

            bytes32 got = OrderHash.digest(o);
            console2.log(v.readString(string.concat(p, ".name")));
            console2.logBytes32(got);
            assertEq(got, v.readBytes32(string.concat(p, ".expected.orderHash")));
        }
    }
}
