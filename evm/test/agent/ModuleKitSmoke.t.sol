// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {RhinestoneModuleKit, AccountInstance} from "modulekit/ModuleKit.sol";

/// ModuleKit is a test-only dependency and it arrives through pnpm rather than as a foundry
/// submodule, so this proves the wiring before anything depends on it.
contract ModuleKitSmokeTest is RhinestoneModuleKit, Test {
    function test_kitBoots() public {
        AccountInstance memory instance = makeAccountInstance("smoke");
        assertTrue(instance.account != address(0));
    }
}
