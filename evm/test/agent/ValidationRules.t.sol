// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {ModuleKitHelpers, UserOpData} from "modulekit/ModuleKit.sol";

import {AgentPolicyBase} from "./AgentPolicyBase.t.sol";
import {BadLayoutValidator} from "./mocks/BadLayoutValidator.sol";

/// ERC-4337's validation rules, run for real.
///
/// The module's storage layout is load-bearing and invisible: an account-first mapping compiles,
/// passes every functional test in this directory, and produces a module no bundler will carry.
/// The only thing that says so is a simulation, so these run one.
contract ValidationRulesTest is AgentPolicyBase {
    using ModuleKitHelpers for *;

    /// @dev Opt-in. The simulator needs forge's debug tracer (`-vvv`) and a gas limit far above the
    ///      default, because the trace itself is metered — so under the repo's documented
    ///      `forge test -vvv` these would fail for reasons that have nothing to do with the module.
    ///      And turning the simulation on is a process-wide switch while forge runs suites in
    ///      parallel, so it must never share a run. CI sets the flag in a step of its own:
    ///
    ///        AGENT_RULES=1 forge test --match-contract ValidationRules --gas-limit 900000000000 -vvv
    function setUp() public override {
        if (!vm.envOr("AGENT_RULES", false)) {
            vm.skip(true);
            return;
        }
        super.setUp();
    }

    /// @dev `simulateUserOp` sets a process-wide env var, so every test here puts it back. Left on,
    ///      it leaks into whatever suite forge runs next in the same process and simulates
    ///      operations that were never meant to be simulated.
    modifier simulating() {
        instance.simulateUserOp(true);
        _;
        instance.simulateUserOp(false);
    }

    function test_aLockUnderTheRealRules() public simulating {
        _agentOp(lockCall(100_000)).execUserOps();
        assertEq(escrow.locks(), 1);
    }

    function test_aSecondLockUnderTheRealRules() public simulating {
        _agentOp(lockCall(1)).execUserOps();
        _agentOp(lockCall(1)).execUserOps();
        assertEq(escrow.locks(), 2, "the hook's writes are inside the rules too");
    }

    /// The mutation: the same work, laid out the way anyone would write it by instinct.
    function test_anAccountFirstLayoutIsRefusedByTheRules() public {
        BadLayoutValidator bad = new BadLayoutValidator();
        instance.installModule(1, address(bad), "");

        UserOpData memory op = instance.getExecOps(address(escrow), 0, lockCall(1), address(bad));
        op.userOp.signature = _sign(op.userOpHash, agentKey);

        instance.simulateUserOp(true);
        assertFalse(_survives(op), "a mapping keyed account-first must not pass the rules");

        // And the same operation is perfectly fine once the simulation is off, which is the point:
        // nothing but the rules check catches this.
        instance.simulateUserOp(false);
        assertTrue(_survives(op), "it works on chain, which is what makes it dangerous");
    }

    function _survives(UserOpData memory op) internal returns (bool) {
        try this.run(op) {
            return true;
        } catch {
            return false;
        }
    }

    function run(UserOpData memory op) external {
        op.execUserOps();
    }
}
