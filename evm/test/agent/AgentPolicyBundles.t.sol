// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {ModuleKitHelpers, UserOpData, PackedUserOperation} from "modulekit/ModuleKit.sol";
import {Execution} from "modulekit/accounts/erc7579/lib/ExecutionLib.sol";

import {ProofBridgeAgentPolicy} from "src/agent/ProofBridgeAgentPolicy.sol";
import {AgentPolicyBase} from "./AgentPolicyBase.t.sol";

/// Every validation in a bundle runs before any execution. Most of what went wrong in this module
/// went wrong there: a marker consumed by the first operation, a revoke or an uninstall that lands
/// between the approval and the trade, and the clockless floor the validator keeps for when the
/// hook never runs. (Review findings D4, E1, H2.)
contract AgentPolicyBundlesTest is AgentPolicyBase {
    using ModuleKitHelpers for *;

    /// An agent can call `handleOps` itself. All validations run before any execution, so a marker
    /// keyed by the account alone is set once per bundle and cleared by the first execution — and
    /// every later operation in the bundle would run with the hook asleep.
    function test_twoOperationsInOneBundleAreBothDebited() public {
        UserOpData memory a = _agentOp(lockCall(400_000));
        UserOpData memory b = _agentOp(lockCall(600_000));
        b.userOp.nonce = a.userOp.nonce + 1;
        b.userOp.signature = _sign(instance.aux.entrypoint.getUserOpHash(b.userOp), agentKey);

        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        ops[0] = a.userOp;
        ops[1] = b.userOp;
        instance.aux.entrypoint.handleOps(ops, payable(address(0x69)));

        assertEq(escrow.locks(), 2, "both trades happened");
        assertEq(
            module.agentBucket(instance.account, agentId, AD_TOKEN).level,
            CAPACITY - 1_000_000,
            "and both were paid for"
        );
    }

    /// D4. Every validation in a bundle runs before any execution, so an operation validated while
    /// the policy was live would execute after the revoke that was bundled ahead of it.
    function test_aRevokeBundledAheadOfTheAgentStillStopsIt() public {
        UserOpData memory revoke = instance.getExecOps(
            address(module), 0, abi.encodeCall(module.revokeAgent, (agentId)), address(instance.defaultValidator)
        );
        revoke = revoke.signDefault();
        UserOpData memory lock = _agentOp(lockCall(1));

        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        ops[0] = revoke.userOp;
        ops[1] = lock.userOp;
        instance.aux.entrypoint.handleOps(ops, payable(address(0x69)));

        assertTrue(module.isRevoked(instance.account, agentId));
        assertEq(escrow.locks(), 0, "revoked means revoked from that execution onward");
    }

    /// E1. D4 put the revoke check in the hook — and an owner operation that *uninstalls the hook*,
    /// bundled ahead of the agent's, removes the thing that checks. Every validation had already
    /// passed against the same untouched bucket, so the locks ran uncounted.
    ///
    /// Rebuilt in pass 4 (H2). The first version sent six operations and asserted an upper bound
    /// inside a try/catch; once the tally existed the *fourth* validation was refused by the tally,
    /// the bundle reverted, nothing landed, and the bound held for the wrong reason — switching the
    /// floor off left it green. Three operations stay under the tally, and their sum is what has to
    /// trip the floor.
    function test_uninstallingTheHookAheadOfTheAgentDoesNotUnboundIt() public {
        for (uint256 i = 0; i < 3; ++i) {
            _agentOp(lockCall(MAX_PER_ORDER)).execUserOps();
        }
        assertEq(module.agentBucket(instance.account, agentId, AD_TOKEN).level, 2 * MAX_PER_ORDER, "stored: two left");

        PackedUserOperation[] memory ops = new PackedUserOperation[](4);
        ops[0] = _uninstallHookOp();
        for (uint256 i = 0; i < 3; ++i) {
            ops[i + 1] = _agentOpAt(i, lockCall(MAX_PER_ORDER));
        }
        // the third asks for more than the stored level holds: refused in validation, by the floor
        vm.expectRevert(abi.encodeWithSelector(FailedOp.selector, uint256(3), "AA24 signature error"));
        instance.aux.entrypoint.handleOps(ops, payable(address(0x69)));
        assertEq(escrow.locks(), 3, "nothing from that bundle landed");
    }

    /// The control: two fit the stored level, so the same bundle shape goes through — which is what
    /// makes the refusal above a refusal by the floor and not by something else.
    function test_control_whatFitsTheStoredLevelRuns() public {
        for (uint256 i = 0; i < 3; ++i) {
            _agentOp(lockCall(MAX_PER_ORDER)).execUserOps();
        }
        PackedUserOperation[] memory ops = new PackedUserOperation[](3);
        ops[0] = _uninstallHookOp();
        ops[1] = _agentOpAt(0, lockCall(MAX_PER_ORDER));
        ops[2] = _agentOpAt(1, lockCall(MAX_PER_ORDER));
        instance.aux.entrypoint.handleOps(ops, payable(address(0x69)));
        assertEq(escrow.locks(), 5, "the race is real; the floor is what contains it");
    }

    /// G4's positive control for E1, adjusted for the tally: with the hook uninstalled ahead of the
    /// agent in one bundle, exactly three operations run hookless — so the bound in the pass-2 test
    /// is a bound on something that happens, not on a bundle that failed for another reason.
    function test_control_uninstallAheadOfExactlyThreeRunsAllThree() public {
        UserOpData memory uninstall = instance.getUninstallModuleOps(
            TYPE_HOOK, address(module), bytes.concat(bytes32(TYPE_HOOK)), address(instance.defaultValidator)
        );
        uninstall = uninstall.signDefault();
        PackedUserOperation[] memory ops = new PackedUserOperation[](4);
        ops[0] = uninstall.userOp;
        for (uint256 i = 0; i < 3; ++i) {
            ops[i + 1] = _agentOpAt(i, lockCall(MAX_PER_ORDER));
        }
        instance.aux.entrypoint.handleOps(ops, payable(address(0x69)));
        assertEq(escrow.locks(), 3, "the race is real; the bound is what contains it");
    }

    /// ...and the floor must not deadlock. A bucket drained long ago stores zero while being full
    /// again; a validator that believed the zero would refuse everything forever.
    function test_aDrainedBucketThatHasRefilledIsNotLockedOutByItsStaleLevel() public {
        for (uint256 i = 0; i < CAPACITY / MAX_PER_ORDER; ++i) {
            _agentOp(lockCall(MAX_PER_ORDER)).execUserOps();
        }
        assertEq(module.agentBucket(instance.account, agentId, AD_TOKEN).level, 0, "stored level: empty");

        vm.warp(block.timestamp + 7 days);
        _agentOp(lockCall(MAX_PER_ORDER)).execUserOps();
        assertEq(escrow.locks(), CAPACITY / MAX_PER_ORDER + 1, "the first request is the hook's to judge");
    }

    /// The cost of that floor, pinned so it is a known behaviour and not a surprise: against a
    /// stale-low stored level a batch is refused although the refilled allowance would cover it,
    /// until one single operation refreshes the level.
    function test_aBatchAgainstAStaleLevelNeedsOneOperationFirst() public {
        for (uint256 i = 0; i < CAPACITY / MAX_PER_ORDER; ++i) {
            _agentOp(lockCall(MAX_PER_ORDER)).execUserOps();
        }
        vm.warp(block.timestamp + 7 days);

        Execution[] memory calls = new Execution[](2);
        calls[0] = Execution({target: address(escrow), value: 0, callData: lockCall(1)});
        calls[1] = Execution({target: address(escrow), value: 0, callData: lockCall(1)});
        uint256 before = escrow.locks();
        UserOpData memory batch = _agentBatch(calls);
        instance.expect4337Revert();
        batch.execUserOps();
        assertEq(escrow.locks(), before, "refused by the validator's floor: the stored level says empty");

        _agentOp(lockCall(1)).execUserOps();
        _agentBatch(calls).execUserOps();
        assertEq(escrow.locks(), before + 3, "one operation refreshed the level, and the batch then fits");
    }
}
