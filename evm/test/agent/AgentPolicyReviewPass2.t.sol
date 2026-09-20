// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {ModuleKitHelpers, UserOpData, PackedUserOperation} from "modulekit/ModuleKit.sol";
import {Execution} from "modulekit/accounts/erc7579/lib/ExecutionLib.sol";

import {ProofBridgeAgentPolicy} from "src/agent/ProofBridgeAgentPolicy.sol";
import {AgentPolicyBase} from "./AgentPolicyBase.t.sol";

/// Review pass 2 (internal-docs/t2/pr-reviews/contracts-33-evm-agent-module.md, E1–E7). As with
/// pass 1, each fix was reverted on its own to watch its test here go red.
contract AgentPolicyReviewPass2Test is AgentPolicyBase {
    using ModuleKitHelpers for *;

    error FailedOp(uint256 opIndex, string reason);

    function _resign(UserOpData memory op) internal view returns (UserOpData memory) {
        op.userOpHash = instance.aux.entrypoint.getUserOpHash(op.userOp);
        op.userOp.signature = _sign(op.userOpHash, agentKey);
        return op;
    }

    function _agentOpAt(uint256 seq, bytes memory callData) internal returns (PackedUserOperation memory) {
        UserOpData memory op = _agentOp(callData);
        op.userOp.nonce += seq;
        return _resign(op).userOp;
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
    function test_E1_uninstallingTheHookAheadOfTheAgentDoesNotUnboundIt() public {
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
    function test_E1_control_whatFitsTheStoredLevelRuns() public {
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

    function _uninstallHookOp() internal returns (PackedUserOperation memory) {
        UserOpData memory uninstall = instance.getUninstallModuleOps(
            TYPE_HOOK, address(module), bytes.concat(bytes32(TYPE_HOOK)), address(instance.defaultValidator)
        );
        return uninstall.signDefault().userOp;
    }

    /// ...and the floor must not deadlock. A bucket drained long ago stores zero while being full
    /// again; a validator that believed the zero would refuse everything forever.
    function test_E1_aDrainedBucketThatHasRefilledIsNotLockedOutByItsStaleLevel() public {
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
    function test_E1_aBatchAgainstAStaleLevelNeedsOneOperationFirst() public {
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

    /// E3. "Zero means no budget, and no budget means refused" was false for a zero-fee operation:
    /// the cost is zero and `0 > 0` is not true. A self-bundling agent picks its own fee.
    function test_E3_aZeroBudgetRefusesAZeroFeeOperation() public {
        _asAccount(abi.encodeCall(module.setAgentGasBudget, (agentId, 0)));
        UserOpData memory op = _agentOp(lockCall(1));
        op.userOp.gasFees = bytes32(0);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _resign(op).userOp;
        try instance.aux.entrypoint.handleOps(ops, payable(address(0x69))) {} catch {}
        assertEq(escrow.locks(), 0, "an owner who zeroes the budget to pause an agent has paused it");
    }

    /// E2, as revised by pass 3 (G2). Pass 2 made "valid but not installed" a no-op so a
    /// half-installed module could be repaired one half at a time — and that let an owner who named
    /// the wrong half keep a hook bit for a hook the account no longer had. Fail shut wins: any
    /// uninstall that does not name an installed type clears both, and the repair is
    /// *uninstall both, install both*.
    function test_E2_anUninstallThatMatchesNothingClearsBoth() public {
        vm.startPrank(instance.account);
        module.onUninstall(bytes.concat(bytes32(TYPE_HOOK)));
        assertTrue(module.isInitialized(instance.account), "one half named and removed: the other stays");
        module.onUninstall(bytes.concat(bytes32(TYPE_HOOK))); // named again, not installed now
        vm.stopPrank();
        assertFalse(module.isInitialized(instance.account), "matches nothing installed: both go");

        // and it still cannot fail, which is what Safe and Nexus need of it
        vm.prank(instance.account);
        module.onUninstall("");
    }

    /// E5. The tombstone is permanent, so revoking an id that was never installed would burn it on
    /// this account for good. Soroban refuses with NoPolicyForAgent; so does this.
    function test_E5_revokingAnIdThatWasNeverInstalledIsRefused() public {
        bytes32 typo = bytes32(uint256(uint160(makeAddr("mistyped"))));
        vm.prank(instance.account);
        vm.expectRevert(ProofBridgeAgentPolicy.AgentPolicy__NoPolicyForAgent.selector);
        module.revokeAgent(typo);
        assertFalse(module.isRevoked(instance.account, typo));

        // and revoking twice is quiet, as on Soroban
        vm.startPrank(instance.account);
        module.revokeAgent(agentId);
        module.revokeAgent(agentId);
        vm.stopPrank();
    }

    /// E7. The pass-1 test for C3 pinned a harness. This pins the thing that matters: through the
    /// real EntryPoint, malformed agent calldata is a *refusal* (AA24), not a validation revert
    /// (AA23) — the second is what gets the maker's account throttled.
    function test_E7_malformedCalldataIsAA24ThroughTheRealEntryPoint() public {
        bytes memory truncatedBatch = abi.encodeWithSelector(bytes4(0xe9ae5c53), bytes32(uint256(1) << 248), hex"1122");
        bytes memory garbageLock = abi.encodeWithSelector(
            bytes4(0xe9ae5c53),
            bytes32(0),
            abi.encodePacked(address(escrow), uint256(0), bytes4(keccak256("nope()")), hex"1122")
        );
        bytes memory lockSelectorGarbageArgs = abi.encodeWithSelector(
            bytes4(0xe9ae5c53),
            bytes32(0),
            abi.encodePacked(address(escrow), uint256(0), bytes4(lockCall(1)), hex"1122")
        );
        bytes[3] memory cases = [truncatedBatch, garbageLock, lockSelectorGarbageArgs];
        for (uint256 i = 0; i < cases.length; ++i) {
            UserOpData memory op = _agentOp(lockCall(1));
            // Kernel wraps every operation in `executeUserOp` and refuses, itself, one that is not —
            // so the malformed payload goes inside whatever wrapper this mount uses.
            bool wrapped = bytes4(op.userOp.callData) == bytes4(0x8dd7712f);
            op.userOp.callData = wrapped ? bytes.concat(bytes4(0x8dd7712f), cases[i]) : cases[i];
            PackedUserOperation[] memory ops = new PackedUserOperation[](1);
            ops[0] = _resign(op).userOp;
            vm.expectRevert(abi.encodeWithSelector(FailedOp.selector, uint256(0), "AA24 signature error"));
            instance.aux.entrypoint.handleOps(ops, payable(address(0x69)));
        }
    }
}
