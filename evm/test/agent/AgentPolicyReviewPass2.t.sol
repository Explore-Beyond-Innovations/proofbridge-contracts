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
    /// passed against the same untouched bucket, so six locks ran against a capacity of five.
    function test_E1_uninstallingTheHookAheadOfTheAgentDoesNotUnboundIt() public {
        UserOpData memory uninstall = instance.getUninstallModuleOps(
            TYPE_HOOK, address(module), bytes.concat(bytes32(TYPE_HOOK)), address(instance.defaultValidator)
        );
        uninstall = uninstall.signDefault();

        uint256 n = CAPACITY / MAX_PER_ORDER + 1;
        PackedUserOperation[] memory ops = new PackedUserOperation[](n + 1);
        ops[0] = uninstall.userOp;
        for (uint256 i = 0; i < n; ++i) {
            ops[i + 1] = _agentOpAt(i, lockCall(MAX_PER_ORDER));
        }
        try instance.aux.entrypoint.handleOps(ops, payable(address(0x69))) {} catch {}

        assertLe(escrow.locks() * MAX_PER_ORDER, CAPACITY, "with the hook gone, the stored allowance still bounds it");
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

    /// E2. A named, valid type that is not installed is a no-op — not a wipe of the other half, or a
    /// half-installed module can never be repaired one half at a time.
    function test_E2_uninstallingAHalfThatIsNotThereLeavesTheOtherAlone() public {
        vm.startPrank(instance.account);
        module.onUninstall(bytes.concat(bytes32(TYPE_HOOK)));
        module.onUninstall(bytes.concat(bytes32(TYPE_HOOK))); // again: not installed now
        vm.stopPrank();
        assertTrue(module.isInitialized(instance.account), "the validator half is still mounted");

        vm.prank(instance.account);
        module.onUninstall(""); // names nothing: fail closed, both go
        assertFalse(module.isInitialized(instance.account));
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
