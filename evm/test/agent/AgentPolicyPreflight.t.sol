// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {ModuleKitHelpers, UserOpData, PackedUserOperation} from "modulekit/ModuleKit.sol";
import {Execution} from "modulekit/accounts/erc7579/lib/ExecutionLib.sol";
import {Vm} from "forge-std/Vm.sol";
import {IAdManager} from "src/interfaces/IAdManager.sol";
import {ProofBridgeAgentPolicy} from "src/agent/ProofBridgeAgentPolicy.sol";
import {AgentPolicyBase} from "./AgentPolicyBase.t.sol";

/// The agent can ask why. `preflight` is a free read that walks a request with the module's own
/// checks and names the first refusal and the call it belongs to — for both halves, validator
/// first. (Review findings I1, I5, and the hook's named refusal.)
///
/// One transaction per `handleOps`, as on a chain. Forge runs a whole test as one transaction by
/// default, so transient state leaks between what a chain would treat as separate ones — which is
/// what once hid a wrong bound here.
/// forge-config: default.isolate = true
contract AgentPolicyPreflightTest is AgentPolicyBase {
    using ModuleKitHelpers for *;

    function test_preflight_namesTheCallAndTheReason() public {
        (ProofBridgeAgentPolicy.Refusal why, uint256 at) = _why(_agentOp(lockCall(1_000)).userOp.callData);
        assertEq(uint8(why), uint8(ProofBridgeAgentPolicy.Refusal.None), "a good request");

        // the culprit is the third call of four, and preflight says so
        Execution[] memory calls = _batch(4, 1_000);
        calls[2].callData = lockCall(MAX_PER_ORDER + 1);
        (why, at) = _why(_agentBatch(calls).userOp.callData);
        assertEq(uint8(why), uint8(ProofBridgeAgentPolicy.Refusal.OverPerOrderCap));
        assertEq(at, 2, "which call");

        calls[2] = Execution({target: address(0xdead), value: 0, callData: lockCall(1)});
        (why, at) = _why(_agentBatch(calls).userOp.callData);
        assertEq(uint8(why), uint8(ProofBridgeAgentPolicy.Refusal.TargetNotPinned));
        assertEq(at, 2);

        (why,) = module.preflight(instance.account, bytes32(uint256(0xabc)), _agentOp(lockCall(1)).userOp.callData);
        assertEq(uint8(why), uint8(ProofBridgeAgentPolicy.Refusal.NoPolicy));
    }

    /// The thing the validator cannot say. It has no clock, so it cannot know the real allowance
    /// and lets the hook find out — at the maker's gas. A read is not a validation: it may look at
    /// the time, and tells the agent before it spends anything.
    function test_preflight_knowsTheRealAllowanceWhereTheValidatorCannot() public {
        for (uint256 i = 0; i < CAPACITY / MAX_PER_ORDER; ++i) {
            _agentOp(lockCall(MAX_PER_ORDER)).execUserOps();
        }
        bytes memory next = _agentOp(lockCall(MAX_PER_ORDER)).userOp.callData;
        (ProofBridgeAgentPolicy.Refusal why,) = _why(next);
        assertEq(uint8(why), uint8(ProofBridgeAgentPolicy.Refusal.AgentAllowanceExceeded), "drained, and it says so");

        vm.warp(block.timestamp + MAX_PER_ORDER / REFILL + 1);
        (why,) = _why(next);
        assertEq(uint8(why), uint8(ProofBridgeAgentPolicy.Refusal.None), "refilled: the read sees the clock");
    }

    /// I1. The one refusal that is deterministic *and* surprising: a batch against a stale-low
    /// stored level. The allowance has refilled, the validator cannot know that, and it refuses the
    /// batch every time until one single trade lands. `preflight` said "fine".
    function test_preflight_agreesWithTheValidatorAboutAStaleLevel() public {
        _drainThenIdle();
        UserOpData memory batch = _agentBatch(_batch(2, 1));

        (ProofBridgeAgentPolicy.Refusal why, uint256 at) = _why(batch.userOp.callData);
        assertEq(uint8(why), uint8(ProofBridgeAgentPolicy.Refusal.OverStoredAllowance), "what the validator will say");
        assertEq(at, 1, "the first call against a bucket is free; it is the second that is refused");

        // ...and the validator does say it
        uint256 before = escrow.locks();
        instance.expect4337Revert();
        batch.execUserOps();
        assertEq(escrow.locks(), before);

        // a single trade is fine, and preflight knows that too
        (why,) = _why(_agentOp(lockCall(1)).userOp.callData);
        assertEq(uint8(why), uint8(ProofBridgeAgentPolicy.Refusal.None));
        _agentOp(lockCall(1)).execUserOps();

        // the level is fresh now, so the same batch passes — on the read and on the chain
        batch = _agentBatch(_batch(2, 1));
        (why,) = _why(batch.userOp.callData);
        assertEq(uint8(why), uint8(ProofBridgeAgentPolicy.Refusal.None), "refreshed");
        batch.execUserOps();
        assertEq(escrow.locks(), before + 3);
    }

    function test_preflight_reportsThePause() public {
        escrow.setFailNext(true);
        for (uint256 i = 0; i < 3; ++i) {
            UserOpData memory failing = _agentOp(lockCall(1));
            instance.expect4337Revert();
            failing.execUserOps();
        }
        (ProofBridgeAgentPolicy.Refusal why,) = _why(_agentOp(lockCall(1)).userOp.callData);
        assertEq(uint8(why), uint8(ProofBridgeAgentPolicy.Refusal.Paused));
    }

    /// I5. `callIndex` 0 meant both "the first call" and "no call in particular".
    function test_preflight_aRefusalAboutTheWholeRequestNamesNoCall() public {
        (ProofBridgeAgentPolicy.Refusal why, uint256 at) =
            module.preflight(instance.account, bytes32(uint256(0xabc)), _agentOp(lockCall(1)).userOp.callData);
        assertEq(uint8(why), uint8(ProofBridgeAgentPolicy.Refusal.NoPolicy));
        assertEq(at, module.NO_CALL(), "nothing about this is call 0's fault");

        (why, at) = _why(hex"deadbeef");
        assertEq(uint8(why), uint8(ProofBridgeAgentPolicy.Refusal.MalformedRequest), "the envelope");
        assertEq(at, module.NO_CALL());

        // ...while a refusal that *is* about the first call still says 0
        (why, at) = _why(_agentOp(lockCall(MAX_PER_ORDER + 1)).userOp.callData);
        assertEq(uint8(why), uint8(ProofBridgeAgentPolicy.Refusal.OverPerOrderCap));
        assertEq(at, 0);
    }

    /// I5. `Malformed` meant both "the envelope cannot be decoded" and "call i is too short".
    function test_preflight_aMalformedCallIsNotAMalformedRequest() public {
        Execution[] memory calls = _batch(3, 1);
        calls[1].callData = hex"aabb";
        (ProofBridgeAgentPolicy.Refusal why, uint256 at) = _why(_agentBatch(calls).userOp.callData);
        assertEq(uint8(why), uint8(ProofBridgeAgentPolicy.Refusal.MalformedCall));
        assertEq(at, 1);
    }

    /// When it is the *hook* that refuses, it says which call and why, instead of one fixed string.
    /// (A failure inside the escrow is the escrow's own error and carries no index; an agent finds
    /// that one by simulating.)
    ///
    /// The validator admits the first request against any bucket without knowing the real
    /// allowance, so a drained second token is where the hook disagrees with it: call 0 spends the
    /// healthy bucket, call 1 is the first request against the drained one.
    function test_theHookNamesTheCallItRefused() public {
        bytes memory drainedTokenLock = abi.encodeCall(
            IAdManager.lockForOrder, (orderParams(MAX_PER_ORDER, ORDER_TOKEN, AD_TOKEN, AD_ID, settlementSigner))
        );
        for (uint256 i = 0; i < CAPACITY / MAX_PER_ORDER; ++i) {
            _agentOp(drainedTokenLock).execUserOps();
        }

        Execution[] memory calls = new Execution[](2);
        calls[0] = Execution({target: address(escrow), value: 0, callData: lockCall(1_000)});
        calls[1] = Execution({target: address(escrow), value: 0, callData: drainedTokenLock});
        UserOpData memory op = _agentBatch(calls);

        (ProofBridgeAgentPolicy.Refusal why, uint256 at) =
            module.preflight(instance.account, agentId, op.userOp.callData);
        assertEq(uint8(why), uint8(ProofBridgeAgentPolicy.Refusal.AgentAllowanceExceeded));
        assertEq(at, 1, "preflight names the second call");

        uint256 before = escrow.locks();
        vm.recordLogs();
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op.userOp;
        instance.aux.entrypoint.handleOps(ops, payable(address(0x69)));
        assertEq(escrow.locks(), before, "the batch was approved, and stopped whole at execution");

        bytes memory expected = abi.encodeWithSelector(
            ProofBridgeAgentPolicy.AgentPolicy__RefusedAtExecution.selector,
            uint256(1),
            ProofBridgeAgentPolicy.Refusal.AgentAllowanceExceeded
        );
        // Whether that reason reaches the chain's log is the *account's* choice. The reference
        // account and Nexus pass the hook's revert data up to the EntryPoint; Safe's adapter and
        // Kernel's multiplexer replace it with their own. So `preflight`, asserted above on every
        // mount, is the dependable way to ask — and the log is a bonus where the account allows it.
        string memory mount = vm.envOr("ACCOUNT_TYPE", string("DEFAULT"));
        bool bubbles = keccak256(bytes(mount)) == keccak256("DEFAULT") || keccak256(bytes(mount)) == keccak256("NEXUS");
        assertEq(
            _someLogContains(vm.getRecordedLogs(), expected),
            bubbles,
            "the hook's reason, where the account passes it on"
        );
    }

    function _why(bytes memory callData) internal view returns (ProofBridgeAgentPolicy.Refusal, uint256) {
        return module.preflight(instance.account, agentId, callData);
    }

    function _drainThenIdle() internal {
        for (uint256 i = 0; i < CAPACITY / MAX_PER_ORDER; ++i) {
            _agentOp(lockCall(MAX_PER_ORDER)).execUserOps();
        }
        vm.warp(block.timestamp + 7 days);
    }

    function _someLogContains(Vm.Log[] memory logs, bytes memory needle) internal pure returns (bool) {
        for (uint256 l = 0; l < logs.length; ++l) {
            bytes memory hay = logs[l].data;
            if (hay.length < needle.length) continue;
            for (uint256 i = 0; i + needle.length <= hay.length; ++i) {
                bool hit = true;
                for (uint256 j = 0; j < needle.length; ++j) {
                    if (hay[i + j] != needle[j]) {
                        hit = false;
                        break;
                    }
                }
                if (hit) return true;
            }
        }
        return false;
    }
}
