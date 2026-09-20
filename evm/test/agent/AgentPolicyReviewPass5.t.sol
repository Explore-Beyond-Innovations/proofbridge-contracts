// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {ModuleKitHelpers, UserOpData, PackedUserOperation} from "modulekit/ModuleKit.sol";
import {Execution} from "modulekit/accounts/erc7579/lib/ExecutionLib.sol";

import {ProofBridgeAgentPolicy} from "src/agent/ProofBridgeAgentPolicy.sol";
import {AgentPolicyBase} from "./AgentPolicyBase.t.sol";

/// Review pass 5 (internal-docs/t2/pr-reviews/contracts-33-evm-agent-module.md, I1–I5).
///
/// `preflight` exists to tell an agent what the module would refuse. These are about it telling
/// the truth — including about the validator's clockless floor, which it used to ignore.
/// forge-config: default.isolate = true
contract AgentPolicyReviewPass5Test is AgentPolicyBase {
    using ModuleKitHelpers for *;

    function _batch(uint256 n, uint256 amount) internal view returns (Execution[] memory calls) {
        calls = new Execution[](n);
        for (uint256 i = 0; i < n; ++i) {
            calls[i] = Execution({target: address(escrow), value: 0, callData: lockCall(amount)});
        }
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

    /// I1. The one refusal that is deterministic *and* surprising: a batch against a stale-low
    /// stored level. The allowance has refilled, the validator cannot know that, and it refuses the
    /// batch every time until one single trade lands. `preflight` said "fine".
    function test_I1_preflightAgreesWithTheValidatorAboutAStaleLevel() public {
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

    /// I5. `callIndex` 0 meant both "the first call" and "no call in particular".
    function test_I5_aRefusalAboutTheWholeRequestNamesNoCall() public {
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
    function test_I5_aMalformedCallIsNotAMalformedRequest() public {
        Execution[] memory calls = _batch(3, 1);
        calls[1].callData = hex"aabb";
        (ProofBridgeAgentPolicy.Refusal why, uint256 at) = _why(_agentBatch(calls).userOp.callData);
        assertEq(uint8(why), uint8(ProofBridgeAgentPolicy.Refusal.MalformedCall));
        assertEq(at, 1);
    }

    /// I2, pinned so the number in the docs is the number on the chain: the hookless bound is per
    /// *agent*. The validator's running totals are transient, so with the hook gone nothing lowers
    /// the stored ceiling and a second agent gets its own batch and its own two single trades.
    function test_I2_theHooklessBoundIsPerAgent() public {
        (address agent2, uint256 key2) = makeAddrAndKey("agent-two");
        bytes32 id2 = bytes32(uint256(uint160(agent2)));
        _asAccount(abi.encodeCall(module.setAgentPolicy, (id2, defaultPolicy())));
        _asAccount(abi.encodeCall(module.setAgentGasBudget, (id2, GAS_BUDGET)));

        vm.mockCall(address(module), abi.encodeWithSelector(module.onUninstall.selector), "");
        instance.uninstallModule(TYPE_HOOK, address(module), bytes.concat(bytes32(TYPE_HOOK)));
        vm.clearMockedCalls();

        uint256[2] memory keys = [agentKey, key2];
        for (uint256 a = 0; a < 2; ++a) {
            for (uint256 i = 0; i < 5; ++i) {
                UserOpData memory op = i == 0
                    ? instance.getExecOps(_batch(5, MAX_PER_ORDER), address(module))
                    : instance.getExecOps(address(escrow), 0, lockCall(MAX_PER_ORDER), address(module));
                op.userOp.signature = _sign(op.userOpHash, keys[a]);
                instance.expect4337Revert();
                op.execUserOps();
            }
        }
        assertEq(escrow.locks(), 14, "two agents: twice (one batch + two single trades)");
    }
}
