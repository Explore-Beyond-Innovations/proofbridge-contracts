// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {ModuleKitHelpers, UserOpData, PackedUserOperation} from "modulekit/ModuleKit.sol";
import {Execution} from "modulekit/accounts/erc7579/lib/ExecutionLib.sol";

import {ProofBridgeAgentPolicy} from "src/agent/ProofBridgeAgentPolicy.sol";
import {AgentPolicyBase} from "./AgentPolicyBase.t.sol";

/// The hook has to prove it is running. The validator counts requests it has approved that the
/// hook has not yet counted; at three the agent is paused until the owner resets it. The tally
/// detects — it does not cap: batches are welcome while it is zero, single trades only above.
/// (Review findings G2, H1, H6, I2.)
///
/// One transaction per `handleOps`, as on a chain. Forge runs a whole test as one transaction by
/// default, so transient state leaks between what a chain would treat as separate ones — which is
/// what once hid a wrong bound here.
/// forge-config: default.isolate = true
contract AgentPolicyTallyTest is AgentPolicyBase {
    using ModuleKitHelpers for *;

    function test_aHealthyMountNeverAccumulates() public {
        for (uint256 i = 0; i < 5; ++i) {
            _agentOp(lockCall(1)).execUserOps();
            assertEq(module.uncountedOf(instance.account, agentId), 0, "approved, then counted");
        }
        assertEq(escrow.locks(), 5);
    }

    /// The owner's objection to counting trades, as a test: a maker with several orders sends them
    /// together, again and again, and never meets a limit.
    function test_aHealthyAgentBatchesFreely() public {
        for (uint256 i = 0; i < 3; ++i) {
            _agentBatch(_batch(6, 1_000)).execUserOps();
            assertEq(module.uncountedOf(instance.account, agentId), 0, "counted, so the next batch is welcome");
        }
        assertEq(escrow.locks(), 18);
    }

    /// One failed trade is harmless: the next counted one zeroes the tally.
    function test_oneFailedTradeIsForgottenByTheNextGoodOne() public {
        escrow.setFailNext(true);
        UserOpData memory op = _agentOp(lockCall(1));
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(module.uncountedOf(instance.account, agentId), 1, "approved, and never counted");

        escrow.setFailNext(false);
        _agentOp(lockCall(1)).execUserOps();
        assertEq(module.uncountedOf(instance.account, agentId), 0);
    }

    /// A failed batch is one strike, like a failed single trade. Until something is counted the
    /// agent sends single trades; one that lands clears the tally and batches are back.
    function test_aFailedBatchIsOneStrikeAndOneGoodTradeClearsIt() public {
        escrow.setFailNext(true);
        UserOpData memory failing = _agentBatch(_batch(4, 1_000));
        instance.expect4337Revert();
        failing.execUserOps();
        assertEq(module.uncountedOf(instance.account, agentId), 1, "one request, one strike, not four");
        escrow.setFailNext(false);

        UserOpData memory batch = _agentBatch(_batch(4, 1_000));
        (ProofBridgeAgentPolicy.Refusal why,) = module.preflight(instance.account, agentId, batch.userOp.callData);
        assertEq(
            uint8(why), uint8(ProofBridgeAgentPolicy.Refusal.SinglesOnly), "preflight says why, before anything is sent"
        );
        instance.expect4337Revert();
        batch.execUserOps();
        assertEq(escrow.locks(), 0, "no batches while a request is still uncounted");

        _agentOp(lockCall(1_000)).execUserOps();
        assertEq(module.uncountedOf(instance.account, agentId), 0, "a single trade landed and was counted");
        _agentBatch(_batch(4, 1_000)).execUserOps();
        assertEq(escrow.locks(), 5, "and batches are back");
    }

    /// The cost, pinned: a reverted execution rolls back the hook's reset, so three approved
    /// operations in a row that never get counted pause the agent — whatever the reason.
    function test_threeUncountedInARowPauseTheAgentUntilTheOwnerResets() public {
        escrow.setFailNext(true);
        for (uint256 i = 0; i < 3; ++i) {
            UserOpData memory failing = _agentOp(lockCall(1));
            instance.expect4337Revert();
            failing.execUserOps();
        }
        assertEq(module.uncountedOf(instance.account, agentId), 3);

        escrow.setFailNext(false);
        UserOpData memory op = _agentOp(lockCall(1));
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(escrow.locks(), 0, "paused: even a trade that would now succeed is refused");

        _asAccount(abi.encodeCall(module.resetAgentTally, (agentId)));
        _agentOp(lockCall(1)).execUserOps();
        assertEq(escrow.locks(), 1, "the owner looked, and reset it");
    }

    function test_onlyTheAccountResetsTheTally() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(ProofBridgeAgentPolicy.AgentPolicy__NotInstalled.selector);
        module.resetAgentTally(agentId);
    }

    /// H6. The typo guard `revokeAgent` has: an id with no policy here is a mistake, not a reset.
    function test_resettingAnIdWithNoPolicyIsRefused() public {
        vm.prank(instance.account);
        vm.expectRevert(ProofBridgeAgentPolicy.AgentPolicy__NoPolicyForAgent.selector);
        module.resetAgentTally(bytes32(uint256(0xabc)));
    }

    /// The backstop, with the note forced wrong on purpose: the hook is removed from the *account*
    /// behind the module's back, so the note still says "both". Whatever route got here, the agent
    /// gets three capped trades in total — not one per token per transaction, indefinitely.
    function test_withTheNoteWrongTheTallyStopsTheAgentAtThree() public {
        _removeHookBehindTheModulesBack();

        uint256 landed;
        for (uint256 i = 0; i < 6; ++i) {
            UserOpData memory op = _agentOp(lockCall(1));
            instance.expect4337Revert();
            op.execUserOps();
            landed = escrow.locks();
        }
        assertEq(landed, 3, "three uncounted approvals, then nothing");
        assertEq(module.agentBucket(instance.account, agentId, AD_TOKEN).lastTs, 0, "and indeed nothing was counting");
    }

    /// The reviewer's run: hook gone, note still says "both", three batch requests of five in three
    /// transactions. Fifteen locks — 15M against an 8M account ceiling — under a docstring that
    /// promised three capped trades.
    function test_withTheHookGoneItIsOneBatchAndTwoSingleTrades() public {
        _removeHookBehindTheModulesBack();

        for (uint256 i = 0; i < 4; ++i) {
            UserOpData memory op = _agentBatch(_batch(5, MAX_PER_ORDER));
            instance.expect4337Revert();
            op.execUserOps();
        }
        assertEq(escrow.locks(), 5, "one batch got through before anything could be known; no second one");

        for (uint256 i = 0; i < 4; ++i) {
            UserOpData memory op = _agentOp(lockCall(MAX_PER_ORDER));
            instance.expect4337Revert();
            op.execUserOps();
        }
        assertEq(escrow.locks(), 7, "then two single trades, and the agent is paused");
    }

    /// I2, pinned so the number in the docs is the number on the chain: the hookless bound is per
    /// *agent*. The validator's running totals are transient, so with the hook gone nothing lowers
    /// the stored ceiling and a second agent gets its own batch and its own two single trades.
    function test_theHooklessBoundIsPerAgent() public {
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
