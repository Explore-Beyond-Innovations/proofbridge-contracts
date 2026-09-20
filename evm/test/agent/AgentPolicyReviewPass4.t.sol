// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {ModuleKitHelpers, UserOpData, PackedUserOperation} from "modulekit/ModuleKit.sol";
import {Execution} from "modulekit/accounts/erc7579/lib/ExecutionLib.sol";

import {IAdManager} from "src/interfaces/IAdManager.sol";
import {ProofBridgeAgentPolicy} from "src/agent/ProofBridgeAgentPolicy.sol";
import {AgentPolicyBase} from "./AgentPolicyBase.t.sol";
import {Vm} from "forge-std/Vm.sol";

/// Review pass 4 (internal-docs/t2/pr-reviews/contracts-33-evm-agent-module.md, H1–H9).
///
/// **One transaction per `handleOps`, as on a chain.** Forge runs a whole test as one transaction
/// by default, so transient state leaks between what a chain would treat as separate transactions.
/// Pass 3's tally tests ran that way and only ever sent single trades, which together is what hid
/// H1: the documented "three trades" bound was really three *requests*, and a request can be a
/// batch.
/// forge-config: default.isolate = true
contract AgentPolicyReviewPass4Test is AgentPolicyBase {
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

    function _batch(uint256 n, uint256 amount) internal view returns (Execution[] memory calls) {
        calls = new Execution[](n);
        for (uint256 i = 0; i < n; ++i) {
            calls[i] = Execution({target: address(escrow), value: 0, callData: lockCall(amount)});
        }
    }

    /// Every mount keeps its hook somewhere different, so "remove it without telling the module" is
    /// done the blunt way: make the module's own `onUninstall` a no-op for the duration.
    function _removeHookBehindTheModulesBack() internal {
        vm.mockCall(address(module), abi.encodeWithSelector(module.onUninstall.selector), "");
        instance.uninstallModule(TYPE_HOOK, address(module), bytes.concat(bytes32(TYPE_HOOK)));
        vm.clearMockedCalls();
    }

    /*//////////////////////////////////////////////////////////////
               H1 — THE HOOKLESS BOUND, WITH BATCHES IN IT
    //////////////////////////////////////////////////////////////*/

    /// The reviewer's run: hook gone, note still says "both", three batch requests of five in three
    /// transactions. Fifteen locks — 15M against an 8M account ceiling — under a docstring that
    /// promised three capped trades.
    function test_H1_withTheHookGoneItIsOneBatchAndTwoSingleTrades() public {
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

    /*//////////////////////////////////////////////////////////////
              THE TALLY DETECTS — IT DOES NOT CAP BATCHES
    //////////////////////////////////////////////////////////////*/

    /// The owner's objection to counting trades, as a test: a maker with several orders sends them
    /// together, again and again, and never meets a limit.
    function test_aHealthyAgentBatchesFreely() public {
        for (uint256 i = 0; i < 3; ++i) {
            _agentBatch(_batch(6, 1_000)).execUserOps();
            assertEq(module.uncountedOf(instance.account, agentId), 0, "counted, so the next batch is welcome");
        }
        assertEq(escrow.locks(), 18);
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

    /*//////////////////////////////////////////////////////////////
                         THE AGENT CAN ASK WHY
    //////////////////////////////////////////////////////////////*/

    function _why(bytes memory callData) internal view returns (ProofBridgeAgentPolicy.Refusal, uint256) {
        return module.preflight(instance.account, agentId, callData);
    }

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

    /// H6. The typo guard `revokeAgent` has: an id with no policy here is a mistake, not a reset.
    function test_H6_resettingAnIdWithNoPolicyIsRefused() public {
        vm.prank(instance.account);
        vm.expectRevert(ProofBridgeAgentPolicy.AgentPolicy__NoPolicyForAgent.selector);
        module.resetAgentTally(bytes32(uint256(0xabc)));
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
