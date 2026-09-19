// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {ModuleKitHelpers, UserOpData, PackedUserOperation} from "modulekit/ModuleKit.sol";

import {ProofBridgeAgentPolicy} from "src/agent/ProofBridgeAgentPolicy.sol";
import {AgentPolicyBase} from "./AgentPolicyBase.t.sol";

/// Review pass 3 (internal-docs/t2/pr-reviews/contracts-33-evm-agent-module.md, G1–G8).
///
/// The module keeps a note of which halves are installed, and three passes found three ways for
/// the note to be wrong. These tests are about not depending on it: the hook has to prove it runs.
contract AgentPolicyReviewPass3Test is AgentPolicyBase {
    using ModuleKitHelpers for *;

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

    /*//////////////////////////////////////////////////////////////
                          THE TALLY — NORMAL LIFE
    //////////////////////////////////////////////////////////////*/

    function test_aHealthyMountNeverAccumulates() public {
        for (uint256 i = 0; i < 5; ++i) {
            _agentOp(lockCall(1)).execUserOps();
            assertEq(module.uncountedOf(instance.account, agentId), 0, "approved, then counted");
        }
        assertEq(escrow.locks(), 5);
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

    /*//////////////////////////////////////////////////////////////
                  G2 — THE NOTE IS WRONG, AND IT STILL HOLDS
    //////////////////////////////////////////////////////////////*/

    /// The reviewer's path, step for step. Note says {hook}; the owner removes the hook from the
    /// account with data naming the *validator*; then installs the validator. Under pass 2's no-op
    /// the note read "both" with nothing debiting.
    function test_G2_namingTheWrongHalfCannotLeaveTheAgentApprovedAndUncounted() public {
        vm.startPrank(instance.account);
        module.onUninstall(bytes.concat(bytes32(TYPE_VALIDATOR))); // note: {hook}
        module.onUninstall(bytes.concat(bytes32(TYPE_VALIDATOR))); // wrong half named, hook really gone
        vm.stopPrank();
        assertFalse(module.isInitialized(instance.account), "an uninstall that matches nothing clears both");
    }

    /// The backstop, with the note forced wrong on purpose: the hook is removed from the *account*
    /// behind the module's back, so the note still says "both". Whatever route got here, the agent
    /// gets three capped trades in total — not one per token per transaction, indefinitely.
    function test_G2_withTheNoteWrongTheTallyStopsTheAgentAtThree() public {
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

    /// G4's positive control for E1, adjusted for the tally: with the hook uninstalled ahead of the
    /// agent in one bundle, exactly three operations run hookless — so the bound in the pass-2 test
    /// is a bound on something that happens, not on a bundle that failed for another reason.
    function test_G4_uninstallAheadOfExactlyThreeRunsAllThree() public {
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

    /// G4's positive control for E3: a zero *fee* is fine when there is a budget, so the zero-budget
    /// test is refusing because of the budget and not because zero-fee operations never work.
    function test_G4_aZeroFeeOperationSucceedsWhenThereIsABudget() public {
        UserOpData memory op = _agentOp(lockCall(1));
        op.userOp.gasFees = bytes32(0);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _resign(op).userOp;
        instance.aux.entrypoint.handleOps(ops, payable(address(0x69)));
        assertEq(escrow.locks(), 1);
    }

    /// Every mount keeps its hook somewhere different, so "remove it without telling the module" is
    /// done the blunt way: make the module's own `onUninstall` a no-op for the duration.
    function _removeHookBehindTheModulesBack() internal {
        vm.mockCall(address(module), abi.encodeWithSelector(module.onUninstall.selector), "");
        instance.uninstallModule(TYPE_HOOK, address(module), bytes.concat(bytes32(TYPE_HOOK)));
        vm.clearMockedCalls();
        assertTrue(module.isInitialized(instance.account), "the note still says installed");
    }
}
