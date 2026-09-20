// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {ModuleKitHelpers, UserOpData, PackedUserOperation} from "modulekit/ModuleKit.sol";
import {Execution} from "modulekit/accounts/erc7579/lib/ExecutionLib.sol";

import {ProofBridgeAgentPolicy} from "src/agent/ProofBridgeAgentPolicy.sol";
import {AgentPolicyBase} from "./AgentPolicyBase.t.sol";

/// Gas is a second way to spend the maker's money, and the volume buckets never see it: an agent
/// that bundles its own operation and names itself beneficiary turns `maxFeePerGas` into a
/// withdrawal. So each agent has a budget in wei, debited in validation at the most the operation
/// could cost. (Review findings D1, E3.)
contract AgentPolicyGasBudgetTest is AgentPolicyBase {
    using ModuleKitHelpers for *;

    /// D1. The policy bounded the trade and never looked at the fee. An agent that bundles its own
    /// operation and names itself beneficiary turns `maxFeePerGas` into a withdrawal.
    function test_theAgentCannotPayItselfTheMakersEthAsGas() public {
        uint256 before = instance.account.balance;
        UserOpData memory op = _agentOp(lockCall(1));
        op.userOp.gasFees = bytes32(abi.encodePacked(uint128(1e12), uint128(1e12)));
        op = _resign(op);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op.userOp;
        vm.prank(agent, agent);
        try instance.aux.entrypoint.handleOps(ops, payable(agent)) {} catch {}

        assertLt(before - instance.account.balance, 0.01 ether, "gas is money too, and it has a budget");
        assertEq(escrow.locks(), 0, "an operation over the gas budget is refused outright");
    }

    function test_theGasBudgetRunsOut() public {
        // ModuleKit's operations cost at most 1 wei x (2e6 + 2e6 + 2e6) = 6e6: room for one, not two.
        _asAccount(abi.encodeCall(module.setAgentGasBudget, (agentId, 9_000_000)));
        _agentOp(lockCall(1)).execUserOps();
        assertEq(escrow.locks(), 1, "the first operation fits the budget");
        assertEq(module.gasBudgetOf(instance.account, agentId), 3_000_000, "debited at the operation's maximum");

        UserOpData memory op = _agentOp(lockCall(1));
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(escrow.locks(), 1, "the second does not, and re-writing the policy is not a refill");
    }

    function test_noBudgetMeansNoOperations() public {
        _asAccount(abi.encodeCall(module.setAgentGasBudget, (agentId, 0)));
        UserOpData memory op = _agentOp(lockCall(1));
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(escrow.locks(), 0);
    }

    /// E3. "Zero means no budget, and no budget means refused" was false for a zero-fee operation:
    /// the cost is zero and `0 > 0` is not true. A self-bundling agent picks its own fee.
    function test_aZeroBudgetRefusesAZeroFeeOperation() public {
        _asAccount(abi.encodeCall(module.setAgentGasBudget, (agentId, 0)));
        UserOpData memory op = _agentOp(lockCall(1));
        op.userOp.gasFees = bytes32(0);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _resign(op).userOp;
        try instance.aux.entrypoint.handleOps(ops, payable(address(0x69))) {} catch {}
        assertEq(escrow.locks(), 0, "an owner who zeroes the budget to pause an agent has paused it");
    }

    /// G4's positive control for E3: a zero *fee* is fine when there is a budget, so the zero-budget
    /// test is refusing because of the budget and not because zero-fee operations never work.
    function test_control_aZeroFeeOperationSucceedsWhenThereIsABudget() public {
        UserOpData memory op = _agentOp(lockCall(1));
        op.userOp.gasFees = bytes32(0);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _resign(op).userOp;
        instance.aux.entrypoint.handleOps(ops, payable(address(0x69)));
        assertEq(escrow.locks(), 1);
    }

    function test_aPaymasterIsRefused() public {
        UserOpData memory op = _agentOp(lockCall(1));
        op.userOp.paymasterAndData = abi.encodePacked(address(0xBEEF), uint128(1e5), uint128(1e5));
        op = _resign(op);
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(escrow.locks(), 0);
    }
}
