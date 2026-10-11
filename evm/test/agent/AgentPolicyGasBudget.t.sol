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

    /*//////////////////////////////////////////////////////////////
                      GAS FIELDS PAST THE ENTRYPOINT'S BOUND
    //////////////////////////////////////////////////////////////*/

    uint256 internal constant TWO_120 = 1 << 120;

    /// An operation whose gas fields the EntryPoint would never accept, sent straight to the
    /// validator: refused with an answer, and nothing charged. With an unlimited budget so the
    /// budget is not what refuses it; the all-`uint128` case is one whose cost overflows 256 bits.
    function test_aGasFieldAboveTwoTo120IsRefusedNotReverted() public {
        _asAccount(abi.encodeCall(module.setAgentGasBudget, (agentId, type(uint256).max)));
        uint256 big = TWO_120 + 1;
        uint256 max = type(uint128).max;
        uint256[4][5] memory cases = [
            [big, 1, 1, 1], // verificationGasLimit
            [uint256(1), big, 1, 1], // callGasLimit
            [uint256(1), 1, big, 1], // preVerificationGas
            [uint256(1), 1, 1, big], // maxFeePerGas
            [max, max, max, max]
        ];
        for (uint256 i = 0; i < cases.length; ++i) {
            assertEq(_validateWith(cases[i]), 1, "VALIDATION_FAILED, not a revert");
            assertEq(module.gasBudgetOf(instance.account, agentId), type(uint256).max, "nothing charged");
        }
    }

    /// The bound itself is priced like any other operation.
    function test_gasFieldsOfExactlyTwoTo120AreCharged() public {
        _asAccount(abi.encodeCall(module.setAgentGasBudget, (agentId, type(uint256).max)));
        assertEq(_validateWith([TWO_120, TWO_120, TWO_120, TWO_120]), 0, "approved");
        assertEq(
            module.gasBudgetOf(instance.account, agentId),
            type(uint256).max - 3 * TWO_120 * TWO_120,
            "debited at (verification + call + preVerification) x maxFeePerGas"
        );
    }

    /// `validateUserOp` called the way the account calls it, with
    /// `[verificationGasLimit, callGasLimit, preVerificationGas, maxFeePerGas]`.
    function _validateWith(uint256[4] memory g) internal returns (uint256) {
        UserOpData memory op = _agentOp(lockCall(1));
        op.userOp.accountGasLimits = bytes32(abi.encodePacked(uint128(g[0]), uint128(g[1])));
        op.userOp.preVerificationGas = g[2];
        op.userOp.gasFees = bytes32(abi.encodePacked(uint128(1), uint128(g[3])));
        bytes32 hash = keccak256("an operation outside the EntryPoint");
        op.userOp.signature = _sign(hash, agentKey);
        vm.prank(instance.account);
        // A raw call, so a revert is a failed assertion here rather than the test's own revert. (The
        // module and ModuleKit each declare `PackedUserOperation`; the encoding is the same.)
        (bool ok, bytes memory ret) =
            address(module).call(abi.encodeWithSelector(module.validateUserOp.selector, op.userOp, hash));
        assertTrue(ok, "validateUserOp reverted");
        return abi.decode(ret, (uint256));
    }
}
