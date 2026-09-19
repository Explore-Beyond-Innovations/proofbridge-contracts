// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {ModuleKitHelpers, UserOpData, PackedUserOperation} from "modulekit/ModuleKit.sol";
import {Execution} from "modulekit/accounts/erc7579/lib/ExecutionLib.sol";

import {AgentRateLimit} from "src/agent/AgentRateLimit.sol";
import {AgentPolicyBase} from "./AgentPolicyBase.t.sol";

/// Found on the review pass over 2.1g. Each of these passed the suite that shipped first, which is
/// the point of keeping them: the first suite never asked.
contract AgentPolicyReviewTest is AgentPolicyBase {
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

    /// The policy speaks about a target, a selector and the trade. ETH attached to the call is
    /// outside all three, so the only safe amount is none.
    function test_anOperationCarryingEthIsRefused() public {
        UserOpData memory op = instance.getExecOps(address(escrow), 1 ether, lockCall(1), address(module));
        op.userOp.signature = _sign(op.userOpHash, agentKey);
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(escrow.locks(), 0);
        assertEq(address(escrow).balance, 0);
    }

    /// Soroban: usable while `now < valid_until`. The EntryPoint: valid while `now <= validUntil`.
    /// One second apart, and the shared fixture (2.1h) would find it the hard way.
    function test_expiryIsExclusiveAsOnSoroban() public {
        uint64 expiry = uint64(block.timestamp + 100);
        _asAccount(
            abi.encodeCall(
                module.setAgentPolicy, (agentId, policyBytes(false, expiry, MAX_PER_ORDER, CAPACITY, REFILL))
            )
        );
        vm.warp(expiry);
        UserOpData memory op = _agentOp(lockCall(1));
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(escrow.locks(), 0, "at the expiry second the policy is already dead");
    }

    /// Changing the ceiling's rate must settle the idle time at the *old* rate first. Left alone,
    /// the whole idle interval is re-priced at whatever rate was just written.
    function test_changingTheCeilingDoesNotRepriceTheIdleTime() public {
        _agentOp(lockCall(MAX_PER_ORDER)).execUserOps();
        uint256 levelAfterSpend = module.accountBucket(instance.account, AD_TOKEN).level;

        vm.warp(block.timestamp + 1000);
        // 1000 idle seconds at the old rate, then a rate 100x higher from now on
        _asAccount(abi.encodeCall(module.setAccountLimit, (AD_TOKEN, ACCOUNT_CAPACITY, ACCOUNT_REFILL * 100)));

        AgentRateLimit.Bucket memory b = module.accountBucket(instance.account, AD_TOKEN);
        assertEq(b.level, levelAfterSpend + 1000 * ACCOUNT_REFILL, "the idle time earned the old rate");
        assertEq(b.lastTs, block.timestamp, "and the clock restarts at the change");
    }
}
