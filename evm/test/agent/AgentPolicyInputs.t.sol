// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {ModuleKitHelpers, UserOpData, PackedUserOperation} from "modulekit/ModuleKit.sol";
import {Execution} from "modulekit/accounts/erc7579/lib/ExecutionLib.sol";
import {AgentRateLimit} from "src/agent/AgentRateLimit.sol";
import {ProofBridgeAgentPolicy} from "src/agent/ProofBridgeAgentPolicy.sol";
import {AgentPolicyBase} from "./AgentPolicyBase.t.sol";
import {AgentPolicyCodec, IAgentPolicyCodecErrors} from "src/agent/AgentPolicyCodec.sol";
import {CodecHarness} from "./AgentPolicyCodec.t.sol";
import {PolicyHarness} from "./mocks/PolicyHarness.sol";

/// What the agent, or the owner, may hand the module: calldata shapes, execution modes, ETH on
/// the call, policy bytes, expiries, a changed ceiling, a mistyped id. Each is either refused
/// cleanly or handled the way Soroban handles it.
/// (Review findings C2, C3, C4, C6, D7, E5, E7.)
contract AgentPolicyInputsTest is AgentPolicyBase {
    using ModuleKitHelpers for *;

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

    /// C4. In try mode the account swallows a failing call, so the hook's debit would stick
    /// although no trade happened — and the agent is the one who picks the mode.
    function test_tryModeIsRefused() public {
        escrow.setFailNext(true);
        UserOpData memory op = _agentOp(lockCall(MAX_PER_ORDER));
        bytes32 tryMode = bytes32(uint256(0x01) << 240);
        op.userOp.callData = _executeSingle(tryMode, address(escrow), lockCall(MAX_PER_ORDER));
        op = _resign(op);
        instance.expect4337Revert();
        op.execUserOps();

        assertEq(escrow.locks(), 0);
        assertEq(
            module.agentBucket(instance.account, agentId, AD_TOKEN).lastTs, 0, "no trade, so no debit, in any mode"
        );
    }

    /// C3. "This agent may not do that" is an answer, not an exception: a revert in validation is
    /// what gets the *maker's account* throttled, and the calldata is the agent's to choose.
    function test_malformedCalldataIsRefusedRatherThanReverting() public {
        PolicyHarness harness = new PolicyHarness();
        (bool ok,) =
            harness.decodeCalls(abi.encodeWithSelector(bytes4(0xe9ae5c53), bytes32(uint256(1) << 248), hex"1122"));
        assertFalse(ok, "a truncated batch");
        assertFalse(harness.orderParamsDecode(abi.encodePacked(bytes4(0x12345678), hex"1122")), "garbage lock args");
    }

    /// E7. The pass-1 test for C3 pinned a harness. This pins the thing that matters: through the
    /// real EntryPoint, malformed agent calldata is a *refusal* (AA24), not a validation revert
    /// (AA23) — the second is what gets the maker's account throttled.
    function test_malformedCalldataIsAA24ThroughTheRealEntryPoint() public {
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

    /// C2. Actions and tokens were checked for strict order; ad ids only for adjacent equality of
    /// their hashes, so a repeated or unsorted scope installed with a fingerprint Soroban — which
    /// always sorts — can never produce.
    function test_adScopeMustBeStrictlyAscendingLikeEverythingElse() public {
        CodecHarness codec = new CodecHarness();
        vm.expectRevert(IAgentPolicyCodecErrors.AgentPolicyCodec__NotAscending.selector);
        codec.parse(_scoped("ad-zulu", "ad-alpha"));
        vm.expectRevert(IAgentPolicyCodecErrors.AgentPolicyCodec__NotAscending.selector);
        codec.parse(_scoped("ad-alpha", "ad-alpha"));
        // a prefix sorts before the longer id, as the TypeScript and Rust encoders have it
        codec.parse(_scoped("ad", "ad-alpha"));
    }

    /// C6. An id this policy language does not know installs a row nothing can match: a policy that
    /// authorizes nothing, which Soroban refuses as `BadPolicy`.
    function test_unknownActionIdsAreNotAPolicy() public {
        CodecHarness codec = new CodecHarness();
        bytes memory policy = defaultPolicy();
        policy[33] = bytes1(uint8(7));
        vm.expectRevert(
            abi.encodeWithSelector(IAgentPolicyCodecErrors.AgentPolicyCodec__UnknownAction.selector, uint8(7))
        );
        codec.parse(policy);
        policy[33] = bytes1(uint8(0));
        vm.expectRevert(
            abi.encodeWithSelector(IAgentPolicyCodecErrors.AgentPolicyCodec__UnknownAction.selector, uint8(0))
        );
        codec.parse(policy);
    }

    /// D7. Same class: a policy already expired when it is written.
    function test_anAlreadyExpiredPolicyIsRefusedAtInstall() public {
        vm.warp(1_000_000);
        vm.startPrank(instance.account);
        vm.expectRevert(ProofBridgeAgentPolicy.AgentPolicy__BadExpiry.selector);
        module.setAgentPolicy(agentId, policyBytes(false, 999_999, MAX_PER_ORDER, CAPACITY, REFILL));
        vm.expectRevert(ProofBridgeAgentPolicy.AgentPolicy__BadExpiry.selector);
        module.setAgentPolicy(agentId, policyBytes(false, 1, MAX_PER_ORDER, CAPACITY, REFILL));
        // ...and one the EntryPoint's 48-bit field cannot carry is refused, not read as "forever"
        vm.expectRevert(ProofBridgeAgentPolicy.AgentPolicy__BadExpiry.selector);
        module.setAgentPolicy(agentId, policyBytes(false, type(uint64).max, MAX_PER_ORDER, CAPACITY, REFILL));
        vm.stopPrank();
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

    /// E5. The tombstone is permanent, so revoking an id that was never installed would burn it on
    /// this account for good. Soroban refuses with NoPolicyForAgent; so does this.
    function test_revokingAnIdThatWasNeverInstalledIsRefused() public {
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

    function _executeSingle(bytes32 mode, address target, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(bytes4(0xe9ae5c53), mode, abi.encodePacked(target, uint256(0), data));
    }

    function _scoped(string memory first, string memory second) internal view returns (bytes memory) {
        bytes memory head = bytes.concat(
            AgentPolicyCodec.DOMAIN,
            bytes1(uint8(1)),
            bytes1(AgentPolicyCodec.ACTION_LOCK_FOR_ORDER),
            bytes1(uint8(1)),
            AD_TOKEN,
            bytes32(uint256(1)),
            bytes32(uint256(1)),
            bytes32(uint256(1))
        );
        return bytes.concat(
            head,
            bytes1(uint8(1)),
            bytes1(uint8(2)),
            bytes2(uint16(bytes(first).length)),
            bytes(first),
            bytes2(uint16(bytes(second).length)),
            bytes(second),
            bytes8(uint64(0)),
            settlementSigner
        );
    }
}
