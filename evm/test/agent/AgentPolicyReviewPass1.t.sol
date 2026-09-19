// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {ModuleKitHelpers, UserOpData, PackedUserOperation} from "modulekit/ModuleKit.sol";

import {ProofBridgeAgentPolicy} from "src/agent/ProofBridgeAgentPolicy.sol";
import {AgentPolicyCodec} from "src/agent/AgentPolicyCodec.sol";
import {AgentPolicyBase} from "./AgentPolicyBase.t.sol";
import {CodecHarness} from "./AgentPolicyCodec.t.sol";
import {PolicyHarness} from "./mocks/PolicyHarness.sol";

/// Review pass 1 (internal-docs/t2/pr-reviews/contracts-33-evm-agent-module.md). Every test here
/// was written against the code as reviewed and watched failing before the fix went in — the
/// review's PoCs were scratch files, and a finding without a test comes back.
contract AgentPolicyReviewPass1Test is AgentPolicyBase {
    using ModuleKitHelpers for *;

    function _resign(UserOpData memory op) internal view returns (UserOpData memory) {
        op.userOpHash = instance.aux.entrypoint.getUserOpHash(op.userOp);
        op.userOp.signature = _sign(op.userOpHash, agentKey);
        return op;
    }

    function _executeSingle(bytes32 mode, address target, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(bytes4(0xe9ae5c53), mode, abi.encodePacked(target, uint256(0), data));
    }

    /*//////////////////////////////////////////////////////////////
                                 HIGH
    //////////////////////////////////////////////////////////////*/

    /// C1. Anyone could nominate the maker's account as *their* forwarder, and an agent could then
    /// pad its calldata so the hook resolved "the account" to that stranger — finding no marker
    /// there, and debiting nothing.
    function test_C1_paddedCalldataCannotPointTheHookAtSomeoneElse() public {
        // Gating the setter is not enough on its own: the squatter simply installs the module on
        // itself first, which anyone may do. So this test does exactly that.
        address stranger = makeAddr("forwarder-squatter");
        vm.startPrank(stranger);
        module.onInstall(bytes.concat(bytes32(TYPE_VALIDATOR)));
        module.setTrustedForwarder(instance.account);
        vm.stopPrank();

        UserOpData memory op = _agentOp(lockCall(MAX_PER_ORDER));
        // The hook reads the last 40 bytes of its own calldata as `forwarder ‖ account`. `msgData`
        // is ABI-padded to a word, so the tail is aligned first or the padding would hide it.
        bytes memory cd = op.userOp.callData;
        uint256 filler = (32 - ((cd.length + 40) % 32)) % 32;
        op.userOp.callData = bytes.concat(cd, new bytes(filler), abi.encodePacked(instance.account, stranger));
        _resign(op).execUserOps();

        assertEq(escrow.locks(), 1, "padding is tolerated by design, so the lock goes through");
        assertEq(
            module.agentBucket(instance.account, agentId, AD_TOKEN).level,
            CAPACITY - MAX_PER_ORDER,
            "and it was debited under the real account, whatever the calldata ended in"
        );
    }

    /// D1. The policy bounded the trade and never looked at the fee. An agent that bundles its own
    /// operation and names itself beneficiary turns `maxFeePerGas` into a withdrawal.
    function test_D1_theAgentCannotPayItselfTheMakersEthAsGas() public {
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

    function test_D1_theGasBudgetRunsOut() public {
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

    function test_D1_noBudgetMeansNoOperations() public {
        _asAccount(abi.encodeCall(module.setAgentGasBudget, (agentId, 0)));
        UserOpData memory op = _agentOp(lockCall(1));
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(escrow.locks(), 0);
    }

    function test_D1_aPaymasterIsRefused() public {
        UserOpData memory op = _agentOp(lockCall(1));
        op.userOp.paymasterAndData = abi.encodePacked(address(0xBEEF), uint128(1e5), uint128(1e5));
        op = _resign(op);
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(escrow.locks(), 0);
    }

    /// D2. Safe and Nexus swallow a reverting `onUninstall` and remove the hook anyway, so a module
    /// that refused empty de-init data kept believing both halves were mounted.
    function test_D2_aRoutineHookUninstallTurnsTheAgentOff() public {
        instance.uninstallModule(TYPE_HOOK, address(module), "");

        UserOpData memory op = _agentOp(lockCall(1));
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(escrow.locks(), 0, "approving with nothing debiting is the one state that must not exist");
    }

    /// D4. Every validation in a bundle runs before any execution, so an operation validated while
    /// the policy was live would execute after the revoke that was bundled ahead of it.
    function test_D4_aRevokeBundledAheadOfTheAgentStillStopsIt() public {
        UserOpData memory revoke = instance.getExecOps(
            address(module), 0, abi.encodeCall(module.revokeAgent, (agentId)), address(instance.defaultValidator)
        );
        revoke = revoke.signDefault();
        UserOpData memory lock = _agentOp(lockCall(1));

        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        ops[0] = revoke.userOp;
        ops[1] = lock.userOp;
        instance.aux.entrypoint.handleOps(ops, payable(address(0x69)));

        assertTrue(module.isRevoked(instance.account, agentId));
        assertEq(escrow.locks(), 0, "revoked means revoked from that execution onward");
    }

    /*//////////////////////////////////////////////////////////////
                                MEDIUM
    //////////////////////////////////////////////////////////////*/

    /// C4. In try mode the account swallows a failing call, so the hook's debit would stick
    /// although no trade happened — and the agent is the one who picks the mode.
    function test_C4_tryModeIsRefused() public {
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
    function test_C3_malformedCalldataIsRefusedRatherThanReverting() public {
        PolicyHarness harness = new PolicyHarness();
        (bool ok,) =
            harness.decodeCalls(abi.encodeWithSelector(bytes4(0xe9ae5c53), bytes32(uint256(1) << 248), hex"1122"));
        assertFalse(ok, "a truncated batch");
        assertFalse(harness.orderParamsDecode(abi.encodePacked(bytes4(0x12345678), hex"1122")), "garbage lock args");
    }

    /// C2. Actions and tokens were checked for strict order; ad ids only for adjacent equality of
    /// their hashes, so a repeated or unsorted scope installed with a fingerprint Soroban — which
    /// always sorts — can never produce.
    function test_C2_adScopeMustBeStrictlyAscendingLikeEverythingElse() public {
        CodecHarness codec = new CodecHarness();
        vm.expectRevert(AgentPolicyCodec.AgentPolicyCodec__NotAscending.selector);
        codec.parse(_scoped("ad-zulu", "ad-alpha"));
        vm.expectRevert(AgentPolicyCodec.AgentPolicyCodec__NotAscending.selector);
        codec.parse(_scoped("ad-alpha", "ad-alpha"));
        // a prefix sorts before the longer id, as the TypeScript and Rust encoders have it
        codec.parse(_scoped("ad", "ad-alpha"));
    }

    /*//////////////////////////////////////////////////////////////
                         REFUSED AT INSTALL, AS ON SOROBAN
    //////////////////////////////////////////////////////////////*/

    /// C6. An id this policy language does not know installs a row nothing can match: a policy that
    /// authorizes nothing, which Soroban refuses as `BadPolicy`.
    function test_C6_unknownActionIdsAreNotAPolicy() public {
        CodecHarness codec = new CodecHarness();
        bytes memory policy = defaultPolicy();
        policy[33] = bytes1(uint8(7));
        vm.expectRevert(abi.encodeWithSelector(AgentPolicyCodec.AgentPolicyCodec__UnknownAction.selector, uint8(7)));
        codec.parse(policy);
        policy[33] = bytes1(uint8(0));
        vm.expectRevert(abi.encodeWithSelector(AgentPolicyCodec.AgentPolicyCodec__UnknownAction.selector, uint8(0)));
        codec.parse(policy);
    }

    /// D7. Same class: a policy already expired when it is written.
    function test_D7_anAlreadyExpiredPolicyIsRefusedAtInstall() public {
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

    /// D10. Soroban's tombstone is permanent. Keyed by the epoch, this one could be lifted by
    /// uninstalling and reinstalling the module.
    function test_D10_theTombstoneOutlivesAReinstall() public {
        _asAccount(abi.encodeCall(module.revokeAgent, (agentId)));
        instance.uninstallModule(TYPE_HOOK, address(module), bytes.concat(bytes32(TYPE_HOOK)));
        instance.uninstallModule(TYPE_VALIDATOR, address(module), bytes.concat(bytes32(TYPE_VALIDATOR)));
        address[] memory targets = new address[](1);
        targets[0] = address(escrow);
        instance.installModule(
            TYPE_VALIDATOR, address(module), bytes.concat(bytes32(TYPE_VALIDATOR), abi.encode(targets))
        );
        instance.installModule(TYPE_HOOK, address(module), bytes.concat(bytes32(TYPE_HOOK)));

        assertTrue(module.isRevoked(instance.account, agentId), "a revoked key stays dead on this account");
        vm.prank(instance.account);
        vm.expectRevert(ProofBridgeAgentPolicy.AgentPolicy__AgentRevoked.selector);
        module.setAgentPolicy(agentId, defaultPolicy());
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
