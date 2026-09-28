// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {ModuleKitHelpers, UserOpData} from "modulekit/ModuleKit.sol";
import {Execution} from "modulekit/accounts/erc7579/lib/ExecutionLib.sol";

import {IAdManager} from "src/interfaces/IAdManager.sol";
import {ProofBridgeAgentPolicy} from "src/agent/ProofBridgeAgentPolicy.sol";
import {AgentRateLimit} from "src/agent/AgentRateLimit.sol";
import {AgentPolicyBase} from "./AgentPolicyBase.t.sol";
import {MockEscrow} from "./mocks/MockEscrow.sol";

/// The four enforcement paths (T-10), the volume accounting, and the things that turn the module
/// off. Each refusal is written as "this operation does not reach the escrow", because that is the
/// property that matters — not which error came back.
contract AgentPolicyEnforcementTest is AgentPolicyBase {
    using ModuleKitHelpers for *;

    function test_aLockWithinPolicyGoesThrough() public {
        _agentOp(lockCall(100_000)).execUserOps();

        assertEq(escrow.locks(), 1, "the escrow saw the lock");
        assertEq(
            module.agentBucket(instance.account, agentId, AD_TOKEN).level,
            CAPACITY - 100_000,
            "the agent's own allowance went down by the trade"
        );
        assertEq(
            module.accountBucket(instance.account, AD_TOKEN).level,
            ACCOUNT_CAPACITY - 100_000,
            "and so did the account-wide ceiling"
        );
    }

    /*//////////////////////////////////////////////////////////////
                         T-10: WHO MAY CONFIGURE
    //////////////////////////////////////////////////////////////*/

    function test_configurationFromAnyoneButTheAccountIsRefused() public {
        address stranger = makeAddr("stranger");
        vm.startPrank(stranger);
        // Not installed for the stranger's own "account", so every configuration path closes on the
        // same check. There is no owner here to impersonate: the account address is the authority.
        vm.expectRevert(ProofBridgeAgentPolicy.AgentPolicy__NotInstalled.selector);
        module.setAgentPolicy(agentId, defaultPolicy());
        vm.expectRevert(ProofBridgeAgentPolicy.AgentPolicy__NotInstalled.selector);
        module.setAccountLimit(AD_TOKEN, 1, 1);
        vm.expectRevert(ProofBridgeAgentPolicy.AgentPolicy__NotInstalled.selector);
        module.revokeAgent(agentId);
        vm.stopPrank();

        // And a stranger who installs the module on themselves cannot touch this account's rows.
        vm.startPrank(stranger);
        module.onInstall(bytes.concat(bytes32(TYPE_VALIDATOR)));
        // Their "account" holds no such policy, so there is nothing of theirs to revoke either.
        vm.expectRevert(ProofBridgeAgentPolicy.AgentPolicy__NoPolicyForAgent.selector);
        module.revokeAgent(agentId);
        vm.stopPrank();
        assertTrue(module.fingerprintOf(instance.account, agentId) != bytes32(0), "our policy is untouched");
    }

    /// C-9: every owner-only entry point, as a table. A stranger gets `NotInstalled` on each; a
    /// stranger who installed the module on itself only ever writes its own rows.
    function test_c9_everyOwnerOnlyEntryPointRefusesAStranger() public {
        bytes[] memory calls = _ownerOnlyCalls();
        address stranger = makeAddr("c9-stranger");
        for (uint256 i = 0; i < calls.length; ++i) {
            vm.prank(stranger);
            (bool ok, bytes memory err) = address(module).call(calls[i]);
            assertFalse(ok, string.concat("a stranger got through: ", vm.toString(bytes4(calls[i]))));
            assertEq(
                err,
                abi.encodeWithSelector(ProofBridgeAgentPolicy.AgentPolicy__NotInstalled.selector),
                string.concat("wrong refusal for ", vm.toString(bytes4(calls[i])))
            );
        }

        // Installed on itself, the stranger's writes land on its own rows. Ours stay as they were.
        bytes32 fingerprint = module.fingerprintOf(instance.account, agentId);
        uint256 budget = module.gasBudgetOf(instance.account, agentId);
        uint256 ceiling = module.accountBucket(instance.account, AD_TOKEN).level;
        // Kernel mounts its hook through an adapter, so the account may already have a forwarder.
        address forwarder = module.trustedForwarder(instance.account);
        vm.prank(stranger);
        module.onInstall(bytes.concat(bytes32(TYPE_VALIDATOR)));
        for (uint256 i = 0; i < calls.length; ++i) {
            vm.prank(stranger);
            (bool ok,) = address(module).call(calls[i]);
            ok; // some succeed on the stranger's own rows, some refuse: either way ours must not move
        }
        assertEq(module.fingerprintOf(instance.account, agentId), fingerprint, "policy untouched");
        assertFalse(module.isRevoked(instance.account, agentId), "not revoked");
        assertEq(module.gasBudgetOf(instance.account, agentId), budget, "budget untouched");
        assertEq(module.accountBucket(instance.account, AD_TOKEN).level, ceiling, "ceiling untouched");
        assertTrue(module.isTargetPinned(instance.account, address(escrow)), "target still pinned");
        assertEq(module.trustedForwarder(instance.account), forwarder, "our forwarder untouched");
    }

    /// C-9: `clearTrustedForwarder` has no install check on purpose (Kernel calls it after
    /// uninstall), so the property is that it only ever clears the caller's own entry.
    function test_c9_clearTrustedForwarderOnlyClearsTheCallersOwnEntry() public {
        address forwarder = makeAddr("c9-forwarder");
        _asAccount(abi.encodeCall(module.setTrustedForwarder, (forwarder)));
        vm.prank(makeAddr("c9-stranger"));
        module.clearTrustedForwarder();
        assertEq(module.trustedForwarder(instance.account), forwarder, "a stranger cleared our forwarder");
    }

    /// C-9 drift guard: every state-changing function in the module's ABI is either in the owner-only
    /// table above or named here as a mount/validation entry point. A new setter fails this until
    /// it is added to the table.
    function test_c9_theOwnerOnlyTableCoversTheWholeAbi() public view {
        string memory artifact = vm.readFile("out/ProofBridgeAgentPolicy.sol/ProofBridgeAgentPolicy.json");
        string[] memory writers = abi.decode(
            vm.parseJson(artifact, "$.abi[?(@.stateMutability!='view' && @.stateMutability!='pure')].name"), (string[])
        );
        bytes[] memory table = _ownerOnlyCalls();
        // Not owner-gated by design: install/uninstall act on the caller, validation and the hook
        // are the account's own 4337 calls, and clearing a forwarder only clears the caller's entry.
        string[6] memory ungated =
            ["onInstall", "onUninstall", "validateUserOp", "preCheck", "postCheck", "clearTrustedForwarder"];
        assertGt(writers.length, ungated.length, "the ABI read found nothing");
        for (uint256 i = 0; i < writers.length; ++i) {
            bool known;
            for (uint256 j = 0; j < ungated.length; ++j) {
                if (keccak256(bytes(writers[i])) == keccak256(bytes(ungated[j]))) known = true;
            }
            for (uint256 j = 0; j < table.length && !known; ++j) {
                if (_nameOf(bytes4(table[j])) == keccak256(bytes(writers[i]))) known = true;
            }
            assertTrue(known, string.concat("state-changing function with no owner-only row: ", writers[i]));
        }
    }

    /// C-19: each refusal on the configuration and mount paths names its own error.
    function test_c19_everyConfigurationRefusalNamesItsError() public {
        vm.startPrank(instance.account);
        vm.expectRevert(ProofBridgeAgentPolicy.AgentPolicy__AlreadyInstalled.selector);
        module.onInstall(bytes.concat(bytes32(TYPE_VALIDATOR)));
        vm.expectRevert(ProofBridgeAgentPolicy.AgentPolicy__InstallDataTooShort.selector);
        module.onInstall(hex"01");
        vm.expectRevert(abi.encodeWithSelector(ProofBridgeAgentPolicy.AgentPolicy__UnsupportedModuleType.selector, 2));
        module.onInstall(bytes.concat(bytes32(uint256(2))));
        vm.expectRevert(ProofBridgeAgentPolicy.AgentPolicy__BadLimit.selector);
        module.setAccountLimit(AD_TOKEN, 0, 1);
        vm.expectRevert(ProofBridgeAgentPolicy.AgentPolicy__BadLimit.selector);
        module.setAccountLimit(AD_TOKEN, 1, 0);
        vm.expectRevert(ProofBridgeAgentPolicy.AgentPolicy__ZeroAgent.selector);
        module.setAgentPolicy(bytes32(0), defaultPolicy());
        vm.expectRevert(ProofBridgeAgentPolicy.AgentPolicy__AgentIdNotAnAddress.selector);
        module.setAgentPolicy(bytes32(uint256(1) << 160), defaultPolicy());
        vm.stopPrank();
    }

    /// C-19: an operation validated while the policy was live, then revoked before its hook ran
    /// (the bundle-ordering case), is refused at execution with its own error.
    function test_c19_aRevokeBetweenValidationAndExecutionIsNamed() public {
        UserOpData memory op = _agentOp(lockCall(1));
        vm.prank(instance.account);
        (bool validated, bytes memory answer) =
            address(module).call(abi.encodeWithSelector(module.validateUserOp.selector, op.userOp, op.userOpHash));
        assertTrue(validated);
        assertEq(uint160(abi.decode(answer, (uint256))), 0, "approved, so a marker waits");

        vm.prank(instance.account);
        module.revokeAgent(agentId);

        vm.prank(instance.account);
        vm.expectRevert(ProofBridgeAgentPolicy.AgentPolicy__RevokedBeforeExecution.selector);
        module.preCheck(address(0), 0, op.userOp.callData);
    }

    function _ownerOnlyCalls() internal view returns (bytes[] memory calls) {
        address[] memory targets = new address[](1);
        targets[0] = address(escrow);
        calls = new bytes[](7);
        calls[0] = abi.encodeCall(module.setTargets, (targets, false));
        calls[1] = abi.encodeCall(module.setAccountLimit, (AD_TOKEN, 1, 1));
        calls[2] = abi.encodeCall(module.setAgentGasBudget, (agentId, 0));
        calls[3] = abi.encodeCall(module.resetAgentTally, (agentId));
        calls[4] = abi.encodeCall(module.setAgentPolicy, (agentId, defaultPolicy()));
        calls[5] = abi.encodeCall(module.revokeAgent, (agentId));
        calls[6] = abi.encodeCall(module.setTrustedForwarder, (address(0xF0F0)));
    }

    /// The function name behind a table row's selector.
    function _nameOf(bytes4 sel) internal view returns (bytes32) {
        if (sel == module.setTargets.selector) return keccak256("setTargets");
        if (sel == module.setAccountLimit.selector) return keccak256("setAccountLimit");
        if (sel == module.setAgentGasBudget.selector) return keccak256("setAgentGasBudget");
        if (sel == module.resetAgentTally.selector) return keccak256("resetAgentTally");
        if (sel == module.setAgentPolicy.selector) return keccak256("setAgentPolicy");
        if (sel == module.revokeAgent.selector) return keccak256("revokeAgent");
        if (sel == module.setTrustedForwarder.selector) return keccak256("setTrustedForwarder");
        return bytes32(0);
    }

    /*//////////////////////////////////////////////////////////////
                         T-10: THE FOUR PATHS
    //////////////////////////////////////////////////////////////*/

    function test_anUnpinnedTargetIsRefused() public {
        MockEscrow other = new MockEscrow();
        UserOpData memory op = instance.getExecOps(address(other), 0, lockCall(1), address(module));
        op.userOp.signature = _sign(op.userOpHash, agentKey);
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(other.locks(), 0);
    }

    function test_aSelectorOutsideThePolicyIsRefused() public {
        bytes memory withdraw = abi.encodeCall(MockEscrow.withdrawFromAd, ("ad-alpha", 1, address(this)));
        UserOpData memory op = _agentOp(withdraw);
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(escrow.locks(), 0, "the escrow was never called");
    }

    function test_aTokenOffTheWhitelistIsRefused() public {
        bytes32 foreign = bytes32(uint256(0xdead));
        bytes memory call =
            abi.encodeCall(IAdManager.lockForOrder, (orderParams(1, foreign, ORDER_TOKEN, AD_ID, settlementSigner)));
        UserOpData memory op = _agentOp(call);
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(escrow.locks(), 0);

        // ...and the order-side token is checked too, not just the one the cap is written against.
        call = abi.encodeCall(IAdManager.lockForOrder, (orderParams(1, AD_TOKEN, foreign, AD_ID, settlementSigner)));
        op = _agentOp(call);
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(escrow.locks(), 0);
    }

    function test_anAdOutsideTheAgentsScopeIsRefused() public {
        _asAccount(
            abi.encodeCall(module.setAgentPolicy, (agentId, policyBytes(true, 0, MAX_PER_ORDER, CAPACITY, REFILL)))
        );

        // the ad the policy names still works
        _agentOp(lockCall(1)).execUserOps();
        assertEq(escrow.locks(), 1);

        bytes memory call = abi.encodeCall(
            IAdManager.lockForOrder, (orderParams(1, AD_TOKEN, ORDER_TOKEN, "ad-other", settlementSigner))
        );
        UserOpData memory op = _agentOp(call);
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(escrow.locks(), 1, "the second lock never landed");
    }

    function test_aForeignSettlementSignerIsRefused() public {
        bytes memory call = abi.encodeCall(
            IAdManager.lockForOrder, (orderParams(1, AD_TOKEN, ORDER_TOKEN, AD_ID, bytes32(uint256(0xfeed))))
        );
        UserOpData memory op = _agentOp(call);
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(escrow.locks(), 0);
    }

    function test_overThePerOrderCapIsRefused() public {
        UserOpData memory op = _agentOp(lockCall(MAX_PER_ORDER + 1));
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(escrow.locks(), 0);

        // exactly at the cap is fine: the boundary belongs to the maker
        _agentOp(lockCall(MAX_PER_ORDER)).execUserOps();
        assertEq(escrow.locks(), 1);
    }

    /*//////////////////////////////////////////////////////////////
                           VOLUME ACCOUNTING
    //////////////////////////////////////////////////////////////*/

    function test_theBucketDrainsAndThenRefuses() public {
        // five locks at the cap is the whole capacity
        for (uint256 i = 0; i < CAPACITY / MAX_PER_ORDER; ++i) {
            _agentOp(lockCall(MAX_PER_ORDER)).execUserOps();
        }
        assertEq(module.agentBucket(instance.account, agentId, AD_TOKEN).level, 0);

        UserOpData memory op = _agentOp(lockCall(1));
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(escrow.locks(), CAPACITY / MAX_PER_ORDER, "nothing more got through");
    }

    function test_theAllowanceComesBackWithTime() public {
        _agentOp(lockCall(MAX_PER_ORDER)).execUserOps();
        uint256 after1 = module.agentBucket(instance.account, agentId, AD_TOKEN).level;

        vm.warp(block.timestamp + 1000);
        _agentOp(lockCall(1)).execUserOps();
        assertEq(
            module.agentBucket(instance.account, agentId, AD_TOKEN).level,
            after1 + 1000 * REFILL - 1,
            "1000 seconds refilled at the configured rate, then one unit spent"
        );
    }

    function test_theAccountCeilingBindsWhenTheAgentStillHasRoom() public {
        // A second agent with the same generous per-agent limits: neither exhausts its own bucket,
        // and together they are stopped by the account's.
        (address agent2, uint256 key2) = makeAddrAndKey("agent-two");
        _asAccount(abi.encodeCall(module.setAgentPolicy, (bytes32(uint256(uint160(agent2))), defaultPolicy())));
        _asAccount(abi.encodeCall(module.setAgentGasBudget, (bytes32(uint256(uint160(agent2))), GAS_BUDGET)));

        for (uint256 i = 0; i < 5; ++i) {
            _agentOp(lockCall(MAX_PER_ORDER)).execUserOps();
        }
        assertEq(module.accountBucket(instance.account, AD_TOKEN).level, ACCOUNT_CAPACITY - CAPACITY);

        // agent two's own bucket is untouched and still full
        UserOpData memory op = instance.getExecOps(address(escrow), 0, lockCall(MAX_PER_ORDER), address(module));
        op.userOp.signature = _sign(op.userOpHash, key2);
        op.execUserOps();
        op = instance.getExecOps(address(escrow), 0, lockCall(MAX_PER_ORDER), address(module));
        op.userOp.signature = _sign(op.userOpHash, key2);
        op.execUserOps();
        op = instance.getExecOps(address(escrow), 0, lockCall(MAX_PER_ORDER), address(module));
        op.userOp.signature = _sign(op.userOpHash, key2);
        op.execUserOps();

        assertEq(module.accountBucket(instance.account, AD_TOKEN).level, 0, "the ceiling is spent");
        assertEq(
            module.agentBucket(instance.account, bytes32(uint256(uint160(agent2))), AD_TOKEN).level,
            CAPACITY - 3 * MAX_PER_ORDER,
            "agent two still has its own allowance left"
        );

        op = instance.getExecOps(address(escrow), 0, lockCall(1), address(module));
        op.userOp.signature = _sign(op.userOpHash, key2);
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(escrow.locks(), 8, "the account-wide ceiling stopped an agent that had room");
    }

    /*//////////////////////////////////////////////////////////////
                          THE OFF SWITCHES
    //////////////////////////////////////////////////////////////*/

    function test_revokingKillsTheAgentAndTheTombstoneIsSticky() public {
        _asAccount(abi.encodeCall(module.revokeAgent, (agentId)));
        assertEq(module.fingerprintOf(instance.account, agentId), bytes32(0));

        UserOpData memory op = _agentOp(lockCall(1));
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(escrow.locks(), 0);

        // and the owner cannot un-revoke by writing the policy again
        vm.prank(instance.account);
        vm.expectRevert(ProofBridgeAgentPolicy.AgentPolicy__AgentRevoked.selector);
        module.setAgentPolicy(agentId, defaultPolicy());
    }

    function test_anExpiredPolicyIsRefused() public {
        uint64 expiry = uint64(block.timestamp + 100);
        _asAccount(
            abi.encodeCall(
                module.setAgentPolicy, (agentId, policyBytes(false, expiry, MAX_PER_ORDER, CAPACITY, REFILL))
            )
        );

        _agentOp(lockCall(1)).execUserOps();
        assertEq(escrow.locks(), 1, "in date");

        vm.warp(expiry + 1);
        UserOpData memory op = _agentOp(lockCall(1));
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(escrow.locks(), 1, "expiry is enforced by the bundler from the validation result");
    }

    function test_theValidatorAloneRefuses() public {
        instance.uninstallModule(TYPE_HOOK, address(module), bytes.concat(bytes32(TYPE_HOOK)));
        UserOpData memory op = _agentOp(lockCall(1));
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(escrow.locks(), 0, "without the hook nothing would debit, so nothing is allowed");
    }

    /*//////////////////////////////////////////////////////////////
                                BATCHES
    //////////////////////////////////////////////////////////////*/

    function test_aBatchOfTwoIsDebitedTwice() public {
        Execution[] memory calls = new Execution[](2);
        calls[0] = Execution({target: address(escrow), value: 0, callData: lockCall(400_000)});
        calls[1] = Execution({target: address(escrow), value: 0, callData: lockCall(600_000)});
        _agentBatch(calls).execUserOps();

        assertEq(escrow.locks(), 2);
        assertEq(
            module.agentBucket(instance.account, agentId, AD_TOKEN).level,
            CAPACITY - 1_000_000,
            "one operation, two calls, both debited"
        );
    }

    function test_aBatchWhoseSecondCallBreaksThePolicyIsRejectedWhole() public {
        Execution[] memory calls = new Execution[](2);
        calls[0] = Execution({target: address(escrow), value: 0, callData: lockCall(1)});
        calls[1] = Execution({target: address(escrow), value: 0, callData: lockCall(MAX_PER_ORDER + 1)});
        UserOpData memory op = _agentBatch(calls);
        instance.expect4337Revert();
        op.execUserOps();

        assertEq(escrow.locks(), 0, "the permitted call did not smuggle the other one through");
        assertEq(module.agentBucket(instance.account, agentId, AD_TOKEN).lastTs, 0, "and nothing was debited");
    }

    function test_aBatchCannotOutspendTheBucketByBeingSplitInTwo() public {
        // Each call fits the per-order cap and, judged against an untouched bucket, each fits the
        // allowance. Together they do not, which only shows up if the walk carries the bucket.
        _agentOp(lockCall(MAX_PER_ORDER)).execUserOps();
        vm.warp(block.timestamp + 1);

        Execution[] memory calls = new Execution[](5);
        for (uint256 i = 0; i < 5; ++i) {
            calls[i] = Execution({target: address(escrow), value: 0, callData: lockCall(MAX_PER_ORDER)});
        }
        UserOpData memory op = _agentBatch(calls);
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(escrow.locks(), 1);
    }

    /*//////////////////////////////////////////////////////////////
                       THE REASON THE HOOK EXISTS
    //////////////////////////////////////////////////////////////*/

    function test_aRevertedExecutionCostsTheMakerNothing() public {
        _agentOp(lockCall(MAX_PER_ORDER)).execUserOps();
        AgentRateLimit.Bucket memory before = module.agentBucket(instance.account, agentId, AD_TOKEN);

        escrow.setFailNext(true);
        UserOpData memory op = _agentOp(lockCall(MAX_PER_ORDER));
        // The operation itself is valid — the agent may do this. The escrow is what refuses, which
        // is the case the hook exists for.
        instance.expect4337Revert();
        op.execUserOps();

        assertEq(escrow.locks(), 1, "the second call reverted inside the escrow");
        AgentRateLimit.Bucket memory afterFail = module.agentBucket(instance.account, agentId, AD_TOKEN);
        assertEq(afterFail.level, before.level, "a trade that did not happen did not spend the allowance");
        assertEq(
            module.accountBucket(instance.account, AD_TOKEN).level,
            ACCOUNT_CAPACITY - MAX_PER_ORDER,
            "and the ceiling is untouched too"
        );
    }

    /*//////////////////////////////////////////////////////////////
                          EPOCH AND VERSIONING
    //////////////////////////////////////////////////////////////*/

    function test_reinstallingOrphansEveryRowTheOldEpochWrote() public {
        instance.uninstallModule(TYPE_HOOK, address(module), bytes.concat(bytes32(TYPE_HOOK)));
        instance.uninstallModule(TYPE_VALIDATOR, address(module), bytes.concat(bytes32(TYPE_VALIDATOR)));

        address[] memory targets = new address[](1);
        targets[0] = address(escrow);
        instance.installModule(
            TYPE_VALIDATOR, address(module), bytes.concat(bytes32(TYPE_VALIDATOR), abi.encode(targets))
        );
        instance.installModule(TYPE_HOOK, address(module), bytes.concat(bytes32(TYPE_HOOK)));

        assertEq(module.fingerprintOf(instance.account, agentId), bytes32(0), "the old policy is unreachable");
        UserOpData memory op = _agentOp(lockCall(1));
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(escrow.locks(), 0);
    }

    function test_writingThePolicyAgainResetsTheAgentButNotTheAccountCeiling() public {
        _agentOp(lockCall(MAX_PER_ORDER)).execUserOps();
        assertEq(module.agentBucket(instance.account, agentId, AD_TOKEN).level, CAPACITY - MAX_PER_ORDER);

        _asAccount(abi.encodeCall(module.setAgentPolicy, (agentId, defaultPolicy())));

        assertEq(module.agentBucket(instance.account, agentId, AD_TOKEN).lastTs, 0, "the agent's spend is reset");
        assertEq(
            module.accountBucket(instance.account, AD_TOKEN).level,
            ACCOUNT_CAPACITY - MAX_PER_ORDER,
            "the aggregate keeps binding across the reset, or the reset would be a way to spend twice"
        );
    }

    function test_aPolicyNeedsAnAccountCeilingForEveryTokenItNames() public {
        bytes32 fresh = bytes32(uint256(0x3333));
        vm.prank(instance.account);
        vm.expectRevert(abi.encodeWithSelector(ProofBridgeAgentPolicy.AgentPolicy__NoAccountCeiling.selector, fresh));
        module.setAgentPolicy(bytes32(uint256(0xa9)), _policyForToken(fresh));
    }

    function _policyForToken(bytes32 token) internal view returns (bytes memory) {
        return bytes.concat(
            bytes.concat(
                hex"",
                abi.encodePacked(
                    keccak256("ProofBridge.AgentPolicy.v1"), bytes1(uint8(1)), bytes1(uint8(1)), bytes1(uint8(1))
                )
            ),
            token,
            bytes32(uint256(1)),
            bytes32(uint256(1)),
            bytes32(uint256(1)),
            hex"0000",
            bytes8(uint64(0)),
            settlementSigner
        );
    }
}
