// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {ModuleKitHelpers, UserOpData, PackedUserOperation} from "modulekit/ModuleKit.sol";

import {ProofBridgeAgentPolicy, IKernelView} from "src/agent/ProofBridgeAgentPolicy.sol";
import {AgentPolicyBase} from "./AgentPolicyBase.t.sol";

/// @dev A hook forwarder. `wide` appends `forwarder ‖ account` (Kernel's multiplexer); otherwise
///      `account` alone (ERC-2771).
contract TailForwarder {
    function forward(address module, bytes calldata hookCall, address account, bool wide) external {
        bytes memory data =
            wide ? abi.encodePacked(hookCall, address(this), account) : abi.encodePacked(hookCall, account);
        (bool ok, bytes memory ret) = module.call(data);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 32), mload(ret))
            }
        }
    }
}

/// The shapes a hook call can arrive in, and whose execution the hook believes it is looking at.
/// An approved trade the hook fails to recognise is charged nothing, so each shape has to either
/// charge exactly once or fail the trade. Runs on every account CI covers (ACCOUNT_TYPE).
contract AgentPolicyHookShapesTest is AgentPolicyBase {
    using ModuleKitHelpers for *;

    bytes4 internal constant EXECUTE_USER_OP = 0x8dd7712f;

    TailForwarder internal forwarder;

    function setUp() public override {
        super.setUp();
        forwarder = new TailForwarder();
    }

    /*//////////////////////////////////////////////////////////////
                         THROUGH THE REAL ACCOUNT
    //////////////////////////////////////////////////////////////*/

    function test_aPlainTradeChargesOnce() public {
        _agentOp(lockCall(MAX_PER_ORDER)).execUserOps();
        _assertChargedOnce(MAX_PER_ORDER, 1);
    }

    /// `0x8dd7712f ‖ execute(...)`. Nexus hooks both `executeUserOp` (full ABI) and the inner
    /// `execute`, so the hook runs twice for one trade there; it must charge once.
    function test_aWrappedTradeChargesOnce() public {
        UserOpData memory op = _wrapped(lockCall(MAX_PER_ORDER, 1), 0);
        if (_mount("SAFE")) {
            // Safe7579 has no `executeUserOp`: the operation fails, and nothing is charged.
            instance.expect4337Revert();
            op.execUserOps();
            assertEq(escrow.locks(), 0);
            assertEq(module.agentBucket(instance.account, agentId, AD_TOKEN).lastTs, 0, "untouched");
            return;
        }
        op.execUserOps();
        _assertChargedOnce(MAX_PER_ORDER, 1);
    }

    function test_twoDifferentWrappedTradesInOneBundleEachChargeOnce() public {
        if (_mount("SAFE")) vm.skip(true);
        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        ops[0] = _wrapped(lockCall(400_000, 1), 0).userOp;
        ops[1] = _wrapped(lockCall(600_000, 2), 1).userOp;
        instance.aux.entrypoint.handleOps(ops, payable(address(0x69)));
        _assertChargedOnce(1_000_000, 2);
    }

    /// One identical operation per transaction: the escrow would refuse the second lock of one order
    /// hash anyway, and it keeps a double hook call from ever popping two markers.
    function test_aSecondIdenticalOperationInOneBundleIsRefusedAtValidation() public {
        bytes memory cd = lockCall(MAX_PER_ORDER);
        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        ops[0] = _agentOpAt(0, cd);
        ops[1] = _agentOpAt(1, cd);
        vm.expectRevert(abi.encodeWithSelector(FailedOp.selector, uint256(1), "AA24 signature error"));
        instance.aux.entrypoint.handleOps(ops, payable(address(0x69)));
        assertEq(escrow.locks(), 0);

        // each on its own lands and is charged once
        _agentOp(cd).execUserOps();
        _assertChargedOnce(MAX_PER_ORDER, 1);
        _agentOp(cd).execUserOps();
        _assertChargedOnce(2 * MAX_PER_ORDER, 2);
    }

    /// The owner's operation ahead of an agent's in one bundle executes while the agent's marker is
    /// already queued. It matches nothing and must pass — or an agent that builds bundles could make
    /// the owner's revoke fail.
    function test_anOwnerOperationAheadOfAnAgentTradeInOneBundlePasses() public {
        UserOpData memory owner = instance.getExecOps(
            address(module),
            0,
            abi.encodeCall(module.setAgentGasBudget, (agentId, 2 ether)),
            address(instance.defaultValidator)
        );
        owner = owner.signDefault();
        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        ops[0] = owner.userOp;
        ops[1] = _agentOp(lockCall(MAX_PER_ORDER)).userOp;
        instance.aux.entrypoint.handleOps(ops, payable(address(0x69)));
        // the agent's gas was charged in validation, before the owner's op set the budget
        assertEq(module.gasBudgetOf(instance.account, agentId), 2 ether, "owner op landed");
        _assertChargedOnce(MAX_PER_ORDER, 1);
    }

    /// Kernel shares its one hook slot through a multiplexer, which the module trusts only when the
    /// account nominated it. With the wrong forwarder nominated the hook cannot tell whose execution
    /// it is: an agent trade fails, and the owner — `setTrustedForwarder` included — is not locked out.
    function test_kernelWithTheWrongForwarderFailsAgentTradesButNotTheOwner() public {
        if (!_mount("KERNEL")) vm.skip(true);
        address multiplexer = module.trustedForwarder(instance.account);
        assertTrue(multiplexer != address(0), "ModuleKit mounts Kernel's hook through its multiplexer");

        _asAccount(abi.encodeCall(module.setTrustedForwarder, (makeAddr("wrong"))));
        (ProofBridgeAgentPolicy.Refusal why,) =
            module.preflight(instance.account, agentId, _agentOp(lockCall(1)).userOp.callData);
        assertEq(
            uint8(why), uint8(ProofBridgeAgentPolicy.Refusal.NotMounted), "Kernel's hook for this validator is not ours"
        );
        _asAccount(abi.encodeCall(module.setAgentGasBudget, (agentId, 2 ether)));
        assertEq(module.gasBudgetOf(instance.account, agentId), 2 ether, "an owner op through the multiplexer");

        UserOpData memory op = _agentOp(lockCall(MAX_PER_ORDER));
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(escrow.locks(), 0, "the agent trade does not run uncharged");

        _asAccount(abi.encodeCall(module.setTrustedForwarder, (multiplexer)));
        _agentOp(lockCall(MAX_PER_ORDER, 2)).execUserOps();
        _assertChargedOnce(MAX_PER_ORDER, 1);
    }

    /// Kernel through ModuleKit, as mounted: multiplexer, 40-byte tail, trusted forwarder.
    function test_kernelThroughItsMultiplexerChargesOnce() public {
        if (!_mount("KERNEL")) vm.skip(true);
        assertEq(bytes4(_agentOp(lockCall(1)).userOp.callData), EXECUTE_USER_OP, "Kernel wraps when a hook is set");
        _agentOp(lockCall(MAX_PER_ORDER)).execUserOps();
        _assertChargedOnce(MAX_PER_ORDER, 1);
    }

    /*//////////////////////////////////////////////////////////////
                        THE HOOK CALLED DIRECTLY
    //////////////////////////////////////////////////////////////*/

    /// The full ABI `executeUserOp(PackedUserOperation, bytes32)`, as an account that hooks
    /// `executeUserOp` itself hands it over — then the inner `execute`, as Nexus follows with.
    function test_aFullAbiHookCallChargesOnce() public {
        UserOpData memory op = _wrapped(lockCall(MAX_PER_ORDER, 1), 0);
        _validateAsAccount(op);

        vm.prank(instance.account);
        module.preCheck(address(0), 0, _fullAbi(op));
        _assertChargedOnce(MAX_PER_ORDER, 0);

        // Nexus's second hook call, for the same execution: nothing left to charge
        vm.prank(instance.account);
        module.preCheck(address(0), 0, _inner(op.userOp.callData));
        _assertChargedOnce(MAX_PER_ORDER, 0);
        assertEq(module.uncountedOf(instance.account, agentId), 0, "counted");
    }

    function test_aMalformedFullAbiHookCallChargesNothing() public {
        UserOpData memory op = _wrapped(lockCall(MAX_PER_ORDER, 1), 0);
        _validateAsAccount(op);
        bytes memory good = _fullAbi(op);

        // the struct's offset, `callData`'s offset inside it, and `callData`'s length, each pushed
        // past the end; and the whole thing cut short
        uint256[3] memory at = [uint256(4), 0, 0];
        at[1] = 4 + _word(good, 4) + 96;
        at[2] = 4 + _word(good, 4) + _word(good, at[1]);
        for (uint256 i = 0; i < 3; ++i) {
            bytes memory bad = bytes.concat(good);
            _setWord(bad, at[i], good.length);
            vm.prank(instance.account);
            module.preCheck(address(0), 0, bad);
        }
        bytes memory cut = new bytes(200);
        for (uint256 i = 0; i < 200; ++i) {
            cut[i] = good[i];
        }
        vm.prank(instance.account);
        module.preCheck(address(0), 0, cut);

        assertEq(module.agentBucket(instance.account, agentId, AD_TOKEN).lastTs, 0, "nothing charged");
        assertEq(module.uncountedOf(instance.account, agentId), 1, "still owed: the tally sees it");
    }

    /// The validator never reads the full ABI form: the struct would be the agent's own words
    /// inside `callData`, while the account executes `callData[4:]`.
    function test_aFullAbiUserOpCallDataIsRefusedAtValidation() public {
        UserOpData memory inner = _wrapped(lockCall(MAX_PER_ORDER, 1), 0);
        UserOpData memory op = _agentOp(lockCall(1));
        op.userOp.callData = _fullAbi(inner);
        op = _resign(op);
        assertEq(_validateAsAccount(op), 1, "VALIDATION_FAILED");
        (ProofBridgeAgentPolicy.Refusal why,) = module.preflight(instance.account, agentId, op.userOp.callData);
        assertEq(uint8(why), uint8(ProofBridgeAgentPolicy.Refusal.MalformedRequest));
    }

    /// A plain ERC-2771 forwarder appends the account alone.
    function test_aTwentyByteTrustedForwarderCharges() public {
        _asAccount(abi.encodeCall(module.setTrustedForwarder, (address(forwarder))));
        // Kernel's install check wants its config to name the forwarder as this validator's hook.
        if (_mount("KERNEL")) {
            vm.mockCall(
                instance.account,
                abi.encodeWithSelector(IKernelView.validationConfig.selector),
                abi.encode(uint32(0), address(forwarder))
            );
        }
        UserOpData memory op = _agentOp(lockCall(MAX_PER_ORDER));
        _validateAsAccount(op);
        forwarder.forward(address(module), _hookCall(op.userOp.callData), instance.account, false);
        _assertChargedOnce(MAX_PER_ORDER, 0);
    }

    function test_anUntrustedForwarderRoutingAnAgentTradeReverts() public {
        UserOpData memory op = _agentOp(lockCall(MAX_PER_ORDER));
        _validateAsAccount(op);
        bytes memory hookCall = _hookCall(op.userOp.callData);
        for (uint256 wide = 0; wide < 2; ++wide) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    ProofBridgeAgentPolicy.AgentPolicy__UnknownHookCaller.selector, address(forwarder)
                )
            );
            forwarder.forward(address(module), hookCall, instance.account, wide == 1);
        }
        assertEq(module.agentBucket(instance.account, agentId, AD_TOKEN).lastTs, 0);
    }

    /// The same untrusted forwarder routing an owner operation: nothing is waiting, so it passes.
    function test_anUntrustedForwarderRoutingAnOwnerOperationPasses() public {
        bytes memory ownerCall = _hookCall(
            abi.encodeWithSelector(
                bytes4(0xe9ae5c53),
                bytes32(0),
                abi.encodePacked(address(module), uint256(0), abi.encodeCall(module.revokeAgent, (agentId)))
            )
        );
        forwarder.forward(address(module), ownerCall, instance.account, false);
        forwarder.forward(address(module), ownerCall, instance.account, true);
    }

    /// The EntryPoint routes to `executeUserOp` only for a `callData` that starts with the wrapper,
    /// and the account executes `callData[4:]`. A full-ABI call whose `callData` is a bare `execute`
    /// is not what would run, so it matches nothing.
    function test_aFullAbiCallWithoutTheWrapperPrefixMatchesNothing() public {
        UserOpData memory op = _wrapped(lockCall(MAX_PER_ORDER, 1), 0);
        _validateAsAccount(op);
        op.userOp.callData = _inner(op.userOp.callData);
        vm.prank(instance.account);
        module.preCheck(address(0), 0, _fullAbi(op));
        assertEq(module.agentBucket(instance.account, agentId, AD_TOKEN).lastTs, 0, "nothing charged");
        assertEq(module.uncountedOf(instance.account, agentId), 1, "still owed");
    }

    /*//////////////////////////////////////////////////////////////
                       THE ACCOUNT MUST LIST THE HOOK
    //////////////////////////////////////////////////////////////*/

    /// The module's note says "both" and the account no longer has the hook. Validation asks the
    /// account, so the agent is refused before anything runs, on every account type.
    function test_aHookRemovedBehindTheModulesBackIsRefusedAtValidation() public {
        _removeHookBehindTheModulesBack();
        UserOpData memory op = _agentOp(lockCall(MAX_PER_ORDER));
        (ProofBridgeAgentPolicy.Refusal why,) = module.preflight(instance.account, agentId, op.userOp.callData);
        assertEq(uint8(why), uint8(ProofBridgeAgentPolicy.Refusal.NotMounted), "preflight");
        assertEq(_validateAsAccount(op), 1, "VALIDATION_FAILED");
    }

    /// ...and a correct mount passes the same check on every account type.
    function test_aCorrectMountPassesTheInstallCheck() public {
        (ProofBridgeAgentPolicy.Refusal why,) =
            module.preflight(instance.account, agentId, _agentOp(lockCall(1)).userOp.callData);
        assertEq(uint8(why), uint8(ProofBridgeAgentPolicy.Refusal.None));
    }

    /*//////////////////////////////////////////////////////////////
                     BATCHES WAIT FOR THE HOOK'S PROOF
    //////////////////////////////////////////////////////////////*/

    /// A new policy version starts unproven: one single trade the hook charges, then batches.
    function test_aBatchBeforeTheHookHasChargedTheAgentIsRefused() public {
        _asAccount(abi.encodeCall(module.setAgentPolicy, (agentId, defaultPolicy())));
        assertFalse(module.hookProvenOf(instance.account, agentId), "a new policy version is unproven");

        UserOpData memory batch = _agentBatch(_batch(2, 1_000));
        (ProofBridgeAgentPolicy.Refusal why,) = module.preflight(instance.account, agentId, batch.userOp.callData);
        assertEq(uint8(why), uint8(ProofBridgeAgentPolicy.Refusal.HookNotProven), "preflight");
        instance.expect4337Revert();
        batch.execUserOps();
        assertEq(escrow.locks(), 0, "the validator refuses it too");

        _agentOp(lockCall(1_000, 7)).execUserOps();
        assertTrue(module.hookProvenOf(instance.account, agentId), "the hook charged a single: proven");
        _agentBatch(_batch(2, 1_000)).execUserOps();
        assertEq(escrow.locks(), 3, "and batches are welcome");
    }

    /// A re-installed hook proves itself again, whatever it proved before.
    function test_reinstallingTheHookStartsUnproven() public {
        assertTrue(module.hookProvenOf(instance.account, agentId));
        instance.uninstallModule(TYPE_HOOK, address(module), bytes.concat(bytes32(TYPE_HOOK)));
        instance.installModule(TYPE_HOOK, address(module), bytes.concat(bytes32(TYPE_HOOK)));
        assertFalse(module.hookProvenOf(instance.account, agentId), "a new hook install is unproven");
    }

    /// The bound for a mount or shape the hook never charges: `MAX_UNCOUNTED` single trades, no
    /// batch, then the agent pauses.
    function test_aHookThatNeverChargesAllowsThreeSingleTradesAndNoBatch() public {
        _asAccount(abi.encodeCall(module.setAgentPolicy, (agentId, defaultPolicy())));
        _silenceTheHook();

        UserOpData memory batch = _agentBatch(_batch(5, MAX_PER_ORDER));
        instance.expect4337Revert();
        batch.execUserOps();
        assertEq(escrow.locks(), 0, "no batch before the hook has proven itself");

        for (uint256 i = 0; i < 5; ++i) {
            UserOpData memory op = _agentOp(lockCall(MAX_PER_ORDER, 100 + i));
            instance.expect4337Revert();
            op.execUserOps();
        }
        assertEq(escrow.locks(), 3, "three single trades, then the agent is paused");
    }

    /*//////////////////////////////////////////////////////////////
                               MODE BYTES
    //////////////////////////////////////////////////////////////*/

    /// Only bytes 0 and 1 (call type, exec type) mean anything to the decoder. An account that
    /// switched layout on the rest could run calls the policy never read.
    function test_junkInTheModeIsRefusedByTheValidatorAndPreflight() public {
        bytes memory single = abi.encodePacked(address(escrow), uint256(0), lockCall(MAX_PER_ORDER));
        uint8[3] memory junkAt = [2, 6, 31]; // unused, selector, payload
        for (uint256 i = 0; i < 3; ++i) {
            bytes32 mode = bytes32(uint256(1) << (8 * (31 - junkAt[i])));
            bytes memory cd = abi.encodeWithSelector(bytes4(0xe9ae5c53), mode, single);
            (ProofBridgeAgentPolicy.Refusal why,) = module.preflight(instance.account, agentId, cd);
            assertEq(uint8(why), uint8(ProofBridgeAgentPolicy.Refusal.MalformedRequest), "preflight");

            UserOpData memory op = _agentOp(lockCall(1));
            op.userOp.callData = cd;
            assertEq(_validateAsAccount(_resign(op)), 1, "validator");
        }
        // single and batch default modes still pass
        (ProofBridgeAgentPolicy.Refusal ok,) =
            module.preflight(instance.account, agentId, abi.encodeWithSelector(bytes4(0xe9ae5c53), bytes32(0), single));
        assertEq(uint8(ok), uint8(ProofBridgeAgentPolicy.Refusal.None));
        (ok,) = module.preflight(instance.account, agentId, _agentBatch(_batch(2, 1)).userOp.callData);
        assertEq(uint8(ok), uint8(ProofBridgeAgentPolicy.Refusal.None));
    }

    /*//////////////////////////////////////////////////////////////
                                 HELPERS
    //////////////////////////////////////////////////////////////*/

    function _mount(string memory name) internal view returns (bool) {
        return keccak256(bytes(vm.envOr("ACCOUNT_TYPE", string("DEFAULT")))) == keccak256(bytes(name));
    }

    /// The agent's lock as `0x8dd7712f ‖ execute(...)`, the `seq`-th operation of its bundle.
    function _wrapped(bytes memory lock, uint256 seq) internal returns (UserOpData memory op) {
        op = _agentOp(lock);
        if (bytes4(op.userOp.callData) != EXECUTE_USER_OP) {
            op.userOp.callData = bytes.concat(EXECUTE_USER_OP, op.userOp.callData);
        }
        op.userOp.nonce += seq;
        op = _resign(op);
    }

    /// What the EntryPoint sends an account for a wrapped operation, and what Nexus hands its hook.
    function _fullAbi(UserOpData memory op) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(EXECUTE_USER_OP, op.userOp, op.userOpHash);
    }

    function _inner(bytes memory wrapped) internal pure returns (bytes memory out) {
        out = new bytes(wrapped.length - 4);
        for (uint256 i = 0; i < out.length; ++i) {
            out[i] = wrapped[i + 4];
        }
    }

    function _hookCall(bytes memory msgData) internal view returns (bytes memory) {
        return abi.encodeCall(module.preCheck, (address(0), 0, msgData));
    }

    /// Validation called as the account, as the account does — by selector, since the module
    /// vendors its own `PackedUserOperation`.
    function _validateAsAccount(UserOpData memory op) internal returns (uint256) {
        vm.prank(instance.account);
        (bool ok, bytes memory answer) =
            address(module).call(abi.encodeWithSelector(module.validateUserOp.selector, op.userOp, op.userOpHash));
        assertTrue(ok, "validation answers, it does not revert");
        return uint160(abi.decode(answer, (uint256)));
    }

    function _assertChargedOnce(uint256 total, uint256 locks) internal view {
        assertEq(module.agentBucket(instance.account, agentId, AD_TOKEN).level, CAPACITY - total, "agent bucket");
        assertEq(module.accountBucket(instance.account, AD_TOKEN).level, ACCOUNT_CAPACITY - total, "account ceiling");
        assertEq(escrow.locks(), locks, "locks");
    }

    function _word(bytes memory b, uint256 at) internal pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 32), at))
        }
    }

    function _setWord(bytes memory b, uint256 at, uint256 w) internal pure {
        assembly ("memory-safe") {
            mstore(add(add(b, 32), at), w)
        }
    }
}
