// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {ProofBridgeAgentPolicy} from "src/agent/ProofBridgeAgentPolicy.sol";
import {IAgentPolicyDirect, ProofBridgeCustodyAccount} from "src/agent/ProofBridgeCustodyAccount.sol";
import {CustodyAccountFactory} from "src/agent/CustodyAccountFactory.sol";
import {AgentPolicyParityTest} from "./AgentPolicyParity.t.sol";
import {MockEscrow} from "./mocks/MockEscrow.sol";

/// Plan 46 D11: the shared policy fixture (T-60) through the custody account's direct path, `executeAsAgent` →
/// `authorizeDirect`, beside the UserOp path `AgentPolicyParityTest` runs. Same walker, same cases; only the
/// account and the way a lock is sent differ. Every lock's verdict is held to `preflight` and to whether the lock
/// landed. The direct path takes one call at a time, so a `request` step (a batch, one authorization) is judged by
/// `preflight` on the batch and, when accepted, sent as its locks one after another.
/// forge-config: default.isolate = true
contract CustodyAccountFixtureTest is AgentPolicyParityTest {
    ProofBridgeCustodyAccount internal custody;

    function setUp() public override {
        module = new ProofBridgeAgentPolicy();
        escrow = new MockEscrow();
        unpinned = new MockEscrow();
        (agent, agentKey) = makeAddrAndKey("agent");
        agentId = bytes32(uint256(uint160(agent)));

        CustodyAccountFactory factory = new CustodyAccountFactory(IAgentPolicyDirect(address(module)));
        address[] memory targets = new address[](1);
        targets[0] = address(escrow);
        vm.prank(makeAddr("custody-owner"));
        custody = ProofBridgeCustodyAccount(payable(factory.deploy(0, targets)));
        // The walker configures and judges "the account" through `instance.account`: the custody account here.
        instance.account = address(custody);
    }

    function _judge(Loaded memory step) internal override {
        address[] memory to = new address[](step.callData.length);
        for (uint256 i = 0; i < to.length; ++i) {
            to[i] = address(step.pinned[i] ? escrow : unpinned);
        }
        // As the UserOp runner does: `HookNotProven` is a 4337 mount-health rule the shared fixture doesn't
        // carry, and the direct path never sends a batch to earn it.
        if (step.request && module.fingerprintOf(address(custody), agentId) != bytes32(0)) _markHookProven();
        (ProofBridgeAgentPolicy.Refusal why, uint256 callIndex) =
            module.preflight(address(custody), agentId, _executeCalldata(to, step.callData, step.request));
        assertEq(uint8(why), uint8(step.refusal), step.at);
        if (step.request && !step.accept) {
            assertEq(callIndex, step.refusedAt, string.concat(step.at, ": the lock refused"));
            return; // a refused batch sends nothing: the module's verdict on the whole is the claim
        }
        uint256 before = escrow.locks() + unpinned.locks();
        for (uint256 i = 0; i < step.callData.length; ++i) {
            vm.prank(agent);
            (bool ok,) = address(custody).call(abi.encodeCall(custody.executeAsAgent, (to[i], step.callData[i])));
            assertEq(ok, step.accept, string.concat(step.at, ": through executeAsAgent"));
        }
        assertEq(
            escrow.locks() + unpinned.locks(),
            before + (step.accept ? step.callData.length : 0),
            string.concat(step.at, ": landed")
        );
    }

    /// The account's `execute` encoding for one call, or a batch for a `request`, as `preflight` reads it.
    function _executeCalldata(address[] memory to, bytes[] memory data, bool batch)
        internal
        pure
        returns (bytes memory)
    {
        if (!batch) {
            return abi.encodeWithSelector(0xe9ae5c53, bytes32(0), abi.encodePacked(to[0], uint256(0), data[0]));
        }
        Exec[] memory calls = new Exec[](data.length);
        for (uint256 i = 0; i < data.length; ++i) {
            calls[i] = Exec({target: to[i], value: 0, callData: data[i]});
        }
        return abi.encodeWithSelector(0xe9ae5c53, bytes32(uint256(1) << 248), abi.encode(calls));
    }

    struct Exec {
        address target;
        uint256 value;
        bytes callData;
    }
}
