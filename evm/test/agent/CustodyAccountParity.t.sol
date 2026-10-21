// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {ModuleKitHelpers, UserOpData} from "modulekit/ModuleKit.sol";

import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IAgentPolicyDirect, ProofBridgeCustodyAccount} from "src/agent/ProofBridgeCustodyAccount.sol";
import {CustodyAccountFactory} from "src/agent/CustodyAccountFactory.sol";
import {AgentPolicyBase} from "./AgentPolicyBase.t.sol";

/// Plan 45 C1: the custody account's direct path (`authorizeDirect`) and a 7579 account's UserOp path give the
/// same verdict on the same request under the same policy, and debit the buckets the same. One module, two
/// accounts: the base rig's ERC-7579 account and a custody account the agent drives directly.
contract CustodyAccountParityTest is AgentPolicyBase {
    using ModuleKitHelpers for *;

    ProofBridgeCustodyAccount internal custody;
    address internal owner = makeAddr("custody-owner");

    function setUp() public override {
        super.setUp();
        CustodyAccountFactory factory = new CustodyAccountFactory(IAgentPolicyDirect(address(module)));
        address[] memory targets = new address[](1);
        targets[0] = address(escrow);
        vm.prank(owner);
        custody = ProofBridgeCustodyAccount(payable(factory.deploy(0, targets)));
        // The base rig's configuration, on the custody account: the same ceilings and the same policy bytes.
        _asOwner(abi.encodeCall(module.setAccountLimit, (AD_TOKEN, ACCOUNT_CAPACITY, ACCOUNT_REFILL)));
        _asOwner(abi.encodeCall(module.setAccountLimit, (ORDER_TOKEN, ACCOUNT_CAPACITY, ACCOUNT_REFILL)));
        _asOwner(abi.encodeCall(module.setAgentPolicy, (agentId, defaultPolicy())));
    }

    /// Every single-call refusal the policy has, plus a lock that passes: both paths agree.
    function test_c1_bothPathsAgreeOnEveryRule() public {
        _same(lockCall(1), "a lock within the policy");
        _same(lockCall(MAX_PER_ORDER + 1, 2), "over the per-order cap");
        _same(
            _lockWith(orderParams(10, bytes32(uint256(0xbad)), ORDER_TOKEN, AD_ID, settlementSigner)),
            "an ad token not listed"
        );
        _same(
            _lockWith(orderParams(10, AD_TOKEN, bytes32(uint256(0xbad)), AD_ID, settlementSigner)),
            "an order token not listed"
        );
        _same(
            _lockWith(orderParams(10, AD_TOKEN, ORDER_TOKEN, AD_ID, bytes32(uint256(0xbad)))),
            "another settlement signer"
        );
        _same(abi.encodeCall(IAdManager.withdrawFromAd, (AD_ID, 1, agent)), "an action the policy doesn't allow");
    }

    /// The buckets drain at the same rate on both: five full locks pass, the sixth is refused on both.
    function test_c1_theBucketsDrainTheSame() public {
        for (uint256 i = 0; i < 6; ++i) {
            _same(lockCall(MAX_PER_ORDER, 100 + i), "draining the agent's allowance");
        }
        assertEq(module.agentBucket(address(custody), agentId, AD_TOKEN).level, 0, "drained");
    }

    function test_c1_bothRefuseAfterExpiry() public {
        uint64 until = uint64(block.timestamp + 1 hours);
        bytes memory expiring = policyBytes(false, until, MAX_PER_ORDER, CAPACITY, REFILL);
        _asAccount(abi.encodeCall(module.setAgentPolicy, (agentId, expiring)));
        _asOwner(abi.encodeCall(module.setAgentPolicy, (agentId, expiring)));
        _same(lockCall(1, 7), "before expiry");
        vm.warp(until);
        _same(lockCall(1, 8), "at expiry");
    }

    function test_c1_bothRefuseARevokedAgent() public {
        _asAccount(abi.encodeCall(module.revokeAgent, (agentId)));
        _asOwner(abi.encodeCall(module.revokeAgent, (agentId)));
        _same(lockCall(1, 9), "revoked");
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// The direct path first; then the UserOp path, expected to land or be refused the same; then the agent's
    /// and the account-wide buckets compared across the two accounts.
    function _same(bytes memory callData, string memory what) internal {
        uint256 locksBefore = escrow.locks();
        vm.prank(agent);
        (bool direct,) = address(custody).call(abi.encodeCall(custody.executeAsAgent, (address(escrow), callData)));
        bool directLanded = direct && escrow.locks() != locksBefore;

        uint256 mid = escrow.locks();
        UserOpData memory op = _agentOp(callData);
        if (!directLanded) instance.expect4337Revert();
        op.execUserOps();
        bool userOpLanded = escrow.locks() != mid;

        assertEq(directLanded, userOpLanded, string.concat("the paths disagree: ", what));
        assertEq(
            module.agentBucket(address(custody), agentId, AD_TOKEN).level,
            module.agentBucket(instance.account, agentId, AD_TOKEN).level,
            string.concat("the agent's bucket differs: ", what)
        );
        assertEq(
            module.accountBucket(address(custody), AD_TOKEN).level,
            module.accountBucket(instance.account, AD_TOKEN).level,
            string.concat("the account's bucket differs: ", what)
        );
    }

    function _lockWith(IAdManager.OrderParams memory p) internal pure returns (bytes memory) {
        return abi.encodeCall(IAdManager.lockForOrder, (p, uint32(0)));
    }

    function _asOwner(bytes memory callData) internal {
        vm.prank(owner);
        custody.execute(address(module), 0, callData);
    }
}
