// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {RhinestoneModuleKit, AccountInstance, UserOpData} from "modulekit/ModuleKit.sol";
import {ModuleKitHelpers} from "modulekit/ModuleKit.sol";
import {Execution} from "modulekit/accounts/erc7579/lib/ExecutionLib.sol";

import {IAdManager} from "src/interfaces/IAdManager.sol";
import {ProofBridgeAgentPolicy} from "src/agent/ProofBridgeAgentPolicy.sol";
import {AgentPolicyCodec} from "src/agent/AgentPolicyCodec.sol";
import {MockEscrow} from "./mocks/MockEscrow.sol";

/// Shared rig for the agent module's tests: an ERC-7579 account with both module types mounted, a
/// stand-in escrow, and one agent whose policy allows a single token pair.
abstract contract AgentPolicyBase is RhinestoneModuleKit, Test {
    using ModuleKitHelpers for *;

    uint256 internal constant TYPE_VALIDATOR = 1;
    uint256 internal constant TYPE_HOOK = 4;

    bytes32 internal constant AD_TOKEN = bytes32(uint256(0x1111));
    bytes32 internal constant ORDER_TOKEN = bytes32(uint256(0x2222));
    string internal constant AD_ID = "ad-alpha";

    uint256 internal constant MAX_PER_ORDER = 1_000_000;
    uint256 internal constant CAPACITY = 5_000_000;
    uint256 internal constant REFILL = 10;
    uint256 internal constant ACCOUNT_CAPACITY = 8_000_000;
    uint256 internal constant ACCOUNT_REFILL = 20;

    AccountInstance internal instance;
    ProofBridgeAgentPolicy internal module;
    MockEscrow internal escrow;

    address internal agent;
    uint256 internal agentKey;
    bytes32 internal agentId;
    bytes32 internal settlementSigner;

    function setUp() public virtual {
        instance = makeAccountInstance("agent-policy");
        vm.deal(instance.account, 10 ether);

        module = new ProofBridgeAgentPolicy();
        escrow = new MockEscrow();
        (agent, agentKey) = makeAddrAndKey("agent");
        agentId = bytes32(uint256(uint160(agent)));
        settlementSigner = bytes32(uint256(uint160(instance.account)));

        address[] memory targets = new address[](1);
        targets[0] = address(escrow);
        instance.installModule(
            TYPE_VALIDATOR, address(module), bytes.concat(bytes32(TYPE_VALIDATOR), abi.encode(targets))
        );
        instance.installModule(TYPE_HOOK, address(module), bytes.concat(bytes32(TYPE_HOOK)));

        _asAccount(abi.encodeCall(module.setAccountLimit, (AD_TOKEN, ACCOUNT_CAPACITY, ACCOUNT_REFILL)));
        _asAccount(abi.encodeCall(module.setAccountLimit, (ORDER_TOKEN, ACCOUNT_CAPACITY, ACCOUNT_REFILL)));
        _asAccount(abi.encodeCall(module.setAgentPolicy, (agentId, defaultPolicy())));
    }

    /*//////////////////////////////////////////////////////////////
                            POLICY BUILDING
    //////////////////////////////////////////////////////////////*/

    /// @dev The canonical encoding, built here rather than read from the vectors because the
    ///      settlement signer is the account this run happened to deploy. `AgentPolicyCodecTest`
    ///      is what pins these bytes against the TypeScript encoder.
    function policyBytes(bool scoped, uint64 validUntil, uint256 maxPerOrder, uint256 capacity, uint256 refill)
        internal
        view
        returns (bytes memory out)
    {
        out = bytes.concat(
            AgentPolicyCodec.DOMAIN, bytes1(uint8(1)), bytes1(AgentPolicyCodec.ACTION_LOCK_FOR_ORDER), bytes1(uint8(2))
        );
        // ascending by token, which is what the parser insists on
        (bytes32 lo, bytes32 hi) =
            uint256(AD_TOKEN) < uint256(ORDER_TOKEN) ? (AD_TOKEN, ORDER_TOKEN) : (ORDER_TOKEN, AD_TOKEN);
        out = bytes.concat(
            out,
            lo,
            bytes32(maxPerOrder),
            bytes32(capacity),
            bytes32(refill),
            hi,
            bytes32(maxPerOrder),
            bytes32(capacity),
            bytes32(refill)
        );
        if (scoped) {
            bytes memory ad = bytes(AD_ID);
            out = bytes.concat(out, bytes1(uint8(1)), bytes1(uint8(1)), bytes2(uint16(ad.length)), ad);
        } else {
            out = bytes.concat(out, bytes1(uint8(0)), bytes1(uint8(0)));
        }
        out = bytes.concat(out, bytes8(validUntil), settlementSigner);
    }

    function defaultPolicy() internal view returns (bytes memory) {
        return policyBytes(false, 0, MAX_PER_ORDER, CAPACITY, REFILL);
    }

    /*//////////////////////////////////////////////////////////////
                              ORDER PARAMS
    //////////////////////////////////////////////////////////////*/

    function orderParams(uint256 amount) internal view returns (IAdManager.OrderParams memory) {
        return orderParams(amount, AD_TOKEN, ORDER_TOKEN, AD_ID, settlementSigner);
    }

    function orderParams(uint256 amount, bytes32 adToken, bytes32 orderToken, string memory adId, bytes32 signer)
        internal
        pure
        returns (IAdManager.OrderParams memory p)
    {
        p = IAdManager.OrderParams({
            orderChainToken: orderToken,
            adChainToken: adToken,
            amount: amount,
            bridger: bytes32(uint256(0xb1)),
            orderChainId: 1,
            srcOrderPortal: bytes32(uint256(0x9a)),
            orderRecipient: bytes32(uint256(0xb2)),
            adId: adId,
            adCreator: bytes32(uint256(0xc1)),
            adRecipient: bytes32(uint256(0xc2)),
            salt: 1,
            // equal decimals, so the ad-unit amount is the order amount and the cap reads directly
            orderDecimals: 18,
            adDecimals: 18,
            deadline: type(uint64).max,
            adSettlementSigner: signer
        });
    }

    function lockCall(uint256 amount) internal view returns (bytes memory) {
        return abi.encodeCall(IAdManager.lockForOrder, (orderParams(amount)));
    }

    /*//////////////////////////////////////////////////////////////
                               EXECUTION
    //////////////////////////////////////////////////////////////*/

    /// @dev A configuration call, made by the account itself through its default validator — which
    ///      is the only way in, and is the whole of T-10's authorization rule.
    function _asAccount(bytes memory callData) internal {
        instance.exec(address(module), 0, callData);
    }

    /// @dev One operation, signed by the agent and validated by our module.
    function _agentOp(bytes memory callData) internal returns (UserOpData memory op) {
        op = instance.getExecOps(address(escrow), 0, callData, address(module));
        op.userOp.signature = _sign(op.userOpHash, agentKey);
    }

    function _agentBatch(Execution[] memory executions) internal returns (UserOpData memory op) {
        op = instance.getExecOps(executions, address(module));
        op.userOp.signature = _sign(op.userOpHash, agentKey);
    }

    function _sign(bytes32 userOpHash, uint256 key) internal pure returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }
}
