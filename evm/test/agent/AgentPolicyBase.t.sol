// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {RhinestoneModuleKit, AccountInstance, UserOpData, PackedUserOperation} from "modulekit/ModuleKit.sol";
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
    uint256 internal constant GAS_BUDGET = 1 ether;

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
        // Generous: these suites are about the policy, and AgentPolicyReviewPass1 is about the budget.
        _asAccount(abi.encodeCall(module.setAgentGasBudget, (agentId, GAS_BUDGET)));
        // As if the hook had already charged this agent once: most suites are about what a batch
        // does, not about earning the right to send one. `AgentPolicyHookShapesTest` starts unproven.
        _markHookProven();
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

    /// @dev A distinct order: the module queues one identical operation per transaction, as the
    ///      escrow locks one order hash, so several locks in one bundle need several salts.
    function lockCall(uint256 amount, uint256 salt) internal view returns (bytes memory) {
        IAdManager.OrderParams memory p = orderParams(amount);
        p.salt = salt;
        return abi.encodeCall(IAdManager.lockForOrder, (p));
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

    /*//////////////////////////////////////////////////////////////
                     SHARED BY THE TOPIC SUITES
    //////////////////////////////////////////////////////////////*/

    /// @dev The EntryPoint's own refusal, for asserting *how* an operation was turned away:
    ///      "AA24 signature error" is how a validator's "no" reads.
    error FailedOp(uint256 opIndex, string reason);

    /// @dev Re-hash and re-sign after a test has edited the operation.
    function _resign(UserOpData memory op) internal view returns (UserOpData memory) {
        op.userOpHash = instance.aux.entrypoint.getUserOpHash(op.userOp);
        op.userOp.signature = _sign(op.userOpHash, agentKey);
        return op;
    }

    /// @dev The `seq`-th agent operation of one bundle: same key space, the next nonce.
    function _agentOpAt(uint256 seq, bytes memory callData) internal returns (PackedUserOperation memory) {
        UserOpData memory op = _agentOp(callData);
        op.userOp.nonce += seq;
        return _resign(op).userOp;
    }

    function _batch(uint256 n, uint256 amount) internal view returns (Execution[] memory calls) {
        calls = new Execution[](n);
        for (uint256 i = 0; i < n; ++i) {
            calls[i] = Execution({target: address(escrow), value: 0, callData: lockCall(amount)});
        }
    }

    /// @dev The owner's operation that uninstalls the hook, for bundling ahead of the agent's.
    function _uninstallHookOp() internal returns (PackedUserOperation memory) {
        UserOpData memory uninstall = instance.getUninstallModuleOps(
            TYPE_HOOK, address(module), bytes.concat(bytes32(TYPE_HOOK)), address(instance.defaultValidator)
        );
        return uninstall.signDefault().userOp;
    }

    /// @dev Every mount keeps its hook somewhere different, so "remove it without telling the module"
    ///      is done the blunt way: the module's own `onUninstall` is a no-op for the duration. The
    ///      module's note then still says "both", which is the state under test.
    function _removeHookBehindTheModulesBack() internal {
        vm.mockCall(address(module), abi.encodeWithSelector(module.onUninstall.selector), "");
        instance.uninstallModule(TYPE_HOOK, address(module), bytes.concat(bytes32(TYPE_HOOK)));
        vm.clearMockedCalls();
        assertTrue(module.isInitialized(instance.account), "the note still says installed");
    }

    /// @dev `_version`, `_hookInstalls` and `_hookProven` in the module's layout, for the suites that
    ///      are about batches and not about earning them: `_markHookProven` checks the module's own
    ///      view agrees afterwards, so a layout change fails loudly rather than writing nowhere.
    uint256 internal constant VERSION_SLOT = 7;
    uint256 internal constant HOOK_INSTALLS_SLOT = 14;
    uint256 internal constant HOOK_PROVEN_SLOT = 15;

    /// @dev What the hook records on its first charge of `id` (`hookProvenOf`), without a trade: the
    ///      batch suites keep their exact bucket and lock counts. `AgentPolicyHookShapesTest` earns it.
    function _markHookProven(bytes32 id) internal {
        address a = instance.account;
        bytes32 aKey = keccak256(abi.encode(module.epochOf(a), id));
        uint256 version = uint256(vm.load(address(module), _nested(aKey, a, VERSION_SLOT)));
        bytes32 vKey = keccak256(abi.encode(aKey, version));
        uint256 installs = uint256(vm.load(address(module), keccak256(abi.encode(a, HOOK_INSTALLS_SLOT))));
        bytes32 proofKey = keccak256(abi.encode(vKey, "hook", installs));
        vm.store(address(module), _nested(proofKey, a, HOOK_PROVEN_SLOT), bytes32(uint256(1)));
        assertTrue(module.hookProvenOf(a, id), "the module reads the flag where it was written");
    }

    function _markHookProven() internal {
        _markHookProven(agentId);
    }

    function _nested(bytes32 key, address a, uint256 slot) internal pure returns (bytes32) {
        return keccak256(abi.encode(a, keccak256(abi.encode(key, slot))));
    }

    function _sign(bytes32 userOpHash, uint256 key) internal pure returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }
}
