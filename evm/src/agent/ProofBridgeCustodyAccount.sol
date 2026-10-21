// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

/// @dev The two policy-module calls the account makes itself; the owner reaches the rest through `execute`.
interface IAgentPolicyDirect {
    function onInstall(bytes calldata data) external;
    function authorizeDirect(bytes32 agentId, bytes calldata callData) external;
}

/**
 * @title ProofBridgeCustodyAccount
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice A maker's custody account on EVM (plan 45): owned by the maker's wallet, it holds the ad's funds and is
 *         the ad's maker on `AdManager`. The owner acts through `execute` with ordinary transactions. An agent acts
 *         through `executeAsAgent`, which `ProofBridgeAgentPolicy` checks and counts before the call runs — the
 *         same rules the module applies to a 7702 account's UserOps, without an EntryPoint or a bundler.
 * @dev An EIP-1167 clone made by `CustodyAccountFactory`; the implementation itself is never initialised. No upgrade
 *      path: a new version is a new account the owner moves to.
 */
contract ProofBridgeCustodyAccount is ReentrancyGuardTransient {
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    /// @notice ERC-7579 `execute(bytes32,bytes)`: the request shape the module's walk and `preflight` read.
    bytes4 internal constant EXECUTE_SELECTOR = 0xe9ae5c53;
    uint256 internal constant MODULE_TYPE_VALIDATOR = 1;
    uint256 internal constant MODULE_TYPE_HOOK = 4;

    IAgentPolicyDirect public immutable module;
    address public immutable factory;

    address public owner;
    address public pendingOwner;

    event Executed(address indexed target, uint256 value, bytes4 selector);
    event AgentExecuted(bytes32 indexed agentId, address indexed target, bytes4 selector);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error CustodyAccount__NotOwner();
    error CustodyAccount__NotFactory();
    error CustodyAccount__AlreadyInitialized();
    error CustodyAccount__ZeroOwner();
    error CustodyAccount__NotPendingOwner();

    modifier onlyOwner() {
        if (msg.sender != owner) revert CustodyAccount__NotOwner();
        _;
    }

    constructor(IAgentPolicyDirect module_, address factory_) {
        module = module_;
        factory = factory_;
        // The implementation: an owner nobody holds, so it can never be initialised or used.
        owner = address(0xdead);
    }

    /// @notice Set the owner and mount the policy module as validator (with `targets` pinned) and as hook.
    function initialize(address owner_, address[] calldata targets) external {
        if (msg.sender != factory) revert CustodyAccount__NotFactory();
        if (owner != address(0)) revert CustodyAccount__AlreadyInitialized();
        if (owner_ == address(0)) revert CustodyAccount__ZeroOwner();
        owner = owner_;
        emit OwnershipTransferred(address(0), owner_);
        module.onInstall(abi.encodePacked(bytes32(MODULE_TYPE_VALIDATOR), abi.encode(targets)));
        module.onInstall(abi.encode(MODULE_TYPE_HOOK));
    }

    /// @notice Any call, as the account: fund and open ads, configure the module, withdraw, close.
    function execute(address target, uint256 value, bytes calldata data)
        external
        payable
        onlyOwner
        nonReentrant
        returns (bytes memory)
    {
        return _call(target, value, data);
    }

    /// @notice Several calls in one transaction (approve, then `createAd`). All or nothing.
    function executeBatch(Call[] calldata calls) external payable onlyOwner nonReentrant {
        for (uint256 i = 0; i < calls.length; ++i) {
            _call(calls[i].target, calls[i].value, calls[i].data);
        }
    }

    /**
     * @notice An agent's call. The agent is the caller; the module refuses anything its policy does not allow
     *         (a target not pinned, a value, any action but a lock, over a limit, another ad, expired or revoked)
     *         and debits the buckets for what it allows.
     */
    function executeAsAgent(address target, bytes calldata data) external nonReentrant returns (bytes memory ret) {
        bytes32 agentId = bytes32(uint256(uint160(msg.sender)));
        module.authorizeDirect(
            agentId, abi.encodeWithSelector(EXECUTE_SELECTOR, bytes32(0), abi.encodePacked(target, uint256(0), data))
        );
        bool ok;
        (ok, ret) = target.call(data);
        if (!ok) _bubble(ret);
        emit AgentExecuted(agentId, target, bytes4(data));
    }

    /// @notice ERC-7579's question, answered for the one module this account mounts: the policy module reads it
    ///         to confirm its hook half is in place.
    function isModuleInstalled(uint256 moduleTypeId, address module_, bytes calldata) external view returns (bool) {
        return module_ == address(module) && (moduleTypeId == MODULE_TYPE_VALIDATOR || moduleTypeId == MODULE_TYPE_HOOK);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert CustodyAccount__NotPendingOwner();
        emit OwnershipTransferred(owner, msg.sender);
        owner = msg.sender;
        pendingOwner = address(0);
    }

    receive() external payable {}

    function _call(address target, uint256 value, bytes calldata data) internal returns (bytes memory ret) {
        bool ok;
        (ok, ret) = target.call{value: value}(data);
        if (!ok) _bubble(ret);
        emit Executed(target, value, data.length >= 4 ? bytes4(data) : bytes4(0));
    }

    function _bubble(bytes memory ret) private pure {
        assembly ("memory-safe") {
            revert(add(ret, 32), mload(ret))
        }
    }
}
