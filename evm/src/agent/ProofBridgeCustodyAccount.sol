// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IAdManager} from "../interfaces/IAdManager.sol";
import {AddressCast} from "../libraries/AddressCast.sol";
import {CustodyGuardRail, IAgentPolicyAdmin} from "./CustodyGuardRail.sol";

/// @dev The policy-module calls the account makes itself; the owner reaches the setters through `execute`.
interface IAgentPolicyDirect {
    function onInstall(bytes calldata data) external;
    function authorizeDirect(bytes32 agentId, bytes calldata callData) external;
    function isTargetPinned(address account, address target) external view returns (bool);
    function isTypeInstalled(address account, uint256 moduleTypeId) external view returns (bool);
}

/**
 * @title ProofBridgeCustodyAccount
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice A maker's custody account on EVM (plans 45, 46): owned by the maker's wallet, it is the ad's maker on
 *         `AdManager` and an authorization gateway. It never holds funds between calls: the funding functions
 *         take the amount from the owner's wallet and hand it to the escrow in the same call. The owner acts with
 *         ordinary transactions; the guard rail (`CustodyGuardRail`) runs on every extractive one. An agent acts
 *         through `executeAsAgent`, which `ProofBridgeAgentPolicy` checks and counts before the call runs — the
 *         same rules the module applies to a 7702 account's UserOps, without an EntryPoint or a bundler.
 * @dev An EIP-1167 clone made by `CustodyAccountFactory`; the implementation itself is never initialised. No upgrade
 *      path: a new version is a new account the owner moves to.
 */
contract ProofBridgeCustodyAccount is ReentrancyGuardTransient, CustodyGuardRail {
    using SafeERC20 for IERC20;
    using AddressCast for address;

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
    event Swept(address indexed token, address indexed to, uint256 amount);

    error CustodyAccount__NotOwner();
    error CustodyAccount__NotFactory();
    error CustodyAccount__AlreadyInitialized();
    error CustodyAccount__ZeroOwner();
    error CustodyAccount__NotPendingOwner();
    error CustodyAccount__NotPinned(address target);
    error CustodyAccount__ValueMismatch(uint256 sent, uint256 amount);
    /// @notice A funding call left the account holding a different balance than it started with.
    error CustodyAccount__FundsLeft(address token);

    function _checkOwner() internal view override {
        if (msg.sender != owner) revert CustodyAccount__NotOwner();
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

    /*//////////////////////////////////////////////////////////////
                           THE OWNER'S AD ACTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Open an ad with this account as its maker, funded from the owner's wallet in this one call. For an
    ///         ERC-20 the owner approves this account for the token first; for native, send the amount as value.
    function createAdFunded(
        IAdManager adManager,
        string calldata adId,
        address adToken,
        uint256 amount,
        uint256 orderChainId,
        bytes32 adRecipient,
        bytes32 settlementSigner
    ) external payable onlyOwner nonReentrant {
        uint256 before = _payIn(adManager, adToken, amount, address(adManager));
        adManager.createAd{value: msg.value}(adId, adToken, amount, orderChainId, adRecipient, settlementSigner);
        _payDone(adToken, before);
    }

    /// @notice Add liquidity to one of this account's ads from the owner's wallet, as `createAdFunded`. The token is
    ///         the ad's own, read from the escrow (81-8).
    function fundAdFunded(IAdManager adManager, string calldata adId, uint256 amount)
        external
        payable
        onlyOwner
        nonReentrant
    {
        _requirePinned(adManager);
        (,, address adToken,,,,,,) = adManager.ads(adId);
        uint256 before = _payIn(adManager, adToken, amount, address(adManager));
        adManager.fundAd{value: msg.value}(adId, amount);
        _payDone(adToken, before);
    }

    /// @notice File a dispute as the ad's maker, the bond paid from the owner's wallet in this one call.
    ///         `bondToken` is the token the dispute module takes (the native sentinel for native).
    function disputeFunded(
        IAdManager adManager,
        IAdManager.OrderParams calldata params,
        bytes32 evidence,
        address bondToken,
        uint256 bond
    ) external payable onlyOwner nonReentrant {
        address disputeModule = address(adManager.disputeManager());
        uint256 before = _payIn(adManager, bondToken, bond, disputeModule);
        adManager.dispute{value: msg.value}(params, evidence);
        _payDone(bondToken, before);
    }

    /// @notice Any other call, as the account: withdraw, close, a manual lock, the response to a dispute, the
    ///         settlement signer, halt and resume, the module's setters. The guard rail runs first.
    function execute(address target, uint256 value, bytes calldata data)
        external
        payable
        onlyOwner
        nonReentrant
        returns (bytes memory)
    {
        _gate(target, value, data);
        return _call(target, value, data);
    }

    /// @notice Several calls in one transaction. All or nothing; each passes the guard rail.
    function executeBatch(Call[] calldata calls) external payable onlyOwner nonReentrant {
        for (uint256 i = 0; i < calls.length; ++i) {
            _gate(calls[i].target, calls[i].value, calls[i].data);
            _call(calls[i].target, calls[i].value, calls[i].data);
        }
    }

    /// @notice The way out for funds at rest in the account (a refunded dispute bond, a claimed credit). While any
    ///         ad is guarded it needs a matured schedule for exactly this call. `token` is the native sentinel for
    ///         native value.
    function sweep(address token, address to, uint256 amount) external onlyOwner nonReentrant {
        _gateSelf(this.sweep.selector);
        if (token.isNative()) {
            (bool ok, bytes memory ret) = to.call{value: amount}("");
            if (!ok) _bubble(ret);
        } else {
            IERC20(token).safeTransfer(to, amount);
        }
        emit Swept(token, to, amount);
    }

    /*//////////////////////////////////////////////////////////////
                                 THE AGENT
    //////////////////////////////////////////////////////////////*/

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

    /// @notice ERC-7579's question, answered for the one module this account mounts from the module's own record:
    ///         the policy module reads it to confirm its hook half is in place.
    function isModuleInstalled(uint256 moduleTypeId, address module_, bytes calldata) external view returns (bool) {
        if (module_ != address(module)) return false;
        if (moduleTypeId != MODULE_TYPE_VALIDATOR && moduleTypeId != MODULE_TYPE_HOOK) return false;
        return module.isTypeInstalled(address(this), moduleTypeId);
    }

    /*//////////////////////////////////////////////////////////////
                                 OWNERSHIP
    //////////////////////////////////////////////////////////////*/

    /// @notice Two steps. While any ad is guarded, starting a transfer needs a matured schedule for this call;
    ///         standing one down (`newOwner` zero) is protective, so it is instant.
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner != address(0)) _gateSelf(this.transferOwnership.selector);
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

    /*//////////////////////////////////////////////////////////////
                                 INTERNALS
    //////////////////////////////////////////////////////////////*/

    /// @dev The escrow must be pinned. Native: the value is the amount. ERC-20: pull from the owner, approve exactly
    ///      `spender`. Returns the balance to end at.
    function _payIn(IAdManager adManager, address token, uint256 amount, address spender)
        private
        returns (uint256 before)
    {
        _requirePinned(adManager);
        if (token.isNative()) {
            if (msg.value != amount) revert CustodyAccount__ValueMismatch(msg.value, amount);
            return address(this).balance - msg.value;
        }
        if (msg.value != 0) revert CustodyAccount__ValueMismatch(msg.value, 0);
        before = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransferFrom(owner, address(this), amount);
        IERC20(token).forceApprove(spender, amount);
    }

    function _requirePinned(IAdManager adManager) private view {
        if (!module.isTargetPinned(address(this), address(adManager))) {
            revert CustodyAccount__NotPinned(address(adManager));
        }
    }

    /// @dev Nothing stays behind. The escrow or dispute module pulls exactly the approved amount, which spends the
    ///      approval to zero; one that pulled less would leave a balance, and this reverts the call, approval and all.
    function _payDone(address token, uint256 before) private view {
        uint256 balance = token.isNative() ? address(this).balance : IERC20(token).balanceOf(address(this));
        if (balance != before) revert CustodyAccount__FundsLeft(token);
    }

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

    function _policyModule() internal view override returns (IAgentPolicyAdmin) {
        return IAgentPolicyAdmin(address(module));
    }

    /// @dev A nomination made before the rail was armed would complete with no announcement (81-3).
    function _onFirstGuard() internal override {
        if (pendingOwner != address(0)) {
            pendingOwner = address(0);
            emit OwnershipTransferStarted(owner, address(0));
        }
    }

    function _sweepSelector() internal pure override returns (bytes4) {
        return this.sweep.selector;
    }

    function _transferOwnershipSelector() internal pure override returns (bytes4) {
        return this.transferOwnership.selector;
    }
}
