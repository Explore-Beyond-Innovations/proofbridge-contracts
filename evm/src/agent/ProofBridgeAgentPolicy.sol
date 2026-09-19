// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {IAdManager} from "../interfaces/IAdManager.sol";
import {DecimalScaling} from "../libraries/DecimalScaling.sol";
import {AgentPolicyCodec} from "./AgentPolicyCodec.sol";
import {AgentRateLimit} from "./AgentRateLimit.sol";
import {
    IValidator,
    IHook,
    PackedUserOperation,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_HOOK,
    VALIDATION_SUCCESS,
    VALIDATION_FAILED
} from "./interfaces/IERC7579Module.sol";

/**
 * @title ProofBridgeAgentPolicy
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice Scoped delegation for EVM makers: the module a maker's smart account installs so a bot
 *         can open trades and do nothing else. The Soroban half of this is the agent account's
 *         `__check_auth`; this is the same policy against ERC-4337 validation.
 *
 *         It declares two ERC-7579 types and needs both.
 *
 *         - **Validator (1)** decides. It reads the policy rows, refuses an operation that breaks
 *           any of them, and writes nothing that matters. A refusal there is free: the operation
 *           never reaches the chain.
 *         - **Hook (4)** records. It runs during execution and debits the volume buckets, so an
 *           operation that validates and then reverts costs the maker nothing — which is what
 *           Soroban does, where a failed call discards the whole frame.
 *
 *         Both halves walk the calldata with the same function (`_walk`, `commit` false then true),
 *         so there is one implementation of the rules rather than two that have to be kept in step.
 *
 * @dev **Storage layout is load-bearing.** ERC-7562 lets a validator write during validation only
 *      to slots associated with the account — `keccak(account ‖ x) + n`, `n` in 0..128 — which
 *      means **the account address must be the last mapping key applied**. Every mapping here is
 *      `key => account => value` for that reason and not by accident; flipping one to
 *      `account => key` produces a module whose operations no bundler will carry, and nothing at
 *      compile time or in a normal test will say so. `test/agent/ValidationRules.t.sol` is what says so.
 *
 *      For the same reason no policy field is stored as an array, a string or `bytes`: their
 *      contents live at `keccak(slot)`, outside the window, however the struct is keyed. Lists
 *      arrive as calldata on the owner's configuration call and are written out as one row each.
 */
contract ProofBridgeAgentPolicy is IValidator, IHook {
    using AgentPolicyCodec for bytes;

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    struct PolicyMeta {
        bytes32 settlementSigner;
        uint64 validUntil;
        bool adScopeAll;
    }

    struct TokenLimitRow {
        uint256 maxPerOrder;
        uint256 capacity;
        uint256 refillPerSecond;
    }

    /// @dev One call pulled out of an `execute`, whatever shape it arrived in.
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    /// @dev A bucket carried across the calls of one batch, so two locks in the same token cannot
    ///      each pass against the same untouched allowance.
    struct Running {
        bytes32 key;
        AgentRateLimit.Bucket bucket;
        bool dirty;
        bool ceiling;
    }

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice ERC-7579 `execute(bytes32,bytes)`.
    bytes4 internal constant EXECUTE_SELECTOR = 0xe9ae5c53;
    /// @notice ERC-4337 `executeUserOp(PackedUserOperation,bytes32)`. Kernel wraps the real
    ///         calldata behind this whenever a hook is attached, so the decoder unwraps it.
    bytes4 internal constant EXECUTE_USER_OP_SELECTOR = 0x8dd7712f;

    uint8 internal constant CALLTYPE_SINGLE = 0x00;
    uint8 internal constant CALLTYPE_BATCH = 0x01;

    /// @notice Calls one operation may carry. Bounded so validation's gas stays predictable; the
    ///         running-bucket bookkeeping below is linear in it.
    uint256 internal constant MAX_BATCH = 8;

    uint256 internal constant TYPE_BIT_VALIDATOR = 1;
    uint256 internal constant TYPE_BIT_HOOK = 2;

    /// @dev Transient slot namespace. Derived like a `mapping(address => bytes32)` slot so it lands
    ///      inside the account-associated window, which ERC-7562 [OP-070] requires of transient
    ///      storage exactly as it does of persistent storage.
    uint256 private constant MARKER_NAMESPACE = uint256(keccak256("ProofBridge.AgentPolicy.marker"));

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Bumped on install and uninstall. Every other key carries it, so re-delegating to
    ///         another implementation and coming back cannot resurrect an old agent's policy: the
    ///         rows are still in storage, and nothing reads them again.
    mapping(address account => uint256) private _epoch;
    mapping(address account => uint256) private _installedTypes;

    /// @notice The hook multiplexer an account routes its single hook slot through, if it uses one.
    ///         ERC-7579 gives an account one hook, so a maker who already runs one mounts ours
    ///         behind a multiplexer and the account arrives appended to the calldata instead of as
    ///         `msg.sender`. Read only during execution, never during validation.
    mapping(address account => address forwarder) public trustedForwarder;

    /// @notice The policy's identity, and its liveness switch: zero means no agent here. Revoking
    ///         is overwriting this one slot, which invalidates the whole policy at once.
    mapping(bytes32 agentKey => mapping(address account => bytes32)) private _fingerprint;
    /// @notice Sticky and permanent, as on Soroban: a revoked agent id cannot be installed on this
    ///         account again. Keyed by the agent alone and **not** by the epoch, or uninstalling and
    ///         reinstalling the module would lift it.
    mapping(bytes32 agentId => mapping(address account => bool)) private _revoked;

    /// @notice Wei this agent may still cost the account in gas. Gas is a second way to spend the
    ///         maker's money and the volume buckets never see it: an agent that bundles its own
    ///         operation and names itself beneficiary turns `maxFeePerGas` into a withdrawal. Keyed
    ///         by the epoch and the agent, not the policy version, so re-writing a policy is not a
    ///         refill. Zero means no budget, and no budget means refused.
    mapping(bytes32 agentKey => mapping(address account => uint256)) private _gasBudget;
    /// @notice Bumped by every policy write so the previous policy's rows become unreachable —
    ///         otherwise dropping a token from the whitelist would leave its limit row behind.
    mapping(bytes32 agentKey => mapping(address account => uint256)) private _version;
    mapping(bytes32 agentKey => mapping(address account => PolicyMeta)) private _meta;

    /// @notice Membership: allowed actions, scoped ad ids, pinned targets. A list would be
    ///         unreadable during validation, and membership is all the validator ever asks.
    mapping(bytes32 flagKey => mapping(address account => bool)) private _flag;

    mapping(bytes32 rowKey => mapping(address account => TokenLimitRow)) private _agentLimit;
    mapping(bytes32 rowKey => mapping(address account => AgentRateLimit.Bucket)) private _agentBucket;

    /// @notice The account-wide ceiling for one token. Deliberately **not** keyed by the agent's
    ///         policy version: re-installing a policy resets that agent's own spend, as on Soroban,
    ///         and the aggregate has to keep binding across the reset or the reset would be a way
    ///         to spend without limit.
    mapping(bytes32 ceilKey => mapping(address account => AgentRateLimit.Limit)) private _accountLimit;
    mapping(bytes32 ceilKey => mapping(address account => AgentRateLimit.Bucket)) private _accountBucket;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event Installed(address indexed account, uint256 moduleTypeId, uint256 epoch);
    event Uninstalled(address indexed account, uint256 moduleTypeId, uint256 epoch);
    event TargetSet(address indexed account, address indexed target, bool allowed);
    event AccountLimitSet(address indexed account, bytes32 indexed token, uint256 capacity, uint256 refillPerSecond);
    /// @dev The policy bytes are emitted whole: nothing on chain can be read back as a list, so
    ///      this log is how an operator reconstructs what the fingerprint stands for.
    event AgentPolicySet(
        address indexed account, bytes32 indexed agentId, uint256 version, bytes32 fingerprint, bytes policy
    );
    event AgentRevoked(address indexed account, bytes32 indexed agentId);
    event AgentGasBudgetSet(address indexed account, bytes32 indexed agentId, uint256 weiBudget);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error AgentPolicy__NotInstalled();
    error AgentPolicy__AlreadyInstalled();
    error AgentPolicy__UnsupportedModuleType(uint256 moduleTypeId);
    error AgentPolicy__AgentRevoked();
    error AgentPolicy__BadLimit();
    error AgentPolicy__NoAccountCeiling(bytes32 token);
    error AgentPolicy__ZeroAgent();
    error AgentPolicy__AgentIdNotAnAddress();
    error AgentPolicy__InstallDataTooShort();
    error AgentPolicy__BadExpiry();
    error AgentPolicy__RevokedBeforeExecution();

    /*//////////////////////////////////////////////////////////////
                             MODULE PLUMBING
    //////////////////////////////////////////////////////////////*/

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR || moduleTypeId == MODULE_TYPE_HOOK;
    }

    function isInitialized(address smartAccount) external view returns (bool) {
        return _installedTypes[smartAccount] != 0;
    }

    /**
     * @notice Install one of the two types on the calling account.
     * @param data the module type id, and for the validator an optional `address[]` of escrows to
     *        pin in the same call.
     * @dev The epoch bumps on the first type installed, so a re-install after an uninstall starts
     *      from empty rows even though the old ones are still in storage.
     */
    function onInstall(bytes calldata data) external {
        (uint256 moduleTypeId, bytes memory extra) = _installArgs(data);
        uint256 bit = _typeBit(moduleTypeId);
        uint256 types = _installedTypes[msg.sender];
        if (types & bit != 0) revert AgentPolicy__AlreadyInstalled();
        if (types == 0) _epoch[msg.sender] += 1;
        _installedTypes[msg.sender] = types | bit;

        if (moduleTypeId == MODULE_TYPE_VALIDATOR && extra.length > 0) {
            address[] memory targets = abi.decode(extra, (address[]));
            uint256 e = _epoch[msg.sender];
            for (uint256 i = 0; i < targets.length; ++i) {
                _flag[_targetKey(e, targets[i])][msg.sender] = true;
                emit TargetSet(msg.sender, targets[i], true);
            }
        }
        emit Installed(msg.sender, moduleTypeId, _epoch[msg.sender]);
    }

    /**
     * @notice Remove one type, or both. **This cannot fail.**
     * @dev Safe7579 and Nexus catch a reverting `onUninstall` and remove the module anyway, and an
     *      empty `0x` is what most uninstall flows send. A module that insisted on knowing which
     *      type was meant kept its own bits set while the account dropped the hook — a validator
     *      approving with nothing debiting, the one state this module must never be in. So when the
     *      data does not name an installed type, **both** bits clear: the worst a routine uninstall
     *      can do is turn the agent off. The epoch bumps once nothing is left.
     */
    function onUninstall(bytes calldata data) external {
        uint256 types = _installedTypes[msg.sender];
        if (types == 0) return;

        uint256 moduleTypeId = data.length >= 32 ? uint256(bytes32(data[0:32])) : 0;
        uint256 bit = moduleTypeId == MODULE_TYPE_VALIDATOR
            ? TYPE_BIT_VALIDATOR
            : moduleTypeId == MODULE_TYPE_HOOK ? TYPE_BIT_HOOK : 0;
        if (bit == 0 || types & bit == 0) {
            moduleTypeId = 0;
            types = 0;
        } else {
            types &= ~bit;
        }
        _installedTypes[msg.sender] = types;
        if (types == 0) {
            _epoch[msg.sender] += 1;
            delete trustedForwarder[msg.sender];
        }
        emit Uninstalled(msg.sender, moduleTypeId, _epoch[msg.sender]);
    }

    /*//////////////////////////////////////////////////////////////
                             CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Pin or unpin an escrow the agent may call. `msg.sender` is the account, which is the
    ///         whole of T-10's configuration rule: nobody else has a way in.
    function setTargets(address[] calldata targets, bool allowed) external {
        _requireInstalled();
        uint256 e = _epoch[msg.sender];
        for (uint256 i = 0; i < targets.length; ++i) {
            _flag[_targetKey(e, targets[i])][msg.sender] = allowed;
            emit TargetSet(msg.sender, targets[i], allowed);
        }
    }

    /// @notice The account-wide ceiling for one token, shared by every agent this account installs.
    function setAccountLimit(bytes32 token, uint256 capacity, uint256 refillPerSecond) external {
        _requireInstalled();
        if (
            capacity == 0 || refillPerSecond == 0 || capacity > type(uint128).max || refillPerSecond > type(uint128).max
        ) {
            revert AgentPolicy__BadLimit();
        }
        bytes32 key = _ceilKey(_epoch[msg.sender], token);
        AgentRateLimit.Limit memory limit = AgentRateLimit.Limit({capacity: capacity, refillPerSecond: refillPerSecond});
        uint64 nowTs = uint64(block.timestamp);
        AgentRateLimit.Bucket memory b = _accountBucket[key][msg.sender];
        if (b.lastTs == 0) {
            _accountBucket[key][msg.sender] = AgentRateLimit.full(limit, nowTs);
        } else {
            // Settle the idle time at the rate it was earned under, then clamp and restart the
            // clock. Writing the new rate over an old stamp would re-price the whole interval.
            uint256 level = AgentRateLimit.available(_accountLimit[key][msg.sender], b, nowTs);
            _accountBucket[key][msg.sender] =
                AgentRateLimit.Bucket({level: level > capacity ? capacity : level, lastTs: nowTs});
        }
        _accountLimit[key][msg.sender] = limit;
        emit AccountLimitSet(msg.sender, token, capacity, refillPerSecond);
    }

    /// @notice What this agent may cost the account in gas, in wei. Replaces the remaining budget
    ///         rather than adding to it, so the owner always knows the number.
    function setAgentGasBudget(bytes32 agentId, uint256 weiBudget) external {
        _requireInstalled();
        _gasBudget[_agentKey(_epoch[msg.sender], agentId)][msg.sender] = weiBudget;
        emit AgentGasBudgetSet(msg.sender, agentId, weiBudget);
    }

    /**
     * @notice Install a policy for one agent, from its canonical bytes.
     * @dev The rows and the fingerprint are both derived from `policy` in this one call, so they
     *      cannot disagree. Everything the validator later reads is a row; the bytes themselves are
     *      never stored, only hashed and logged.
     */
    function setAgentPolicy(bytes32 agentId, bytes calldata policy) external {
        _requireInstalled();
        if (agentId == bytes32(0)) revert AgentPolicy__ZeroAgent();
        // An agent is whoever `ecrecover` returns, left-padded. Anything else can never match a
        // signature, and an owner who installed it would believe they had an agent.
        if (uint256(agentId) >> 160 != 0) revert AgentPolicy__AgentIdNotAnAddress();
        uint256 e = _epoch[msg.sender];
        bytes32 aKey = _agentKey(e, agentId);
        if (_revoked[agentId][msg.sender]) revert AgentPolicy__AgentRevoked();

        AgentPolicyCodec.View memory v = AgentPolicyCodec.parse(policy);
        // Already expired, or past what the EntryPoint's 48-bit field can carry: an installed policy
        // that authorizes nothing, or one silently read as "forever". Soroban refuses the first at
        // install too. This is a configuration call, so it may read the clock.
        if (v.validUntil != 0 && (v.validUntil <= block.timestamp || v.validUntil - 1 > type(uint48).max)) {
            revert AgentPolicy__BadExpiry();
        }
        uint256 version = _version[aKey][msg.sender] + 1;
        _version[aKey][msg.sender] = version;
        bytes32 vKey = _versionKey(aKey, version);

        _meta[aKey][msg.sender] =
            PolicyMeta({settlementSigner: v.settlementSigner, validUntil: v.validUntil, adScopeAll: v.adScopeAll});

        for (uint256 i = 0; i < v.actionCount; ++i) {
            _flag[_actionKey(vKey, AgentPolicyCodec.actionAt(policy, v, i))][msg.sender] = true;
        }

        for (uint256 i = 0; i < v.tokenCount; ++i) {
            AgentPolicyCodec.TokenRow memory row = AgentPolicyCodec.tokenRowAt(policy, v, i);
            // Above `capacity` the per-order cap can never bind, so a larger one is inert; refused
            // rather than ignored, because an owner who wrote it meant something by it.
            if (row.capacity == 0 || row.refillPerSecond == 0 || row.maxPerOrder == 0 || row.maxPerOrder > row.capacity)
            {
                revert AgentPolicy__BadLimit();
            }
            // The account-wide ceiling has to exist first, or the policy installs cleanly and the
            // agent's first lock fails for a reason the owner never sees at configuration time.
            if (_accountLimit[_ceilKey(e, row.token)][msg.sender].capacity == 0) {
                revert AgentPolicy__NoAccountCeiling(row.token);
            }
            _agentLimit[_tokenKey(vKey, row.token)][msg.sender] = TokenLimitRow({
                maxPerOrder: row.maxPerOrder, capacity: row.capacity, refillPerSecond: row.refillPerSecond
            });
        }

        bytes32[] memory ads = AgentPolicyCodec.adScopeHashes(policy, v);
        for (uint256 i = 0; i < ads.length; ++i) {
            _flag[_adKey(vKey, ads[i])][msg.sender] = true;
        }

        bytes32 fingerprint = keccak256(policy);
        _fingerprint[aKey][msg.sender] = fingerprint;
        emit AgentPolicySet(msg.sender, agentId, version, fingerprint, policy);
    }

    /// @notice Kill one agent. Overwriting the fingerprint invalidates the whole policy at once,
    ///         and the tombstone is permanent: this agent id cannot be installed on this account
    ///         again, in this epoch or any later one.
    function revokeAgent(bytes32 agentId) external {
        _requireInstalled();
        bytes32 aKey = _agentKey(_epoch[msg.sender], agentId);
        _fingerprint[aKey][msg.sender] = bytes32(0);
        _revoked[agentId][msg.sender] = true;
        emit AgentRevoked(msg.sender, agentId);
    }

    /*//////////////////////////////////////////////////////////////
                               VALIDATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Decide whether the agent may do what this operation asks.
     * @dev Refusals return `VALIDATION_FAILED` rather than reverting wherever the answer is "no":
     *      a revert in validation is what gets an entity dropped from the mempool, and "this agent
     *      may not do that" is an ordinary answer, not a malformed request.
     */
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external returns (uint256) {
        address account = msg.sender;
        // Both halves have to be mounted. With the validator alone nothing would ever debit a
        // bucket, and the limits would read as enforced while being enforced by nobody.
        if (_installedTypes[account] != (TYPE_BIT_VALIDATOR | TYPE_BIT_HOOK)) return VALIDATION_FAILED;

        (address agent, ECDSA.RecoverError err,) =
            ECDSA.tryRecover(MessageHashUtils.toEthSignedMessageHash(userOpHash), userOp.signature);
        if (err != ECDSA.RecoverError.NoError || agent == address(0)) return VALIDATION_FAILED;

        bytes32 agentId = bytes32(uint256(uint160(agent)));
        uint256 e = _epoch[account];
        bytes32 aKey = _agentKey(e, agentId);
        if (_fingerprint[aKey][account] == bytes32(0)) return VALIDATION_FAILED;

        PolicyMeta memory meta = _meta[aKey][account];
        bytes32 vKey = _versionKey(aKey, _version[aKey][account]);

        if (!_walk(account, e, vKey, meta, userOp.callData, false)) return VALIDATION_FAILED;
        if (!_chargeGas(account, aKey, userOp)) return VALIDATION_FAILED;
        if (!_pushMarker(account, userOp.callData, agentId)) return VALIDATION_FAILED;

        // Expiry is the bundler's job once it is in the return value, so there is no comparison
        // against `block.timestamp` here to get wrong. Soroban's rule is `now < valid_until` and
        // the EntryPoint's is `now <= validUntil`, so the second before is what gets packed — or
        // the two chains would disagree for one second per policy.
        // `setAgentPolicy` refuses a `validUntil` of 1 or one past 48 bits, so neither arm below can
        // turn an expiry into "forever"; the guard stays because a wrong answer here is silent.
        if (meta.validUntil == 1 || (meta.validUntil != 0 && meta.validUntil - 1 > type(uint48).max)) {
            return VALIDATION_FAILED;
        }
        uint48 validUntil = meta.validUntil == 0 ? 0 : uint48(meta.validUntil - 1);
        return uint256(validUntil) << 160 | VALIDATION_SUCCESS;
    }

    /// @notice Agents do not sign for the account off chain; only operations.
    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return 0xffffffff;
    }

    /*//////////////////////////////////////////////////////////////
                                  HOOK
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Debit the buckets for an operation the validator already approved.
     * @dev Anything without a marker is not an agent operation — the owner acting directly, or
     *      another validator's work — and passes through untouched.
     */
    function preCheck(address, uint256, bytes calldata msgData) external returns (bytes memory) {
        address account = _getAccount();
        bytes32 agentId = _popMarker(account, msgData);
        if (agentId == bytes32(0)) return "";

        uint256 e = _epoch[account];
        bytes32 aKey = _agentKey(e, agentId);
        // Every validation in a bundle runs before any execution, so this operation may have been
        // validated while the policy was live and reach here after a revoke bundled ahead of it.
        if (_fingerprint[aKey][account] == bytes32(0)) revert AgentPolicy__RevokedBeforeExecution();
        PolicyMeta memory meta = _meta[aKey][account];
        bytes32 vKey = _versionKey(aKey, _version[aKey][account]);
        // The same walk the validator ran, with `commit` on. A disagreement between the two is
        // impossible rather than unlikely: it is one function.
        require(_walk(account, e, vKey, meta, msgData, true), "AgentPolicy: refused at execution");
        return "";
    }

    /// @notice Nothing to do: `preCheck` consumed the marker it acted on.
    function postCheck(bytes calldata) external {}

    /*//////////////////////////////////////////////////////////////
                           HOOK MULTIPLEXING
    //////////////////////////////////////////////////////////////*/

    /// @notice Route this account's hook calls through a multiplexer. `msg.sender` is the account.
    function setTrustedForwarder(address forwarder) external {
        _requireInstalled();
        trustedForwarder[msg.sender] = forwarder;
    }

    /// @dev No install check, unlike the setter: Kernel's uninstall flow calls this *after*
    ///      `onUninstall`, and clearing one's own entry can harm nobody.
    function clearTrustedForwarder() external {
        trustedForwarder[msg.sender] = address(0);
    }

    function isTrustedForwarder(address forwarder, address account) public view returns (bool) {
        return forwarder != address(0) && forwarder == trustedForwarder[account];
    }

    /// @dev The account this hook call is about: `msg.sender` normally, or the address appended to
    ///      the calldata when a multiplexer the account itself nominated made the call.
    function _getAccount() internal view returns (address account) {
        account = msg.sender;
        // A caller with this module installed *is* an account, and the bytes after its calldata are
        // the agent's to choose. Believing them let anyone who had nominated the maker's account as
        // their own "forwarder" have the hook look for the marker under their address, find none,
        // and debit nothing. A multiplexer has nothing installed, so its path is unchanged.
        if (_installedTypes[msg.sender] != 0) return account;
        if (msg.data.length >= 40) {
            address appended;
            address forwarder;
            assembly ("memory-safe") {
                appended := shr(96, calldataload(sub(calldatasize(), 20)))
                forwarder := shr(96, calldataload(sub(calldatasize(), 40)))
            }
            if (forwarder == msg.sender && isTrustedForwarder(forwarder, appended)) account = appended;
        }
    }

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    function epochOf(address account) external view returns (uint256) {
        return _epoch[account];
    }

    function fingerprintOf(address account, bytes32 agentId) external view returns (bytes32) {
        return _fingerprint[_agentKey(_epoch[account], agentId)][account];
    }

    function isRevoked(address account, bytes32 agentId) external view returns (bool) {
        return _revoked[agentId][account];
    }

    function agentLimit(address account, bytes32 agentId, bytes32 token) external view returns (TokenLimitRow memory) {
        bytes32 aKey = _agentKey(_epoch[account], agentId);
        return _agentLimit[_tokenKey(_versionKey(aKey, _version[aKey][account]), token)][account];
    }

    function agentBucket(address account, bytes32 agentId, bytes32 token)
        external
        view
        returns (AgentRateLimit.Bucket memory)
    {
        bytes32 aKey = _agentKey(_epoch[account], agentId);
        return _agentBucket[_tokenKey(_versionKey(aKey, _version[aKey][account]), token)][account];
    }

    function accountBucket(address account, bytes32 token) external view returns (AgentRateLimit.Bucket memory) {
        return _accountBucket[_ceilKey(_epoch[account], token)][account];
    }

    function gasBudgetOf(address account, bytes32 agentId) external view returns (uint256) {
        return _gasBudget[_agentKey(_epoch[account], agentId)][account];
    }

    function isTargetPinned(address account, address target) external view returns (bool) {
        return _flag[_targetKey(_epoch[account], target)][account];
    }

    /*//////////////////////////////////////////////////////////////
                           CALLDATA DECODING
    //////////////////////////////////////////////////////////////*/

    /// @dev ERC-7579's batch element.
    struct Execution {
        address target;
        uint256 value;
        bytes callData;
    }

    /**
     * @dev Pull the individual calls out of an account's `execute`.
     *
     *      Three shapes reach here. Plain `execute(mode, executionCalldata)` is the common one.
     *      Kernel wraps that behind `executeUserOp` whenever a hook is attached, which is always
     *      for us, so the wrapper is stripped first. Static and delegate call types are refused
     *      outright: a policy that reasons about a target and a selector says nothing useful about
     *      code running in the account's own context.
     */
    /// @dev `mode` and `executionCalldata` out of an `execute`, with Kernel's `executeUserOp`
    ///      wrapper stripped. The validator and the hook both come through here, so they agree on
    ///      what an operation *is* however the account chose to wrap or pad it.
    function _executeArgs(bytes calldata cd) internal pure returns (bool ok, bytes32 mode, bytes calldata ec) {
        ec = cd[0:0];
        if (cd.length < 4) return (false, mode, ec);
        bytes calldata body = cd;
        if (bytes4(body[0:4]) == EXECUTE_USER_OP_SELECTOR) {
            if (body.length < 8) return (false, mode, ec);
            body = body[4:];
        }
        if (body.length < 68 || bytes4(body[0:4]) != EXECUTE_SELECTOR) return (false, mode, ec);
        mode = bytes32(body[4:36]);
        uint256 offset = uint256(bytes32(body[36:68]));
        if (offset > body.length) return (false, mode, ec);
        uint256 at = 4 + offset;
        if (at + 32 > body.length) return (false, mode, ec);
        uint256 len = uint256(bytes32(body[at:at + 32]));
        if (len > body.length || at + 32 + len > body.length) return (false, mode, ec);
        return (true, mode, body[at + 32:at + 32 + len]);
    }

    /// @dev External only so `_decodeCalls` can `try` it: `abi.decode` reverts on malformed input,
    ///      the input is the agent's, and a revert during validation throttles the *maker's*
    ///      account. "This agent may not do that" is an answer, not an exception.
    function decodeBatch(bytes calldata executionCalldata) external pure returns (Execution[] memory) {
        return abi.decode(executionCalldata, (Execution[]));
    }

    /// @dev As `decodeBatch`, for a lock's arguments. Slicing calldata also replaces a byte-by-byte
    ///      copy that ran in both the validator and the hook, per call, on the maker's gas.
    function decodeLock(bytes calldata data) external pure returns (IAdManager.OrderParams memory) {
        return abi.decode(data[4:], (IAdManager.OrderParams));
    }

    function _decodeCalls(bytes calldata cd) internal view returns (bool ok, Call[] memory calls) {
        bytes32 mode;
        bytes calldata ec;
        (ok, mode, ec) = _executeArgs(cd);
        if (!ok) return (false, calls);
        uint8 callType = uint8(mode[0]);
        // ExecType 0x01 is "try": the account swallows a failing call, so the hook's debit would
        // stick although no trade happened — and the agent is the one who picks the mode.
        if (uint8(mode[1]) != 0) return (false, calls);

        if (callType == CALLTYPE_SINGLE) {
            if (ec.length < 52) return (false, calls);
            calls = new Call[](1);
            calls[0] = Call({target: address(bytes20(ec[0:20])), value: uint256(bytes32(ec[20:52])), data: ec[52:]});
            return (true, calls);
        }
        if (callType == CALLTYPE_BATCH) {
            Execution[] memory execs;
            try this.decodeBatch(ec) returns (Execution[] memory decoded) {
                execs = decoded;
            } catch {
                return (false, calls);
            }
            if (execs.length == 0 || execs.length > MAX_BATCH) return (false, calls);
            calls = new Call[](execs.length);
            for (uint256 i = 0; i < execs.length; ++i) {
                calls[i] = Call({target: execs[i].target, value: execs[i].value, data: execs[i].callData});
            }
            return (true, calls);
        }
        return (false, calls);
    }

    /// @dev Chain-neutral action ids, as the canonical encoding carries them. Zero is "not an
    ///      action this policy language can express", which is a refusal rather than a default.
    function _actionIdOf(bytes4 selector) internal pure returns (uint8) {
        if (selector == IAdManager.lockForOrder.selector) return AgentPolicyCodec.ACTION_LOCK_FOR_ORDER;
        return 0;
    }

    /**
     * @dev The order's size in the ad token's own units, which is what the escrow locks and
     *      therefore what the per-order cap is written against.
     *
     *      `DecimalScaling.scale` reverts on the cases this returns false for. A revert during
     *      validation is what gets a module dropped from the mempool, so the arithmetic is repeated
     *      here as an answer rather than an exception —
     *      `testFuzz_scalingMatchesTheEscrowsOrRefuses` fuzzes the two against each other.
     */
    function _adAmount(IAdManager.OrderParams memory p) internal pure returns (bool ok, uint256 out) {
        uint8 from = p.orderDecimals;
        uint8 to = p.adDecimals;
        if (from > DecimalScaling.MAX_DECIMALS || to > DecimalScaling.MAX_DECIMALS) return (false, 0);
        if (from == to) return (true, p.amount);
        if (to > from) {
            uint256 factor = 10 ** uint256(to - from);
            unchecked {
                out = p.amount * factor;
            }
            if (p.amount != 0 && out / p.amount != factor) return (false, 0);
            return (true, out);
        }
        uint256 divisor = 10 ** uint256(from - to);
        if (p.amount % divisor != 0) return (false, 0);
        return (true, p.amount / divisor);
    }

    /*//////////////////////////////////////////////////////////////
                                THE RULES
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev One implementation of the policy, run twice.
     *
     *      `commit` false is the validator: read the buckets, refuse anything that does not fit,
     *      write nothing. `commit` true is the hook: the same walk, and the buckets are written at
     *      the end. Splitting these into two functions would be the obvious shape and would put the
     *      rules in two places, which is how a check and its enforcement drift apart.
     *
     *      Buckets are carried across the calls of a batch in memory, so two locks in the same
     *      token cannot each be judged against the same untouched allowance, and are written once
     *      at the end rather than per call.
     */
    /// @dev Everything the per-call helpers need, in memory rather than on the stack: the whole
    ///      rule set in one frame does not fit the EVM's 16 slots, and `running`/`used` travel with
    ///      it so the running buckets survive across calls of a batch.
    struct WalkCtx {
        address account;
        uint256 epoch;
        bytes32 vKey;
        bytes32 settlementSigner;
        bool adScopeAll;
        /// @dev Zero on the validator's pass: ERC-7562 [OP-011] bans TIMESTAMP during validation,
        ///      so the clock only exists on the hook's.
        uint64 nowTs;
        bool commit;
        Running[] running;
        uint256 used;
    }

    function _walk(
        address account,
        uint256 e,
        bytes32 vKey,
        PolicyMeta memory meta,
        bytes calldata callData,
        bool commit
    ) internal returns (bool) {
        (bool decoded, Call[] memory calls) = _decodeCalls(callData);
        if (!decoded || calls.length == 0 || calls.length > MAX_BATCH) return false;

        WalkCtx memory ctx = WalkCtx({
            account: account,
            epoch: e,
            vKey: vKey,
            settlementSigner: meta.settlementSigner,
            adScopeAll: meta.adScopeAll,
            nowTs: commit ? uint64(block.timestamp) : 0,
            commit: commit,
            // Two running buckets per call at worst: the agent's and the account's.
            running: new Running[](calls.length * 2),
            used: 0
        });

        for (uint256 i = 0; i < calls.length; ++i) {
            if (!_checkOne(ctx, calls[i])) return false;
        }
        if (ctx.commit) _commit(ctx);
        return true;
    }

    function _checkOne(WalkCtx memory ctx, Call memory c) internal view returns (bool) {
        if (!_flag[_targetKey(ctx.epoch, c.target)][ctx.account]) return false;
        // The policy speaks about a target, a selector and the trade. ETH riding on the call is
        // outside all three, so the only amount it can vouch for is none.
        if (c.value != 0) return false;
        if (c.data.length < 4) return false;

        uint8 actionId = _actionIdOf(bytes4(c.data));
        if (actionId == 0 || !_flag[_actionKey(ctx.vKey, actionId)][ctx.account]) return false;

        IAdManager.OrderParams memory params;
        try this.decodeLock(c.data) returns (IAdManager.OrderParams memory decoded) {
            params = decoded;
        } catch {
            return false;
        }
        if (params.adSettlementSigner != ctx.settlementSigner) return false;
        if (!ctx.adScopeAll && !_flag[_adKey(ctx.vKey, keccak256(bytes(params.adId)))][ctx.account]) return false;

        // Reach before size, as on Soroban: a trade the agent may not serve at all is not a sizing
        // question. Both tokens have to be on the whitelist, and a whitelisted token with no limit
        // row is refused rather than waved through.
        TokenLimitRow memory row = _agentLimit[_tokenKey(ctx.vKey, params.adChainToken)][ctx.account];
        if (row.capacity == 0) return false;
        if (_agentLimit[_tokenKey(ctx.vKey, params.orderChainToken)][ctx.account].capacity == 0) return false;

        (bool scaled, uint256 amount) = _adAmount(params);
        if (!scaled || amount == 0 || amount > row.maxPerOrder) return false;

        // The volume bucket is the hook's alone. Refilling it needs the elapsed time and
        // ERC-7562 [OP-011] bans TIMESTAMP during validation, so a validator that priced the
        // bucket would be a validator no bundler carries — which
        // `ValidationRulesTest` catches by simulating the real rules rather than reasoning about
        // them. The per-order cap above is time-independent and still refuses an oversized call
        // for free; the aggregate is refused at execution, where the maker pays the gas.
        if (!ctx.commit) return true;
        return _spend(ctx, params.adChainToken, row, amount);
    }

    /// @dev Both allowances are checked before either is written, so a call the account-wide
    ///      ceiling refuses leaves the agent's own allowance untouched.
    function _spend(WalkCtx memory ctx, bytes32 token, TokenLimitRow memory row, uint256 amount)
        internal
        view
        returns (bool)
    {
        uint256 ai = _acquireAgent(ctx, token, row);
        uint256 ci = _acquireCeiling(ctx, token);
        if (ci == type(uint256).max) return false;

        AgentRateLimit.Limit memory rate =
            AgentRateLimit.Limit({capacity: row.capacity, refillPerSecond: row.refillPerSecond});
        (bool okAgent, AgentRateLimit.Bucket memory nextAgent) =
            AgentRateLimit.trySpend(rate, ctx.running[ai].bucket, amount, ctx.nowTs);
        if (!okAgent) return false;

        (bool okCeil, AgentRateLimit.Bucket memory nextCeil) = AgentRateLimit.trySpend(
            _accountLimit[_ceilKey(ctx.epoch, token)][ctx.account], ctx.running[ci].bucket, amount, ctx.nowTs
        );
        if (!okCeil) return false;

        ctx.running[ai].bucket = nextAgent;
        ctx.running[ai].dirty = true;
        ctx.running[ci].bucket = nextCeil;
        ctx.running[ci].dirty = true;
        return true;
    }

    function _acquireAgent(WalkCtx memory ctx, bytes32 token, TokenLimitRow memory row)
        internal
        view
        returns (uint256)
    {
        bytes32 key = _tokenKey(ctx.vKey, token);
        uint256 i = _slotFor(ctx.running, ctx.used, key);
        if (i != type(uint256).max) return i;
        i = ctx.used++;
        ctx.running[i] = Running({
            key: key,
            bucket: _readBucket(
                _agentBucket[key][ctx.account],
                AgentRateLimit.Limit({capacity: row.capacity, refillPerSecond: row.refillPerSecond}),
                ctx.nowTs
            ),
            dirty: false,
            ceiling: false
        });
        return i;
    }

    /// @return the running index, or `type(uint256).max` when no ceiling is configured for the
    ///         token — which is a refusal, not a default, so a token nobody set a ceiling for
    ///         cannot be spent.
    function _acquireCeiling(WalkCtx memory ctx, bytes32 token) internal view returns (uint256) {
        bytes32 key = _ceilKey(ctx.epoch, token);
        AgentRateLimit.Limit memory rate = _accountLimit[key][ctx.account];
        if (rate.capacity == 0) return type(uint256).max;
        uint256 i = _slotFor(ctx.running, ctx.used, key);
        if (i != type(uint256).max) return i;
        i = ctx.used++;
        ctx.running[i] = Running({
            key: key,
            bucket: _readBucket(_accountBucket[key][ctx.account], rate, ctx.nowTs),
            dirty: false,
            ceiling: true
        });
        return i;
    }

    /// @dev The buckets are written once at the end rather than per call, so a batch whose last
    ///      call is refused leaves none of the earlier ones debited.
    function _commit(WalkCtx memory ctx) internal {
        for (uint256 i = 0; i < ctx.used; ++i) {
            if (!ctx.running[i].dirty) continue;
            if (ctx.running[i].ceiling) {
                _accountBucket[ctx.running[i].key][ctx.account] = ctx.running[i].bucket;
            } else {
                _agentBucket[ctx.running[i].key][ctx.account] = ctx.running[i].bucket;
            }
        }
    }

    function _readBucket(AgentRateLimit.Bucket memory stored, AgentRateLimit.Limit memory limit, uint64 nowTs)
        internal
        pure
        returns (AgentRateLimit.Bucket memory)
    {
        // A never-spent bucket reads as full rather than empty. `lastTs == 0` is the sentinel: a
        // real ledger stamp is never zero, and absence meaning "no allowance" would make a fresh
        // agent unusable rather than fresh.
        if (stored.lastTs == 0) return AgentRateLimit.full(limit, nowTs);
        return stored;
    }

    function _slotFor(Running[] memory running, uint256 used, bytes32 key) internal pure returns (uint256) {
        for (uint256 i = 0; i < used; ++i) {
            if (running[i].key == key) return i;
        }
        return type(uint256).max;
    }

    /*//////////////////////////////////////////////////////////////
                          KEYS, MARKER, HELPERS
    //////////////////////////////////////////////////////////////*/

    function _agentKey(uint256 e, bytes32 agentId) internal pure returns (bytes32) {
        return keccak256(abi.encode(e, agentId));
    }

    function _versionKey(bytes32 aKey, uint256 version) internal pure returns (bytes32) {
        return keccak256(abi.encode(aKey, version));
    }

    function _actionKey(bytes32 vKey, uint8 actionId) internal pure returns (bytes32) {
        return keccak256(abi.encode(vKey, "action", actionId));
    }

    function _adKey(bytes32 vKey, bytes32 adIdHash) internal pure returns (bytes32) {
        return keccak256(abi.encode(vKey, "ad", adIdHash));
    }

    function _tokenKey(bytes32 vKey, bytes32 token) internal pure returns (bytes32) {
        return keccak256(abi.encode(vKey, "token", token));
    }

    function _targetKey(uint256 e, address target) internal pure returns (bytes32) {
        return keccak256(abi.encode(e, "target", target));
    }

    function _ceilKey(uint256 e, bytes32 token) internal pure returns (bytes32) {
        return keccak256(abi.encode(e, "ceiling", token));
    }

    /**
     * @dev The marker's slot, keyed by the account **and by what the operation does**.
     *
     *      Keyed by the account alone it would be wrong in a way no single-operation test shows:
     *      every validation in a bundle runs before any execution, so one slot per account is set
     *      once, consumed by the first execution, and every later operation in the bundle runs with
     *      the hook asleep. An agent can build that bundle itself by calling `handleOps`.
     *
     *      Keyed by the decoded `(mode, executionCalldata)` rather than raw bytes, so a wrapper or
     *      trailing padding the account adds between validation and execution cannot make the hook
     *      miss. Shaped `keccak(account ‖ x)` so the transient write lands inside the
     *      account-associated window ERC-7562 [OP-070] requires; the count lives at `+1`.
     */
    function _markerSlot(address account, bytes32 mode, bytes calldata ec) internal pure returns (bytes32) {
        return keccak256(abi.encode(account, keccak256(abi.encode(MARKER_NAMESPACE, mode, keccak256(ec)))));
    }

    /// @return false when another agent already queued the identical operation in this
    ///         transaction; the hook could not tell the two apart, so the second is refused.
    function _pushMarker(address account, bytes calldata callData, bytes32 agentId) internal returns (bool) {
        (bool ok, bytes32 mode, bytes calldata ec) = _executeArgs(callData);
        if (!ok) return false;
        bytes32 slot = _markerSlot(account, mode, ec);
        bytes32 queued;
        uint256 count;
        assembly ("memory-safe") {
            queued := tload(slot)
            count := tload(add(slot, 1))
        }
        if (count != 0 && queued != agentId) return false;
        assembly ("memory-safe") {
            tstore(slot, agentId)
            tstore(add(slot, 1), add(count, 1))
        }
        return true;
    }

    /// @return agentId zero when this execution was not queued by the validator — the owner acting
    ///         directly, or another validator's work.
    function _popMarker(address account, bytes calldata msgData) internal returns (bytes32 agentId) {
        (bool ok, bytes32 mode, bytes calldata ec) = _executeArgs(msgData);
        if (!ok) return bytes32(0);
        bytes32 slot = _markerSlot(account, mode, ec);
        uint256 count;
        assembly ("memory-safe") {
            agentId := tload(slot)
            count := tload(add(slot, 1))
        }
        if (count == 0) return bytes32(0);
        assembly ("memory-safe") {
            tstore(add(slot, 1), sub(count, 1))
            if eq(count, 1) { tstore(slot, 0) }
        }
    }

    /**
     * @dev Debit the most this operation could cost the account, or refuse it.
     *
     *      During validation, unlike the volume buckets: gas is charged whether or not the trade
     *      happens, and the debit needs no clock, so the validator can and must do it. The maximum
     *      over-counts what the EntryPoint finally takes; the only party that hurts is an agent
     *      overstating its own limits. A paymaster is refused: with one attached the account is not
     *      the payer and this would be the wrong ledger.
     */
    function _chargeGas(address account, bytes32 aKey, PackedUserOperation calldata userOp) internal returns (bool) {
        if (userOp.paymasterAndData.length != 0) return false;
        uint256 gasLimit =
            uint256(uint128(bytes16(userOp.accountGasLimits))) + uint256(uint128(uint256(userOp.accountGasLimits)));
        if (userOp.preVerificationGas > type(uint128).max) return false;
        gasLimit += userOp.preVerificationGas;
        // maxFeePerGas is the low half; both factors fit 130 and 128 bits, so this cannot overflow.
        uint256 maxCost = gasLimit * uint256(uint128(uint256(userOp.gasFees)));
        uint256 budget = _gasBudget[aKey][account];
        if (maxCost > budget) return false;
        _gasBudget[aKey][account] = budget - maxCost;
        return true;
    }

    function _installArgs(bytes calldata data) internal pure returns (uint256 moduleTypeId, bytes memory extra) {
        // This module is two types and `onInstall` does not say which one is meant. Guessing would
        // register the hook as a second validator, so the caller has to say.
        if (data.length < 32) revert AgentPolicy__InstallDataTooShort();
        moduleTypeId = uint256(bytes32(data[0:32]));
        if (data.length > 32) extra = data[32:];
    }

    function _typeBit(uint256 moduleTypeId) internal pure returns (uint256) {
        if (moduleTypeId == MODULE_TYPE_VALIDATOR) return TYPE_BIT_VALIDATOR;
        if (moduleTypeId == MODULE_TYPE_HOOK) return TYPE_BIT_HOOK;
        revert AgentPolicy__UnsupportedModuleType(moduleTypeId);
    }

    function _requireInstalled() internal view {
        if (_installedTypes[msg.sender] == 0) revert AgentPolicy__NotInstalled();
    }
}
