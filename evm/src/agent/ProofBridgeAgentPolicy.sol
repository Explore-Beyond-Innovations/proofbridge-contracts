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
 *      compile time or in a normal test will say so. `test/agent/StorageRules.t.sol` is what says so.
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
        bytes data;
    }

    /// @dev A bucket carried across the calls of one batch, so two locks in the same token cannot
    ///      each pass against the same untouched allowance.
    struct Running {
        bytes32 key;
        AgentRateLimit.Bucket bucket;
        bool dirty;
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

    /// @notice The policy's identity, and its liveness switch: zero means no agent here. Revoking
    ///         is overwriting this one slot, which invalidates the whole policy at once.
    mapping(bytes32 agentKey => mapping(address account => bytes32)) private _fingerprint;
    /// @notice Sticky, as on Soroban: a revoked agent id cannot be re-installed on this account.
    mapping(bytes32 agentKey => mapping(address account => bool)) private _revoked;
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

    /// @notice Remove one type. The epoch bumps once the last one goes, orphaning every row.
    function onUninstall(bytes calldata data) external {
        (uint256 moduleTypeId,) = _installArgs(data);
        uint256 bit = _typeBit(moduleTypeId);
        uint256 types = _installedTypes[msg.sender];
        if (types & bit == 0) revert AgentPolicy__NotInstalled();
        types &= ~bit;
        _installedTypes[msg.sender] = types;
        if (types == 0) _epoch[msg.sender] += 1;
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
        _accountLimit[key][msg.sender] = limit;
        // Settle at the old rate before the new one applies, then clamp: leaving `lastTs` alone
        // would re-price the idle interval at whatever rate was just written.
        AgentRateLimit.Bucket memory b = _accountBucket[key][msg.sender];
        if (b.lastTs == 0) {
            _accountBucket[key][msg.sender] = AgentRateLimit.full(limit, uint64(block.timestamp));
        } else if (b.level > capacity) {
            _accountBucket[key][msg.sender] = AgentRateLimit.Bucket({level: capacity, lastTs: uint64(block.timestamp)});
        }
        emit AccountLimitSet(msg.sender, token, capacity, refillPerSecond);
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
        uint256 e = _epoch[msg.sender];
        bytes32 aKey = _agentKey(e, agentId);
        if (_revoked[aKey][msg.sender]) revert AgentPolicy__AgentRevoked();

        AgentPolicyCodec.View memory v = AgentPolicyCodec.parse(policy);
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
    ///         and the tombstone is sticky: this agent id cannot be installed again on this epoch.
    function revokeAgent(bytes32 agentId) external {
        _requireInstalled();
        bytes32 aKey = _agentKey(_epoch[msg.sender], agentId);
        _fingerprint[aKey][msg.sender] = bytes32(0);
        _revoked[aKey][msg.sender] = true;
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

        _setMarker(account, agentId);
        // Expiry is the bundler's job once it is in the return value, so there is no comparison
        // against `block.timestamp` here to get wrong.
        uint48 validUntil = meta.validUntil > type(uint48).max ? 0 : uint48(meta.validUntil);
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
        address account = msg.sender;
        bytes32 agentId = _marker(account);
        if (agentId == bytes32(0)) return "";

        uint256 e = _epoch[account];
        bytes32 aKey = _agentKey(e, agentId);
        PolicyMeta memory meta = _meta[aKey][account];
        bytes32 vKey = _versionKey(aKey, _version[aKey][account]);
        // The same walk the validator ran, with `commit` on. A disagreement between the two is
        // impossible rather than unlikely: it is one function.
        require(_walk(account, e, vKey, meta, msgData, true), "AgentPolicy: refused at execution");
        return "";
    }

    /// @notice Clear the marker, so a second call in the same transaction cannot ride the first
    ///         operation's authorization.
    function postCheck(bytes calldata) external {
        _clearMarker(msg.sender);
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
        return _revoked[_agentKey(_epoch[account], agentId)][account];
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
    function _decodeCalls(bytes calldata cd) internal pure returns (bool ok, Call[] memory calls) {
        if (cd.length < 4) return (false, calls);
        bytes calldata body = cd;
        if (bytes4(body[0:4]) == EXECUTE_USER_OP_SELECTOR) {
            if (body.length < 8) return (false, calls);
            body = body[4:];
        }
        if (body.length < 68 || bytes4(body[0:4]) != EXECUTE_SELECTOR) return (false, calls);

        bytes32 mode = bytes32(body[4:36]);
        uint8 callType = uint8(mode[0]);

        uint256 at = 4 + uint256(bytes32(body[36:68]));
        if (at + 32 > body.length) return (false, calls);
        uint256 len = uint256(bytes32(body[at:at + 32]));
        if (at + 32 + len > body.length) return (false, calls);
        bytes calldata ec = body[at + 32:at + 32 + len];

        if (callType == CALLTYPE_SINGLE) {
            if (ec.length < 52) return (false, calls);
            calls = new Call[](1);
            calls[0] = Call({target: address(bytes20(ec[0:20])), data: ec[52:]});
            return (true, calls);
        }
        if (callType == CALLTYPE_BATCH) {
            Execution[] memory execs = abi.decode(ec, (Execution[]));
            if (execs.length == 0 || execs.length > MAX_BATCH) return (false, calls);
            calls = new Call[](execs.length);
            for (uint256 i = 0; i < execs.length; ++i) {
                calls[i] = Call({target: execs[i].target, data: execs[i].callData});
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
     *      `test_scaleMatchesDecimalScaling` fuzzes the two against each other.
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
        uint64 nowTs;
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
            nowTs: uint64(block.timestamp),
            // Two running buckets per call at worst: the agent's and the account's.
            running: new Running[](calls.length * 2),
            used: 0
        });

        for (uint256 i = 0; i < calls.length; ++i) {
            if (!_checkOne(ctx, calls[i])) return false;
        }
        if (commit) _commit(ctx);
        return true;
    }

    function _checkOne(WalkCtx memory ctx, Call memory c) internal view returns (bool) {
        if (!_flag[_targetKey(ctx.epoch, c.target)][ctx.account]) return false;
        if (c.data.length < 4) return false;

        uint8 actionId = _actionIdOf(bytes4(c.data));
        if (actionId == 0 || !_flag[_actionKey(ctx.vKey, actionId)][ctx.account]) return false;

        IAdManager.OrderParams memory params = _decodeOrderParams(c.data);
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
            dirty: false
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
        ctx.running[i] =
            Running({key: key, bucket: _readBucket(_accountBucket[key][ctx.account], rate, ctx.nowTs), dirty: false});
        return i;
    }

    /// @dev The buckets are written once at the end rather than per call, so a batch whose last
    ///      call is refused leaves none of the earlier ones debited.
    function _commit(WalkCtx memory ctx) internal {
        for (uint256 i = 0; i < ctx.used; ++i) {
            if (!ctx.running[i].dirty) continue;
            // The agent rows are keyed by the policy version and the ceilings by the epoch, so the
            // two key spaces cannot collide and this cannot write the wrong mapping.
            if (_accountLimit[ctx.running[i].key][ctx.account].capacity != 0) {
                _accountBucket[ctx.running[i].key][ctx.account] = ctx.running[i].bucket;
            } else {
                _agentBucket[ctx.running[i].key][ctx.account] = ctx.running[i].bucket;
            }
        }
    }

    function _decodeOrderParams(bytes memory data) internal pure returns (IAdManager.OrderParams memory params) {
        bytes memory args = new bytes(data.length - 4);
        for (uint256 i = 0; i < args.length; ++i) {
            args[i] = data[i + 4];
        }
        params = abi.decode(args, (IAdManager.OrderParams));
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

    /// @dev Derived the way Solidity derives a `mapping(address => bytes32)` slot, so the transient
    ///      write lands inside the account-associated window ERC-7562 [OP-070] requires.
    function _markerSlot(address account) internal pure returns (bytes32) {
        return keccak256(abi.encode(account, MARKER_NAMESPACE));
    }

    function _setMarker(address account, bytes32 agentId) internal {
        bytes32 slot = _markerSlot(account);
        assembly ("memory-safe") {
            tstore(slot, agentId)
        }
    }

    function _marker(address account) internal view returns (bytes32 agentId) {
        bytes32 slot = _markerSlot(account);
        assembly ("memory-safe") {
            agentId := tload(slot)
        }
    }

    function _clearMarker(address account) internal {
        bytes32 slot = _markerSlot(account);
        assembly ("memory-safe") {
            tstore(slot, 0)
        }
    }

    function _installArgs(bytes calldata data) internal pure returns (uint256 moduleTypeId, bytes memory extra) {
        if (data.length < 32) return (MODULE_TYPE_VALIDATOR, extra);
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
