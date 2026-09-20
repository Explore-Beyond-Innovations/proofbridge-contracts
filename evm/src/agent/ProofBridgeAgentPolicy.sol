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

    /**
     * @notice Why a request was refused. `None` is "not refused".
     * @dev The validator can only answer yes or no — ERC-4337 gives it nowhere to put a reason — so
     *      these surface in two places: the hook's `AgentPolicy__RefusedAtExecution(callIndex, reason)`
     *      and the free `preflight` read, which is how an agent finds out *which* call of a batch
     *      the module would refuse, and why, before spending anything. Appended to, never reordered:
     *      agents decode these numbers.
     */
    enum Refusal {
        None,
        NotMounted, // both halves have to be installed
        NoPolicy, // no live fingerprint for this agent: never installed, or revoked
        Paused, // MAX_UNCOUNTED reached; the owner resets
        SinglesOnly, // a batch while an approved request is still uncounted
        Expired, // preflight only: the validator leaves expiry to the EntryPoint
        MalformedRequest, // not an `execute` this module understands, or over MAX_BATCH: no call to blame
        MalformedCall, // this call is too short to carry a selector
        TargetNotPinned,
        ValueAttached,
        ActionNotAllowed,
        BadArguments,
        SettlementSignerMismatch,
        AdNotInScope,
        TokenNotAllowed,
        AmountNotScalable,
        OverPerOrderCap,
        NoAccountCeiling,
        OverStoredAllowance, // the validator's clockless floor (`_reserve`)
        AgentAllowanceExceeded, // the hook, or preflight: the real, refilled number
        AccountCeilingExceeded
    }

    /// @notice The `callIndex` of a refusal that is about the request or the agent as a whole —
    ///         not mounted, no policy, paused, an envelope that cannot be decoded. Zero would have
    ///         read as "the first call's fault".
    uint256 public constant NO_CALL = type(uint256).max;

    /// @dev Validate: no clock, reserve against the stored floor. Commit: the hook — real refill,
    ///      buckets written. Dry: `preflight` — the hook's arithmetic with nothing written.
    enum Mode {
        Validate,
        Commit,
        Dry
    }

    /// @dev What the clock-free half of the rules learned about one call.
    struct Checked {
        Refusal refusal;
        bytes32 token;
        TokenLimitRow row;
        uint256 amount;
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

    /**
     * @notice Approved-but-uncounted operations after which the agent is refused until the owner
     *         resets the tally.
     * @dev The module keeps a note of which halves are installed (`_installedTypes`), and three
     *      review passes found three ways for that note to be wrong — leaving a validator that
     *      approves with no hook debiting. This does not depend on the note: the hook has to *prove*
     *      it is running. With the hook missing, however it went missing, nothing zeroes the tally
     *      and the agent stops after this many capped trades, in total — not per transaction.
     *
     *      **It detects; it does not cap.** While the tally is zero everything approved so far has
     *      been counted and the agent may batch up to `MAX_BATCH`. While it is above zero — an
     *      approved request not yet counted, the warning sign — the agent may send single trades
     *      only, until the hook proves itself again. So a maker with several orders batches them
     *      freely, a failed batch is one strike like a failed single trade, and the hookless bound is
     *      **one batch plus two single trades, per token, per agent**, where the batch can never
     *      exceed the stored allowance (`_reserve`). Per *agent*: the validator's running totals are
     *      transient, so with the hook gone nothing lowers the stored ceiling, and each agent on the
     *      account gets its own batch and its own two trades. The one batch is unavoidable in any design that allows
     *      batches: when the hook first goes missing the tally still reads zero. An agent is expected
     *      to read `uncountedOf` and, if it is not zero, lead with a single trade.
     *
     *      Costs, stated rather than discovered. An approved request that does not end up counted
     *      looks the same as a missing hook, because a reverted execution rolls the hook's reset back
     *      with it — and **not every such failure is the agent's doing**: a bridger's `deadline` at
     *      the edge of the window that lands a block late, another agent of the same owner draining
     *      the shared ceiling so the hook refuses, an escrow pause, a liquidity race. Three in a row
     *      pause the agent until the owner resets it, and there is no decay — decay needs the clock
     *      and the validator has none. The agent runtime is expected to read `uncountedOf` and alert
     *      at one or two. And since every validation in a bundle runs before any hook, one bundle
     *      carries at most `MAX_UNCOUNTED` minus the outstanding tally requests per agent, singles
     *      after the first; one too many fails the **whole bundle**, other senders' operations
     *      included.
     */
    uint256 internal constant MAX_UNCOUNTED = 3;

    uint256 internal constant TYPE_BIT_VALIDATOR = 1;
    uint256 internal constant TYPE_BIT_HOOK = 2;

    /// @dev Transient slot namespace. Derived like a `mapping(address => bytes32)` slot so it lands
    ///      inside the account-associated window, which ERC-7562 [OP-070] requires of transient
    ///      storage exactly as it does of persistent storage.
    uint256 private constant MARKER_NAMESPACE = uint256(keccak256("ProofBridge.AgentPolicy.marker"));
    uint256 private constant PENDING_NAMESPACE = uint256(keccak256("ProofBridge.AgentPolicy.pending"));

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

    /// @notice Operations the validator has approved for this agent that the hook has not yet
    ///         counted. Up by one on every approval, back to zero whenever the hook debits — so in a
    ///         healthy mount it reads 1, 0, 1, 0. See `MAX_UNCOUNTED`.
    mapping(bytes32 agentKey => mapping(address account => uint256)) private _uncounted;
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
    event AgentTallyReset(address indexed account, bytes32 indexed agentId, uint256 priorTally, uint256 epoch);

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
    error AgentPolicy__NoPolicyForAgent();
    /// @notice The hook refused call `callIndex` of the request, for `reason`.
    /// @dev Whether this reaches the EntryPoint's `UserOperationRevertReason` is the account's
    ///      choice: the reference account and Nexus pass it up, Safe's adapter and Kernel's
    ///      multiplexer replace it with their own. `preflight` answers the same question on every
    ///      account, before anything is sent.
    error AgentPolicy__RefusedAtExecution(uint256 callIndex, Refusal reason);

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
     *      can do is turn the agent off. The epoch bumps once nothing is left. `MAX_UNCOUNTED` is
     *      the backstop for the cases where this note is wrong anyway.
     *
     *      **Runbook: revoke first, in its own transaction, then uninstall.** Every validation in a
     *      bundle runs before any execution, so an agent operation bundled *behind* an uninstall of
     *      the hook has already been approved and then executes with no hook to debit it.
     *      `_reserve` bounds that to the stored allowance or one operation; a revoke that has landed
     *      closes it outright.
     */
    function onUninstall(bytes calldata data) external {
        uint256 types = _installedTypes[msg.sender];
        if (types == 0) return;

        uint256 moduleTypeId = data.length >= 32 ? uint256(bytes32(data[0:32])) : 0;
        uint256 bit = moduleTypeId == MODULE_TYPE_VALIDATOR
            ? TYPE_BIT_VALIDATOR
            : moduleTypeId == MODULE_TYPE_HOOK ? TYPE_BIT_HOOK : 0;
        if (bit == 0 || types & bit == 0) {
            // Anything that does not name an *installed* type clears both. Pass 2 made "valid but
            // not installed" a no-op so a half-installed module could be repaired one half at a
            // time, and that let an owner who named the wrong half keep a hook bit for a hook the
            // account no longer had. Fail shut wins: **repair = uninstall both, install both.**
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

    /// @notice Un-pause an agent stopped by `MAX_UNCOUNTED`. The owner calling this is the owner
    ///         having looked, which is the point of the pause.
    function resetAgentTally(bytes32 agentId) external {
        _requireInstalled();
        uint256 e = _epoch[msg.sender];
        bytes32 aKey = _agentKey(e, agentId);
        // The typo guard `revokeAgent` has: an id with no policy here is a mistake, not a reset.
        if (_fingerprint[aKey][msg.sender] == bytes32(0)) revert AgentPolicy__NoPolicyForAgent();
        emit AgentTallyReset(msg.sender, agentId, _uncounted[aKey][msg.sender], e);
        _uncounted[aKey][msg.sender] = 0;
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

        // A deployed library, reached by DELEGATECALL: the parser's code does not count against this
        // contract's size, and this configuration call is the only place it is ever needed.
        AgentPolicyCodec.Decoded memory d = AgentPolicyCodec.decode(policy);
        // Already expired, or past what the EntryPoint's 48-bit field can carry: an installed policy
        // that authorizes nothing, or one silently read as "forever". Soroban refuses the first at
        // install too. This is a configuration call, so it may read the clock.
        if (d.validUntil != 0 && (d.validUntil <= block.timestamp || d.validUntil - 1 > type(uint48).max)) {
            revert AgentPolicy__BadExpiry();
        }
        uint256 version = _version[aKey][msg.sender] + 1;
        _version[aKey][msg.sender] = version;
        bytes32 vKey = _versionKey(aKey, version);

        _meta[aKey][msg.sender] =
            PolicyMeta({settlementSigner: d.settlementSigner, validUntil: d.validUntil, adScopeAll: d.adScopeAll});

        for (uint256 i = 0; i < d.actions.length; ++i) {
            _flag[_actionKey(vKey, d.actions[i])][msg.sender] = true;
        }

        for (uint256 i = 0; i < d.tokens.length; ++i) {
            AgentPolicyCodec.TokenRow memory row = d.tokens[i];
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

        for (uint256 i = 0; i < d.adScopeHashes.length; ++i) {
            _flag[_adKey(vKey, d.adScopeHashes[i])][msg.sender] = true;
        }

        bytes32 fingerprint = keccak256(policy);
        _fingerprint[aKey][msg.sender] = fingerprint;
        _uncounted[aKey][msg.sender] = 0;
        emit AgentPolicySet(msg.sender, agentId, version, fingerprint, policy);
    }

    /// @notice Kill one agent. Overwriting the fingerprint invalidates the whole policy at once,
    ///         and the tombstone is permanent: this agent id cannot be installed on this account
    ///         again, in this epoch or any later one.
    function revokeAgent(bytes32 agentId) external {
        _requireInstalled();
        // Idempotent once revoked, and refused for an id that was never installed — both as on
        // Soroban. The tombstone is permanent, so without the second rule a mistyped id would be
        // burned on this account for good.
        if (_revoked[agentId][msg.sender]) return;
        bytes32 aKey = _agentKey(_epoch[msg.sender], agentId);
        if (_fingerprint[aKey][msg.sender] == bytes32(0)) revert AgentPolicy__NoPolicyForAgent();
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
        (address agent, ECDSA.RecoverError err,) =
            ECDSA.tryRecover(MessageHashUtils.toEthSignedMessageHash(userOpHash), userOp.signature);
        if (err != ECDSA.RecoverError.NoError || agent == address(0)) return VALIDATION_FAILED;
        bytes32 agentId = bytes32(uint256(uint160(agent)));

        // Mounted as both halves, a live policy, not paused — and how many calls this request may
        // carry. The pause is checked before anything is decoded: it needs nothing decoded.
        Gate memory gate = _gate(account, agentId, Mode.Validate);
        if (gate.refusal != Refusal.None) return VALIDATION_FAILED;

        (Refusal refusal,) = _walk(account, gate, userOp.callData, Mode.Validate);
        if (refusal != Refusal.None) return VALIDATION_FAILED;
        if (!_chargeGas(account, gate.aKey, userOp)) return VALIDATION_FAILED;
        if (!_pushMarker(account, userOp.callData, agentId)) return VALIDATION_FAILED;

        // Approved. The hook owes a count for it; see `MAX_UNCOUNTED`.
        _uncounted[gate.aKey][account] += 1;

        // Expiry is the bundler's job once it is in the return value, so there is no comparison
        // against `block.timestamp` here to get wrong. Soroban's rule is `now < valid_until` and
        // the EntryPoint's is `now <= validUntil`, so the second before is what gets packed — or
        // the two chains would disagree for one second per policy.
        // `setAgentPolicy` refuses a `validUntil` of 1 or one past 48 bits, so neither arm below can
        // turn an expiry into "forever"; the guard stays because a wrong answer here is silent.
        uint64 until = gate.meta.validUntil;
        if (until == 1 || (until != 0 && until - 1 > type(uint48).max)) return VALIDATION_FAILED;
        return uint256(until == 0 ? 0 : uint48(until - 1)) << 160 | VALIDATION_SUCCESS;
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

        // Every validation in a bundle runs before any execution, so this operation may have been
        // validated while the policy was live and reach here after a revoke — or an uninstall of the
        // other half — bundled ahead of it.
        Gate memory gate = _gate(account, agentId, Mode.Commit);
        if (gate.refusal == Refusal.NoPolicy) revert AgentPolicy__RevokedBeforeExecution();
        if (gate.refusal != Refusal.None) revert AgentPolicy__RefusedAtExecution(NO_CALL, gate.refusal);

        // The same walk the validator ran, in `Mode.Commit`. A disagreement between the two is
        // impossible rather than unlikely: it is one function.
        (Refusal refusal, uint256 callIndex) = _walk(account, gate, msgData, Mode.Commit);
        if (refusal != Refusal.None) revert AgentPolicy__RefusedAtExecution(callIndex, refusal);
        // Counted. If the trade reverts after this, so does this line — which is why a failed trade
        // and a missing hook look alike to the validator.
        _uncounted[gate.aKey][account] = 0;
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

    /**
     * @notice Would the module carry this request — and if not, which call, and why?
     * @param callData the account's `execute(mode, executionCalldata)`, i.e. what the operation's
     *        `callData` would be.
     * @dev For agents, before they spend anything. It walks the request exactly as the validator and
     *      the hook do — the same functions — and being an `eth_call` rather than a validation it
     *      **may read the clock**, so unlike the validator it judges the allowance against the real,
     *      refilled number and answers `AgentAllowanceExceeded` where the validator could only let
     *      the hook find out. It cannot see an operation's gas fields: read `gasBudgetOf` for that.
     *      It answers for **both** halves, validator first: a batch the validator's floor would
     *      refuse against a stale-low stored level is `OverStoredAllowance` here even though the
     *      refilled allowance covers it, because that is what the chain will say until a single
     *      trade lands. A `None` is not a promise — another operation can land first. A refusal that
     *      depends only on the policy is one; `AgentAllowanceExceeded`, `AccountCeilingExceeded`,
     *      `OverStoredAllowance`, `SinglesOnly` and `Paused` clear with time, a landed operation, or
     *      the owner's reset.
     */
    function preflight(address account, bytes32 agentId, bytes calldata callData)
        external
        view
        returns (Refusal reason, uint256 callIndex)
    {
        Gate memory gate = _gate(account, agentId, Mode.Dry);
        if (gate.refusal != Refusal.None) return (gate.refusal, NO_CALL);

        Call[] memory calls;
        WalkCtx memory ctx;
        (reason, calls, ctx) = _begin(account, gate, callData, Mode.Dry);
        if (reason != Refusal.None) return (reason, NO_CALL);
        // The one Dry walk (`_walk` refuses the mode): the same per-call checks, then both halves'
        // verdicts in the order the chain reaches them — the validator's clockless floor first,
        // then the hook's real arithmetic — with nothing written.
        Asked memory asked = Asked(new bytes32[](calls.length * 2), new uint256[](calls.length * 2), 0);
        for (uint256 i = 0; i < calls.length; ++i) {
            Checked memory checked = _checkStatic(ctx, calls[i]);
            if (checked.refusal != Refusal.None) return (checked.refusal, i);
            reason = _reserveDry(ctx, checked, asked);
            if (reason != Refusal.None) return (reason, i);
            reason = _spend(ctx, checked.token, checked.row, checked.amount);
            if (reason != Refusal.None) return (reason, i);
        }
        return (Refusal.None, NO_CALL);
    }

    /// @dev The agent-level answers, before any call is looked at — one function for the validator,
    ///      the hook and `preflight`, so the three cannot disagree about who the agent is.
    struct Gate {
        Refusal refusal;
        uint256 epoch;
        bytes32 aKey;
        bytes32 vKey;
        PolicyMeta meta;
        uint256 maxCalls;
    }

    /**
     * @dev What differs by mode, and why:
     *      - **Validate** never reads the clock (ERC-7562 bans TIMESTAMP in validation; the
     *        comparison below is not reached) and applies the tally: paused at `MAX_UNCOUNTED`,
     *        single calls only while anything is uncounted.
     *      - **Commit** is the hook, which runs *after* the validator has already counted this very
     *        request — so the tally it sees is never zero, and applying the tally rules here would
     *        refuse every batch the validator just approved.
     *      - **Dry** is `preflight`: the validator's rules plus the clock.
     */
    function _gate(address account, bytes32 agentId, Mode mode) internal view returns (Gate memory gate) {
        // Both halves have to be mounted. With the validator alone nothing would ever debit a
        // bucket, and the limits would read as enforced while being enforced by nobody.
        if (_installedTypes[account] != (TYPE_BIT_VALIDATOR | TYPE_BIT_HOOK)) {
            gate.refusal = Refusal.NotMounted;
            return gate;
        }
        gate.epoch = _epoch[account];
        gate.aKey = _agentKey(gate.epoch, agentId);
        if (_fingerprint[gate.aKey][account] == bytes32(0)) {
            gate.refusal = Refusal.NoPolicy;
            return gate;
        }
        gate.meta = _meta[gate.aKey][account];
        gate.vKey = _versionKey(gate.aKey, _version[gate.aKey][account]);
        gate.maxCalls = MAX_BATCH;
        if (mode == Mode.Commit) return gate;

        if (mode == Mode.Dry && gate.meta.validUntil != 0 && block.timestamp >= gate.meta.validUntil) {
            gate.refusal = Refusal.Expired;
            return gate;
        }
        uint256 uncounted = _uncounted[gate.aKey][account];
        if (uncounted >= MAX_UNCOUNTED) {
            gate.refusal = Refusal.Paused;
            return gate;
        }
        if (uncounted != 0) gate.maxCalls = 1;
    }

    function uncountedOf(address account, bytes32 agentId) external view returns (uint256) {
        return _uncounted[_agentKey(_epoch[account], agentId)][account];
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

    /// @dev As `decodeBatch`, for a lock's arguments. The external call copies the arguments once
    ///      and the return copies the struct back; that replaced a byte-by-byte loop, not the copy.
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
            // `abi.encode(Execution[])` is an offset word, then the length. Read it before decoding,
            // or an agent-sized array is decoded and ABI-returned in full just to be refused.
            if (ec.length < 64 || uint256(bytes32(ec[0:32])) != 32) return (false, calls);
            uint256 declared = uint256(bytes32(ec[32:64]));
            if (declared == 0 || declared > MAX_BATCH) return (false, calls);
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
        Mode mode;
        Running[] running;
        uint256 used;
    }

    /// @dev Decode the request and set up the walk. Shared by all three modes, so they cannot
    ///      disagree about what a request *is* or how many calls it may carry.
    function _begin(address account, Gate memory gate, bytes calldata callData, Mode mode)
        internal
        view
        returns (Refusal refusal, Call[] memory calls, WalkCtx memory ctx)
    {
        bool decoded;
        (decoded, calls) = _decodeCalls(callData);
        if (!decoded || calls.length == 0 || calls.length > MAX_BATCH) {
            return (Refusal.MalformedRequest, calls, ctx);
        }
        // Batches only while the tally is zero: see `MAX_UNCOUNTED`.
        if (calls.length > gate.maxCalls) return (Refusal.SinglesOnly, calls, ctx);

        ctx = WalkCtx({
            account: account,
            epoch: gate.epoch,
            vKey: gate.vKey,
            settlementSigner: gate.meta.settlementSigner,
            adScopeAll: gate.meta.adScopeAll,
            nowTs: mode == Mode.Validate ? 0 : uint64(block.timestamp),
            mode: mode,
            // Two running buckets per call at worst: the agent's and the account's.
            running: new Running[](calls.length * 2),
            used: 0
        });
    }

    function _walk(address account, Gate memory gate, bytes calldata callData, Mode mode)
        internal
        returns (Refusal refusal, uint256 callIndex)
    {
        // `preflight` is the one Dry walk. Taken here, Dry would fall into the branch that writes.
        assert(mode != Mode.Dry);
        Call[] memory calls;
        WalkCtx memory ctx;
        (refusal, calls, ctx) = _begin(account, gate, callData, mode);
        if (refusal != Refusal.None) return (refusal, NO_CALL);

        for (uint256 i = 0; i < calls.length; ++i) {
            Checked memory checked = _checkStatic(ctx, calls[i]);
            if (checked.refusal != Refusal.None) return (checked.refusal, i);

            if (mode == Mode.Validate) {
                // The volume bucket is the hook's alone. Refilling it needs the elapsed time and
                // ERC-7562 [OP-011] bans TIMESTAMP during validation, so a validator that priced the
                // bucket would be one no bundler carries — which `ValidationRulesTest` catches by
                // simulating the real rules rather than reasoning about them. What the validator
                // can do without a clock is hold the request to the stored floor.
                refusal = _reserve(ctx, checked.token, checked.row, checked.amount);
                if (refusal != Refusal.None) return (refusal, i);
            } else {
                refusal = _spend(ctx, checked.token, checked.row, checked.amount);
                if (refusal != Refusal.None) return (refusal, i);
                // Debited for real now, so it is no longer "asked for and not yet counted". Without
                // this the running total would double-count against a level the hook has already
                // lowered whenever one transaction carries more than one `handleOps`.
                _release(ctx, checked.token, checked.amount);
            }
        }
        if (mode == Mode.Commit) _commit(ctx);
        return (Refusal.None, 0);
    }

    /// @dev The clock-free rules for one call: everything but the buckets. A `view`, so `preflight`
    ///      runs the very same checks the validator and the hook do.
    function _checkStatic(WalkCtx memory ctx, Call memory c) internal view returns (Checked memory out) {
        if (!_flag[_targetKey(ctx.epoch, c.target)][ctx.account]) return _refuse(out, Refusal.TargetNotPinned);
        // The policy speaks about a target, a selector and the trade. ETH riding on the call is
        // outside all three, so the only amount it can vouch for is none.
        if (c.value != 0) return _refuse(out, Refusal.ValueAttached);
        if (c.data.length < 4) return _refuse(out, Refusal.MalformedCall);

        uint8 actionId = _actionIdOf(bytes4(c.data));
        if (actionId == 0 || !_flag[_actionKey(ctx.vKey, actionId)][ctx.account]) {
            return _refuse(out, Refusal.ActionNotAllowed);
        }

        IAdManager.OrderParams memory params;
        try this.decodeLock(c.data) returns (IAdManager.OrderParams memory decoded) {
            params = decoded;
        } catch {
            return _refuse(out, Refusal.BadArguments);
        }
        if (params.adSettlementSigner != ctx.settlementSigner) return _refuse(out, Refusal.SettlementSignerMismatch);
        if (!ctx.adScopeAll && !_flag[_adKey(ctx.vKey, keccak256(bytes(params.adId)))][ctx.account]) {
            return _refuse(out, Refusal.AdNotInScope);
        }

        // Reach before size, as on Soroban: a trade the agent may not serve at all is not a sizing
        // question. Both tokens have to be on the whitelist, and a whitelisted token with no limit
        // row is refused rather than waved through.
        out.token = params.adChainToken;
        out.row = _agentLimit[_tokenKey(ctx.vKey, out.token)][ctx.account];
        if (out.row.capacity == 0) return _refuse(out, Refusal.TokenNotAllowed);
        if (_agentLimit[_tokenKey(ctx.vKey, params.orderChainToken)][ctx.account].capacity == 0) {
            return _refuse(out, Refusal.TokenNotAllowed);
        }

        bool scaled;
        (scaled, out.amount) = _adAmount(params);
        if (!scaled || out.amount == 0) return _refuse(out, Refusal.AmountNotScalable);
        if (out.amount > out.row.maxPerOrder) return _refuse(out, Refusal.OverPerOrderCap);
    }

    function _refuse(Checked memory out, Refusal refusal) private pure returns (Checked memory) {
        out.refusal = refusal;
        return out;
    }

    /**
     * @dev The validator's floor, for when the hook never runs.
     *
     *      Every validation in a bundle runs before any execution and validation never debits, so N
     *      operations all pass against the same untouched bucket. Normally the hook then refuses the
     *      ones that do not fit. But an owner operation that uninstalls the hook, bundled ahead of
     *      the agent's, removes the hook after the approvals and before the executions — and the
     *      agent builds the bundle.
     *
     *      No clock here, so no refill and no true allowance; but the **stored** level is a floor
     *      the true one is never below. A transient running total per bucket admits an operation
     *      while the transaction's requests still fit that floor. The first request against a bucket
     *      is always admitted: a bucket drained long ago stores zero while being full again, and a
     *      validator that believed the zero would refuse everything forever, with nothing able to
     *      execute and let the hook refresh it. So with the hook gone the bound is the stored level
     *      or one operation **per token, per transaction** — a policy with T tokens has T buckets and
     *      so T first requests. `MAX_UNCOUNTED` is what bounds it across transactions.
     *
     *      A refusal here fails the whole bundle, not just the operation: against a stale-low
     *      *shared* ceiling, a second agent's perfectly valid operation can be dropped alongside the
     *      first's. Each passes simulation alone, and one landing refreshes the level.
     *
     *      The total is "asked for and not yet debited": the hook subtracts what it debits. Transient,
     *      so nothing outlives the transaction; *within* one, a reverted execution rolls back the
     *      hook's subtraction and leaves the total inflated, which only ever refuses more.
     *      Account-associated, as [OP-070] requires. Both buckets are checked before either total is
     *      written.
     */
    function _reserve(WalkCtx memory ctx, bytes32 token, TokenLimitRow memory row, uint256 amount)
        internal
        returns (Refusal)
    {
        Floors memory f = _floors(ctx, token, row);
        if (f.refusal != Refusal.None) return f.refusal;

        bytes32 agentSlot = _pendingSlot(ctx.account, f.agentKey);
        bytes32 ceilingSlot = _pendingSlot(ctx.account, f.ceilingKey);
        (bool okAgent, uint256 agentTotal) = _fits(agentSlot, amount, f.agentFloor);
        (bool okCeiling, uint256 ceilingTotal) = _fits(ceilingSlot, amount, f.ceilingFloor);
        if (!okAgent || !okCeiling) return Refusal.OverStoredAllowance;

        _tstore(agentSlot, agentTotal);
        _tstore(ceilingSlot, ceilingTotal);
        return Refusal.None;
    }

    /// @dev The two buckets a call draws on and the stored level of each — the floor. One reading
    ///      of storage for the validator's `_reserve` and `preflight`'s `_reserveDry`. A bucket
    ///      never spent from stores nothing and reads as full.
    struct Floors {
        Refusal refusal;
        bytes32 agentKey;
        bytes32 ceilingKey;
        uint256 agentFloor;
        uint256 ceilingFloor;
    }

    function _floors(WalkCtx memory ctx, bytes32 token, TokenLimitRow memory row)
        internal
        view
        returns (Floors memory f)
    {
        f.agentKey = _tokenKey(ctx.vKey, token);
        f.ceilingKey = _ceilKey(ctx.epoch, token);
        uint256 ceilingCapacity = _accountLimit[f.ceilingKey][ctx.account].capacity;
        if (ceilingCapacity == 0) {
            f.refusal = Refusal.NoAccountCeiling;
            return f;
        }
        AgentRateLimit.Bucket memory stored = _agentBucket[f.agentKey][ctx.account];
        f.agentFloor = stored.lastTs == 0 ? row.capacity : stored.level;
        stored = _accountBucket[f.ceilingKey][ctx.account];
        f.ceilingFloor = stored.lastTs == 0 ? ceilingCapacity : stored.level;
    }

    function _release(WalkCtx memory ctx, bytes32 token, uint256 amount) internal {
        bytes32[2] memory slots = [
            _pendingSlot(ctx.account, _tokenKey(ctx.vKey, token)), _pendingSlot(ctx.account, _ceilKey(ctx.epoch, token))
        ];
        for (uint256 i = 0; i < 2; ++i) {
            bytes32 slot = slots[i];
            uint256 pending;
            assembly ("memory-safe") {
                pending := tload(slot)
            }
            if (pending == 0) continue;
            _tstore(slot, pending > amount ? pending - amount : 0);
        }
    }

    function _fits(bytes32 slot, uint256 amount, uint256 floor) internal view returns (bool ok, uint256 total) {
        uint256 pending;
        assembly ("memory-safe") {
            pending := tload(slot)
        }
        return _fitsFloor(pending, amount, floor);
    }

    /// @dev The floor rule itself, once: the first request against a bucket is free, the rest are
    ///      held cumulatively to the stored level. `_reserve` feeds it transient totals, `preflight`
    ///      in-memory ones, and neither can restate it differently.
    function _fitsFloor(uint256 pending, uint256 amount, uint256 floor) internal pure returns (bool ok, uint256 total) {
        total = pending + amount;
        ok = pending == 0 || total <= floor;
    }

    /// @dev What `preflight` has been asked for so far, per bucket — `_reserve`'s transient totals,
    ///      in memory. In an `eth_call` nothing is pending, so starting from zero is exact.
    struct Asked {
        bytes32[] keys;
        uint256[] totals;
        uint256 used;
    }

    /// @dev `_reserve`, read-only: same keys, same floors, same rule, both checked before either
    ///      total moves.
    function _reserveDry(WalkCtx memory ctx, Checked memory c, Asked memory asked) internal view returns (Refusal) {
        Floors memory f = _floors(ctx, c.token, c.row);
        if (f.refusal != Refusal.None) return f.refusal;

        uint256 ai = _askedIndex(asked, f.agentKey);
        uint256 ci = _askedIndex(asked, f.ceilingKey);
        (bool okAgent, uint256 agentTotal) = _fitsFloor(asked.totals[ai], c.amount, f.agentFloor);
        (bool okCeiling, uint256 ceilingTotal) = _fitsFloor(asked.totals[ci], c.amount, f.ceilingFloor);
        if (!okAgent || !okCeiling) return Refusal.OverStoredAllowance;

        asked.totals[ai] = agentTotal;
        asked.totals[ci] = ceilingTotal;
        return Refusal.None;
    }

    function _askedIndex(Asked memory asked, bytes32 key) internal pure returns (uint256 i) {
        for (i = 0; i < asked.used; ++i) {
            if (asked.keys[i] == key) return i;
        }
        asked.keys[i] = key;
        asked.used = i + 1;
    }

    function _tstore(bytes32 slot, uint256 value) internal {
        assembly ("memory-safe") {
            tstore(slot, value)
        }
    }

    function _pendingSlot(address account, bytes32 key) internal pure returns (bytes32) {
        return keccak256(abi.encode(account, keccak256(abi.encode(PENDING_NAMESPACE, key))));
    }

    /// @dev Both allowances are checked before either is written, so a call the account-wide
    ///      ceiling refuses leaves the agent's own allowance untouched.
    function _spend(WalkCtx memory ctx, bytes32 token, TokenLimitRow memory row, uint256 amount)
        internal
        view
        returns (Refusal)
    {
        uint256 ai = _acquireAgent(ctx, token, row);
        uint256 ci = _acquireCeiling(ctx, token);
        if (ci == type(uint256).max) return Refusal.NoAccountCeiling;

        AgentRateLimit.Limit memory rate =
            AgentRateLimit.Limit({capacity: row.capacity, refillPerSecond: row.refillPerSecond});
        (bool okAgent, AgentRateLimit.Bucket memory nextAgent) =
            AgentRateLimit.trySpend(rate, ctx.running[ai].bucket, amount, ctx.nowTs);
        if (!okAgent) return Refusal.AgentAllowanceExceeded;

        (bool okCeil, AgentRateLimit.Bucket memory nextCeil) = AgentRateLimit.trySpend(
            _accountLimit[_ceilKey(ctx.epoch, token)][ctx.account], ctx.running[ci].bucket, amount, ctx.nowTs
        );
        if (!okCeil) return Refusal.AccountCeilingExceeded;

        ctx.running[ai].bucket = nextAgent;
        ctx.running[ai].dirty = true;
        ctx.running[ci].bucket = nextCeil;
        ctx.running[ci].dirty = true;
        return Refusal.None;
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
        // `budget == 0` on its own line of reasoning: a self-bundling agent can set a zero fee, the
        // cost is then zero, and `0 > 0` is false — so an owner who zeroed the budget to pause an
        // agent would have paused nothing.
        if (budget == 0 || maxCost > budget) return false;
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
