// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IAdManager} from "../interfaces/IAdManager.sol";
import {IEscrow} from "../interfaces/IEscrow.sol";
import {DecimalScaling} from "../libraries/DecimalScaling.sol";
import {AgentRateLimit} from "./AgentRateLimit.sol";

/// @dev The policy module's setters the guard rail judges, and the reads it needs.
interface IAgentPolicyAdmin {
    function setAgentPolicy(bytes32 agentId, bytes calldata policy) external;
    function setTargets(address[] calldata targets, bool allowed) external;
    function setAccountLimit(bytes32 token, uint256 capacity, uint256 refillPerSecond) external;
    function setAgentGasBudget(bytes32 agentId, uint256 weiBudget) external;
    function resetAgentTally(bytes32 agentId) external;
    function setTrustedForwarder(address forwarder) external;
    function onInstall(bytes calldata data) external;
    function onUninstall(bytes calldata data) external;
    function accountLimit(address account, bytes32 token) external view returns (AgentRateLimit.Limit memory);
}

/**
 * @title CustodyGuardRail
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice The owner's guard rail on the EVM custody account (plan 46 D9), the Soroban agent account's rules on
 *         EVM: instant to protect, slow to extract. A stolen owner key otherwise empties every ad in one
 *         transaction. An owner who arms an ad's guard rail makes the extractive calls on it two steps — announce
 *         the exact call (`schedule`), then make it once `delay` has passed — and every schedule is an event a
 *         watcher can alert on.
 *
 *         - **Per ad**: a withdraw above `threshold`, any close, and a manual lock above `threshold` need a matured
 *           schedule; below the threshold they spend a refilling bucket, so the unannounced flow is a rate, not
 *           the balance.
 *         - **Account-wide, while any ad is guarded**: moving funds out of the account (a token transfer, approval
 *           or transfer-from, native value, an escrow `claimTo`, `sweep`), any agent-policy write, a loosened
 *           account limit, a new pinned target, the module's install and uninstall, a trusted forwarder, a gas
 *           budget or tally reset, and an ownership transfer. Timed by the longest delay and the shortest window
 *           across guarded ads.
 *         - **Never delayed**: revoking an agent, unpinning a target, lowering an account limit, arming or
 *           tightening a guard rail. Delaying a protective action only helps whoever stole the key.
 *
 *         Unlike Soroban, every agent-policy write is delayed while guarded, tightening included: deciding
 *         "tighter" needs the policy module's stored rows, and the module has no room left under EIP-170.
 *
 * @dev A schedule commits to `keccak256(abi.encode(target, value, data))` of the exact call, is single use, and
 *      sits in one row per (scope, action); a new one replaces it.
 */
abstract contract CustodyGuardRail {
    struct GuardRail {
        uint256 threshold;
        uint64 delay;
        uint64 window;
        uint256 capacity;
        uint256 refillPerSecond;
    }

    struct Guard {
        GuardRail rail;
        AgentRateLimit.Bucket bucket;
        bool armed;
    }

    struct Schedule {
        bytes32 commitment;
        uint64 readyAt;
        uint64 expiresAt;
    }

    /// @notice The scope of account-wide schedules; an ad's scope is `keccak256(bytes(adId))`.
    bytes32 public constant ACCOUNT_SCOPE = bytes32(0);
    uint256 public constant MAX_GUARDED_ADS = 16;
    /// @notice The action of a call that sends native value out of the account.
    bytes4 public constant NATIVE_OUT = 0xffffffff;

    bytes4 internal constant WITHDRAW = IAdManager.withdrawFromAd.selector;
    bytes4 internal constant CLOSE = IAdManager.closeAd.selector;
    bytes4 internal constant LOCK = IAdManager.lockForOrder.selector;
    bytes4 internal constant INCREASE_ALLOWANCE = bytes4(keccak256("increaseAllowance(address,uint256)"));

    mapping(bytes32 adKey => Guard) internal _guards;
    bytes32[] internal _guarded;
    mapping(bytes32 slot => Schedule) internal _schedules;

    event GuardRailSet(bytes32 indexed adKey, string adId, bool armed, uint256 threshold, uint64 delay, uint64 window);
    event Scheduled(
        bytes32 indexed scope,
        bytes4 indexed action,
        address target,
        uint256 value,
        bytes data,
        uint64 readyAt,
        uint64 expiresAt
    );
    event Cancelled(bytes32 indexed scope, bytes4 indexed action);

    error GuardRail__NotScheduled();
    error GuardRail__BadGuardRail();
    error GuardRail__NoGuardRail();
    error GuardRail__ScopeMismatch();
    error GuardRail__VolumeExceeded();
    error GuardRail__SelfCall();

    modifier onlyOwner() virtual;

    function _policyModule() internal view virtual returns (IAgentPolicyAdmin);

    /*//////////////////////////////////////////////////////////////
                              OWNER CONTROLS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Arm or change an ad's guard rail. Arming and tightening are instant; a loosening needs a matured
     *         schedule for exactly this call, and clears the ad's and the account's pending schedules.
     */
    function setGuardRail(string calldata adId, GuardRail calldata rail) external onlyOwner {
        if (rail.delay == 0 || rail.window == 0 || rail.capacity == 0 || rail.refillPerSecond == 0) {
            revert GuardRail__BadGuardRail();
        }
        if (rail.capacity > type(uint128).max || rail.refillPerSecond > type(uint128).max) {
            revert GuardRail__BadGuardRail();
        }
        bytes32 key = keccak256(bytes(adId));
        Guard storage g = _guards[key];
        uint64 nowTs = uint64(block.timestamp);
        bool loosening = g.armed && !_isTightening(g.rail, rail);
        if (loosening) _spend(key, this.setGuardRail.selector, address(this), 0, msg.data);

        uint64 adDelayBefore = g.armed ? g.rail.delay : 0;
        (uint64 accountDelayBefore,) = _guarded.length == 0 ? (uint64(0), uint64(0)) : _accountTimelock();
        // Settle the old bucket at the old rate, then clamp: carrying the idle interval into a new rate would
        // re-price it and hand back a full bucket.
        uint256 level = rail.capacity;
        if (g.armed) {
            uint256 settled = AgentRateLimit.available(_limit(g.rail), g.bucket, nowTs);
            level = settled > rail.capacity ? rail.capacity : settled;
        } else {
            if (_guarded.length >= MAX_GUARDED_ADS) revert GuardRail__BadGuardRail();
            _guarded.push(key);
        }
        g.rail = rail;
        g.bucket = AgentRateLimit.Bucket({level: level, lastTs: nowTs});
        g.armed = true;

        if (loosening) {
            _clearSchedules(key);
        } else {
            // A pending change waits the new, longer delay (Soroban 49S-1).
            if (rail.delay > adDelayBefore) _restamp(key, nowTs + rail.delay);
            if (rail.delay > accountDelayBefore) _restamp(ACCOUNT_SCOPE, nowTs + rail.delay);
        }
        emit GuardRailSet(key, adId, true, rail.threshold, rail.delay, rail.window);
    }

    /// @notice Take an ad's guard rail off. Always a loosening: it needs a matured schedule for exactly this call.
    function disarmGuardRail(string calldata adId) external onlyOwner {
        bytes32 key = keccak256(bytes(adId));
        if (!_guards[key].armed) revert GuardRail__NoGuardRail();
        _spend(key, this.disarmGuardRail.selector, address(this), 0, msg.data);
        delete _guards[key];
        for (uint256 i = 0; i < _guarded.length; ++i) {
            if (_guarded[i] == key) {
                _guarded[i] = _guarded[_guarded.length - 1];
                _guarded.pop();
                break;
            }
        }
        _clearSchedules(key);
        emit GuardRailSet(key, adId, false, 0, 0, 0);
    }

    /**
     * @notice Announce a delayed call and start its clock. `target`, `value` and `data` are the exact call that
     *         will be made (for the account's own functions, `target` is this account). `scope` is the ad's key for
     *         a per-ad action and must be the ad the call names; `ACCOUNT_SCOPE` for the account-wide ones.
     */
    function schedule(bytes32 scope, address target, uint256 value, bytes calldata data) external onlyOwner {
        (bytes4 action, bytes32 adKey) = _actionOf(target, value, data);
        uint64 delay;
        uint64 window;
        if (scope == ACCOUNT_SCOPE) {
            if (adKey != bytes32(0)) revert GuardRail__ScopeMismatch();
            if (_guarded.length == 0) revert GuardRail__NoGuardRail();
            (delay, window) = _accountTimelock();
        } else {
            if (adKey != scope) revert GuardRail__ScopeMismatch();
            Guard storage g = _guards[scope];
            if (!g.armed) revert GuardRail__NoGuardRail();
            (delay, window) = (g.rail.delay, g.rail.window);
        }
        uint64 readyAt = uint64(block.timestamp) + delay;
        uint64 expiresAt = readyAt + window;
        _schedules[_slot(scope, action)] =
            Schedule({commitment: keccak256(abi.encode(target, value, data)), readyAt: readyAt, expiresAt: expiresAt});
        emit Scheduled(scope, action, target, value, data, readyAt, expiresAt);
    }

    /// @notice Stand a schedule down: what an owner does on seeing a `Scheduled` they did not cause.
    function cancel(bytes32 scope, bytes4 action) external onlyOwner {
        bytes32 slot = _slot(scope, action);
        if (_schedules[slot].readyAt == 0) revert GuardRail__NotScheduled();
        delete _schedules[slot];
        emit Cancelled(scope, action);
    }

    /*//////////////////////////////////////////////////////////////
                                  VIEWS
    //////////////////////////////////////////////////////////////*/

    function guardRail(string calldata adId) external view returns (Guard memory) {
        return _guards[keccak256(bytes(adId))];
    }

    function guardedAds() external view returns (bytes32[] memory) {
        return _guarded;
    }

    function scheduled(bytes32 scope, bytes4 action) external view returns (Schedule memory) {
        return _schedules[_slot(scope, action)];
    }

    /*//////////////////////////////////////////////////////////////
                                 THE GATE
    //////////////////////////////////////////////////////////////*/

    /// @dev Every owner call the account makes on the owner's behalf (`execute`, `executeBatch`) comes through
    ///      here before it runs.
    function _gate(address target, uint256 value, bytes calldata data) internal {
        if (target == address(this)) revert GuardRail__SelfCall();
        (bytes4 action, bytes32 adKey) = _actionOf(target, value, data);
        if (adKey != bytes32(0)) {
            _gateAdCall(adKey, action, target, value, data);
            return;
        }
        if (_guarded.length == 0 || !_isAccountGated(action, target, data)) return;
        _spend(ACCOUNT_SCOPE, action, target, value, data);
    }

    /// @dev For the account's own owner functions that are account-wide extractive (`sweep`, `transferOwnership`).
    function _gateSelf(bytes4 action) internal {
        if (_guarded.length != 0) _spend(ACCOUNT_SCOPE, action, address(this), 0, msg.data);
    }

    function _gateAdCall(bytes32 adKey, bytes4 action, address target, uint256 value, bytes calldata data) private {
        Guard storage g = _guards[adKey];
        if (!g.armed) {
            // Value riding on an escrow call is still value leaving the account.
            if (value != 0 && _guarded.length != 0) _spend(ACCOUNT_SCOPE, NATIVE_OUT, target, value, data);
            return;
        }
        uint256 amount = _amountOf(action, data);
        if (action == CLOSE || amount > g.rail.threshold) {
            _spend(adKey, action, target, value, data);
            return;
        }
        (bool ok, AgentRateLimit.Bucket memory next) =
            AgentRateLimit.trySpend(_limit(g.rail), g.bucket, amount, uint64(block.timestamp));
        if (!ok) revert GuardRail__VolumeExceeded();
        g.bucket = next;
    }

    /// @dev Whether an account-wide action needs its schedule while guarded.
    function _isAccountGated(bytes4 action, address target, bytes calldata data) private view returns (bool) {
        if (
            action == NATIVE_OUT || action == IERC20.transfer.selector || action == IERC20.approve.selector
                || action == IERC20.transferFrom.selector || action == INCREASE_ALLOWANCE
                || action == IEscrow.claimTo.selector
        ) return true;
        if (target != address(_policyModule())) return false;
        if (
            action == IAgentPolicyAdmin.setAgentPolicy.selector || action == IAgentPolicyAdmin.onInstall.selector
                || action == IAgentPolicyAdmin.onUninstall.selector
                || action == IAgentPolicyAdmin.setTrustedForwarder.selector
                || action == IAgentPolicyAdmin.setAgentGasBudget.selector
                || action == IAgentPolicyAdmin.resetAgentTally.selector
        ) return true;
        if (action == IAgentPolicyAdmin.setTargets.selector) {
            (, bool allowed) = abi.decode(data[4:], (address[], bool));
            return allowed; // unpinning is protective
        }
        if (action == IAgentPolicyAdmin.setAccountLimit.selector) {
            (bytes32 token, uint256 capacity, uint256 refill) = abi.decode(data[4:], (bytes32, uint256, uint256));
            AgentRateLimit.Limit memory cur = _policyModule().accountLimit(address(this), token);
            return cur.capacity == 0 || capacity > cur.capacity || refill > cur.refillPerSecond;
        }
        return false; // revokeAgent, clearTrustedForwarder: protective
    }

    /// @dev The action a call is, and the ad it names for a per-ad action (zero otherwise). Malformed escrow
    ///      calldata reverts: a call the account can't read is one it can't judge.
    function _actionOf(address target, uint256 value, bytes calldata data)
        private
        view
        returns (bytes4 action, bytes32 adKey)
    {
        action = data.length >= 4 ? bytes4(data[:4]) : bytes4(0);
        if (action == WITHDRAW) {
            (string memory adId,,) = abi.decode(data[4:], (string, uint256, address));
            return (action, keccak256(bytes(adId)));
        }
        if (action == CLOSE) {
            (string memory adId,) = abi.decode(data[4:], (string, address));
            return (action, keccak256(bytes(adId)));
        }
        if (action == LOCK) {
            (IAdManager.OrderParams memory p,) = abi.decode(data[4:], (IAdManager.OrderParams, uint32));
            return (action, keccak256(bytes(p.adId)));
        }
        if (
            target == address(this) && (action == this.setGuardRail.selector || action == this.disarmGuardRail.selector)
        ) {
            string memory adId = abi.decode(data[4:], (string));
            return (action, keccak256(bytes(adId)));
        }
        if (value != 0) action = NATIVE_OUT;
    }

    function _amountOf(bytes4 action, bytes calldata data) private pure returns (uint256) {
        if (action == WITHDRAW) {
            (, uint256 amount,) = abi.decode(data[4:], (string, uint256, address));
            return amount;
        }
        if (action == LOCK) {
            (IAdManager.OrderParams memory p,) = abi.decode(data[4:], (IAdManager.OrderParams, uint32));
            return DecimalScaling.scale(p.amount, p.orderDecimals, p.adDecimals);
        }
        return 0;
    }

    /*//////////////////////////////////////////////////////////////
                                SCHEDULES
    //////////////////////////////////////////////////////////////*/

    /// @dev Spend a matured, unexpired schedule committed to exactly this call, or refuse. Single use.
    function _spend(bytes32 scope, bytes4 action, address target, uint256 value, bytes calldata data) internal {
        bytes32 slot = _slot(scope, action);
        Schedule memory s = _schedules[slot];
        if (
            s.readyAt == 0 || s.commitment != keccak256(abi.encode(target, value, data)) || block.timestamp < s.readyAt
                || block.timestamp >= s.expiresAt
        ) revert GuardRail__NotScheduled();
        delete _schedules[slot];
    }

    /// @dev The longest delay and the shortest window across guarded ads.
    function _accountTimelock() private view returns (uint64 delay, uint64 window) {
        window = type(uint64).max;
        for (uint256 i = 0; i < _guarded.length; ++i) {
            GuardRail storage r = _guards[_guarded[i]].rail;
            if (r.delay > delay) delay = r.delay;
            if (r.window < window) window = r.window;
        }
    }

    function _restamp(bytes32 scope, uint64 notBefore) private {
        bytes4[16] memory actions = scope == ACCOUNT_SCOPE ? _accountActions() : _adActions();
        for (uint256 i = 0; i < actions.length; ++i) {
            if (actions[i] == bytes4(0)) break;
            Schedule storage s = _schedules[_slot(scope, actions[i])];
            if (s.readyAt != 0 && s.readyAt < notBefore) {
                s.expiresAt += notBefore - s.readyAt;
                s.readyAt = notBefore;
            }
        }
    }

    /// @dev The settings a schedule was made under are gone, so the schedules go with them: the ad's and the
    ///      account-wide ones (Soroban `clear_all_schedules`).
    function _clearSchedules(bytes32 adKey) private {
        bytes4[16] memory ad = _adActions();
        bytes4[16] memory account = _accountActions();
        for (uint256 i = 0; i < 16; ++i) {
            if (ad[i] != bytes4(0)) delete _schedules[_slot(adKey, ad[i])];
            if (account[i] != bytes4(0)) delete _schedules[_slot(ACCOUNT_SCOPE, account[i])];
        }
    }

    function _adActions() private pure returns (bytes4[16] memory a) {
        a[0] = WITHDRAW;
        a[1] = CLOSE;
        a[2] = LOCK;
        a[3] = this.setGuardRail.selector;
        a[4] = this.disarmGuardRail.selector;
    }

    function _accountActions() private pure returns (bytes4[16] memory a) {
        a[0] = NATIVE_OUT;
        a[1] = IERC20.transfer.selector;
        a[2] = IERC20.approve.selector;
        a[3] = IERC20.transferFrom.selector;
        a[4] = INCREASE_ALLOWANCE;
        a[5] = IEscrow.claimTo.selector;
        a[6] = IAgentPolicyAdmin.setAgentPolicy.selector;
        a[7] = IAgentPolicyAdmin.setTargets.selector;
        a[8] = IAgentPolicyAdmin.setAccountLimit.selector;
        a[9] = IAgentPolicyAdmin.onInstall.selector;
        a[10] = IAgentPolicyAdmin.onUninstall.selector;
        a[11] = IAgentPolicyAdmin.setTrustedForwarder.selector;
        a[12] = IAgentPolicyAdmin.setAgentGasBudget.selector;
        a[13] = IAgentPolicyAdmin.resetAgentTally.selector;
        a[14] = _sweepSelector();
        a[15] = _transferOwnershipSelector();
    }

    function _sweepSelector() internal pure virtual returns (bytes4);
    function _transferOwnershipSelector() internal pure virtual returns (bytes4);

    function _slot(bytes32 scope, bytes4 action) private pure returns (bytes32) {
        return keccak256(abi.encode(scope, action));
    }

    function _limit(GuardRail storage r) private view returns (AgentRateLimit.Limit memory) {
        return AgentRateLimit.Limit({capacity: r.capacity, refillPerSecond: r.refillPerSecond});
    }

    function _isTightening(GuardRail storage cur, GuardRail calldata next) private view returns (bool) {
        return next.threshold <= cur.threshold && next.delay >= cur.delay && next.window <= cur.window
            && next.capacity <= cur.capacity && next.refillPerSecond <= cur.refillPerSecond;
    }
}
