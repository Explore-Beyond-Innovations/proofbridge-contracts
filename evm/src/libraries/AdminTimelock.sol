// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IAdminTimelock} from "../interfaces/IAdminTimelock.sol";
import {Timelock} from "./Timelock.sol";
import {TwoStepAdmin} from "./TwoStepAdmin.sol";

/**
 * @title AdminTimelock — a 24-hour delay on admin setters, with a one-time bootstrap bypass.
 * @dev A setter marked `timelocked` is its own execute: before activation the admin calls it directly
 *      (the bootstrap, so initial config does not take days); after activation it runs only when its
 *      exact calldata was proposed at least `TIMELOCK_DELAY` ago (and at most 14 days after that, in
 *      this admin epoch), and then anyone may send it. The rules are `Timelock`'s; the `_tl*` hooks
 *      let the escrows route them through the linked `ProofBridgeUtils` for EIP-170 headroom. `pause`,
 *      `unpause` and the admin handover stay instant; an accepted handover voids pending proposals.
 */
abstract contract AdminTimelock is IAdminTimelock, TwoStepAdmin {
    /// @inheritdoc IAdminTimelock
    uint256 public constant TIMELOCK_DELAY = Timelock.DELAY;

    Timelock.State internal _timelock;

    /// @dev Bootstrap: admin only. Active: a ripe proposal for this exact calldata, from anyone.
    modifier timelocked() {
        _timelocked(0);
        _;
    }

    /// @inheritdoc IAdminTimelock
    function timelockActive() external view returns (bool) {
        return _timelock.active;
    }

    /// @inheritdoc IAdminTimelock
    function timelockEta(bytes32 id) external view returns (uint256) {
        return _tlEta(id);
    }

    /// @inheritdoc IAdminTimelock
    function activateTimelock() external onlyAdmin {
        _tlActivate();
    }

    /// @inheritdoc IAdminTimelock
    function proposeAction(bytes calldata data) external onlyAdmin {
        _tlPropose(data);
    }

    /// @inheritdoc IAdminTimelock
    function cancelAction(bytes32 id) external onlyAdmin {
        _tlCancel(id);
    }

    /// @dev D6: a new admin starts with no pending proposals; the old admin's are void.
    function _afterAdminAccepted() internal override {
        _timelock.epoch++;
    }

    /// @dev `key` names what a brake on this setter de-trusts (zero = none).
    function _timelocked(bytes32 key) internal {
        if (!_timelock.active) {
            if (msg.sender != admin) revert NotAdmin();
            return;
        }
        _tlConsume(keccak256(msg.data), key);
    }

    /// @dev A brake (unwire, revoke) stays instant for the admin and voids every proposal on `key` made
    ///      up to now, so none can undo it; anything else goes through the delay.
    function _timelockedUnless(bool brake, bytes32 key) internal {
        if (brake) {
            if (msg.sender != admin) revert NotAdmin();
            _timelock.brakedAt[key] = block.timestamp;
        } else {
            _timelocked(key);
        }
    }

    function _tlActivate() internal virtual {
        Timelock.activate(_timelock);
    }

    function _tlPropose(bytes calldata data) internal virtual {
        Timelock.propose(_timelock, data);
    }

    function _tlCancel(bytes32 id) internal virtual {
        Timelock.cancel(_timelock, id);
    }

    function _tlConsume(bytes32 id, bytes32 key) internal virtual {
        Timelock.consume(_timelock, id, key);
    }

    function _tlEta(bytes32 id) internal view virtual returns (uint256) {
        return Timelock.liveEta(_timelock, id);
    }
}
