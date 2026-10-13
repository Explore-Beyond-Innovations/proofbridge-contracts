// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IAdminTimelock} from "../interfaces/IAdminTimelock.sol";
import {Timelock} from "./Timelock.sol";
import {TwoStepAdmin} from "./TwoStepAdmin.sol";

/**
 * @title AdminTimelock — a 24-hour delay on admin setters, with a one-time bootstrap bypass.
 * @dev A setter marked `timelocked` is its own execute: before activation the admin calls it directly
 *      (the bootstrap, so initial config does not take days); after activation it runs only when its
 *      exact calldata was proposed at least `TIMELOCK_DELAY` ago, and then anyone may send it. The
 *      rules are `Timelock`'s; the `_tl*` hooks let the escrows route them through the linked
 *      `ProofBridgeUtils` for EIP-170 headroom. `pause`, `unpause` and the admin handover stay instant.
 */
abstract contract AdminTimelock is IAdminTimelock, TwoStepAdmin {
    /// @inheritdoc IAdminTimelock
    uint256 public constant TIMELOCK_DELAY = Timelock.DELAY;

    Timelock.State internal _timelock;

    /// @dev Bootstrap: admin only. Active: a ripe proposal for this exact calldata, from anyone.
    modifier timelocked() {
        _timelocked();
        _;
    }

    /// @inheritdoc IAdminTimelock
    function timelockActive() external view returns (bool) {
        return _timelock.active;
    }

    /// @inheritdoc IAdminTimelock
    function timelockEta(bytes32 id) external view returns (uint256) {
        return _timelock.eta[id];
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

    function _timelocked() internal {
        if (!_timelock.active) {
            if (msg.sender != admin) revert NotAdmin();
            return;
        }
        _tlConsume(keccak256(msg.data));
    }

    /// @dev A brake (unwire, revoke) stays instant for the admin; anything else goes through the delay.
    function _timelockedUnless(bool brake) internal {
        if (brake) {
            if (msg.sender != admin) revert NotAdmin();
        } else {
            _timelocked();
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

    function _tlConsume(bytes32 id) internal virtual {
        Timelock.consume(_timelock, id);
    }
}
