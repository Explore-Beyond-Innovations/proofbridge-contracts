// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IAdminTimelock} from "../interfaces/IAdminTimelock.sol";

/**
 * @title Timelock — the delay rules, one copy for every contract that has admin setters.
 * @dev Internal, so the contracts with room inline it; the escrows reach it through the linked
 *      `ProofBridgeUtils` for EIP-170 headroom (the same split as `DecimalScaling`).
 *
 *      Rules: a proposal is `keccak256` of the setter's exact calldata. It may run once, by anyone,
 *      in `[eta, eta + GRACE]` where `eta = proposedAt + DELAY`, and only under the admin epoch it was
 *      proposed in (a handover voids the old admin's proposals). The admin may cancel it before. A
 *      brake (an instant de-trust) records its time under a key; a proposal on that key made at or
 *      before the brake can never run, so a stale proposal cannot undo a brake. The bootstrap bypass
 *      (`active == false`) closes on `activate` or on the first `propose` and never reopens.
 */
library Timelock {
    uint256 internal constant DELAY = 24 hours;
    /// @notice How long a ripe proposal stays executable before it expires.
    uint256 internal constant GRACE = 14 days;

    struct State {
        bool active;
        /// @dev Bumped on every admin handover; a proposal carries the epoch it was made in.
        uint64 epoch;
        /// @dev id → `eta | epoch << 64`.
        mapping(bytes32 id => uint256) proposals;
        /// @dev brake key → when the brake was last pulled.
        mapping(bytes32 key => uint256) brakedAt;
    }

    function activate(State storage s) internal {
        if (s.active) revert IAdminTimelock.Timelock__AlreadyActive();
        s.active = true;
        emit IAdminTimelock.TimelockActivated();
    }

    /// @dev The eta of a proposal that can still run (this epoch, not expired), else 0.
    function liveEta(State storage s, bytes32 id) internal view returns (uint256 eta) {
        uint256 p = s.proposals[id];
        eta = uint64(p);
        if (p >> 64 != s.epoch || block.timestamp > eta + GRACE) return 0;
    }

    function propose(State storage s, bytes calldata data) internal {
        if (!s.active) activate(s);
        bytes32 id = keccak256(data);
        if (liveEta(s, id) != 0) revert IAdminTimelock.Timelock__AlreadyProposed(id);
        uint256 eta = block.timestamp + DELAY;
        s.proposals[id] = eta | (uint256(s.epoch) << 64);
        emit IAdminTimelock.ActionProposed(id, eta, data);
    }

    function cancel(State storage s, bytes32 id) internal {
        if (s.proposals[id] == 0) revert IAdminTimelock.Timelock__NotProposed(id);
        delete s.proposals[id];
        emit IAdminTimelock.ActionCancelled(id);
    }

    /// @dev The active-mode gate: `id`'s proposal exists in this epoch, is ripe and not expired, and
    ///      was not made at or before a brake on `key` (zero = no brake key). Consumed here.
    function consume(State storage s, bytes32 id, bytes32 key) internal {
        uint256 p = s.proposals[id];
        uint256 eta = uint64(p);
        if (p == 0 || p >> 64 != s.epoch) revert IAdminTimelock.Timelock__NotProposed(id);
        if (block.timestamp < eta) revert IAdminTimelock.Timelock__TooEarly(eta);
        if (block.timestamp > eta + GRACE) revert IAdminTimelock.Timelock__Expired(eta + GRACE);
        if (key != 0 && eta - DELAY <= s.brakedAt[key]) revert IAdminTimelock.Timelock__CancelledByBrake(id);
        delete s.proposals[id];
        emit IAdminTimelock.ActionExecuted(id);
    }
}
