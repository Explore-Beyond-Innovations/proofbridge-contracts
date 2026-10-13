// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IAdminTimelock} from "../interfaces/IAdminTimelock.sol";

/**
 * @title Timelock — the delay rules, one copy for every contract that has admin setters.
 * @dev Internal, so MerkleManager and DisputeManager inline it; the escrows reach it through the
 *      linked `ProofBridgeUtils` for EIP-170 headroom (the same split as `DecimalScaling`).
 *
 *      Rules: a proposal is `keccak256` of the setter's exact calldata; it may run once, by anyone,
 *      at or after `proposedAt + DELAY`; the admin may cancel it before then. The bootstrap bypass
 *      (`active == false`) closes on `activate` or on the first `propose` and never reopens.
 */
library Timelock {
    uint256 internal constant DELAY = 24 hours;

    struct State {
        bool active;
        mapping(bytes32 id => uint256 eta) eta;
    }

    function activate(State storage s) internal {
        if (s.active) revert IAdminTimelock.Timelock__AlreadyActive();
        s.active = true;
        emit IAdminTimelock.TimelockActivated();
    }

    function propose(State storage s, bytes calldata data) internal {
        if (!s.active) activate(s);
        bytes32 id = keccak256(data);
        if (s.eta[id] != 0) revert IAdminTimelock.Timelock__AlreadyProposed(id);
        uint256 eta = block.timestamp + DELAY;
        s.eta[id] = eta;
        emit IAdminTimelock.ActionProposed(id, eta, data);
    }

    function cancel(State storage s, bytes32 id) internal {
        if (s.eta[id] == 0) revert IAdminTimelock.Timelock__NotProposed(id);
        delete s.eta[id];
        emit IAdminTimelock.ActionCancelled(id);
    }

    /// @dev The active-mode gate: `id`'s proposal exists and is ripe; consumed here.
    function consume(State storage s, bytes32 id) internal {
        uint256 eta = s.eta[id];
        if (eta == 0) revert IAdminTimelock.Timelock__NotProposed(id);
        if (block.timestamp < eta) revert IAdminTimelock.Timelock__TooEarly(eta);
        delete s.eta[id];
        emit IAdminTimelock.ActionExecuted(id);
    }
}
