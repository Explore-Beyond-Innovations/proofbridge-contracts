// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @title TwoStepAdmin — pending/accept admin handover over AccessControl.
abstract contract TwoStepAdmin is AccessControl {
    address public admin;
    address public pendingAdmin;

    event AdminTransferStarted(address indexed from, address indexed to);
    event AdminTransferred(address indexed from, address indexed to);

    error NotPendingAdmin();
    /// @notice A self transfer: accepting it grants and then revokes the role from the same
    ///         address, leaving the contract with no admin.
    error InvalidAdmin(address to);

    function _initAdmin(address admin_) internal {
        admin = admin_;
        _grantRole(DEFAULT_ADMIN_ROLE, admin_);
    }

    /// @notice Nominate the next admin; `address(0)` withdraws a pending nomination (zero can
    ///         never accept, so it is the cancel).
    function transferAdmin(address to) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (to == admin) revert InvalidAdmin(to);
        pendingAdmin = to;
        emit AdminTransferStarted(admin, to);
    }

    function acceptAdmin() external {
        if (msg.sender != pendingAdmin) revert NotPendingAdmin();
        address old = admin;
        admin = msg.sender;
        pendingAdmin = address(0);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _revokeRole(DEFAULT_ADMIN_ROLE, old);
        emit AdminTransferred(old, msg.sender);
    }
}
