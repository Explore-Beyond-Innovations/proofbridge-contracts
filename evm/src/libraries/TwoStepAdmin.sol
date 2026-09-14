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
    /// @notice A zero or self transfer: accepting either would leave the contract with no admin.
    error InvalidAdmin(address to);

    function _initAdmin(address admin_) internal {
        admin = admin_;
        _grantRole(DEFAULT_ADMIN_ROLE, admin_);
    }

    function transferAdmin(address to) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (to == address(0) || to == admin) revert InvalidAdmin(to);
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
