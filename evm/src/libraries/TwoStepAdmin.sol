// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/**
 * @title TwoStepAdmin — pending/accept admin handover.
 * @dev One admin address, nominated and then accepted, so a typo cannot orphan a contract. Deliberately
 *      not a role system: every contract here has exactly one privileged party, and the escrows carry
 *      the role machinery's ~800 bytes of code against the EIP-170 limit for nothing. A list of
 *      callers (MerkleManager's managers) is a plain mapping the admin edits.
 */
abstract contract TwoStepAdmin {
    address public admin;
    address public pendingAdmin;

    event AdminTransferStarted(address indexed from, address indexed to);
    event AdminTransferred(address indexed from, address indexed to);

    error NotAdmin();
    error NotPendingAdmin();
    /// @notice A self transfer: accepting it would hand the contract to the address that already
    ///         holds it, so the nomination is refused instead of being silently a no-op.
    error InvalidAdmin(address to);

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    function _initAdmin(address admin_) internal {
        admin = admin_;
    }

    /// @notice Nominate the next admin; `address(0)` withdraws a pending nomination (zero can
    /// never accept, so it is the cancel).
    function transferAdmin(address to) external onlyAdmin {
        if (to == admin) revert InvalidAdmin(to);
        pendingAdmin = to;
        emit AdminTransferStarted(admin, to);
    }

    function acceptAdmin() external {
        if (msg.sender != pendingAdmin) revert NotPendingAdmin();
        address old = admin;
        admin = msg.sender;
        pendingAdmin = address(0);
        emit AdminTransferred(old, msg.sender);
    }
}
