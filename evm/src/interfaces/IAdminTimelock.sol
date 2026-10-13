// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/// @title IAdminTimelock — the 24-hour delay on admin setters (escrows, MerkleManager, DisputeManager).
interface IAdminTimelock {
    event TimelockActivated();
    event ActionProposed(bytes32 indexed id, uint256 eta, bytes data);
    event ActionCancelled(bytes32 indexed id);
    event ActionExecuted(bytes32 indexed id);

    error Timelock__AlreadyActive();
    error Timelock__AlreadyProposed(bytes32 id);
    error Timelock__NotProposed(bytes32 id);
    error Timelock__TooEarly(uint256 eta);

    /// @notice The minimum time between a proposal and its execution: 24 hours.
    function TIMELOCK_DELAY() external view returns (uint256);
    /// @notice The bootstrap bypass is closed. One-way.
    function timelockActive() external view returns (bool);
    /// @notice Earliest execution time of a pending proposal (`keccak256` of its calldata); 0 = none.
    function timelockEta(bytes32 id) external view returns (uint256);

    /// @notice Close the bootstrap bypass for good. Admin only; not itself delayed.
    function activateTimelock() external;
    /// @notice Queue a timelocked setter's full calldata. Admin only; closes the bypass if still open.
    function proposeAction(bytes calldata data) external;
    /// @notice Drop a pending proposal. Admin only.
    function cancelAction(bytes32 id) external;
}
