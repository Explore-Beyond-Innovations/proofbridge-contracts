// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/**
 * @title ERC-7579 module interfaces
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice The slice of ERC-4337 and ERC-7579 the agent module implements, vendored rather than
 *         imported. They are small, stable and standard, and vendoring keeps production code free
 *         of the test kit that mounts it on real accounts.
 */

// ERC-4337 v0.7+ user operation, as the EntryPoint hands it to the account.
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

uint256 constant MODULE_TYPE_VALIDATOR = 1;
uint256 constant MODULE_TYPE_EXECUTOR = 2;
uint256 constant MODULE_TYPE_FALLBACK = 3;
uint256 constant MODULE_TYPE_HOOK = 4;

// The EntryPoint reads the low 160 bits of a validator's return as the authorizer: 0 is valid,
// 1 is a signature error.
uint256 constant VALIDATION_SUCCESS = 0;
uint256 constant VALIDATION_FAILED = 1;

interface IModule {
    function onInstall(bytes calldata data) external;
    function onUninstall(bytes calldata data) external;
    function isModuleType(uint256 moduleTypeId) external view returns (bool);
    function isInitialized(address smartAccount) external view returns (bool);
}

interface IValidator is IModule {
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external returns (uint256);
    function isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata data)
        external
        view
        returns (bytes4);
}

interface IHook is IModule {
    function preCheck(address msgSender, uint256 value, bytes calldata msgData) external returns (bytes memory hookData);
    function postCheck(bytes calldata hookData) external;
}
