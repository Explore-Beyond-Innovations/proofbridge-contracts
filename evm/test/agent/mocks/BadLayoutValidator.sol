// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {PackedUserOperation} from "src/agent/interfaces/IERC7579Module.sol";

/// @dev The same job as the real module's bucket write, laid out account-first.
///
///      `_count[account][key]` hashes to `keccak(key ‖ keccak(account ‖ p))`, so the outer hash no
///      longer starts with the account and the slot is not one ERC-7562 lets a validator touch.
///      Nothing about that is visible at compile time or in a functional test, which is why this
///      contract exists: `ValidationRulesTest` uses it to prove the rules check can fail.
contract BadLayoutValidator {
    mapping(address account => mapping(bytes32 key => uint256)) private _count;

    function onInstall(bytes calldata) external {}
    function onUninstall(bytes calldata) external {}

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == 1;
    }

    function isInitialized(address) external pure returns (bool) {
        return false;
    }

    function validateUserOp(PackedUserOperation calldata, bytes32) external returns (uint256) {
        _count[msg.sender][bytes32(uint256(1))] += 1;
        return 0;
    }

    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return 0xffffffff;
    }
}
