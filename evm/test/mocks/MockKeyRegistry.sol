// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IKeyRegistry} from "../../src/interfaces/IKeyRegistry.sol";

/// Stands in for BLSKeyRegistry.hasUsableSlot: an account is "registered" iff a test marked it so.
contract MockKeyRegistry is IKeyRegistry {
    mapping(bytes32 => bool) public usable;

    function set(bytes32 account, bool ok) external {
        usable[account] = ok;
    }

    function hasUsableSlot(bytes32 account) external view returns (bool) {
        return usable[account];
    }

    mapping(bytes32 => uint64) public lastShortenedAt;

    function setLastShortenedAt(bytes32 account, uint64 at) external {
        lastShortenedAt[account] = at;
    }
}
