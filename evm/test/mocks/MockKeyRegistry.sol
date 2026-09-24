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

    /// Expiries of the account's (fake) slots, for `anySlotExpiredWithin`.
    mapping(bytes32 => uint64[]) internal expiries;

    function addSlotExpiry(bytes32 account, uint64 validUntil) external {
        expiries[account].push(validUntil);
    }

    function anySlotExpiredWithin(bytes32 account, uint64 from, uint64 to) external view returns (bool) {
        uint64[] storage e = expiries[account];
        for (uint256 i = 0; i < e.length; i++) {
            if (e[i] != 0 && e[i] >= from && e[i] <= to) return true;
        }
        return false;
    }
}
