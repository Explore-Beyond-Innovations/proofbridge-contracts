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

    /// `approvedMaker[account][maker]`: the account let the maker name it as settlement signer.
    mapping(bytes32 => mapping(bytes32 => bool)) public approvedMaker;

    function approve(bytes32 account, bytes32 maker, bool ok) external {
        approvedMaker[account][maker] = ok;
    }

    function isApprovedMaker(bytes32 account, bytes32 maker) external view returns (bool) {
        return approvedMaker[account][maker];
    }

    /// Plan 12 C: per-slot expiry (`expiredAt`) and how many slots exist (`slotCount - 1` extra; slot
    /// 0 always exists for a usable account, the slot the suites pin).
    mapping(bytes32 => mapping(uint32 => uint64)) public slotExpiry;
    mapping(bytes32 => uint32) public extraSlots;

    /// The pinned slot (0) expires at `validUntil`: what the #422 cases mean by "the signer's key".
    function addSlotExpiry(bytes32 account, uint64 validUntil) external {
        slotExpiry[account][0] = validUntil;
    }

    /// Another slot's expiry, not the pinned one: a rotation of a slot that never co-signed.
    function setSlotExpiry(bytes32 account, uint32 slot, uint64 validUntil) external {
        slotExpiry[account][slot] = validUntil;
        if (slot > extraSlots[account]) extraSlots[account] = slot;
    }

    function expiredAt(bytes32 account, uint32 slot) external view returns (uint64) {
        return slotExpiry[account][slot];
    }

    /// Answers for a usable account's existing, unexpired slot, as `BLSKeyRegistry.commitmentAt` does.
    function commitmentAt(bytes32 account, uint32 slot) external view returns (bytes32) {
        require(usable[account] && slot <= extraSlots[account], "MockKeyRegistry: no such slot");
        uint64 e = slotExpiry[account][slot];
        require(e == 0 || block.timestamp < e, "MockKeyRegistry: slot expired");
        return keccak256(abi.encode(account, slot));
    }

    struct Repin {
        uint32 fromSlot;
        uint32 toSlot;
        uint64 nonce;
    }

    mapping(bytes32 => mapping(bytes32 => Repin)) internal repins;

    function setRepin(bytes32 account, bytes32 orderHash, uint32 fromSlot, uint32 toSlot) external {
        Repin storage r = repins[account][orderHash];
        repins[account][orderHash] = Repin(fromSlot, toSlot, r.nonce + 1);
    }

    function repinApproval(bytes32 account, bytes32 orderHash) external view returns (uint32, uint32, uint64) {
        Repin storage r = repins[account][orderHash];
        return (r.fromSlot, r.toSlot, r.nonce);
    }
}
