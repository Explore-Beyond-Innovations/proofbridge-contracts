// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/// @title IKeyRegistry — the one registry read the escrows make.
/// @notice `createAd` / `setSettlementSigner` refuse an identity with no live, unexpired key
///         (design 01 §1.5, risk 01 F8): an ad pointed at an unregistered account would trap a
///         bridger's deposit until the deadline.
interface IKeyRegistry {
    function hasUsableSlot(bytes32 account) external view returns (bool);
}
