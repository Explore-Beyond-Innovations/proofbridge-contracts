// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/// @title IKeyRegistry — the one registry read the escrows make.
/// @notice `createAd` / `setSettlementSigner` refuse an identity with no live, unexpired key, and
///         `lockForOrder` refuses one whose key was retired since (design 01 §1.5, risk 01 F8): an ad
///         pointed at an unusable key would trap a bridger's deposit until the deadline.
/// @dev Registrations are per chain (the digests bind `block.chainid`), so this gate proves a key on
///      *this* chain only. The maker's own unlock on the order chain resolves the same identity in
///      that chain's registry; registering there is a relayer / UX precondition, enforced nowhere
///      on chain.
interface IKeyRegistry {
    function hasUsableSlot(bytes32 account) external view returns (bool);
    /// @notice When `account` last shortened a slot to the past (a kill, never a rotation's future
    ///         date); 0 if never. The escrow's cancel grace reads it (#422): a kill since the order
    ///         was locked means the co-signed payout was denied.
    function lastRetiredAt(bytes32 account) external view returns (uint64);
}
