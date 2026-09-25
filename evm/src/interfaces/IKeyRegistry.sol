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
    /// @notice Did any of `account`'s slots expire in `[from, to]` (#422 D12/D14/D14b). The escrow's
    ///         cancel grace asks it over the order's life as a payout, `[lockedAt, cutoff]` (D16):
    ///         a slot the order may have been co-signed under died while the payout could still
    ///         land. A slot expires at the later of the date its shorten named and the moment of
    ///         the shorten (a kill names `1`), and a later shorten can only move that earlier, so a
    ///         kill, a near-future shorten, a pre-lock shorten naming a date inside the window and a
    ///         re-kill after it all count; a rotation whose old slot outlives the cutoff does not.
    ///         A dead slot is forgotten once the account has no open positions, or 30 days on.
    function anySlotExpiredWithin(bytes32 account, uint64 from, uint64 to) external view returns (bool);
}
