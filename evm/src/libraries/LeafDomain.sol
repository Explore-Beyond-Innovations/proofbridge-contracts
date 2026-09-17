// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/**
 * @title LeafDomain
 * @notice What an MMR leaf records: `leaf = poseidon2(orderHash % p, domain)`, and the event circuit's
 *         last public input. ORDER/AD are deposits (the side the leaf is unlocked on) and prove the
 *         trade secret; the rest are event claims and prove none. Always a contract constant, never
 *         calldata. Mirrors `Side` in proofbridge-mmr.
 */
library LeafDomain {
    uint256 internal constant ORDER = 0;
    uint256 internal constant AD = 1;
    uint256 internal constant CANCEL = 2;
    uint256 internal constant SETTLED = 3;
    uint256 internal constant REGISTERED = 4;
    /// @dev The primary's ruling that the bridger forfeits (2.3g). Its own domain because the
    ///      follower must distinguish "refund the bridger" (CANCEL) from "pay the maker", and those
    ///      are the only two actions a dispute can ask of it.
    uint256 internal constant FORFEIT = 5;
}
