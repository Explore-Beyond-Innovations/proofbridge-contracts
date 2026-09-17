// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Dispute} from "../libraries/Dispute.sol";

/**
 * @title IDisputeManager
 * @notice What an escrow needs from the dispute module, and nothing more.
 * @dev The escrow reads; the module never moves the escrow's funds. Same shape as `IRootAnchor`,
 *      where the escrow's whole dependency is `isAnchored`.
 */
interface IDisputeManager {
    /**
     * @notice How a dispute on `orderHash` has ended, if it has.
     * @return outcome The ruling, or the mutual refund the fallback applies. `None` while the
     *         dispute is still running.
     * @return windowOver Whether the presentation window the ruling (or the fallback) opened has
     *         closed, in real time — paused seconds included.
     * @return initiator Who filed. The escrow needs this to know which side to pay.
     */
    function outcomeOf(bytes32 orderHash)
        external
        view
        returns (Dispute.Outcome outcome, bool windowOver, address initiator);

    /// @notice Whether a dispute is open on this order at all.
    function isDisputed(bytes32 orderHash) external view returns (bool);

    /**
     * @notice Open a dispute on an order the escrow has already hashed and checked, taking the bond.
     * @dev Escrow-only, and payable: the bond arrives with the call rather than sitting in the
     *      escrow. The escrow must pass `amount` because it does not store one — an order's leg is
     *      `{status, pausedAtOpen}` and the amount lives in the caller's `OrderParams`, validated
     *      against the hash. So the escrow is the only party that can vouch for it.
     * @return bond The bond actually required and taken.
     */
    function openDispute(bytes32 orderHash, uint256 amount, uint256 peerChainId, address filer, bytes32 evidence)
        external
        payable
        returns (uint128 bond);

    /**
     * @notice Settle the bond for a dispute the escrow has just finalized, and close the record.
     * @dev Escrow-only. The module holds the bond, so this is the one direction funds move — out of
     *      the module, never out of the escrow.
     * @param filerIsBridger True when the dispute was filed by the bridger.
     *
     *        Absolute, not relative to the calling escrow. Each leg authenticates a different party,
     *        so "the filer is my counterparty" means opposite things on the two escrows — phrasing
     *        it that way inverted the bond routing on the follower leg, returning a forfeited bond
     *        and forfeiting a vindicated one. The escrow answers the same question either way.
     */
    function settleBond(bytes32 orderHash, bool filerIsBridger) external;
}
