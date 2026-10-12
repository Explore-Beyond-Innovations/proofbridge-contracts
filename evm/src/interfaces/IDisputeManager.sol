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
     * @return windowOver Whether the record's one deadline has passed (`now ≥ effectiveChallengeDeadline`).
     * @return initiator Who filed. The escrow needs this to know which side to pay.
     */
    function outcomeOf(bytes32 orderHash)
        external
        view
        returns (Dispute.Outcome outcome, bool windowOver, address initiator);

    /// @notice Who filed, if anyone. Reads no clock, so the escrow can call it mid-transaction.
    function initiatorOf(bytes32 orderHash) external view returns (address);

    /// @notice The record's one deadline, in plain time: `max(filedAt + challengePeriod, orderDeadline
    ///         + buffer)` at filing, `max(ruledAt, orderDeadline) + buffer` once ruled. The escrow's
    ///         cancel grace counts from it (#422).
    function effectiveChallengeDeadline(bytes32 orderHash) external view returns (uint256);

    /// @notice Whether a dispute is open on this order at all.
    function isDisputed(bytes32 orderHash) external view returns (bool);

    /**
     * @notice Open a dispute on an order the escrow has already hashed and checked, taking the bond.
     * @dev Escrow-only, and payable: the bond arrives with the call rather than sitting in the
     *      escrow. The bond is the route's flat floor (`bondFor(peerChainId)`), so no order amount
     *      is passed.
     *
     *      The escrow vouches for every value here. `deadline` and `buffer` (the order's own timing
     *      version's) are what stop a short challenge period finalizing a dispute before the order's
     *      own deadline (D3, T-50).
     * @return bond The bond actually required and taken.
     */
    function openDispute(
        bytes32 orderHash,
        uint256 peerChainId,
        address filer,
        bytes32 evidence,
        uint64 deadline,
        uint64 buffer
    ) external payable returns (uint128 bond);

    /**
     * @notice Record the counterparty's response to an open dispute: one non-zero hash, strictly
     *         before the effective challenge deadline (D5).
     * @dev Escrow-only: only the escrow knows who the order's two parties are, so only it can say
     *      that this responder is the one that did not file (D11). The module authenticating "some
     *      address that is not the filer" would let anyone overwrite the genuine counterparty's
     *      evidence hash, including one block before the arbiter reads it.
     */
    function recordResponse(bytes32 orderHash, address responder, bytes32 evidence) external;

    /**
     * @notice Settle the bond for a dispute the escrow has just finalized, and close the record.
     * @dev Escrow-only. The module holds the bond, so this is the one direction funds move — out of
     *      the module, never out of the escrow.
     * @param outcome What the escrow's path proved. Passed in rather than read from the record,
     *        because an evidence termination overrides any ruling — deciding the bond from a ruling
     *        evidence has just overturned would route it by a finding that no longer holds. The
     *        escrow passes `TradeProceeds` for a settle, `MutualRefund` for a cancel-refund, and the
     *        record's own ruling only from `finalizeDispute`.
     * @param filerIsBridger True when the dispute was filed by the bridger.
     *
     *        Absolute, not relative to the calling escrow. Each leg authenticates a different party,
     *        so "the filer is my counterparty" means opposite things on the two escrows — phrasing
     *        it that way inverted the bond routing on the follower leg, returning a forfeited bond
     *        and forfeiting a vindicated one. The escrow answers the same question either way.
     * @param returnToFiler True when the bond goes back to the filer whatever `outcome` says: set
     *        by the escrow on an evidence close when the bridger filed and the maker had denied the
     *        co-signed payout (a halt, an unwired verifier, a killed key). The record's outcome
     *        stays `TradeProceeds`; only the bond's recipient changes.
     */
    function settleBond(bytes32 orderHash, Dispute.Outcome outcome, bool filerIsBridger, bool returnToFiler) external;
}

