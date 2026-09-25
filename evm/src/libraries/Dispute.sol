// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/**
 * @title Dispute
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice The dispute record, its per-route parameters and the bond maths (2.3g, amendment A1–A7).
 * @dev A library rather than inline code for size: AdManager sits against the 24 KB limit and 2.3h
 *      lands on it next, so the maths and validation live here and the entry points stay thin.
 *
 *      Three rules shape everything below, and they are worth stating where they are implemented:
 *
 *      1. **Evidence beats arbitration.** A proof that the trade settled terminates a dispute
 *         immediately, whatever the arbiter thinks and without waiting out the challenge period.
 *      2. **The arbiter only rules the vacuum.** It picks among outcomes none of which is "the trade
 *         went through" — {TradeProceeds} is reachable by evidence alone, never by a ruling.
 *      3. **A ruling opens a window; it does not pay.** Evidence inside that window overrides it.
 */
library Dispute {
    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice How a dispute ended.
     * @dev `TradeProceeds` stays in the enum because it *is* the outcome of an evidence
     *      termination — removing it would misname the result. The arbiter is refused it at the
     *      boundary instead (2.3g D6), which is a guard on the caller, not on the vocabulary.
     */
    enum Outcome {
        None,
        MutualRefund,
        TradeProceeds,
        BridgerForfeit,
        MakerForfeit
    }

    /// @notice Per-peer-chain dispute parameters, admin-set and validated at the write.
    /// @dev Separate from `RouteTiming` on purpose (D1): that five-tuple is read by the deploy CLI,
    ///      the relayer and the manifest, and widening it would ripple through all three.
    struct Params {
        /// @dev How long after filing the arbiter may still rule. Pause-aware at read time.
        uint64 challengePeriod;
        /// @dev The bond floor, in wrapped native. Dominates on small orders.
        uint128 bondFloor;
        /// @dev Basis points of the order amount. Dominates on large ones.
        uint16 bondBps;
    }

    /// @notice One dispute, keyed by order hash.
    struct Record {
        address initiator;
        uint128 bond;
        /// @dev Unadjusted. Every read goes through `effectiveChallengeDeadline`, which applies the
        ///      escrow's paused seconds once; storing an already-adjusted value here would let a
        ///      later read adjust it twice.
        uint64 challengeDeadline;
        /// @dev The *escrow's* paused-seconds counter as of the order's lock (D10, c41-J: the
        ///      filing carries the order's own snapshot, so the deadline counts every pause the
        ///      unlock's cutoff counts). The escrow's, not this contract's: a pause is what stops
        ///      someone presenting, and it is the escrow that gates presentation.
        uint64 pausedAtOpen;
        bytes32 initiatorEvidence;
        bytes32 responderEvidence;
        Outcome ruling;
        /// @dev The order's signed deadline and the route's buffer, handed over by the escrow at
        ///      filing. They are what keep a dispute from finalizing early (D3, T-50): no dispute
        ///      path may complete before `deadline + buffer`, however short the challenge period is.
        ///      Both pack into the slot `ruling` already occupies, so the record costs no more.
        uint64 orderDeadline;
        uint64 buffer;
    }

    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice A challenge period shorter than this leaves no room to gather evidence.
    uint64 internal constant MIN_CHALLENGE_PERIOD = 1 hours;

    /// @notice Bond ceiling: 10%. Above this the bond deters honest disputes as much as frivolous ones.
    uint16 internal constant MAX_BOND_BPS = 1000;

    uint256 private constant _BPS_DENOMINATOR = 10_000;

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice `field`: 1 challengePeriod, 2 bondFloor, 3 bondBps.
    error Dispute__InvalidParams(uint8 field);
    error Dispute__NoParams(uint256 chainId);

    /*//////////////////////////////////////////////////////////////
                                  LOGIC
    //////////////////////////////////////////////////////////////*/

    /// @dev Fail-closed, the same shape as `RouteTiming.validate`: a zero `challengePeriod` is what
    ///      an unset route reads as, so it can never be a legal written value.
    function validate(Params calldata p) internal pure {
        if (p.challengePeriod < MIN_CHALLENGE_PERIOD) revert Dispute__InvalidParams(1);
        if (p.bondFloor == 0) revert Dispute__InvalidParams(2);
        if (p.bondBps > MAX_BOND_BPS) revert Dispute__InvalidParams(3);
    }

    /// @dev Load or fail closed. `challengePeriod` is never zero on a validated record.
    function load(mapping(uint256 => Params) storage self, uint256 chainId) internal view returns (Params storage p) {
        p = self[chainId];
        if (p.challengePeriod == 0) revert Dispute__NoParams(chainId);
    }

    /**
     * @notice The bond a filer must post: `max(floor, bps × amount)`.
     * @dev Both terms are per route and admin-tuned, which is the pricing mechanism the design
     *      allows in place of an oracle — the percentage is meaningful where the route's token
     *      tracks native, and the floor dominates where it does not. Rounds down, so the floor is
     *      what guarantees a non-zero bond.
     */
    function bondFor(uint256 amount, Params memory p) internal pure returns (uint256) {
        uint256 scaled = (amount * p.bondBps) / _BPS_DENOMINATOR;
        return scaled > p.bondFloor ? scaled : p.bondFloor;
    }

    /**
     * @notice Whether the filer's position was vindicated, which is what routes the bond (D7).
     * @dev There is no separate "frivolous" discretion anywhere: the outcome *is* the finding. A
     *      `MutualRefund` returns the bond because neither side was shown wrong; a forfeit returns
     *      it only when the forfeited party is the one the filer accused.
     */
    function bondReturnsToFiler(Outcome outcome, bool filerIsBridger) internal pure returns (bool) {
        if (outcome == Outcome.MutualRefund) return true;
        // The filer accused the other side; the ruling agreeing means that side forfeits.
        if (outcome == Outcome.MakerForfeit) return filerIsBridger;
        if (outcome == Outcome.BridgerForfeit) return !filerIsBridger;
        // TradeProceeds: the trade was provably fine, so the filer disputed a settleable trade (A4).
        return false;
    }
}
