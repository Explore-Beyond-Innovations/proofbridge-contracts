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
    /// @dev Separate from `RouteTiming` on purpose (D1): that timing tuple is read by the deploy CLI,
    ///      the relayer and the manifest, and widening it would ripple through all three.
    struct Params {
        /// @dev How long after filing the arbiter may still rule.
        uint64 challengePeriod;
        /// @dev The route's flat bond, in wrapped native. The same for every order on the route.
        uint128 bondFloor;
    }

    /// @notice A route's bond in the order's own token (`DisputeManager.bondConfig[token][peerChainId]`):
    ///         `max(minBond, amount × bondBps / 10,000)`, in the token's raw units. Unset
    ///         (`minBond == 0`) means the route posts the flat `Params.bondFloor` in wrapped native.
    struct BondConfig {
        uint128 minBond;
        uint16 bondBps;
    }

    /// @notice One dispute, keyed by order hash.
    struct Record {
        address initiator;
        uint128 bond;
        /// @dev The one deadline, in plain time: the filing's, replaced by the ruling's when ruled.
        uint64 challengeDeadline;
        bytes32 initiatorEvidence;
        bytes32 responderEvidence;
        Outcome ruling;
        /// @dev The order's signed deadline and the route's buffer, handed over by the escrow at
        ///      filing. They are what keep a dispute from finalizing early (D3, T-50): no dispute
        ///      path may complete before `deadline + buffer`, however short the challenge period is.
        ///      Both pack into the slot `ruling` already occupies, so the record costs no more.
        uint64 orderDeadline;
        uint64 buffer;
        /// @dev The bond's token: `address(0)` for wrapped native (the flat floor, or a native-token
        ///      route), else the order's ERC20 on a route with a `BondConfig`.
        address bondToken;
    }

    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice A challenge period shorter than this leaves no room to gather evidence.
    uint64 internal constant MIN_CHALLENGE_PERIOD = 1 hours;

    /// @notice C-36: bounds how long a dispute can delay the other party's exit.
    uint64 internal constant MAX_CHALLENGE_PERIOD = 7 days;

    /// @notice The ceiling on a route's `bondBps` (5% of the order).
    uint16 internal constant MAX_BOND_BPS = 500;

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice `field`: 1 challengePeriod, 2 bondFloor. 3 is retired (the old percentage term).
    error Dispute__InvalidParams(uint8 field);
    error Dispute__NoParams(uint256 chainId);
    /// @notice A `BondConfig` with a zero `minBond` but a ratio, or a ratio above `MAX_BOND_BPS`.
    error Dispute__InvalidBondConfig();

    /*//////////////////////////////////////////////////////////////
                                  LOGIC
    //////////////////////////////////////////////////////////////*/

    /// @dev Fail-closed, the same shape as `RouteTiming.validate`: a zero `challengePeriod` is what
    ///      an unset route reads as, so it can never be a legal written value.
    function validate(Params calldata p) internal pure {
        if (p.challengePeriod < MIN_CHALLENGE_PERIOD || p.challengePeriod > MAX_CHALLENGE_PERIOD) {
            revert Dispute__InvalidParams(1);
        }
        // No ceiling on `bondFloor`: it is in the wrapped-native token's units, so no one number fits every chain.
        if (p.bondFloor == 0) revert Dispute__InvalidParams(2);
    }

    /// @dev Load or fail closed. `challengePeriod` is never zero on a validated record.
    function load(mapping(uint256 => Params) storage self, uint256 chainId) internal view returns (Params storage p) {
        p = self[chainId];
        if (p.challengePeriod == 0) revert Dispute__NoParams(chainId);
    }

    /**
     * @notice The bond a filer must post: the route's flat floor, whatever the order's size.
     * @dev A percentage of the order amount would mix the ad token's raw units with native ones, and
     *      pricing it properly needs an oracle. Routes that carry large orders get a higher floor.
     */
    function bondFor(Params memory p) internal pure returns (uint256) {
        return p.bondFloor;
    }

    /// @dev `{0, 0}` clears the route's config (back to the flat floor); otherwise the floor is
    ///      non-zero and the ratio at most `MAX_BOND_BPS`.
    function validateBond(BondConfig calldata c) internal pure {
        if (c.minBond == 0 ? c.bondBps != 0 : c.bondBps > MAX_BOND_BPS) revert Dispute__InvalidBondConfig();
    }

    /**
     * @notice The scaled bond, in the order's token: `max(minBond, amount × bondBps / 10,000)`,
     *         the ratio rounded down. The floor keeps small orders bondable; the ratio scales large ones.
     */
    function routeBond(BondConfig memory c, uint256 amount) internal pure returns (uint256 bond) {
        bond = amount * c.bondBps / 10_000;
        if (bond < c.minBond) bond = c.minBond;
    }

    /**
     * @notice Whether the filer's position was vindicated, which is what routes the bond (D7).
     * @dev There is no separate "frivolous" discretion anywhere: the outcome *is* the finding. A
     *      `MutualRefund` returns the bond because neither side was shown wrong; a forfeit returns
     *      it only when the forfeited party is the one the filer accused. `returnToFiler` is the
     *      escrow's own finding on an evidence close: the bridger filed against a co-signed payout
     *      the maker denied, so filing was justified even though the trade then settled.
     */
    function bondReturnsToFiler(Outcome outcome, bool filerIsBridger, bool returnToFiler) internal pure returns (bool) {
        if (returnToFiler || outcome == Outcome.MutualRefund) return true;
        // The filer accused the other side; the ruling agreeing means that side forfeits.
        if (outcome == Outcome.MakerForfeit) return filerIsBridger;
        if (outcome == Outcome.BridgerForfeit) return !filerIsBridger;
        // TradeProceeds: the trade was provably fine, so the filer disputed a settleable trade (A4).
        return false;
    }
}
