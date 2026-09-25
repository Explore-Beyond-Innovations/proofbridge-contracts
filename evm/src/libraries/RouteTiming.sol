// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/**
 * @title RouteTiming
 * @notice The per-peer-chain clock parameters the termination primitive reads (2.3e D6). Seconds.
 *         Admin-set per route, validated once at write time, and fail-closed: an unset route
 *         (`buffer == 0`) makes every timed path revert `NoRouteTiming`.
 * @dev `minWindow` — the shortest `deadline − now` a lock/create accepts (the monotonicity
 *      precondition for `cancelNeverLocked`). `buffer` — the primary's presentation window after the
 *      deadline, and the follower's backstop window after its claim. `margin` — how much before the
 *      end of the window the primary stops accepting the co-signed unlock (EVM proposer skew);
 *      primary-only, the follower's unlock never runs inside a window.
 *      `longBackstop` — how long after the deadline the follower may open a backstop claim.
 *      `claimStagger` — how much before the deadline the follower's co-signed unlock stops, so the
 *      maker's claim always leaves the watchtower time to land the bridger's leg.
 */
library RouteTiming {
    struct Timing {
        uint64 minWindow;
        uint64 buffer;
        uint64 margin;
        uint64 longBackstop;
        uint64 claimStagger;
    }

    /// @notice A presentation window can never be shorter than this.
    uint64 internal constant MIN_BUFFER = 30 minutes;

    /// @notice #453: nor longer than this. With {MAX_ORDER_WINDOW} and the anchor delay's cap it keeps
    ///         an order's last protected moment inside the key registry's 30-day memory of a dead slot.
    uint64 internal constant MAX_BUFFER = 1 days;

    /// @notice #453: the longest `deadline − now` a lock/create accepts, and so the longest `minWindow`.
    uint64 internal constant MAX_ORDER_WINDOW = 7 days;

    /// @notice `field`: 1 buffer, 2 margin, 3 longBackstop, 4 claimStagger, 5 minWindow.
    error RouteTiming__Invalid(uint8 field);
    error RouteTiming__NotSet(uint256 chainId);

    /// @dev D6 rules: `MIN_BUFFER ≤ buffer ≤ MAX_BUFFER`, `margin < buffer`, `longBackstop ≥ buffer`,
    ///      `claimStagger < minWindow` when the stagger is on (`0` = off, always legal),
    ///      `margin ≤ minWindow ≤ MAX_ORDER_WINDOW` (the upper bounds are #453's).
    function validate(Timing calldata t) internal pure {
        if (t.buffer < MIN_BUFFER || t.buffer > MAX_BUFFER) revert RouteTiming__Invalid(1);
        if (t.margin >= t.buffer) revert RouteTiming__Invalid(2);
        if (t.longBackstop < t.buffer) revert RouteTiming__Invalid(3);
        if (t.claimStagger != 0 && t.claimStagger >= t.minWindow) revert RouteTiming__Invalid(4);
        if (t.minWindow < t.margin || t.minWindow > MAX_ORDER_WINDOW) revert RouteTiming__Invalid(5);
    }

    /// @dev Load or fail closed. `buffer` is never zero on a validated record.
    function load(mapping(uint256 => Timing) storage self, uint256 chainId) internal view returns (Timing storage t) {
        t = self[chainId];
        if (t.buffer == 0) revert RouteTiming__NotSet(chainId);
    }
}
