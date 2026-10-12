// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/**
 * @title RouteTiming
 * @notice The per-peer-chain clock parameters the termination primitive reads (2.3e D6). Seconds.
 *         Admin-set per route and validated once at write time. Versioned: each write is a new
 *         version, and each order keeps the version it opened under, so a retiming moves no live
 *         order. Version 0 is unset and fails closed (`RouteTiming__NotSet`).
 * @dev `minWindow` — the shortest `deadline − now` a lock/create accepts (the monotonicity
 *      precondition for `cancelNeverLocked`). `buffer` — the primary's presentation window after the
 *      deadline. `margin` — how much before the end of the window the primary stops accepting the
 *      co-signed unlock (EVM proposer skew), at most half the buffer; primary-only, the follower's unlock never runs inside a
 *      window. `claimStagger` — how much before the deadline the follower's co-signed unlock stops,
 *      so the maker's claim always leaves the watchtower time to land the bridger's leg.
 */
library RouteTiming {
    struct Timing {
        uint64 minWindow;
        uint64 buffer;
        uint64 margin;
        uint64 claimStagger;
    }

    /// @notice A presentation window can never be shorter than this.
    uint64 internal constant MIN_BUFFER = 30 minutes;

    /// @notice #453: nor longer than this, so an order's last protected moment stays bounded.
    uint64 internal constant MAX_BUFFER = 1 days;

    /// @notice #453: the longest `deadline − now` a lock/create accepts. `minWindow` is at most half of
    ///         it, so a deadline at twice the min window (the lock lands after the create) still fits.
    uint64 internal constant MAX_ORDER_WINDOW = 7 days;

    /// @notice `field`: 1 buffer, 2 margin, 4 claimStagger, 5 minWindow. 3 is retired (the follower's backstop).
    error RouteTiming__Invalid(uint8 field);
    error RouteTiming__NotSet(uint256 chainId);

    /// @dev D6 rules: `MIN_BUFFER ≤ buffer ≤ MAX_BUFFER`, `margin ≤ buffer / 2` (the bridger always
    ///      keeps at least half the window for the co-signed unlock),
    ///      `claimStagger < minWindow` when the stagger is on (`0` = off, always legal),
    ///      `margin ≤ minWindow ≤ MAX_ORDER_WINDOW / 2` (the upper bounds are #453's).
    function validate(Timing calldata t) internal pure {
        if (t.buffer < MIN_BUFFER || t.buffer > MAX_BUFFER) revert RouteTiming__Invalid(1);
        if (t.margin > t.buffer / 2) revert RouteTiming__Invalid(2);
        if (t.claimStagger != 0 && t.claimStagger >= t.minWindow) revert RouteTiming__Invalid(4);
        if (t.minWindow < t.margin || t.minWindow > MAX_ORDER_WINDOW / 2) revert RouteTiming__Invalid(5);
    }

    /// @dev The route's current version, or fail closed when none was ever written.
    function current(mapping(uint256 => uint32) storage versions, uint256 chainId) internal view returns (uint32 v) {
        v = versions[chainId];
        if (v == 0) revert RouteTiming__NotSet(chainId);
    }
}
