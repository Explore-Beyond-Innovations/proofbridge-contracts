// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/**
 * @title AgentRateLimit
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice Token-bucket volume accounting, mirroring
 *         `contracts/stellar/lib/proofbridge-core/src/rate_limit.rs` exactly.
 *
 *         A fixed window lets an agent spend the cap either side of a rollover and get twice the
 *         allowance in seconds. A bucket that refills continuously has no boundary to straddle.
 *
 *         Two things here look like Solidity written badly and are neither. Both exist because one
 *         fixture (2.1h) drives this file and the Rust one, and an answer the two reach differently
 *         is a bug even when the number matches.
 */
library AgentRateLimit {
    /// @dev Soroban's limits are `u128`. The canonical encoding gives them 32-byte fields for the
    ///      EVM's convenience, but the values stay inside `u128` so a policy means the same thing
    ///      on both chains — and so the overflow clamp below triggers at the same place.
    uint256 internal constant U128_MAX = type(uint128).max;

    struct Limit {
        uint256 capacity;
        uint256 refillPerSecond;
    }

    struct Bucket {
        uint256 level;
        uint64 lastTs;
    }

    /**
     * @notice The allowance available at `nowTs`, without spending it.
     * @dev Clock skew is no time passing rather than a refund: a `lastTs` ahead of `nowTs` would
     *      otherwise let a backwards step top the bucket up.
     *
     *      The overflow arms return `capacity` rather than reverting. Solidity 0.8 would revert on
     *      a `u128` overflow it never sees — the arithmetic fits `uint256` easily — so the `u128`
     *      ceiling is checked by hand. Rust's `checked_mul`/`checked_add` both read overflow as
     *      "more than capacity", and a mirror that reverted where the original clamped could not be
     *      covered by the fixture that is meant to prove the two agree.
     */
    function available(Limit memory limit, Bucket memory bucket, uint64 nowTs) internal pure returns (uint256) {
        uint256 elapsed = nowTs > bucket.lastTs ? uint256(nowTs - bucket.lastTs) : 0;
        uint256 refill = limit.refillPerSecond * elapsed;
        if (refill > U128_MAX) return limit.capacity;
        uint256 sum = bucket.level + refill;
        // Rust's `checked_add` overflowing `u128` needs no arm of its own here: `capacity` is bounded
        // to `u128` wherever a limit is written, so a sum past `u128` is already a sum past it.
        if (sum > limit.capacity) return limit.capacity;
        return sum;
    }

    /**
     * @notice Refill, then spend.
     * @return ok false when the bucket cannot cover `spend`; the caller must then debit nothing
     *         else it was going to debit alongside.
     */
    function trySpend(Limit memory limit, Bucket memory bucket, uint256 spend, uint64 nowTs)
        internal
        pure
        returns (bool ok, Bucket memory next)
    {
        uint256 level = available(limit, bucket, nowTs);
        if (level < spend) return (false, bucket);
        // Never earlier than the stored stamp. `nowTs` alone would let a call at an earlier
        // timestamp rewind the clock, and the next call at the true time would refill that interval
        // a second time — so "a clock that goes backwards is not a refund" would hold for a read and
        // break across a sequence.
        next = Bucket({level: level - spend, lastTs: nowTs > bucket.lastTs ? nowTs : bucket.lastTs});
        ok = true;
    }

    /// @notice A bucket that has never been spent from.
    function full(Limit memory limit, uint64 nowTs) internal pure returns (Bucket memory) {
        return Bucket({level: limit.capacity, lastTs: nowTs});
    }
}
