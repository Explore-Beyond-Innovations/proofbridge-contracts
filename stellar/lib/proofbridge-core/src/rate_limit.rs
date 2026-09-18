//! Token-bucket volume accounting (2.1d, risk 01 F7).
//!
//! A fixed window lets an agent spend the cap either side of a rollover and get 2× in seconds. A
//! bucket that refills continuously has no boundary to straddle, so the doubling stops existing
//! rather than getting a bigger number.
//!
//! Pure integer math, no host calls: this is the cross-chain contract. The EVM validator (2.1g)
//! mirrors it and one fixture (2.1h) drives both, so anything that would make the two disagree —
//! floating point, saturating-vs-checked arithmetic, a different clamp order — belongs nowhere
//! near this file.

use soroban_sdk::contracttype;

/// A configured limit. `capacity` is the most that can be spent in one burst; `refill_per_second`
/// is how fast the allowance returns.
///
/// `contracttype` so the stored shape and the math share one definition: a separate storage struct
/// plus a conversion is one more place for the two chains to drift apart.
#[contracttype]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Limit {
    pub capacity: u128,
    pub refill_per_second: u128,
}

/// Live state. `level` is the **remaining** allowance, so a fresh bucket starts full.
#[contracttype]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Bucket {
    pub level: u128,
    pub last_ts: u64,
}

impl Bucket {
    /// A bucket that has never been spent from.
    pub fn full(limit: &Limit, now: u64) -> Self {
        Bucket {
            level: limit.capacity,
            last_ts: now,
        }
    }
}

/// The allowance available at `now`, without spending it.
///
/// Clock skew is treated as no time passing rather than as a refund: `last_ts` ahead of `now`
/// would otherwise let a backwards step top the bucket up.
pub fn available(limit: &Limit, bucket: &Bucket, now: u64) -> u128 {
    let elapsed = u128::from(now.saturating_sub(bucket.last_ts));
    // Checked, then clamped. A saturating multiply would silently pin an absurd refill_rate to
    // u128::MAX and then clamp to capacity — the same answer here, but only by luck, and the two
    // chains would have to get lucky identically. Overflow means "more than capacity" outright.
    let refilled = limit
        .refill_per_second
        .checked_mul(elapsed)
        .and_then(|r| bucket.level.checked_add(r));
    match refilled {
        Some(r) if r <= limit.capacity => r,
        // Both arms of the arithmetic are checked, and both overflows mean the same thing: more
        // than capacity. A saturating add would land on u128::MAX and clamp to the same answer by
        // luck — and an EVM mirror would revert on the row instead of returning capacity, so the
        // fixture that is supposed to prove the two agree could not cover it.
        _ => limit.capacity,
    }
}

/// Refill, then spend. `None` when the bucket cannot cover `spend` — the caller must not debit
/// anything else it was going to debit alongside.
pub fn try_spend(limit: &Limit, bucket: &Bucket, spend: u128, now: u64) -> Option<Bucket> {
    let level = available(limit, bucket, now);
    if level < spend {
        return None;
    }
    Some(Bucket {
        level: level - spend,
        // Never earlier than the stored stamp. `now` alone would let a call at an earlier timestamp
        // rewind the clock, and the next call at the true time would then refill that interval a
        // second time — so the "a clock that goes backwards is not a refund" rule would hold for a
        // read and break across a sequence. Neither chain can produce a decreasing timestamp today;
        // this file is the one 2.1g mirrors and 2.1h drives from a single fixture, where the two
        // agreeing is the whole point.
        last_ts: if now > bucket.last_ts {
            now
        } else {
            bucket.last_ts
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const L: Limit = Limit {
        capacity: 1_000,
        refill_per_second: 10,
    };

    #[test]
    fn a_fresh_bucket_is_full_and_spends_down() {
        let b = Bucket::full(&L, 100);
        assert_eq!(available(&L, &b, 100), 1_000);
        let b = try_spend(&L, &b, 400, 100).unwrap();
        assert_eq!(b.level, 600);
        assert_eq!(b.last_ts, 100);
    }

    #[test]
    fn over_the_remaining_allowance_is_refused_and_changes_nothing() {
        let b = Bucket {
            level: 50,
            last_ts: 100,
        };
        assert!(try_spend(&L, &b, 51, 100).is_none());
        assert_eq!(b.level, 50, "the caller's bucket is untouched");
    }

    /// F7's boundary doubling, as an assertion. A fixed window passes this at 2×.
    #[test]
    fn there_is_no_boundary_to_straddle() {
        let b = try_spend(&L, &Bucket::full(&L, 0), 1_000, 0).unwrap();
        assert!(
            try_spend(&L, &b, 1_000, 1).is_none(),
            "a second full spend one second later"
        );
        assert!(
            try_spend(&L, &b, 11, 1).is_none(),
            "one unit past the refill"
        );
        assert!(try_spend(&L, &b, 10, 1).is_some(), "exactly the refill");
    }

    #[test]
    fn refill_is_continuous_and_clamps_at_capacity() {
        let spent = try_spend(&L, &Bucket::full(&L, 0), 1_000, 0).unwrap();
        assert_eq!(
            available(&L, &spent, 50),
            500,
            "half the capacity back after 50s"
        );
        assert_eq!(available(&L, &spent, 100), 1_000, "exactly full at 100s");
        assert_eq!(available(&L, &spent, 10_000), 1_000, "never more than full");
    }

    #[test]
    fn spending_twice_in_one_second_consumes_twice() {
        let b = Bucket::full(&L, 7);
        let b = try_spend(&L, &b, 600, 7).unwrap();
        assert!(try_spend(&L, &b, 600, 7).is_none());
        assert!(try_spend(&L, &b, 400, 7).is_some());
    }

    #[test]
    fn a_clock_that_goes_backwards_does_not_refund() {
        let b = try_spend(&L, &Bucket::full(&L, 1_000), 1_000, 1_000).unwrap();
        assert_eq!(
            available(&L, &b, 900),
            0,
            "an earlier `now` is not a refill"
        );
    }

    /// F3: the rule has to survive a *sequence*, not just a query. Spend at an earlier stamp than
    /// the stored one, then at the true time: the rewound interval must not be paid for twice.
    #[test]
    fn a_backwards_spend_does_not_rewind_the_stored_clock() {
        let b = try_spend(&L, &Bucket::full(&L, 1_000), 1_000, 1_000).unwrap();
        let b = try_spend(&L, &b, 0, 900).unwrap();
        assert_eq!(b.last_ts, 1_000, "the stamp never moves backwards");
        assert_eq!(available(&L, &b, 1_010), 100, "10s of refill, not 110s");
    }

    /// G3: a level near the ceiling plus a large refill must resolve to capacity through the
    /// checked path, not by saturating to u128::MAX and clamping.
    #[test]
    fn an_overflowing_level_plus_refill_is_capacity_not_a_wrap() {
        let wide = Limit {
            capacity: u128::MAX,
            refill_per_second: u128::MAX,
        };
        let b = Bucket {
            level: u128::MAX - 1,
            last_ts: 0,
        };
        assert_eq!(available(&wide, &b, 1), u128::MAX);
    }

    #[test]
    fn an_overflowing_refill_is_capacity_not_a_wrap() {
        let wide = Limit {
            capacity: 1_000,
            refill_per_second: u128::MAX,
        };
        let b = Bucket {
            level: 0,
            last_ts: 0,
        };
        assert_eq!(available(&wide, &b, 2), 1_000);
    }

    #[test]
    fn a_zero_capacity_limit_admits_nothing() {
        let zero = Limit {
            capacity: 0,
            refill_per_second: 5,
        };
        let b = Bucket::full(&zero, 0);
        assert!(try_spend(&zero, &b, 1, 1_000).is_none());
        assert!(
            try_spend(&zero, &b, 0, 0).is_some(),
            "a zero spend is vacuously fine"
        );
    }
}
