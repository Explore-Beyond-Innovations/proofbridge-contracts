//! T-60, layer 1: the arithmetic under an agent policy, against the shared vectors.
//!
//! The token bucket and decimal scaling are each hand-written more than once — here, in Solidity,
//! and (scaling) in TypeScript — and each copy's own tests assert what that copy already believes.
//! `../../../test-vectors/agent-policy-math.json` is computed in unbounded integers by a generator
//! that imports none of them, and every copy reads it.

extern crate std;

use std::string::ToString;

use crate::decimal_scaling::{self, DecimalScalingError};
use crate::rate_limit::{self, Bucket, Limit};

const VECTORS: &str = include_str!("../../../../test-vectors/agent-policy-math.json");

fn vectors() -> serde_json::Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn u128_of(row: &serde_json::Value, key: &str) -> u128 {
    row[key].as_str().unwrap().parse().unwrap()
}

fn u64_of(row: &serde_json::Value, key: &str) -> u64 {
    row[key].as_str().unwrap().parse().unwrap()
}

#[test]
fn the_bucket_matches_the_shared_vectors() {
    let v = vectors();
    let rows = v["bucket"].as_array().unwrap();
    let mut ran = 0u64;

    for row in rows {
        let label = row["label"].as_str().unwrap();
        let limit = Limit {
            capacity: u128_of(row, "capacity"),
            refill_per_second: u128_of(row, "refillPerSecond"),
        };
        let bucket = Bucket {
            level: u128_of(row, "level"),
            last_ts: u64_of(row, "lastTs"),
        };
        let now = u64_of(row, "now");

        assert_eq!(
            rate_limit::available(&limit, &bucket, now),
            u128_of(row, "available"),
            "available: {label}"
        );

        let next = rate_limit::try_spend(&limit, &bucket, u128_of(row, "spend"), now);
        assert_eq!(next.is_some(), row["ok"].as_bool().unwrap(), "ok: {label}");
        // A refusal returns nothing here; the vectors say the bucket is left as it was, which is
        // what "returns nothing" has to mean to a caller.
        let after = next.unwrap_or(bucket);
        assert_eq!(after.level, u128_of(row, "nextLevel"), "nextLevel: {label}");
        assert_eq!(
            after.last_ts,
            u64_of(row, "nextLastTs"),
            "nextLastTs: {label}"
        );
        ran += 1;
    }

    // Zero rows is a failure, and so is some: a reader that parsed half the file would pass.
    assert!(ran > 0, "no bucket rows ran");
    assert_eq!(
        ran,
        v["counts"]["bucket"].as_u64().unwrap(),
        "bucket rows ran"
    );
}

#[test]
fn scaling_matches_the_shared_vectors() {
    let v = vectors();
    let rows = v["scaling"].as_array().unwrap();
    let mut ran = 0u64;

    for row in rows {
        let label = row["label"].as_str().unwrap();
        let got = decimal_scaling::scale(
            u128_of(row, "amount"),
            row["fromDecimals"].as_u64().unwrap() as u32,
            row["toDecimals"].as_u64().unwrap() as u32,
        );

        if row["ok"].as_bool().unwrap() {
            assert_eq!(got, Ok(u128_of(row, "value")), "value: {label}");
        } else {
            // The shared word for each refusal, mapped to this implementation's. A rename on
            // either side lands in the last arm and fails, rather than quietly matching nothing.
            let want = match row["reason"].as_str().unwrap() {
                "decimals-out-of-range" => DecimalScalingError::DecimalsOutOfRange,
                "non-exact-downscale" => DecimalScalingError::NonExactDownscale,
                "overflow" => DecimalScalingError::Overflow,
                other => panic!(
                    "{label}: a reason this reader does not know: {}",
                    other.to_string()
                ),
            };
            assert_eq!(got, Err(want), "reason: {label}");
        }
        ran += 1;
    }

    assert!(ran > 0, "no scaling rows ran");
    assert_eq!(
        ran,
        v["counts"]["scaling"].as_u64().unwrap(),
        "scaling rows ran"
    );
}
