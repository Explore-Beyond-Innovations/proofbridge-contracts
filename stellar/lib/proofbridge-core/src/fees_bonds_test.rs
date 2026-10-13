//! #586: the fee split and the per-route bond against `test-vectors/fees-bonds.json`, which the
//! EVM suites read too.

extern crate std;

use crate::dispute::{self, MAX_BOND_BPS};
use crate::fees::{self, MAX_FEE_BPS};
use crate::types::BondConfig;

const VECTORS: &str = include_str!("../../../../test-vectors/fees-bonds.json");

fn vectors() -> serde_json::Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn u128_of(row: &serde_json::Value, key: &str) -> u128 {
    row[key].as_str().unwrap().parse().unwrap()
}

fn u32_of(row: &serde_json::Value, key: &str) -> u32 {
    row[key].as_u64().unwrap() as u32
}

fn rows<'a>(v: &'a serde_json::Value, key: &str) -> &'a std::vec::Vec<serde_json::Value> {
    let rows = v[key].as_array().unwrap();
    assert_eq!(
        rows.len() as u64,
        v["counts"][key].as_u64().unwrap(),
        "{key} count"
    );
    assert!(!rows.is_empty(), "{key} is empty");
    rows
}

#[test]
fn the_ceilings_match_the_shared_vectors() {
    let v = vectors();
    assert_eq!(
        MAX_FEE_BPS as u64,
        v["constants"]["maxFeeBps"].as_u64().unwrap()
    );
    assert_eq!(
        MAX_BOND_BPS as u64,
        v["constants"]["maxBondBps"].as_u64().unwrap()
    );
    assert_eq!(
        crate::timelock::DELAY,
        v["constants"]["timelockDelay"].as_u64().unwrap()
    );
}

#[test]
fn the_fee_split_matches_the_shared_vectors() {
    let v = vectors();
    for row in rows(&v, "feeSplit") {
        let label = row["label"].as_str().unwrap();
        let (lp, protocol) = fees::split_fee(
            u128_of(row, "amount"),
            u32_of(row, "lpBps"),
            u32_of(row, "protocolBps"),
        );
        assert_eq!(lp, u128_of(row, "lpFee"), "lpFee: {label}");
        assert_eq!(
            protocol,
            u128_of(row, "protocolFee"),
            "protocolFee: {label}"
        );
        assert_eq!(
            u128_of(row, "amount") - lp - protocol,
            u128_of(row, "net"),
            "net: {label}"
        );
    }
}

#[test]
fn fee_validation_matches_the_shared_vectors() {
    let v = vectors();
    for row in rows(&v, "feeValidation") {
        let label = row["label"].as_str().unwrap();
        assert_eq!(
            fees::fees_valid(
                u32_of(row, "lpBps"),
                u32_of(row, "protocolBps"),
                row["poolSet"].as_bool().unwrap()
            ),
            row["valid"].as_bool().unwrap(),
            "{label}"
        );
    }
}

#[test]
fn the_route_bond_matches_the_shared_vectors() {
    let v = vectors();
    for row in rows(&v, "routeBond") {
        let label = row["label"].as_str().unwrap();
        let c = BondConfig {
            min_bond: u128_of(row, "minBond"),
            bond_bps: u32_of(row, "bondBps"),
        };
        assert_eq!(
            dispute::route_bond(&c, u128_of(row, "amount")),
            u128_of(row, "bond"),
            "{label}"
        );
    }
}

#[test]
fn bond_config_validation_matches_the_shared_vectors() {
    let v = vectors();
    for row in rows(&v, "bondConfigValidation") {
        let label = row["label"].as_str().unwrap();
        let c = BondConfig {
            min_bond: u128_of(row, "minBond"),
            bond_bps: u32_of(row, "bondBps"),
        };
        assert_eq!(
            dispute::validate_bond(&c),
            row["valid"].as_bool().unwrap(),
            "{label}"
        );
    }
}
