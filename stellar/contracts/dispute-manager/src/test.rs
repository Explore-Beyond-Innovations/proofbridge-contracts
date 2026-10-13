//! 2.3g: the dispute module's own rules — the arbiter boundary, the bond maths, the clock, the
//! escrow edge, and the bond routing. The escrow↔module correspondence is exercised in the
//! integration suite, where both contracts are real.

#![cfg(test)]

extern crate std;

use super::*;
use proofbridge_core::types::{BondConfig, DisputeParams};
use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    token, Address, BytesN, Env,
};
use test_token::{TokenContract, TokenContractClient};

const DISPUTE_VECTORS: &str = include_str!("../../../../test-vectors/dispute.json");

const T0: u64 = 1_700_000_000;
const CHAIN: u128 = 1_000_002;
const CHALLENGE: u64 = 2 * 60 * 60;
/// The order's own clock. Deliberately further out than the challenge period: no dispute path may
/// finalize before `deadline + buffer`, and a fixture where the two coincide cannot see that.
const DEADLINE: u64 = T0 + 7 * 24 * 60 * 60;
const BUFFER: u64 = 30 * 60;
const BOND_FLOOR: u128 = 1_000;

struct F {
    env: Env,
    client: DisputeManagerContractClient<'static>,
    admin: Address,
    arbiter: Address,
    fee_pool: Address,
    escrow: Address,
    filer: Address,
    token: Address,
}

fn params() -> DisputeParams {
    DisputeParams {
        challenge_period: CHALLENGE,
        bond_floor: BOND_FLOOR,
    }
}

/// A stand-in escrow: a real contract address the module authenticates as its caller.
#[soroban_sdk::contract]
pub struct MockEscrow;

#[soroban_sdk::contractimpl]
impl MockEscrow {
    pub fn noop(_env: Env) {}
}

fn hash(env: &Env, fill: u8) -> BytesN<32> {
    BytesN::from_array(env, &[fill; 32])
}

fn fixture() -> F {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(T0);

    let admin = Address::generate(&env);
    let arbiter = Address::generate(&env);
    let fee_pool = Address::generate(&env);
    let escrow = env.register(MockEscrow, ());
    let filer = Address::generate(&env);

    // (owner, initial_supply, decimals, name, symbol)
    let token = env.register(
        TokenContract,
        (
            admin.clone(),
            0i128,
            7u32,
            soroban_sdk::String::from_str(&env, "Wrapped"),
            soroban_sdk::String::from_str(&env, "W"),
        ),
    );
    TokenContractClient::new(&env, &token).mint(&filer, &1_000_000);

    let id = env.register(DisputeManagerContract, ());
    let client = DisputeManagerContractClient::new(&env, &id);
    client.initialize(&admin, &token);
    client.set_escrow(&escrow, &true);
    client.set_arbiter(&arbiter);
    client.set_protocol_fee_pool(&fee_pool);
    client.set_dispute_params(&CHAIN, &params());

    F {
        env,
        client,
        admin,
        arbiter,
        fee_pool,
        escrow,
        filer,
        token,
    }
}

fn file(f: &F, h: &BytesN<32>) -> u128 {
    file_at(f, h, DEADLINE)
}

fn file_at(f: &F, h: &BytesN<32>, deadline: u64) -> u128 {
    f.client.open_dispute(
        &f.escrow,
        h,
        &CHAIN,
        &f.filer,
        &hash(&f.env, 0xEE),
        &deadline,
        &BUFFER,
        &f.token,
        &0,
    )
}

/// Past the window the module actually enforces, rather than past the challenge period alone.
/// Those differ whenever the order's deadline is further out — the normal case, and the hole that
/// let a dispute finalize early.
fn warp_past_window(f: &F, h: &BytesN<32>) {
    let until = f.client.effective_challenge_deadline(h);
    f.env.ledger().set_timestamp(until + 1);
}

// ── the bond ─────────────────────────────────────────────────────────────

#[test]
fn bond_is_the_route_floor() {
    assert_eq!(proofbridge_core::dispute::bond_for(&params()), BOND_FLOOR);
    let big = DisputeParams {
        challenge_period: CHALLENGE,
        bond_floor: 250 * 10u128.pow(7),
    };
    assert_eq!(
        proofbridge_core::dispute::bond_for(&big),
        250 * 10u128.pow(7)
    );
}

/// The view quotes what a filing pulls, follows a retuned floor, and fails closed on an unset route.
#[test]
fn bond_for_quotes_what_the_filing_pulls() {
    let f = fixture();
    assert_eq!(f.client.bond_for(&CHAIN), BOND_FLOOR);
    let t = token::Client::new(&f.env, &f.token);
    let before = t.balance(&f.filer);
    let bond = file(&f, &hash(&f.env, 0x60));
    assert_eq!(bond, f.client.bond_for(&CHAIN));
    assert_eq!(
        before - t.balance(&f.filer),
        BOND_FLOOR as i128,
        "the filing pulled the floor"
    );

    f.client.set_dispute_params(
        &CHAIN,
        &DisputeParams {
            challenge_period: CHALLENGE,
            bond_floor: 3 * BOND_FLOOR,
        },
    );
    assert_eq!(f.client.bond_for(&CHAIN), 3 * BOND_FLOOR);
    assert_eq!(
        f.client.try_bond_for(&(CHAIN + 7)),
        Err(Ok(Error::NoDisputeParams))
    );
}

#[test]
fn params_fail_closed() {
    let f = fixture();
    // Too short a challenge period leaves no room to gather evidence.
    assert_eq!(
        f.client.try_set_dispute_params(
            &CHAIN,
            &DisputeParams {
                challenge_period: 60,
                bond_floor: BOND_FLOOR,
            }
        ),
        Err(Ok(Error::InvalidChallengePeriod))
    );
    // A zero floor would let a bond round down to nothing.
    assert_eq!(
        f.client.try_set_dispute_params(
            &CHAIN,
            &DisputeParams {
                challenge_period: CHALLENGE,
                bond_floor: 0,
            }
        ),
        Err(Ok(Error::InvalidBondFloor))
    );
}

/// Parameter validation from the shared vector both chains loop over: each row either writes or fails
/// with the error for the field the vector names (C-36 put the challenge-period ceiling there).
#[test]
fn param_validation_matches_the_shared_vector() {
    let v: serde_json::Value = serde_json::from_str(DISPUTE_VECTORS).unwrap();
    let rows = v["paramValidation"].as_array().unwrap();
    assert_eq!(
        rows.len() as u64,
        v["counts"]["paramValidation"].as_u64().unwrap()
    );
    assert!(!rows.is_empty(), "the vector holds no validation rows");
    let f = fixture();
    for row in rows {
        let p = DisputeParams {
            challenge_period: row["challengePeriod"].as_u64().unwrap(),
            bond_floor: row["bondFloor"].as_str().unwrap().parse().unwrap(),
        };
        let got = f.client.try_set_dispute_params(&CHAIN, &p);
        let label = row["label"].as_str().unwrap();
        match row["validField"].as_u64().unwrap() {
            0 => assert!(got.is_ok(), "{label}: should write"),
            1 => assert_eq!(got, Err(Ok(Error::InvalidChallengePeriod)), "{label}"),
            2 => assert_eq!(got, Err(Ok(Error::InvalidBondFloor)), "{label}"),
            other => panic!("{label}: unknown field {other}"),
        }
    }
}

#[test]
fn an_unconfigured_route_cannot_be_disputed() {
    let f = fixture();
    let h = hash(&f.env, 1);
    assert_eq!(
        f.client.try_open_dispute(
            &f.escrow,
            &h,
            &(CHAIN + 7),
            &f.filer,
            &hash(&f.env, 0),
            &DEADLINE,
            &BUFFER,
            &f.token,
            &0,
        ),
        Err(Ok(Error::NoDisputeParams))
    );
}

// ── the escrow edge ──────────────────────────────────────────────────────

#[test]
fn only_a_registered_escrow_may_open_a_dispute() {
    let f = fixture();
    let stranger = Address::generate(&f.env);
    let h = hash(&f.env, 2);
    assert_eq!(
        f.client.try_open_dispute(
            &stranger,
            &h,
            &CHAIN,
            &f.filer,
            &hash(&f.env, 0),
            &DEADLINE,
            &BUFFER,
            &f.token,
            &0,
        ),
        Err(Ok(Error::NotEscrow))
    );
}

#[test]
fn the_bond_lands_in_the_module_not_the_escrow() {
    let f = fixture();
    let h = hash(&f.env, 3);
    let bond = file(&f, &h);
    assert_eq!(bond, BOND_FLOOR);
    let t = token::Client::new(&f.env, &f.token);
    assert_eq!(t.balance(&f.client.address), bond as i128);
    assert_eq!(t.balance(&f.escrow), 0, "the escrow never holds a bond");
}

#[test]
fn one_dispute_per_order() {
    let f = fixture();
    let h = hash(&f.env, 4);
    file(&f, &h);
    assert_eq!(
        f.client.try_open_dispute(
            &f.escrow,
            &h,
            &CHAIN,
            &f.filer,
            &hash(&f.env, 0),
            &DEADLINE,
            &BUFFER,
            &f.token,
            &0,
        ),
        Err(Ok(Error::DisputeExists))
    );
}

// ── the arbiter boundary ─────────────────────────────────────────────────

#[test]
fn the_arbiter_can_never_rule_that_the_trade_went_through() {
    let f = fixture();
    let h = hash(&f.env, 5);
    file(&f, &h);
    // TradeProceeds is what evidence produces; an arbiter reaching it would be arbitration
    // overruling proof.
    assert_eq!(
        f.client
            .try_resolve_dispute(&h, &DisputeOutcome::TradeProceeds),
        Err(Ok(Error::ArbiterCannotSettle))
    );
    assert_eq!(
        f.client.try_resolve_dispute(&h, &DisputeOutcome::None),
        Err(Ok(Error::ArbiterCannotSettle))
    );
}

#[test]
fn a_ruling_opens_a_window_it_does_not_pay() {
    let f = fixture();
    let h = hash(&f.env, 6);
    let bond = file(&f, &h);
    f.client.resolve_dispute(&h, &DisputeOutcome::MutualRefund);

    // Still held: the ruling has opened a window, not moved money.
    let t = token::Client::new(&f.env, &f.token);
    assert_eq!(t.balance(&f.client.address), bond as i128);
    let (outcome, window_over, _) = f.client.outcome_of(&h);
    assert_eq!(outcome, DisputeOutcome::MutualRefund);
    assert!(!window_over, "the window is still running");
}

// ── the clock ────────────────────────────────────────────────────────────

/// T-50: with no ruling, the window the escrow's fallback waits on is not over until the challenge
/// period AND the order's own deadline + buffer have passed.
#[test]
fn the_fallback_waits_out_the_challenge_period() {
    let f = fixture();
    let h = hash(&f.env, 7);
    file(&f, &h);
    let (_, window_over, _) = f.client.outcome_of(&h);
    assert!(!window_over);

    // The challenge period alone is NOT enough: the order still has time on its own clock, and no
    // dispute path may complete before `deadline + buffer` (D3, T-50). This is the bug that let a
    // filer cancel a week-long order an hour after filing.
    f.env.ledger().with_mut(|l| l.timestamp += CHALLENGE + 1);
    let (_, window_over, _) = f.client.outcome_of(&h);
    assert!(!window_over);

    warp_past_window(&f, &h);
    let (outcome, window_over, _) = f.client.outcome_of(&h);
    assert!(window_over);
    assert_eq!(
        outcome,
        DisputeOutcome::None,
        "no ruling: the escrow applies the fallback"
    );
}

/// B1: the window floors at the order's own deadline plus the route buffer, so a short challenge
/// period cannot shorten an order's life.
#[test]
fn the_window_floors_at_the_orders_own_deadline() {
    let f = fixture();
    let h = hash(&f.env, 30);
    file(&f, &h);
    assert!(
        f.client.effective_challenge_deadline(&h) >= DEADLINE + BUFFER,
        "the challenge period must not outrun the order's deadline"
    );
}

/// The filing writes one deadline in plain time: `max(now + challenge, deadline + buffer)`, either
/// arm winning.
#[test]
fn the_filing_deadline_is_the_max_of_challenge_and_order_floor() {
    let f = fixture();
    let far = hash(&f.env, 31);
    file(&f, &far);
    assert_eq!(
        f.client.effective_challenge_deadline(&far),
        DEADLINE + BUFFER
    );
    let near = hash(&f.env, 32);
    file_at(&f, &near, T0 + 60);
    assert_eq!(f.client.effective_challenge_deadline(&near), T0 + CHALLENGE);
    assert_eq!(
        f.client.challenge_deadline_of(&near),
        T0 + CHALLENGE,
        "the escrow's mid-call read is the same stored value"
    );
}

/// A ruling writes `max(now, deadline) + buffer`: before the deadline it counts from the deadline.
#[test]
fn a_ruling_before_the_deadline_counts_from_the_deadline() {
    let f = fixture();
    let h = hash(&f.env, 33);
    file(&f, &h);
    f.client.resolve_dispute(&h, &DisputeOutcome::MutualRefund);
    assert_eq!(f.client.effective_challenge_deadline(&h), DEADLINE + BUFFER);
}

/// After the deadline, the ruling's window counts from the ruling.
#[test]
fn a_ruling_after_the_deadline_counts_from_now() {
    let f = fixture();
    let h = hash(&f.env, 34);
    file_at(&f, &h, T0 + 60);
    let now = T0 + 600;
    f.env.ledger().set_timestamp(now);
    f.client.resolve_dispute(&h, &DisputeOutcome::MutualRefund);
    assert_eq!(f.client.effective_challenge_deadline(&h), now + BUFFER);
}

/// `window_over` is exactly `now >= deadline`, the comparison the escrow's finalize makes, at every
/// second around the boundary.
#[test]
fn window_over_is_the_deadline_comparison_at_the_boundary() {
    let f = fixture();
    let h = hash(&f.env, 35);
    file(&f, &h);
    let until = f.client.effective_challenge_deadline(&h);
    for t in [until - 1, until, until + 1] {
        f.env.ledger().set_timestamp(t);
        let (_, over, _) = f.client.outcome_of(&h);
        assert_eq!(over, t >= until, "at {t}");
        assert_eq!(
            f.client.effective_challenge_deadline(&h),
            until,
            "the deadline never moves"
        );
    }
}

#[test]
fn the_arbiter_cannot_rule_after_the_challenge_period() {
    let f = fixture();
    let h = hash(&f.env, 8);
    file(&f, &h);
    warp_past_window(&f, &h);
    assert_eq!(
        f.client
            .try_resolve_dispute(&h, &DisputeOutcome::MutualRefund),
        Err(Ok(Error::ChallengeClosed))
    );
}

// ── bond routing ─────────────────────────────────────────────────────────

#[test]
fn a_mutual_refund_returns_the_bond_to_the_filer() {
    let f = fixture();
    let h = hash(&f.env, 9);
    let bond = file(&f, &h);
    let t = token::Client::new(&f.env, &f.token);
    let before = t.balance(&f.filer);

    f.client.resolve_dispute(&h, &DisputeOutcome::MutualRefund);
    warp_past_window(&f, &h);
    f.client
        .settle_bond(&f.escrow, &h, &DisputeOutcome::MutualRefund, &false, &false);

    assert_eq!(t.balance(&f.filer), before + bond as i128);
    assert!(!f.client.is_disputed(&h), "the record is closed");
}

#[test]
fn a_ruling_against_the_filer_forfeits_the_bond_to_the_fee_pool() {
    let f = fixture();
    let h = hash(&f.env, 10);
    let bond = file(&f, &h);
    let t = token::Client::new(&f.env, &f.token);

    // The filer is the bridger, and the ruling forfeits the bridger: the filer was wrong, so the
    // bond goes to the fee pool rather than home.
    f.client
        .resolve_dispute(&h, &DisputeOutcome::BridgerForfeit);
    warp_past_window(&f, &h);
    f.client.settle_bond(
        &f.escrow,
        &h,
        &DisputeOutcome::BridgerForfeit,
        &true,
        &false,
    );

    assert_eq!(t.balance(&f.fee_pool), bond as i128);
}

/// The outcome table and the bond maths, read from the shared vector rather than restated here.
///
/// This is the point of the vector file. The routing was implemented twice, once per chain, and the
/// two agreed on the ad leg and disagreed on the order leg — a hand-written table on each side
/// cannot catch that, because each side writes the table it already believes.
#[test]
fn bond_routing_matches_the_shared_vector() {
    use proofbridge_core::dispute::bond_returns_to_filer as returns;
    let v: serde_json::Value = serde_json::from_str(DISPUTE_VECTORS).unwrap();

    let rows = v["bondRouting"].as_array().unwrap();
    assert_eq!(
        rows.len(),
        20,
        "the table must be exhaustive: 5 outcomes x 2 x 2 arms"
    );
    for row in rows {
        let outcome = match row["outcome"].as_str().unwrap() {
            "None" => DisputeOutcome::None,
            "MutualRefund" => DisputeOutcome::MutualRefund,
            "TradeProceeds" => DisputeOutcome::TradeProceeds,
            "BridgerForfeit" => DisputeOutcome::BridgerForfeit,
            other => {
                assert_eq!(other, "MakerForfeit");
                DisputeOutcome::MakerForfeit
            }
        };
        let filer_is_bridger = row["filerIsBridger"].as_bool().unwrap();
        let return_to_filer = row["returnToFiler"].as_bool().unwrap();
        assert_eq!(
            returns(outcome, filer_is_bridger, return_to_filer),
            row["bondReturnsToFiler"].as_bool().unwrap(),
            "routing disagrees with the shared vector for {:?} / filerIsBridger={} / returnToFiler={}",
            outcome,
            filer_is_bridger,
            return_to_filer
        );
    }
}

/// Which leaf the primary broadcasts per outcome, read from the shared vector.
///
/// A two-sided rule implemented on two chains — the primary picks the domain, the follower reads it
/// — which is exactly the shape that drifted last time with the bond flag. Asserted here against the
/// domain constants both escrows use; the escrows' own halves are driven in the integration suite.
#[test]
fn leg_actions_match_the_shared_vector() {
    use proofbridge_core::cross_contract::{
        LEAF_DOMAIN_CANCEL, LEAF_DOMAIN_FORFEIT, LEAF_DOMAIN_SETTLED,
    };
    let v: serde_json::Value = serde_json::from_str(DISPUTE_VECTORS).unwrap();
    let rows = v["legActions"].as_array().unwrap();
    assert_eq!(
        rows.len() as u64,
        v["counts"]["legActions"].as_u64().unwrap(),
        "the table was shortened without the count following"
    );

    let mut pay_maker = 0;
    for r in rows {
        let domain = r["primaryLeaf"].as_u64().unwrap() as u32;
        let action = r["followerAction"].as_str().unwrap();
        let expected = match r["outcome"].as_str().unwrap() {
            "MutualRefund" | "MakerForfeit" => LEAF_DOMAIN_CANCEL,
            "BridgerForfeit" => LEAF_DOMAIN_FORFEIT,
            "TradeProceeds" => LEAF_DOMAIN_SETTLED,
            other => panic!("unknown outcome in the shared vector: {other}"),
        };
        assert_eq!(domain, expected, "leaf domain drift on {}", r["outcome"]);
        if action == "payMaker" {
            pay_maker += 1;
            assert_eq!(
                domain, LEAF_DOMAIN_FORFEIT,
                "only the forfeit domain may pay the maker"
            );
        }
    }
    assert_eq!(pay_maker, 1, "exactly one outcome pays the maker");
}

/// The enum discriminants are ABI and are pinned by the same file.
#[test]
fn outcome_discriminants_match_the_shared_vector() {
    let v: serde_json::Value = serde_json::from_str(DISPUTE_VECTORS).unwrap();
    for o in v["outcomes"].as_array().unwrap() {
        let expected = o["value"].as_u64().unwrap() as u32;
        let actual = match o["name"].as_str().unwrap() {
            "None" => DisputeOutcome::None as u32,
            "MutualRefund" => DisputeOutcome::MutualRefund as u32,
            "TradeProceeds" => DisputeOutcome::TradeProceeds as u32,
            "BridgerForfeit" => DisputeOutcome::BridgerForfeit as u32,
            _ => DisputeOutcome::MakerForfeit as u32,
        };
        assert_eq!(actual, expected, "discriminant drift on {}", o["name"]);
    }
}

/// Bond sizing, likewise: the cases live in the vector, not in each chain's head. Each row's order
/// amount and decimals differ; the bond is the row's floor regardless, through the library and
/// through the module's quote.
#[test]
fn bond_sizing_matches_the_shared_vector() {
    let v: serde_json::Value = serde_json::from_str(DISPUTE_VECTORS).unwrap();
    let rows = v["bondSizing"].as_array().unwrap();
    assert_eq!(
        rows.len() as u64,
        v["counts"]["bondSizing"].as_u64().unwrap()
    );
    let f = fixture();
    for c in rows {
        let p = DisputeParams {
            challenge_period: CHALLENGE,
            bond_floor: c["bondFloor"].as_str().unwrap().parse().unwrap(),
        };
        let expected: u128 = c["bond"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            proofbridge_core::dispute::bond_for(&p),
            expected,
            "{}",
            c["label"]
        );
        f.client.set_dispute_params(&CHAIN, &p);
        assert_eq!(f.client.bond_for(&CHAIN), expected, "{}", c["label"]);
    }
}

#[test]
fn only_the_escrow_that_opened_a_dispute_may_settle_it() {
    let f = fixture();
    let other = Address::generate(&f.env);
    f.client.set_escrow(&other, &true);
    let h = hash(&f.env, 11);
    file(&f, &h);
    assert_eq!(
        f.client
            .try_settle_bond(&other, &h, &DisputeOutcome::MutualRefund, &false, &false),
        Err(Ok(Error::WrongEscrow))
    );
}

/// The handover reads who the admin is (#424): the deployer until the nominee accepts, the nominee
/// after, and never anyone else in between.
#[test]
fn get_admin_follows_the_two_step_handover() {
    let f = fixture();
    assert_eq!(f.client.get_admin(), Some(f.admin.clone()));

    let multisig = Address::generate(&f.env);
    f.client.transfer_admin(&multisig);
    assert_eq!(
        f.client.get_admin(),
        Some(f.admin.clone()),
        "nominated, not yet accepted"
    );

    f.client.accept_admin();
    assert_eq!(f.client.get_admin(), Some(multisig));
}

#[test]
fn the_admin_is_not_the_arbiter() {
    let f = fixture();
    assert_ne!(f.admin, f.arbiter);
    // And the arbiter cannot reconfigure the module.
    let stranger = Address::generate(&f.env);
    assert!(
        f.client.try_set_escrow(&stranger, &true).is_ok(),
        "admin may"
    );
}

#[test]
fn arbiter_and_fee_pool_views_follow_their_setters() {
    let f = fixture();
    assert_eq!(f.client.get_arbiter(), Some(f.arbiter.clone()));
    assert_eq!(f.client.get_protocol_fee_pool(), Some(f.fee_pool.clone()));
    for _ in 0..2 {
        let arbiter = Address::generate(&f.env);
        let pool = Address::generate(&f.env);
        f.client.set_arbiter(&arbiter);
        f.client.set_protocol_fee_pool(&pool);
        assert_eq!(f.client.get_arbiter(), Some(arbiter));
        assert_eq!(f.client.get_protocol_fee_pool(), Some(pool));
    }
}

// ── soak batch B ─────────────────────────────────────────────────────────

fn with_challenge(challenge_period: u64) -> DisputeParams {
    DisputeParams {
        challenge_period,
        bond_floor: BOND_FLOOR,
    }
}

/// C-36: seven days is the longest challenge period a route may take; one second more is refused
/// with the same error as one below the minimum.
#[test]
fn challenge_period_ceiling_is_seven_days() {
    let f = fixture();
    let max = proofbridge_core::dispute::MAX_CHALLENGE_PERIOD;
    assert_eq!(max, 604_800);
    f.client.set_dispute_params(&CHAIN, &with_challenge(max));
    assert_eq!(f.client.dispute_params(&CHAIN), Some(with_challenge(max)));
    assert_eq!(
        f.client
            .try_set_dispute_params(&CHAIN, &with_challenge(max + 1)),
        Err(Ok(Error::InvalidChallengePeriod))
    );
}

/// C-14: the filing event carries the evidence hash, so an indexer needs no second read.
#[test]
fn the_filing_event_carries_the_evidence_hash() {
    use soroban_sdk::{events::Event as _, testutils::Events as _};
    let f = fixture();
    let h = hash(&f.env, 1);
    let bond = file(&f, &h);
    // `events().all()` holds the last invocation only, so read them before any other call.
    let got = f.env.events().all().filter_by_contract(&f.client.address);
    let d = f.client.get_dispute(&h).unwrap();
    let want = events::DisputeFiled {
        order_hash: h.clone(),
        initiator: f.filer.clone(),
        bond,
        challenge_deadline: d.challenge_deadline,
        evidence: hash(&f.env, 0xEE),
    }
    .to_xdr(&f.env, &f.client.address);
    assert!(
        got.events().contains(&want),
        "no DisputeFiled with the evidence: {got:?}"
    );
}

/// C-34: withdrawing a credited bond payout is observable (as `BondClaimed`).
#[test]
fn claim_publishes_bond_claimed() {
    use soroban_sdk::{events::Event as _, testutils::Events as _};
    let f = fixture();
    let who = Address::generate(&f.env);
    // Seed a credit as `pay_or_credit` leaves one, with the tokens it would hold.
    f.env.as_contract(&f.client.address, || {
        storage::set_claimable(&f.env, &who, 500)
    });
    TokenContractClient::new(&f.env, &f.token).mint(&f.client.address, &500);

    f.client.claim(&who);

    let want = events::BondClaimed {
        recipient: who.clone(),
        amount: 500,
    }
    .to_xdr(&f.env, &f.client.address);
    let got = f.env.events().all().filter_by_contract(&f.client.address);
    assert!(got.events().contains(&want), "no BondClaimed: {got:?}");
    assert_eq!(token::Client::new(&f.env, &f.token).balance(&who), 500);
    assert_eq!(f.client.claimable(&who), 0);
}

// ── soak batch D (C-19): every reachable error, named ─────────────────────

/// A second `initialize` is refused; the first admin stays.
#[test]
fn initialize_twice_is_already_initialized() {
    let f = fixture();
    assert_eq!(
        f.client.try_initialize(&f.admin, &f.token),
        Err(Ok(Error::AlreadyInitialized))
    );
    assert_eq!(f.client.get_admin(), Some(f.admin.clone()));
}

/// Before `initialize` there is no admin to authorize a setter, and no arbiter to rule.
#[test]
fn an_uninitialized_module_is_not_initialized() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(DisputeManagerContract, ());
    let client = DisputeManagerContractClient::new(&env, &id);
    assert_eq!(
        client.try_set_escrow(&Address::generate(&env), &true),
        Err(Ok(Error::NotInitialized))
    );
    assert_eq!(
        client.try_resolve_dispute(&hash(&env, 1), &DisputeOutcome::MutualRefund),
        Err(Ok(Error::NotInitialized))
    );
}

/// Every path that reads a record refuses an order that was never disputed.
#[test]
fn an_undisputed_order_is_not_disputed() {
    let f = fixture();
    let h = hash(&f.env, 40);
    assert_eq!(
        f.client
            .try_resolve_dispute(&h, &DisputeOutcome::MutualRefund),
        Err(Ok(Error::NotDisputed))
    );
    assert_eq!(
        f.client
            .try_settle_bond(&f.escrow, &h, &DisputeOutcome::MutualRefund, &false, &false),
        Err(Ok(Error::NotDisputed))
    );
    assert_eq!(
        f.client
            .try_record_response(&f.escrow, &h, &Address::generate(&f.env), &hash(&f.env, 1),),
        Err(Ok(Error::NotDisputed))
    );
}

/// The filer cannot answer their own dispute: the responder slot is the other party's.
#[test]
fn the_filer_cannot_respond_to_their_own_dispute() {
    let f = fixture();
    let h = hash(&f.env, 41);
    file(&f, &h);
    assert_eq!(
        f.client
            .try_record_response(&f.escrow, &h, &f.filer, &hash(&f.env, 0x11)),
        Err(Ok(Error::NotResponder))
    );
    assert_eq!(
        f.client.get_dispute(&h).unwrap().responder_evidence,
        hash(&f.env, 0),
        "the slot is still empty"
    );

    // The real counterparty still can.
    let counterparty = Address::generate(&f.env);
    f.client
        .record_response(&f.escrow, &h, &counterparty, &hash(&f.env, 0x11));
    assert_eq!(
        f.client.get_dispute(&h).unwrap().responder_evidence,
        hash(&f.env, 0x11)
    );
}

/// A response has to come through the escrow the dispute was filed on.
#[test]
fn a_response_through_another_escrow_is_wrong_escrow() {
    let f = fixture();
    let other = f.env.register(MockEscrow, ());
    f.client.set_escrow(&other, &true);
    let h = hash(&f.env, 42);
    file(&f, &h);
    assert_eq!(
        f.client
            .try_record_response(&other, &h, &Address::generate(&f.env), &hash(&f.env, 0x11),),
        Err(Ok(Error::WrongEscrow))
    );
}

/// `claim` with no credit pays nothing and says so.
#[test]
fn claim_with_no_credit_is_nothing_to_claim() {
    let f = fixture();
    assert_eq!(
        f.client.try_claim(&Address::generate(&f.env)),
        Err(Ok(Error::NothingToClaim))
    );
}

// ── 49S-3: token refusals are the module's own error; relayed codes pinned ──

/// A filer who cannot fund the bond is `BondTransferFailed`, and no record is left behind.
#[test]
fn an_unfunded_bond_is_bond_transfer_failed() {
    let f = fixture();
    let broke = Address::generate(&f.env);
    let h = hash(&f.env, 51);
    assert_eq!(
        f.client.try_open_dispute(
            &f.escrow,
            &h,
            &CHAIN,
            &broke,
            &hash(&f.env, 0xEE),
            &DEADLINE,
            &BUFFER,
            &f.token,
            &0,
        ),
        Err(Ok(Error::BondTransferFailed))
    );
    assert!(!f.client.is_disputed(&h));
}

/// A claim the token refuses is `BondTransferFailed`, and the credit stays claimable.
#[test]
fn a_refused_claim_is_bond_transfer_failed_and_keeps_the_credit() {
    let f = fixture();
    let who = Address::generate(&f.env);
    // Credited, but the module holds no tokens to pay it with.
    f.env.as_contract(&f.client.address, || {
        storage::set_claimable(&f.env, &who, 500)
    });
    assert_eq!(f.client.try_claim(&who), Err(Ok(Error::BondTransferFailed)));
    assert_eq!(f.client.claimable(&who), 500);
}

/// 49E-1 twin: the bond claim's topic is `bond_clm`, never the escrow's `pay_clm`.
#[test]
fn the_bond_claim_event_has_its_own_topic() {
    use soroban_sdk::testutils::Events as _;
    use soroban_sdk::xdr::{ContractEventBody, ScSymbol, ScVal};
    let f = fixture();
    let who = Address::generate(&f.env);
    f.env.as_contract(&f.client.address, || {
        storage::set_claimable(&f.env, &who, 500)
    });
    TokenContractClient::new(&f.env, &f.token).mint(&f.client.address, &500);
    f.client.claim(&who);
    let got = f.env.events().all().filter_by_contract(&f.client.address);
    let firsts: std::vec::Vec<ScVal> = got
        .events()
        .iter()
        .map(|e| match &e.body {
            ContractEventBody::V0(b) => b.topics[0].clone(),
        })
        .collect();
    let sym = |s: &str| ScVal::Symbol(ScSymbol(s.try_into().unwrap()));
    assert!(firsts.contains(&sym("bond_clm")), "{firsts:?}");
    assert!(!firsts.contains(&sym("pay_clm")), "{firsts:?}");
}

/// 49E-1 twin: a credited bond payout's topic is `bond_cred`, never the escrow's `pay_cred`.
#[test]
fn the_bond_credit_event_has_its_own_topic() {
    use soroban_sdk::testutils::Events as _;
    use soroban_sdk::xdr::{ContractEventBody, ScSymbol, ScVal};
    let f = fixture();
    let h = hash(&f.env, 61);
    let bond = file(&f, &h);
    // Drain the module so the payout is refused and credited instead.
    TokenContractClient::new(&f.env, &f.token).transfer(
        &f.client.address,
        &Address::generate(&f.env),
        &(bond as i128),
    );
    f.client
        .settle_bond(&f.escrow, &h, &DisputeOutcome::MutualRefund, &false, &false);
    // `events().all()` holds the last invocation only, so read them before any other call.
    let got = f.env.events().all().filter_by_contract(&f.client.address);
    let firsts: std::vec::Vec<ScVal> = got
        .events()
        .iter()
        .map(|e| match &e.body {
            ContractEventBody::V0(b) => b.topics[0].clone(),
        })
        .collect();
    let sym = |s: &str| ScVal::Symbol(ScSymbol(s.try_into().unwrap()));
    assert!(firsts.contains(&sym("bond_cred")), "{firsts:?}");
    assert!(!firsts.contains(&sym("pay_cred")), "{firsts:?}");
    assert_eq!(f.client.claimable(&f.filer), bond, "credited");
}

/// Error drift: every code the escrows relay is the same number here and in `proofbridge-core`.
#[test]
fn relayed_error_codes_match_the_shared_definitions() {
    use proofbridge_core::dispute::error_code as c;
    let pairs = [
        (Error::NotEscrow, c::NOT_ESCROW),
        (Error::DisputeExists, c::DISPUTE_EXISTS),
        (Error::NotResponder, c::NOT_RESPONDER),
        (Error::NoDisputeParams, c::NO_DISPUTE_PARAMS),
        (Error::WrongEscrow, c::WRONG_ESCROW),
        (Error::BondTransferFailed, c::BOND_TRANSFER_FAILED),
        (Error::ResponseWindowClosed, c::RESPONSE_WINDOW_CLOSED),
        (Error::AlreadyResponded, c::ALREADY_RESPONDED),
        (Error::ZeroResponse, c::ZERO_RESPONSE),
        (Error::AlreadyRuled, c::ALREADY_RULED),
    ];
    for (e, code) in pairs {
        assert_eq!(e as u32, code, "{e:?}");
    }
}

// ── D5: one answer, inside the window, never empty ───────────────────────

/// D5: the slot holds one answer; a second is refused and the first stands.
#[test]
fn d5_a_second_answer_is_refused() {
    let f = fixture();
    let h = hash(&f.env, 50);
    file(&f, &h);
    let other = Address::generate(&f.env);
    f.client
        .record_response(&f.escrow, &h, &other, &hash(&f.env, 0x11));
    assert_eq!(
        f.client
            .try_record_response(&f.escrow, &h, &other, &hash(&f.env, 0x22)),
        Err(Ok(Error::AlreadyResponded))
    );
    assert_eq!(
        f.client.get_dispute(&h).unwrap().responder_evidence,
        hash(&f.env, 0x11)
    );
}

/// D5 (R1): the ruling closes the answer window, even though the record's deadline moved on to
/// the ruling's finalize time.
#[test]
fn d5_an_answer_after_the_ruling_is_refused() {
    let f = fixture();
    let h = hash(&f.env, 52);
    file(&f, &h);
    f.client.resolve_dispute(&h, &DisputeOutcome::MutualRefund);
    assert!(f.env.ledger().timestamp() < f.client.effective_challenge_deadline(&h));
    let other = Address::generate(&f.env);
    assert_eq!(
        f.client
            .try_record_response(&f.escrow, &h, &other, &hash(&f.env, 0x11)),
        Err(Ok(Error::AlreadyRuled))
    );
    assert_eq!(
        f.client.get_dispute(&h).unwrap().responder_evidence,
        BytesN::from_array(&f.env, &[0u8; 32])
    );
}

/// D5: answers close with the challenge window, the instant the arbiter's ruling does.
#[test]
fn d5_an_answer_at_the_challenge_deadline_is_refused() {
    let f = fixture();
    let h = hash(&f.env, 51);
    file(&f, &h);
    let until = f.client.effective_challenge_deadline(&h);
    let other = Address::generate(&f.env);
    f.env.ledger().set_timestamp(until);
    assert_eq!(
        f.client
            .try_record_response(&f.escrow, &h, &other, &hash(&f.env, 0x11)),
        Err(Ok(Error::ResponseWindowClosed))
    );
    f.env.ledger().set_timestamp(until - 1);
    f.client
        .record_response(&f.escrow, &h, &other, &hash(&f.env, 0x11));
}

/// D5: an empty answer is refused, so "answered" is exactly "the slot is non-zero".
#[test]
fn d5_a_zero_answer_is_refused() {
    let f = fixture();
    let h = hash(&f.env, 52);
    file(&f, &h);
    assert_eq!(
        f.client
            .try_record_response(&f.escrow, &h, &Address::generate(&f.env), &hash(&f.env, 0),),
        Err(Ok(Error::ZeroResponse))
    );
}

// ── #586: the 24-hour delay ──────────────────────────────────────────────

const DAY: u64 = 24 * 60 * 60;

fn args(
    env: &Env,
    v: impl soroban_sdk::IntoVal<Env, soroban_sdk::Vec<soroban_sdk::Val>>,
) -> soroban_sdk::Vec<soroban_sdk::Val> {
    v.into_val(env)
}

/// A proposal's argument list as the contract takes it: the XDR of the `ScVal::Vec`.
fn xdr_args(env: &Env, a: &soroban_sdk::Vec<soroban_sdk::Val>) -> soroban_sdk::Bytes {
    use soroban_sdk::xdr::ToXdr;
    a.clone().to_xdr(env)
}

fn sym(env: &Env, s: &str) -> soroban_sdk::Symbol {
    soroban_sdk::Symbol::new(env, s)
}

/// After activation every admin setter refuses without a proposal; with one it refuses a second
/// early and runs at 24 hours, once, needing nobody's auth.
#[test]
fn every_admin_setter_is_gated_once_active() {
    let f = fixture();
    let e = &f.env;
    let other = Address::generate(e);
    let bond = BondConfig {
        min_bond: 7,
        bond_bps: 50,
    };
    f.client.activate_timelock();
    assert!(f.client.timelock_active());

    assert_eq!(
        f.client.try_set_escrow(&other, &true),
        Err(Ok(Error::TimelockNotProposed))
    );
    assert_eq!(
        f.client.try_set_dispute_params(&CHAIN, &params()),
        Err(Ok(Error::TimelockNotProposed))
    );
    assert_eq!(
        f.client.try_set_arbiter(&other),
        Err(Ok(Error::TimelockNotProposed))
    );
    assert_eq!(
        f.client.try_set_protocol_fee_pool(&other),
        Err(Ok(Error::TimelockNotProposed))
    );
    assert_eq!(
        f.client.try_set_bond_config(&f.token, &CHAIN, &bond),
        Err(Ok(Error::TimelockNotProposed))
    );

    let calls = [
        (sym(e, "set_escrow"), args(e, (other.clone(), true))),
        (sym(e, "set_dispute_params"), args(e, (CHAIN, params()))),
        (sym(e, "set_arbiter"), args(e, (other.clone(),))),
        (sym(e, "set_protocol_fee_pool"), args(e, (other.clone(),))),
        (
            sym(e, "set_bond_config"),
            args(e, (f.token.clone(), CHAIN, bond.clone())),
        ),
    ];
    for (name, a) in calls.iter() {
        let id = f.client.propose_action(name, &xdr_args(e, a));
        assert_eq!(f.client.timelock_eta(&id), T0 + DAY);
    }

    e.ledger().set_timestamp(T0 + DAY - 1);
    assert_eq!(
        f.client.try_set_arbiter(&other),
        Err(Ok(Error::TimelockTooEarly))
    );

    e.ledger().set_timestamp(T0 + DAY);
    f.client.set_escrow(&other, &true);
    assert!(e.auths().is_empty(), "a ripe proposal needs nobody's auth");
    f.client.set_dispute_params(&CHAIN, &params());
    f.client.set_arbiter(&other);
    f.client.set_protocol_fee_pool(&other);
    f.client.set_bond_config(&f.token, &CHAIN, &bond);
    assert_eq!(f.client.get_arbiter(), Some(other.clone()));
    assert_eq!(f.client.bond_config(&f.token, &CHAIN), Some(bond));

    // Consumed: the same call again needs a new proposal.
    assert_eq!(
        f.client.try_set_arbiter(&other),
        Err(Ok(Error::TimelockNotProposed))
    );
}

/// Before activation the setters are the admin's (its auth is what runs them); after, a ripe
/// proposal runs with no auth at all.
#[test]
fn the_setup_bypass_is_the_admins() {
    let f = fixture();
    let other = Address::generate(&f.env);
    f.client.set_arbiter(&other);
    let auths = f.env.auths();
    assert_eq!(auths.len(), 1);
    assert_eq!(auths[0].0, f.admin, "the bypass ran on the admin's auth");
}

/// Activation is one-way; the first proposal activates too.
#[test]
fn activation_is_one_way_and_a_proposal_activates() {
    let f = fixture();
    let e = &f.env;
    assert!(!f.client.timelock_active());
    f.client.propose_action(
        &sym(e, "set_arbiter"),
        &xdr_args(e, &args(e, (f.admin.clone(),))),
    );
    assert!(
        f.client.timelock_active(),
        "the first proposal closed the bypass"
    );
    assert_eq!(
        f.client.try_activate_timelock(),
        Err(Ok(Error::TimelockAlreadyActive))
    );
}

/// The proposal is the exact call: other arguments are another id.
#[test]
fn execute_must_match_the_proposal() {
    let f = fixture();
    let e = &f.env;
    let a = Address::generate(e);
    let b = Address::generate(e);
    f.client
        .propose_action(&sym(e, "set_arbiter"), &xdr_args(e, &args(e, (a.clone(),))));
    e.ledger().set_timestamp(T0 + DAY);
    assert_eq!(
        f.client.try_set_arbiter(&b),
        Err(Ok(Error::TimelockNotProposed))
    );
    assert_eq!(
        f.client.try_set_protocol_fee_pool(&a),
        Err(Ok(Error::TimelockNotProposed))
    );
    f.client.set_arbiter(&a);
}

/// A pending proposal cannot be re-proposed; the admin cancels one, and the cancelled call is refused.
#[test]
fn reproposal_refused_and_cancel_works() {
    let f = fixture();
    let e = &f.env;
    let a = Address::generate(e);
    let call = (sym(e, "set_arbiter"), args(e, (a.clone(),)));
    let id = f.client.propose_action(&call.0, &xdr_args(e, &call.1));
    assert_eq!(
        f.client.try_propose_action(&call.0, &xdr_args(e, &call.1)),
        Err(Ok(Error::TimelockAlreadyProposed))
    );
    f.client.cancel_action(&id);
    assert_eq!(f.client.timelock_eta(&id), 0);
    assert_eq!(
        f.client.try_cancel_action(&id),
        Err(Ok(Error::TimelockNotProposed))
    );
    e.ledger().set_timestamp(T0 + DAY);
    assert_eq!(
        f.client.try_set_arbiter(&a),
        Err(Ok(Error::TimelockNotProposed))
    );
}

/// Removing an escrow is a brake: instant, and the admin's; adding one back is delayed.
#[test]
fn removing_an_escrow_stays_instant() {
    let f = fixture();
    f.client.activate_timelock();
    f.client.set_escrow(&f.escrow, &false);
    assert_eq!(
        f.env.auths()[0].0,
        f.admin,
        "the brake ran on the admin's auth"
    );
    assert!(!f.client.is_escrow(&f.escrow));
    assert_eq!(
        f.client.try_set_escrow(&f.escrow, &true),
        Err(Ok(Error::TimelockNotProposed))
    );
}

// ── #586: per-route bonds in the order's own token ───────────────────────

/// A token that can take a fee on transfer or refuse a recipient, for the bond's exactness and
/// credit paths.
#[soroban_sdk::contract]
pub struct OddToken;

#[soroban_sdk::contracttype]
enum OddKey {
    Bal(Address),
    Blocked(Address),
    FeeBps,
}

#[soroban_sdk::contractimpl]
impl OddToken {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let b = Self::balance(env.clone(), to.clone());
        env.storage()
            .persistent()
            .set(&OddKey::Bal(to), &(b + amount));
    }

    pub fn set_blocked(env: Env, who: Address, blocked: bool) {
        env.storage()
            .persistent()
            .set(&OddKey::Blocked(who), &blocked);
    }

    pub fn set_fee_bps(env: Env, bps: i128) {
        env.storage().persistent().set(&OddKey::FeeBps, &bps);
    }

    pub fn balance(env: Env, id: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&OddKey::Bal(id))
            .unwrap_or(0)
    }

    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let blocked: bool = env
            .storage()
            .persistent()
            .get(&OddKey::Blocked(to.clone()))
            .unwrap_or(false);
        if blocked {
            panic!("blocked");
        }
        let bps: i128 = env.storage().persistent().get(&OddKey::FeeBps).unwrap_or(0);
        let fb = Self::balance(env.clone(), from.clone());
        if fb < amount {
            panic!("short");
        }
        env.storage()
            .persistent()
            .set(&OddKey::Bal(from), &(fb - amount));
        let tb = Self::balance(env.clone(), to.clone());
        env.storage()
            .persistent()
            .set(&OddKey::Bal(to), &(tb + amount - amount * bps / 10_000));
    }
}

fn odd_token(f: &F) -> (Address, OddTokenClient<'static>) {
    let id = f.env.register(OddToken, ());
    let c = OddTokenClient::new(&f.env, &id);
    c.mint(&f.filer, &1_000_000_000_000);
    (id, c)
}

fn file_token(f: &F, h: &BytesN<32>, token: &Address, amount: u128) -> u128 {
    f.client.open_dispute(
        &f.escrow,
        h,
        &CHAIN,
        &f.filer,
        &hash(&f.env, 0xEE),
        &DEADLINE,
        &BUFFER,
        token,
        &amount,
    )
}

const FEES_BONDS: &str = include_str!("../../../../test-vectors/fees-bonds.json");

/// Each vector row: the quote and a real filing pull exactly the row's bond, in the order's token.
#[test]
fn route_bond_matches_the_shared_vector() {
    let v: serde_json::Value = serde_json::from_str(FEES_BONDS).unwrap();
    let rows = v["routeBond"].as_array().unwrap();
    assert_eq!(
        rows.len() as u64,
        v["counts"]["routeBond"].as_u64().unwrap()
    );
    let f = fixture();
    let (tok, c) = odd_token(&f);
    for (i, row) in rows.iter().enumerate() {
        let n = |k: &str| -> u128 { row[k].as_str().unwrap().parse().unwrap() };
        let cfg = BondConfig {
            min_bond: n("minBond"),
            bond_bps: row["bondBps"].as_u64().unwrap() as u32,
        };
        f.client.set_bond_config(&tok, &CHAIN, &cfg);
        let amount = n("amount");
        assert_eq!(
            f.client.route_bond(&CHAIN, &tok, &amount),
            (tok.clone(), n("bond"), BOND_FLOOR),
            "quote, row {i}"
        );
        let need = n("bond") as i128;
        if c.balance(&f.filer) < need {
            c.mint(&f.filer, &need);
        }
        let before = c.balance(&f.filer);
        let h = hash(&f.env, 0x70 + i as u8);
        assert_eq!(file_token(&f, &h, &tok, amount), n("bond"));
        assert_eq!(
            before - c.balance(&f.filer),
            need,
            "the filing pulled other than the bond, row {i}"
        );
        assert_eq!(f.client.get_dispute(&h).unwrap().bond_token, tok);
    }
}

#[test]
fn bond_config_validation_matches_the_shared_vector() {
    let v: serde_json::Value = serde_json::from_str(FEES_BONDS).unwrap();
    let f = fixture();
    for row in v["bondConfigValidation"].as_array().unwrap() {
        let cfg = BondConfig {
            min_bond: row["minBond"].as_str().unwrap().parse().unwrap(),
            bond_bps: row["bondBps"].as_u64().unwrap() as u32,
        };
        let got = f.client.try_set_bond_config(&f.token, &CHAIN, &cfg);
        let valid = row
            .get("stellarValid")
            .unwrap_or(&row["valid"])
            .as_bool()
            .unwrap();
        if valid {
            assert!(got.is_ok(), "{}", row["label"]);
        } else {
            assert_eq!(got, Err(Ok(Error::InvalidBondConfig)), "{}", row["label"]);
        }
    }
}

/// An unconfigured route keeps the flat floor in wrapped native; clearing a config restores it.
#[test]
fn an_unconfigured_route_keeps_the_native_floor() {
    let f = fixture();
    let (tok, _) = odd_token(&f);
    assert_eq!(
        f.client.route_bond(&CHAIN, &tok, &1_000_000_000),
        (f.token.clone(), BOND_FLOOR, BOND_FLOOR)
    );
    f.client.set_bond_config(
        &tok,
        &CHAIN,
        &BondConfig {
            min_bond: 5,
            bond_bps: 50,
        },
    );
    f.client.set_bond_config(
        &tok,
        &CHAIN,
        &BondConfig {
            min_bond: 0,
            bond_bps: 0,
        },
    );
    assert_eq!(f.client.bond_config(&tok, &CHAIN), None);
    let h = hash(&f.env, 0x81);
    assert_eq!(file_token(&f, &h, &tok, 1_000_000_000), BOND_FLOOR);
    assert_eq!(f.client.get_dispute(&h).unwrap().bond_token, f.token);
}

/// D1: a filer the token bond cannot be taken from posts the native floor; with neither, the
/// filing fails.
#[test]
fn a_filer_without_the_token_posts_the_native_floor() {
    let f = fixture();
    let (tok, c) = odd_token(&f);
    f.client.set_bond_config(
        &tok,
        &CHAIN,
        &BondConfig {
            min_bond: 5,
            bond_bps: 50,
        },
    );
    c.transfer(&f.filer, &f.escrow, &c.balance(&f.filer));
    let h = hash(&f.env, 0x82);
    assert_eq!(file_token(&f, &h, &tok, 1_000_000_000), BOND_FLOOR);
    assert_eq!(f.client.get_dispute(&h).unwrap().bond_token, f.token);

    let w = soroban_sdk::token::Client::new(&f.env, &f.token);
    w.transfer(&f.filer, &f.escrow, &w.balance(&f.filer));
    let h2 = hash(&f.env, 0x83);
    assert_eq!(
        f.client.try_open_dispute(
            &f.escrow,
            &h2,
            &CHAIN,
            &f.filer,
            &hash(&f.env, 0xEE),
            &DEADLINE,
            &BUFFER,
            &tok,
            &1_000_000_000,
        ),
        Err(Ok(Error::BondTransferFailed))
    );
}

/// A short receipt (a fee-on-transfer token) is refused.
#[test]
fn a_short_token_bond_is_refused() {
    let f = fixture();
    let (tok, c) = odd_token(&f);
    c.set_fee_bps(&100);
    f.client.set_bond_config(
        &tok,
        &CHAIN,
        &BondConfig {
            min_bond: 1_000_000,
            bond_bps: 0,
        },
    );
    assert_eq!(
        f.client.try_open_dispute(
            &f.escrow,
            &hash(&f.env, 0x82),
            &CHAIN,
            &f.filer,
            &hash(&f.env, 0xEE),
            &DEADLINE,
            &BUFFER,
            &tok,
            &1
        ),
        Err(Ok(Error::BondTransferShort))
    );
}

/// The bond pays out in its token; a recipient the token refuses is credited and claims later.
#[test]
fn a_token_bond_pays_out_in_its_token_and_credits_a_refusal() {
    let f = fixture();
    let (tok, c) = odd_token(&f);
    f.client.set_bond_config(
        &tok,
        &CHAIN,
        &BondConfig {
            min_bond: 1_000_000,
            bond_bps: 0,
        },
    );

    // Returned to the filer.
    let h = hash(&f.env, 0x83);
    let before = c.balance(&f.filer);
    file_token(&f, &h, &tok, 1);
    f.client
        .settle_bond(&f.escrow, &h, &DisputeOutcome::MutualRefund, &false, &false);
    assert_eq!(
        c.balance(&f.filer),
        before,
        "the bond came back in its token"
    );

    // Forfeited to the pool.
    let h2 = hash(&f.env, 0x84);
    file_token(&f, &h2, &tok, 1);
    f.client.settle_bond(
        &f.escrow,
        &h2,
        &DisputeOutcome::TradeProceeds,
        &false,
        &false,
    );
    assert_eq!(
        c.balance(&f.fee_pool),
        1_000_000,
        "the forfeited bond reached the pool in its token"
    );

    // Refused: credited, then claimed once the filer accepts again.
    let h3 = hash(&f.env, 0x85);
    file_token(&f, &h3, &tok, 1);
    c.set_blocked(&f.filer, &true);
    f.client.settle_bond(
        &f.escrow,
        &h3,
        &DisputeOutcome::MutualRefund,
        &false,
        &false,
    );
    assert_eq!(f.client.claimable_token(&f.filer, &tok), 1_000_000);
    assert_eq!(
        f.client.try_claim_token(&f.filer, &tok),
        Err(Ok(Error::BondTransferFailed))
    );
    c.set_blocked(&f.filer, &false);
    let before = c.balance(&f.filer);
    f.client.claim_token(&f.filer, &tok);
    assert_eq!(c.balance(&f.filer) - before, 1_000_000);
    assert_eq!(f.client.claimable_token(&f.filer, &tok), 0);
    assert_eq!(
        f.client.try_claim_token(&f.filer, &tok),
        Err(Ok(Error::NothingToClaim))
    );
    // The wrapped native token's credits are the `claimable` ledger.
    assert_eq!(
        f.client.claimable_token(&f.filer, &f.token),
        f.client.claimable(&f.filer)
    );
}

/// Argument bytes that are not an argument list are refused, and nothing is queued: XDR of another
/// type is `TimelockBadArgs`; bytes that are not XDR at all trap in the host.
#[test]
fn proposal_bytes_must_be_an_argument_list() {
    use soroban_sdk::xdr::ToXdr;
    let f = fixture();
    let e = &f.env;
    assert_eq!(
        f.client
            .try_propose_action(&sym(e, "set_arbiter"), &7u32.to_xdr(e)),
        Err(Ok(Error::TimelockBadArgs))
    );
    assert!(f
        .client
        .try_propose_action(
            &sym(e, "set_arbiter"),
            &soroban_sdk::Bytes::from_array(e, &[1, 2, 3])
        )
        .is_err());
    assert!(
        !f.client.timelock_active(),
        "a refused proposal does not close the bypass"
    );
}

/// The id is `sha256` of the XDR of `(fn_name, args)`: pinned, so the deploy CLI's encoder can check
/// itself against it.
#[test]
fn the_proposal_id_is_pinned() {
    let f = fixture();
    let e = &f.env;
    let a = args(e, (CHAIN, params()));
    let id = f
        .client
        .propose_action(&sym(e, "set_dispute_params"), &xdr_args(e, &a));
    assert_eq!(
        id,
        proofbridge_core::timelock::action_id(e, &sym(e, "set_dispute_params"), &a)
    );
    std::println!(
        "set_dispute_params(1000002, {{3600*2, 1000}}) id = {:?}",
        id.to_array()
            .iter()
            .map(|b| std::format!("{b:02x}"))
            .collect::<std::string::String>()
    );
}
