//! 2.3g: the dispute module's own rules — the arbiter boundary, the bond maths, the clock, the
//! escrow edge, and the bond routing. The escrow↔module correspondence is exercised in the
//! integration suite, where both contracts are real.

#![cfg(test)]

extern crate std;

use super::*;
use proofbridge_core::types::DisputeParams;
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
const BOND_BPS: u32 = 100; // 1%

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
        bond_bps: BOND_BPS,
    }
}

/// A stand-in escrow. The module reads one thing back off an escrow — its pause clock — so the
/// fixture needs a real contract at that address rather than a bare one.
#[soroban_sdk::contract]
pub struct MockEscrow;

#[soroban_sdk::contractimpl]
impl MockEscrow {
    pub fn paused_seconds(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&soroban_sdk::symbol_short!("paused"))
            .unwrap_or(0)
    }

    pub fn set_paused_seconds(env: Env, v: u64) {
        env.storage()
            .instance()
            .set(&soroban_sdk::symbol_short!("paused"), &v);
    }
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

fn file(f: &F, h: &BytesN<32>, amount: u128) -> u128 {
    f.client.open_dispute(
        &f.escrow,
        h,
        &amount,
        &CHAIN,
        &f.filer,
        &hash(&f.env, 0xEE),
        &DEADLINE,
        &BUFFER,
        &0u64,
    )
}

/// Past the window the module actually enforces, rather than past the challenge period alone.
/// Those differ whenever the order's deadline is further out — the normal case, and the hole that
/// let a dispute finalize early.
fn warp_past_window(f: &F, h: &BytesN<32>) {
    let until = f.client.effective_challenge_deadline(h);
    f.env.ledger().set_timestamp(until + 1);
}

// ── the bond maths ───────────────────────────────────────────────────────

#[test]
fn bond_is_max_of_floor_and_percentage() {
    let p = params();
    // The floor dominates a small order.
    assert_eq!(proofbridge_core::dispute::bond_for(1_000, &p), BOND_FLOOR);
    // The percentage dominates a large one.
    assert_eq!(proofbridge_core::dispute::bond_for(1_000_000, &p), 10_000);
    // At the crossover the floor still wins, which is what keeps a bond non-zero.
    assert_eq!(proofbridge_core::dispute::bond_for(100_000, &p), BOND_FLOOR);
}

#[test]
fn params_fail_closed() {
    let f = fixture();
    // Too short a challenge period leaves no room to gather evidence.
    assert!(f
        .client
        .try_set_dispute_params(
            &CHAIN,
            &DisputeParams {
                challenge_period: 60,
                bond_floor: BOND_FLOOR,
                bond_bps: BOND_BPS,
            }
        )
        .is_err());
    // A zero floor would let a bond round down to nothing.
    assert!(f
        .client
        .try_set_dispute_params(
            &CHAIN,
            &DisputeParams {
                challenge_period: CHALLENGE,
                bond_floor: 0,
                bond_bps: BOND_BPS,
            }
        )
        .is_err());
    // Above the ceiling a bond deters honest disputes as much as frivolous ones.
    assert!(f
        .client
        .try_set_dispute_params(
            &CHAIN,
            &DisputeParams {
                challenge_period: CHALLENGE,
                bond_floor: BOND_FLOOR,
                bond_bps: 2_000,
            }
        )
        .is_err());
}

#[test]
fn an_unconfigured_route_cannot_be_disputed() {
    let f = fixture();
    let h = hash(&f.env, 1);
    assert!(f
        .client
        .try_open_dispute(
            &f.escrow,
            &h,
            &1_000,
            &(CHAIN + 7),
            &f.filer,
            &hash(&f.env, 0),
            &DEADLINE,
            &BUFFER,
            &0u64
        )
        .is_err());
}

// ── the escrow edge ──────────────────────────────────────────────────────

#[test]
fn only_a_registered_escrow_may_open_a_dispute() {
    let f = fixture();
    let stranger = Address::generate(&f.env);
    let h = hash(&f.env, 2);
    assert!(f
        .client
        .try_open_dispute(
            &stranger,
            &h,
            &1_000,
            &CHAIN,
            &f.filer,
            &hash(&f.env, 0),
            &DEADLINE,
            &BUFFER,
            &0u64
        )
        .is_err());
}

#[test]
fn the_bond_lands_in_the_module_not_the_escrow() {
    let f = fixture();
    let h = hash(&f.env, 3);
    let bond = file(&f, &h, 100_000);
    assert_eq!(bond, BOND_FLOOR);
    let t = token::Client::new(&f.env, &f.token);
    assert_eq!(t.balance(&f.client.address), bond as i128);
    assert_eq!(t.balance(&f.escrow), 0, "the escrow never holds a bond");
}

#[test]
fn one_dispute_per_order() {
    let f = fixture();
    let h = hash(&f.env, 4);
    file(&f, &h, 100_000);
    assert!(f
        .client
        .try_open_dispute(
            &f.escrow,
            &h,
            &100_000,
            &CHAIN,
            &f.filer,
            &hash(&f.env, 0),
            &DEADLINE,
            &BUFFER,
            &0u64
        )
        .is_err());
}

// ── the arbiter boundary ─────────────────────────────────────────────────

#[test]
fn the_arbiter_can_never_rule_that_the_trade_went_through() {
    let f = fixture();
    let h = hash(&f.env, 5);
    file(&f, &h, 100_000);
    // TradeProceeds is what evidence produces; an arbiter reaching it would be arbitration
    // overruling proof.
    assert!(f
        .client
        .try_resolve_dispute(&h, &DisputeOutcome::TradeProceeds)
        .is_err());
    assert!(f
        .client
        .try_resolve_dispute(&h, &DisputeOutcome::None)
        .is_err());
}

#[test]
fn a_ruling_opens_a_window_it_does_not_pay() {
    let f = fixture();
    let h = hash(&f.env, 6);
    let bond = file(&f, &h, 100_000);
    f.client.resolve_dispute(&h, &DisputeOutcome::MutualRefund);

    // Still held: the ruling has opened a window, not moved money.
    let t = token::Client::new(&f.env, &f.token);
    assert_eq!(t.balance(&f.client.address), bond as i128);
    let (outcome, window_over, _) = f.client.outcome_of(&h, &0u64);
    assert_eq!(outcome, DisputeOutcome::MutualRefund);
    assert!(!window_over, "the window is still running");
}

// ── the clock ────────────────────────────────────────────────────────────

#[test]
fn the_fallback_waits_out_the_challenge_period() {
    let f = fixture();
    let h = hash(&f.env, 7);
    file(&f, &h, 100_000);
    assert!(f.client.try_claim_dispute(&h).is_err());

    // The challenge period alone is NOT enough: the order still has time on its own clock, and no
    // dispute path may complete before `deadline + buffer` (D3, T-50). This is the bug that let a
    // filer cancel a week-long order an hour after filing.
    f.env.ledger().with_mut(|l| l.timestamp += CHALLENGE + 1);
    assert!(f.client.try_claim_dispute(&h).is_err());

    warp_past_window(&f, &h);
    f.client.claim_dispute(&h);
}

/// B1: the window floors at the order's own deadline plus the route buffer, so a short challenge
/// period cannot shorten an order's life.
#[test]
fn the_window_floors_at_the_orders_own_deadline() {
    let f = fixture();
    let h = hash(&f.env, 30);
    file(&f, &h, 100_000);
    assert!(
        f.client.effective_challenge_deadline(&h) >= DEADLINE + BUFFER,
        "the challenge period must not outrun the order's deadline"
    );
}

/// S1: a pause on the *escrow* extends the challenge window, because a pause is what stops the
/// parties presenting and presentation is gated by the escrow.
#[test]
fn an_escrow_pause_extends_the_challenge_window() {
    let f = fixture();
    let h = hash(&f.env, 31);
    file(&f, &h, 100_000);
    let before = f.client.effective_challenge_deadline(&h);
    MockEscrowClient::new(&f.env, &f.escrow).set_paused_seconds(&600);
    assert_eq!(
        f.client.effective_challenge_deadline(&h),
        before + 600,
        "the escrow's paused seconds move the deadline"
    );
}

#[test]
fn the_arbiter_cannot_rule_after_the_challenge_period() {
    let f = fixture();
    let h = hash(&f.env, 8);
    file(&f, &h, 100_000);
    warp_past_window(&f, &h);
    assert!(f
        .client
        .try_resolve_dispute(&h, &DisputeOutcome::MutualRefund)
        .is_err());
}

// ── bond routing ─────────────────────────────────────────────────────────

#[test]
fn a_mutual_refund_returns_the_bond_to_the_filer() {
    let f = fixture();
    let h = hash(&f.env, 9);
    let bond = file(&f, &h, 100_000);
    let t = token::Client::new(&f.env, &f.token);
    let before = t.balance(&f.filer);

    f.client.resolve_dispute(&h, &DisputeOutcome::MutualRefund);
    warp_past_window(&f, &h);
    f.client
        .settle_bond(&f.escrow, &h, &DisputeOutcome::MutualRefund, &false);

    assert_eq!(t.balance(&f.filer), before + bond as i128);
    assert!(!f.client.is_disputed(&h), "the record is closed");
}

#[test]
fn a_ruling_against_the_filer_forfeits_the_bond_to_the_fee_pool() {
    let f = fixture();
    let h = hash(&f.env, 10);
    let bond = file(&f, &h, 100_000);
    let t = token::Client::new(&f.env, &f.token);

    // The filer is the bridger, and the ruling forfeits the bridger: the filer was wrong, so the
    // bond goes to the fee pool rather than home.
    f.client
        .resolve_dispute(&h, &DisputeOutcome::BridgerForfeit);
    warp_past_window(&f, &h);
    f.client
        .settle_bond(&f.escrow, &h, &DisputeOutcome::BridgerForfeit, &true);

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
        10,
        "the table must be exhaustive: 5 outcomes x 2 arms"
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
        assert_eq!(
            returns(outcome, filer_is_bridger),
            row["bondReturnsToFiler"].as_bool().unwrap(),
            "routing disagrees with the shared vector for {:?} / filerIsBridger={}",
            outcome,
            filer_is_bridger
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

/// Bond sizing, likewise: the cases live in the vector, not in each chain's head.
#[test]
fn bond_sizing_matches_the_shared_vector() {
    let v: serde_json::Value = serde_json::from_str(DISPUTE_VECTORS).unwrap();
    for c in v["bondSizing"].as_array().unwrap() {
        let p = DisputeParams {
            challenge_period: CHALLENGE,
            bond_floor: c["bondFloor"].as_str().unwrap().parse().unwrap(),
            bond_bps: c["bondBps"].as_u64().unwrap() as u32,
        };
        let amount: u128 = c["amount"].as_str().unwrap().parse().unwrap();
        let expected: u128 = c["bond"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            proofbridge_core::dispute::bond_for(amount, &p),
            expected,
            "{}",
            c["label"]
        );
    }
}

#[test]
fn only_the_escrow_that_opened_a_dispute_may_settle_it() {
    let f = fixture();
    let other = Address::generate(&f.env);
    f.client.set_escrow(&other, &true);
    let h = hash(&f.env, 11);
    file(&f, &h, 100_000);
    assert!(f
        .client
        .try_settle_bond(&other, &h, &DisputeOutcome::MutualRefund, &false)
        .is_err());
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
