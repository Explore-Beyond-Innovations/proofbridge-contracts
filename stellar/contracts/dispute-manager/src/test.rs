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
    assert_eq!(
        f.client.try_set_dispute_params(
            &CHAIN,
            &DisputeParams {
                challenge_period: 60,
                bond_floor: BOND_FLOOR,
                bond_bps: BOND_BPS,
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
                bond_bps: BOND_BPS,
            }
        ),
        Err(Ok(Error::InvalidBondFloor))
    );
    // Above the ceiling a bond deters honest disputes as much as frivolous ones.
    assert_eq!(
        f.client.try_set_dispute_params(
            &CHAIN,
            &DisputeParams {
                challenge_period: CHALLENGE,
                bond_floor: BOND_FLOOR,
                bond_bps: 2_000,
            }
        ),
        Err(Ok(Error::InvalidBondBps))
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
            bond_bps: row["bondBps"].as_u64().unwrap() as _,
        };
        let got = f.client.try_set_dispute_params(&CHAIN, &p);
        let label = row["label"].as_str().unwrap();
        match row["validField"].as_u64().unwrap() {
            0 => assert!(got.is_ok(), "{label}: should write"),
            1 => assert_eq!(got, Err(Ok(Error::InvalidChallengePeriod)), "{label}"),
            2 => assert_eq!(got, Err(Ok(Error::InvalidBondFloor)), "{label}"),
            3 => assert_eq!(got, Err(Ok(Error::InvalidBondBps)), "{label}"),
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
            &1_000,
            &(CHAIN + 7),
            &f.filer,
            &hash(&f.env, 0),
            &DEADLINE,
            &BUFFER,
            &0u64
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
            &1_000,
            &CHAIN,
            &f.filer,
            &hash(&f.env, 0),
            &DEADLINE,
            &BUFFER,
            &0u64
        ),
        Err(Ok(Error::NotEscrow))
    );
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
    assert_eq!(
        f.client.try_open_dispute(
            &f.escrow,
            &h,
            &100_000,
            &CHAIN,
            &f.filer,
            &hash(&f.env, 0),
            &DEADLINE,
            &BUFFER,
            &0u64
        ),
        Err(Ok(Error::DisputeExists))
    );
}

// ── the arbiter boundary ─────────────────────────────────────────────────

#[test]
fn the_arbiter_can_never_rule_that_the_trade_went_through() {
    let f = fixture();
    let h = hash(&f.env, 5);
    file(&f, &h, 100_000);
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
    assert_eq!(
        f.client.try_claim_dispute(&h),
        Err(Ok(Error::ChallengeOpen))
    );

    // The challenge period alone is NOT enough: the order still has time on its own clock, and no
    // dispute path may complete before `deadline + buffer` (D3, T-50). This is the bug that let a
    // filer cancel a week-long order an hour after filing.
    f.env.ledger().with_mut(|l| l.timestamp += CHALLENGE + 1);
    assert_eq!(
        f.client.try_claim_dispute(&h),
        Err(Ok(Error::ChallengeOpen))
    );

    warp_past_window(&f, &h);
    f.client.claim_dispute(&h);
}

/// #452: once the arbiter rules, the no-ruling fallback is refused with its own error, even after
/// the ruling's window has passed.
#[test]
fn a_claim_after_a_ruling_is_already_ruled() {
    let f = fixture();
    let h = hash(&f.env, 31);
    file(&f, &h, 100_000);
    f.client.resolve_dispute(&h, &DisputeOutcome::MutualRefund);

    assert_eq!(f.client.try_claim_dispute(&h), Err(Ok(Error::AlreadyRuled)));

    warp_past_window(&f, &h);
    assert_eq!(f.client.try_claim_dispute(&h), Err(Ok(Error::AlreadyRuled)));
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
    assert_eq!(
        f.client
            .try_settle_bond(&other, &h, &DisputeOutcome::MutualRefund, &false),
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
        bond_bps: BOND_BPS,
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
    let bond = file(&f, &h, 1_000);
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
    assert_eq!(f.client.try_claim_dispute(&h), Err(Ok(Error::NotDisputed)));
    assert_eq!(
        f.client
            .try_settle_bond(&f.escrow, &h, &DisputeOutcome::MutualRefund, &false),
        Err(Ok(Error::NotDisputed))
    );
    assert_eq!(
        f.client
            .try_record_response(&f.escrow, &h, &Address::generate(&f.env), &hash(&f.env, 1)),
        Err(Ok(Error::NotDisputed))
    );
}

/// The filer cannot answer their own dispute: the responder slot is the other party's.
#[test]
fn the_filer_cannot_respond_to_their_own_dispute() {
    let f = fixture();
    let h = hash(&f.env, 41);
    file(&f, &h, 100_000);
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
    file(&f, &h, 100_000);
    assert_eq!(
        f.client
            .try_record_response(&other, &h, &Address::generate(&f.env), &hash(&f.env, 0x11)),
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
            &1_000,
            &CHAIN,
            &broke,
            &hash(&f.env, 0xEE),
            &DEADLINE,
            &BUFFER,
            &0u64,
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
    let bond = file(&f, &h, 1_000);
    // Drain the module so the payout is refused and credited instead.
    TokenContractClient::new(&f.env, &f.token).transfer(
        &f.client.address,
        &Address::generate(&f.env),
        &(bond as i128),
    );
    f.client
        .settle_bond(&f.escrow, &h, &DisputeOutcome::MutualRefund, &false);
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
        (Error::BondTooSmall, c::BOND_TOO_SMALL),
        (Error::ChallengeOpen, c::CHALLENGE_OPEN),
        (Error::ChallengeClosed, c::CHALLENGE_CLOSED),
        (Error::NotResponder, c::NOT_RESPONDER),
        (Error::NoDisputeParams, c::NO_DISPUTE_PARAMS),
        (Error::WrongEscrow, c::WRONG_ESCROW),
        (Error::BondTransferFailed, c::BOND_TRANSFER_FAILED),
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
    file(&f, &h, 100_000);
    let other = Address::generate(&f.env);
    f.client
        .record_response(&f.escrow, &h, &other, &hash(&f.env, 0x11));
    assert!(f
        .client
        .try_record_response(&f.escrow, &h, &other, &hash(&f.env, 0x22))
        .is_err());
    assert_eq!(
        f.client.get_dispute(&h).unwrap().responder_evidence,
        hash(&f.env, 0x11)
    );
}

/// D5: answers close with the challenge window, the instant the arbiter's ruling does.
#[test]
fn d5_an_answer_at_the_challenge_deadline_is_refused() {
    let f = fixture();
    let h = hash(&f.env, 51);
    file(&f, &h, 100_000);
    let until = f.client.effective_challenge_deadline(&h);
    let other = Address::generate(&f.env);
    f.env.ledger().set_timestamp(until);
    assert!(f
        .client
        .try_record_response(&f.escrow, &h, &other, &hash(&f.env, 0x11))
        .is_err());
    f.env.ledger().set_timestamp(until - 1);
    f.client
        .record_response(&f.escrow, &h, &other, &hash(&f.env, 0x11));
}

/// D5: an empty answer is refused, so "answered" is exactly "the slot is non-zero".
#[test]
fn d5_a_zero_answer_is_refused() {
    let f = fixture();
    let h = hash(&f.env, 52);
    file(&f, &h, 100_000);
    assert!(f
        .client
        .try_record_response(&f.escrow, &h, &Address::generate(&f.env), &hash(&f.env, 0))
        .is_err());
}
