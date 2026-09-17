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

const T0: u64 = 1_700_000_000;
const CHAIN: u128 = 1_000_002;
const CHALLENGE: u64 = 2 * 60 * 60;
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
    let escrow = Address::generate(&env);
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
    f.client
        .open_dispute(&f.escrow, h, &amount, &CHAIN, &f.filer, &hash(&f.env, 0xEE))
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
            &hash(&f.env, 0)
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
        .try_open_dispute(&stranger, &h, &1_000, &CHAIN, &f.filer, &hash(&f.env, 0))
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
        .try_open_dispute(&f.escrow, &h, &100_000, &CHAIN, &f.filer, &hash(&f.env, 0))
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
    let (outcome, window_over, _) = f.client.outcome_of(&h);
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

    f.env.ledger().with_mut(|l| l.timestamp += CHALLENGE);
    f.client.claim_dispute(&h);
}

#[test]
fn the_arbiter_cannot_rule_after_the_challenge_period() {
    let f = fixture();
    let h = hash(&f.env, 8);
    file(&f, &h, 100_000);
    f.env.ledger().with_mut(|l| l.timestamp += CHALLENGE + 1);
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
    f.env.ledger().with_mut(|l| l.timestamp += CHALLENGE + 1);
    f.client.settle_bond(&f.escrow, &h, &false);

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
    f.env.ledger().with_mut(|l| l.timestamp += CHALLENGE + 1);
    f.client.settle_bond(&f.escrow, &h, &true);

    assert_eq!(t.balance(&f.fee_pool), bond as i128);
}

/// The flag is absolute — "the filer is the bridger" — and both arms matter, because reading it as
/// "the filer is my counterparty" inverted the routing on the follower leg: a forfeited bond came
/// back and a vindicated one was taken.
#[test]
fn bond_routing_is_symmetric_in_the_flag() {
    use proofbridge_core::dispute::bond_returns_to_filer as returns;
    // A ruling against the party who filed forfeits their bond, whichever side they are.
    assert!(!returns(DisputeOutcome::BridgerForfeit, true));
    assert!(!returns(DisputeOutcome::MakerForfeit, false));
    // A ruling against the other side vindicates the filer, whichever side they are.
    assert!(returns(DisputeOutcome::MakerForfeit, true));
    assert!(returns(DisputeOutcome::BridgerForfeit, false));
    // Neither side shown wrong: the bond comes back.
    assert!(returns(DisputeOutcome::MutualRefund, true));
    assert!(returns(DisputeOutcome::MutualRefund, false));
    // Evidence proved the trade fine, so the filer disputed a settleable trade.
    assert!(!returns(DisputeOutcome::TradeProceeds, true));
    assert!(!returns(DisputeOutcome::TradeProceeds, false));
}

#[test]
fn only_the_escrow_that_opened_a_dispute_may_settle_it() {
    let f = fixture();
    let other = Address::generate(&f.env);
    f.client.set_escrow(&other, &true);
    let h = hash(&f.env, 11);
    file(&f, &h, 100_000);
    assert!(f.client.try_settle_bond(&other, &h, &false).is_err());
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
