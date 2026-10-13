//! #586: proposal ids pinned for a few calls of every argument type, so the deploy CLI's encoder
//! (stellar/deploy/src/timelock.ts) is checked against the contract's own keying.

extern crate std;

use soroban_sdk::{Address, BytesN, Env, IntoVal, Symbol, Val, Vec};

use crate::timelock::action_id;
use crate::types::{BondConfig, DisputeParams, RouteTiming};

fn id(env: &Env, f: &str, args: Vec<Val>) -> std::string::String {
    action_id(env, &Symbol::new(env, f), &args)
        .to_array()
        .iter()
        .map(|b| std::format!("{b:02x}"))
        .collect()
}

#[test]
fn proposal_ids_are_pinned() {
    let env = Env::default();
    let e = &env;
    // u128 + struct (u64, u128)
    let p = DisputeParams {
        challenge_period: 7200,
        bond_floor: 1000,
    };
    assert_eq!(
        id(e, "set_dispute_params", (1_000_002u128, p).into_val(e)),
        "66d8a158ae74a6c625d65297d0808577d1b4be0dd2edbc2d5d9a95d811f488b3"
    );
    // u128 + bytes32
    let peer = BytesN::from_array(e, &[0x42; 32]);
    assert_eq!(
        id(e, "set_chain", (7_777u128, peer).into_val(e)),
        "e0bfc09fd7d4d14b64ca54e572e655222bc7b80a05b3dbf392b39179008b3bff"
    );
    // u32 + u32
    assert_eq!(
        id(e, "set_fee_bps", (30u32, 20u32).into_val(e)),
        "ea4f2da6bd9ea0128b70c3fdbf92fbc3d68a95b770fe1c9669119282f772b275"
    );
    // u128 + struct of four u64
    let t = RouteTiming {
        min_window: 0,
        buffer: 1800,
        margin: 0,
        claim_stagger: 0,
    };
    assert_eq!(
        id(e, "set_route_timing", (7_777u128, t).into_val(e)),
        "937d6c2158d5bce4d88f155cb703ee0e86edf754d14e7ab016aa554aad1414cb"
    );
    // address + u128 + struct (u128, u32): a contract address
    let tok = Address::from_str(
        e,
        "CAIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRDB3V",
    );
    let c = BondConfig {
        min_bond: 1_000_000,
        bond_bps: 50,
    };
    assert_eq!(
        id(e, "set_bond_config", (tok, 1_000_002u128, c).into_val(e)),
        "dd1faec679716838e42560f4a0f81347ce0473b32a32b84ef05d97af0178db82"
    );
    // address + bool: an account address
    let who = Address::from_str(
        e,
        "GARCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCFRVX",
    );
    assert_eq!(
        id(e, "set_manager", (who.clone(), true).into_val(e)),
        "8d7bff83e54b34b14f272be202c745d99bad76ccb3645eb8bd7e5c763aa2498e"
    );
    // a contract address + bool
    let escrow = Address::from_str(
        e,
        "CAIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRDB3V",
    );
    assert_eq!(
        id(
            e,
            "set_escrow_appender",
            (escrow.clone(), false).into_val(e)
        ),
        "7bbe7109b0cf1bf22f497e93d00c169387d256cd1568173929b16e11a0bb0df6"
    );
    // a vec of addresses + u32
    let signers: Vec<Address> = soroban_sdk::vec![e, who.clone()];
    assert_eq!(
        id(e, "set_signers", (signers, 1u32).into_val(e)),
        "100d2335126ea0e1dd3e4d59bbef42c0c34725f53cb6d9bc4d91c7da7b117fbe"
    );
    // address + address + a vec of u128 + bool
    let sources: Vec<u128> = soroban_sdk::vec![e, 1_000_002u128];
    assert_eq!(
        id(
            e,
            "set_proof_registration",
            (escrow.clone(), escrow, sources, true).into_val(e)
        ),
        "47c0f7edb3e2211853a154b3bdd3b20b59220b4c489b450b5d1e3b21fe3dfd64"
    );
}
