//! 2.3f (#343): the RootAnchor module. T-42 (forged extension / rollback never anchors), T-63 (the
//! delay, and the writer swap as a config change), plus the consumer seam 2.3e will call through.

#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    vec, Address, BytesN, Env, Vec,
};

const T0: u64 = 1_700_000_000;
const CHAIN: u128 = 1_000_001;
const OTHER: u128 = 1_000_002;

struct F {
    env: Env,
    client: RootAnchorClient<'static>,
    id: Address,
    admin: Address,
    s1: Address,
    s2: Address,
    s3: Address,
    stranger: Address,
}

fn root(env: &Env, fill: u8) -> BytesN<32> {
    BytesN::from_array(env, &[fill; 32])
}

fn warp(env: &Env, secs: u64) {
    env.ledger().with_mut(|l| l.timestamp += secs);
}

fn fixture() -> F {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(T0);

    let admin = Address::generate(&env);
    let s1 = Address::generate(&env);
    let s2 = Address::generate(&env);
    let s3 = Address::generate(&env);
    let stranger = Address::generate(&env);

    let id = env.register(RootAnchor, ());
    let client = RootAnchorClient::new(&env, &id);
    client.initialize(&admin, &vec![&env, s1.clone()], &1);

    F {
        env,
        client,
        id,
        admin,
        s1,
        s2,
        s3,
        stranger,
    }
}

fn three(f: &F, threshold: u32) {
    let set: Vec<Address> = vec![&f.env, f.s1.clone(), f.s2.clone(), f.s3.clone()];
    f.client.set_signers(&set, &threshold);
}

/// Stands in for the escrow's follower refund (2.3e): proceeds only against an anchored root,
/// through the shared `proofbridge_core` client.
#[soroban_sdk::contract]
pub struct MockAnchorConsumer;

#[soroban_sdk::contractimpl]
impl MockAnchorConsumer {
    pub fn refund(env: Env, anchor: Address, chain_id: u128, root: BytesN<32>) -> bool {
        proofbridge_core::cross_contract::is_anchored(&env, &anchor, chain_id, &root)
    }
}

// --- init ---------------------------------------------------------------------

#[test]
fn initialize_twice_errors() {
    let f = fixture();
    assert_eq!(
        f.client
            .try_initialize(&f.admin, &vec![&f.env, f.s1.clone()], &1),
        Err(Ok(RootAnchorError::AlreadyInitialized))
    );
}

#[test]
fn initialize_records_the_set_and_defaults() {
    let f = fixture();
    assert_eq!(f.client.signers(), vec![&f.env, f.s1.clone()]);
    assert_eq!(f.client.threshold(), 1);
    assert!(f.client.monotonic());
    assert_eq!(f.client.admin(), f.admin);
}

// --- T-42: only what was notarized is anchored --------------------------------

#[test]
fn unanchored_root_is_false() {
    let f = fixture();
    assert!(!f.client.is_anchored(&CHAIN, &root(&f.env, 0xA1)));
}

#[test]
fn anchor_is_true_with_zero_delay() {
    let f = fixture();
    let r = root(&f.env, 0xA1);
    f.client.anchor(&f.s1, &CHAIN, &r, &10);
    assert!(f.client.is_anchored(&CHAIN, &r));
    let rec = f.client.anchor_of(&CHAIN, &r).unwrap();
    assert_eq!(rec.ledger_seq, 10);
    assert_eq!(rec.anchored_at, T0);
    assert_eq!(rec.approvals, 1);
}

#[test]
fn only_the_exact_root_is_anchored() {
    let f = fixture();
    f.client.anchor(&f.s1, &CHAIN, &root(&f.env, 0xA1), &10);
    // A forged extension is a different root; the same root on another chain is a different key.
    assert!(!f.client.is_anchored(&CHAIN, &root(&f.env, 0xB2)));
    assert!(!f.client.is_anchored(&OTHER, &root(&f.env, 0xA1)));
}

#[test]
fn lower_seq_errors_when_monotonic() {
    let f = fixture();
    f.client.anchor(&f.s1, &CHAIN, &root(&f.env, 0xA1), &10);
    assert_eq!(
        f.client.try_anchor(&f.s1, &CHAIN, &root(&f.env, 0xB2), &9),
        Err(Ok(RootAnchorError::SeqNotMonotonic))
    );
}

#[test]
fn equal_seq_errors_when_monotonic() {
    let f = fixture();
    f.client.anchor(&f.s1, &CHAIN, &root(&f.env, 0xA1), &10);
    assert_eq!(
        f.client.try_anchor(&f.s1, &CHAIN, &root(&f.env, 0xB2), &10),
        Err(Ok(RootAnchorError::SeqNotMonotonic))
    );
}

#[test]
fn monotonicity_is_per_chain() {
    let f = fixture();
    f.client.anchor(&f.s1, &CHAIN, &root(&f.env, 0xA1), &10);
    f.client.anchor(&f.s1, &OTHER, &root(&f.env, 0xB2), &3);
    assert!(f.client.is_anchored(&OTHER, &root(&f.env, 0xB2)));
}

#[test]
fn lower_seq_allowed_when_monotonic_off() {
    let f = fixture();
    f.client.set_monotonic(&false);
    f.client.anchor(&f.s1, &CHAIN, &root(&f.env, 0xA1), &10);
    f.client.anchor(&f.s1, &CHAIN, &root(&f.env, 0xB2), &9);
    assert!(f.client.is_anchored(&CHAIN, &root(&f.env, 0xB2)));
    assert_eq!(
        f.client.latest_seq(&CHAIN),
        10,
        "latest_seq never decreases"
    );
}

#[test]
fn non_signer_errors() {
    let f = fixture();
    assert_eq!(
        f.client
            .try_anchor(&f.stranger, &CHAIN, &root(&f.env, 0xA1), &10),
        Err(Ok(RootAnchorError::NotSigner))
    );
}

#[test]
fn reanchor_is_noop() {
    let f = fixture();
    let r = root(&f.env, 0xA1);
    f.client.anchor(&f.s1, &CHAIN, &r, &10);
    let before = f.client.anchor_of(&CHAIN, &r).unwrap();
    warp(&f.env, 100);
    f.client.anchor(&f.s1, &CHAIN, &r, &10);
    let after = f.client.anchor_of(&CHAIN, &r).unwrap();
    assert_eq!(before, after);
}

// --- T-63: the delay, and the writer as config --------------------------------

#[test]
fn inside_delay_false_after_delay_true() {
    let f = fixture();
    f.client.set_anchor_delay(&CHAIN, &600);
    let r = root(&f.env, 0xA1);
    f.client.anchor(&f.s1, &CHAIN, &r, &10);
    assert!(
        !f.client.is_anchored(&CHAIN, &r),
        "usable only after the delay"
    );
    warp(&f.env, 599);
    assert!(!f.client.is_anchored(&CHAIN, &r));
    warp(&f.env, 1);
    assert!(f.client.is_anchored(&CHAIN, &r));
}

#[test]
fn delay_is_per_chain() {
    let f = fixture();
    f.client.set_anchor_delay(&CHAIN, &600);
    f.client.anchor(&f.s1, &CHAIN, &root(&f.env, 0xA1), &10);
    f.client.anchor(&f.s1, &OTHER, &root(&f.env, 0xB2), &10);
    assert!(!f.client.is_anchored(&CHAIN, &root(&f.env, 0xA1)));
    assert!(f.client.is_anchored(&OTHER, &root(&f.env, 0xB2)));
}

#[test]
fn set_signers_rotates_the_writer_without_redeploy() {
    let f = fixture();
    f.client.set_signers(&vec![&f.env, f.s2.clone()], &1);
    assert_eq!(
        f.client.try_anchor(&f.s1, &CHAIN, &root(&f.env, 0xA1), &10),
        Err(Ok(RootAnchorError::NotSigner))
    );
    f.client.anchor(&f.s2, &CHAIN, &root(&f.env, 0xA1), &10);
    assert!(f.client.is_anchored(&CHAIN, &root(&f.env, 0xA1)));
    assert_eq!(f.client.signers(), vec![&f.env, f.s2.clone()]);
}

#[test]
fn threshold_2_of_3_needs_two_distinct_signers() {
    let f = fixture();
    three(&f, 2);
    let r = root(&f.env, 0xA1);

    f.client.anchor(&f.s1, &CHAIN, &r, &10);
    assert!(!f.client.is_anchored(&CHAIN, &r));
    assert_eq!(f.client.anchor_of(&CHAIN, &r).unwrap().approvals, 1);

    // The same signer again counts once.
    f.client.anchor(&f.s1, &CHAIN, &r, &10);
    assert_eq!(f.client.anchor_of(&CHAIN, &r).unwrap().approvals, 1);
    assert!(!f.client.is_anchored(&CHAIN, &r));

    f.client.anchor(&f.s2, &CHAIN, &r, &10);
    assert!(f.client.is_anchored(&CHAIN, &r));
    assert_eq!(f.client.anchor_of(&CHAIN, &r).unwrap().approvals, 2);
}

#[test]
fn seq_mismatch_on_pending_root_errors() {
    let f = fixture();
    three(&f, 2);
    let r = root(&f.env, 0xA1);
    f.client.anchor(&f.s1, &CHAIN, &r, &10);
    assert_eq!(
        f.client.try_anchor(&f.s2, &CHAIN, &r, &11),
        Err(Ok(RootAnchorError::SeqMismatch))
    );
}

#[test]
fn set_signers_bad_threshold_errors() {
    let f = fixture();
    let two: Vec<Address> = vec![&f.env, f.s1.clone(), f.s2.clone()];
    assert_eq!(
        f.client.try_set_signers(&two, &0),
        Err(Ok(RootAnchorError::BadThreshold))
    );
    assert_eq!(
        f.client.try_set_signers(&two, &3),
        Err(Ok(RootAnchorError::BadThreshold))
    );
}

#[test]
fn set_signers_duplicate_errors() {
    let f = fixture();
    let dup: Vec<Address> = vec![&f.env, f.s1.clone(), f.s1.clone()];
    assert_eq!(
        f.client.try_set_signers(&dup, &1),
        Err(Ok(RootAnchorError::DuplicateSigner))
    );
}

// --- pause + admin ------------------------------------------------------------

#[test]
fn pause_blocks_anchor_never_is_anchored() {
    let f = fixture();
    let a = root(&f.env, 0xA1);
    f.client.anchor(&f.s1, &CHAIN, &a, &10);

    f.client.pause();
    assert_eq!(
        f.client.try_anchor(&f.s1, &CHAIN, &root(&f.env, 0xB2), &11),
        Err(Ok(RootAnchorError::ContractPaused))
    );
    // The read on the refund path keeps answering under pause (D4).
    assert!(f.client.is_anchored(&CHAIN, &a));

    f.client.unpause();
    f.client.anchor(&f.s1, &CHAIN, &root(&f.env, 0xB2), &11);
    assert!(f.client.is_anchored(&CHAIN, &root(&f.env, 0xB2)));
}

#[test]
fn two_step_admin() {
    let f = fixture();
    let next = Address::generate(&f.env);
    assert_eq!(
        f.client.try_accept_admin(),
        Err(Ok(RootAnchorError::NotPendingAdmin))
    );
    f.client.transfer_admin(&next);
    f.client.accept_admin();
    assert_eq!(f.client.admin(), next);
}

// --- the seam 2.3e's cancel_order calls ----------------------------------------

#[test]
fn consumer_proceeds_only_against_an_anchored_root() {
    let f = fixture();
    let consumer = f.env.register(MockAnchorConsumer, ());
    let cc = MockAnchorConsumerClient::new(&f.env, &consumer);
    let r = root(&f.env, 0xA1);

    assert!(!cc.refund(&f.id, &CHAIN, &r));
    f.client.anchor(&f.s1, &CHAIN, &r, &10);
    assert!(cc.refund(&f.id, &CHAIN, &r));
}

#[test]
fn consumer_respects_the_delay() {
    let f = fixture();
    let consumer = f.env.register(MockAnchorConsumer, ());
    let cc = MockAnchorConsumerClient::new(&f.env, &consumer);
    let r = root(&f.env, 0xA1);

    f.client.set_anchor_delay(&CHAIN, &300);
    f.client.anchor(&f.s1, &CHAIN, &r, &10);
    assert!(!cc.refund(&f.id, &CHAIN, &r));
    warp(&f.env, 300);
    assert!(cc.refund(&f.id, &CHAIN, &r));
}
