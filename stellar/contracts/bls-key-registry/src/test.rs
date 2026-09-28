//! Vector-driven tests; the EVM registry suite consumes the same JSON.

#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Ledger as _},
    Env, String as SString,
};

const VECTORS: &str = include_str!("../../../../test-vectors/bls-encodings.json");

// The vectors bind the Soroban registry to chain 1000002 + this dummy id.
const REGISTRY_ID: [u8; 32] = [0x22; 32];
const CHAIN_ID: u128 = 1_000_002;
const T0: u64 = 1_700_000_000;

fn vectors() -> serde_json::Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn hexval(v: &serde_json::Value) -> std::vec::Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

fn bn<const N: usize>(env: &Env, v: &serde_json::Value) -> BytesN<N> {
    let bytes = hexval(v);
    let arr: [u8; N] = bytes.as_slice().try_into().unwrap();
    BytesN::from_array(env, &arr)
}

/// The maker's Stellar wallet address (G-strkey of the vector ed25519 pubkey).
fn maker_owner(env: &Env, v: &serde_json::Value) -> Address {
    let pk = hexval(&v["keys"]["makerWallet"]["pk"]);
    let strkey = stellar_strkey::ed25519::PublicKey(pk.try_into().unwrap()).to_string();
    Address::from_string(&SString::from_str(env, &strkey))
}

/// Deploys the registry at the exact contract id the vectors bind, so the
/// vector PoPs / digests verify end-to-end.
fn setup() -> (Env, BlsKeyRegistryClient<'static>, serde_json::Value) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(T0);

    let strkey = stellar_strkey::Contract(REGISTRY_ID).to_string();
    let at = Address::from_string(&SString::from_str(&env, &strkey));
    let contract_id = env.register_at(&at, BlsKeyRegistry, ());
    let client = BlsKeyRegistryClient::new(&env, &contract_id);

    client.initialize(&Address::generate(&env), &CHAIN_ID);
    (env, client, vectors())
}

fn reg(v: &serde_json::Value, who: &str) -> serde_json::Value {
    v["registration"][who].clone()
}

// ---- registry v2 slot vectors: `slots.<who>.registrations[i]` (nonce i, distinct key) ----

const MAKER: &str = "makerOnStellarTestnet";
const BRIDGER: &str = "bridgerOnStellarTestnet";

fn slot_reg(v: &serde_json::Value, who: &str, i: usize) -> serde_json::Value {
    v["slots"][who]["registrations"][i].clone()
}

fn slot_account(env: &Env, v: &serde_json::Value, who: &str) -> BytesN<32> {
    bn::<32>(env, &v["slots"][who]["account"])
}

// ---- 2.6 owner auth: `ownerAuth.<maker|bridger>` (one signature, both registries) ----

/// The `ownerAuth` actor for a slots name: the maker signs ed25519 (SEP-53), the bridger secp256k1.
fn oa<'a>(v: &'a serde_json::Value, who: &str) -> &'a serde_json::Value {
    &v["ownerAuth"][if who == MAKER { "maker" } else { "bridger" }]
}

fn legs_of(env: &Env, e: &serde_json::Value) -> Vec<KeyLeg> {
    let mut legs = Vec::new(env);
    for l in e["legs"].as_array().into_iter().flatten() {
        legs.push_back(KeyLeg {
            chain_id: l["chainId"].as_str().unwrap().parse().unwrap(),
            registry: bn::<32>(env, &l["registry"]),
            nonce: l["nonce"].as_str().unwrap().parse().unwrap(),
        });
    }
    legs
}

fn sig_of(env: &Env, e: &serde_json::Value) -> OwnerSig {
    if e["scheme"] == "sep53" {
        OwnerSig::Sep53(bn::<64>(env, &e["sig"]))
    } else {
        OwnerSig::Secp256k1(bn::<65>(env, &e["sig"]))
    }
}

/// A vector entry as the signed owner auth it is.
fn signed(env: &Env, e: &serde_json::Value) -> OwnerAuth {
    signed_with(env, legs_of(env, e), sig_of(env, e))
}

fn signed_with(_env: &Env, legs: Vec<KeyLeg>, sig: OwnerSig) -> OwnerAuth {
    OwnerAuth::Signed(SignedOwner { legs, sig })
}

/// Registers slot vector i for `who` at nonce i under its `ownerAuth.register[i]` signature.
fn register_slot(
    env: &Env,
    client: &BlsKeyRegistryClient,
    v: &serde_json::Value,
    who: &str,
    i: usize,
) -> u32 {
    let r = slot_reg(v, who, i);
    client.register(
        &slot_account(env, v, who),
        &signed(env, &oa(v, who)["register"][i]),
        &bn::<96>(env, &r["pkNative"]),
        &bn::<192>(env, &r["pop"]),
        &(i as u64),
    )
}

fn slot_commitment(env: &Env, v: &serde_json::Value, who: &str, i: usize) -> BytesN<32> {
    bn::<32>(env, &slot_reg(v, who, i)["commitment"])
}

/// The fingerprint key i is named by in the owner's messages (keccak of its EIP-2537 form).
fn fingerprint(env: &Env, v: &serde_json::Value, who: &str, i: usize) -> BytesN<32> {
    bn::<32>(env, &oa(v, who)["register"][i]["keyCommitment"])
}

fn grace_ts(v: &serde_json::Value) -> u64 {
    v["slots"]["graceTs"].as_str().unwrap().parse().unwrap()
}

/// `ownerAuth.<who>.retire[]` is (key, validUntil) x {1, graceTs}: index = key*2 + (retire ? 0 : 1).
fn svu_owner(env: &Env, v: &serde_json::Value, who: &str, key: u32, retire: bool) -> OwnerAuth {
    signed(
        env,
        &oa(v, who)["retire"][(key as usize) * 2 + if retire { 0 } else { 1 }],
    )
}

/// Retires key i (whatever slot it occupies) under its pre-signed `RetireKey`.
fn set_valid_until(
    env: &Env,
    client: &BlsKeyRegistryClient,
    v: &serde_json::Value,
    who: &str,
    key: u32,
    retire: bool,
) {
    client.set_valid_until(
        &slot_account(env, v, who),
        &svu_owner(env, v, who, key, retire),
        &fingerprint(env, v, who, key as usize),
        &if retire { 1 } else { grace_ts(v) },
    );
}

fn busy_guard(env: &Env, client: &BlsKeyRegistryClient) {
    let guard = env.register(MockGuard, ());
    client.set_position_guards(&soroban_sdk::vec![env, guard]);
}

fn idle_guard(env: &Env, client: &BlsKeyRegistryClient) {
    let guard = env.register(IdleGuard, ());
    client.set_position_guards(&soroban_sdk::vec![env, guard]);
}

// =============================================================================
// Happy paths
// =============================================================================

#[test]
fn register_stellar_home_account_via_require_auth() {
    let (env, client, v) = setup();
    let r = reg(&v, "makerOnStellarTestnet");

    client.register(
        &bn::<32>(&env, &r["account"]),
        &OwnerAuth::Stellar(maker_owner(&env, &v)),
        &bn::<96>(&env, &r["pkNative"]),
        &bn::<192>(&env, &r["pop"]),
        &0,
    );

    assert_eq!(
        client.commitment_at(&bn::<32>(&env, &r["account"]), &0),
        bn::<32>(&env, &r["commitment"])
    );
    assert_eq!(client.nonce_of(&bn::<32>(&env, &r["account"])), 1);
}

#[test]
fn register_evm_home_account_via_secp256k1() {
    let (env, client, v) = setup();
    let r = reg(&v, "bridgerOnStellarTestnet");

    client.register(
        &bn::<32>(&env, &r["account"]),
        &signed(&env, &oa(&v, BRIDGER)["register"][0]),
        &bn::<96>(&env, &r["pkNative"]),
        &bn::<192>(&env, &r["pop"]),
        &0,
    );

    assert_eq!(
        client.commitment_at(&bn::<32>(&env, &r["account"]), &0),
        bn::<32>(&env, &r["commitment"])
    );
}

#[test]
fn revoke_stellar_home_then_key_is_gone() {
    let (env, client, v) = setup();
    let r = reg(&v, "makerOnStellarTestnet");
    let account = bn::<32>(&env, &r["account"]);
    let owner = maker_owner(&env, &v);

    client.register(
        &account,
        &OwnerAuth::Stellar(owner.clone()),
        &bn::<96>(&env, &r["pkNative"]),
        &bn::<192>(&env, &r["pop"]),
        &0,
    );
    client.revoke(&account, &OwnerAuth::Stellar(owner), &1);

    assert_eq!(
        client.try_commitment_at(&account, &0),
        Err(Ok(RegistryError::NoSuchSlot))
    );
    assert_eq!(client.nonce_of(&account), 2);
}

#[test]
fn revoke_evm_home_with_nonce1_signature() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, BRIDGER);
    register_slot(&env, &client, &v, BRIDGER, 0);
    client.revoke(&account, &signed(&env, &oa(&v, BRIDGER)["revoke"][1]), &1);

    assert_eq!(
        client.try_commitment_at(&account, &0),
        Err(Ok(RegistryError::NoSuchSlot))
    );
}

// =============================================================================
// Negative paths
// =============================================================================

/// Same nonce → BadNonce; bumped nonce with a stale PoP → InvalidPop.
#[test]
fn reregister_without_fresh_pop_reverts() {
    let (env, client, v) = setup();
    let r = reg(&v, "makerOnStellarTestnet");
    let account = bn::<32>(&env, &r["account"]);
    let owner = maker_owner(&env, &v);
    let pk = bn::<96>(&env, &r["pkNative"]);
    let pop = bn::<192>(&env, &r["pop"]);

    client.register(&account, &OwnerAuth::Stellar(owner.clone()), &pk, &pop, &0);

    assert_eq!(
        client.try_register(&account, &OwnerAuth::Stellar(owner.clone()), &pk, &pop, &0),
        Err(Ok(RegistryError::BadNonce))
    );
    assert_eq!(
        client.try_register(&account, &OwnerAuth::Stellar(owner), &pk, &pop, &1),
        Err(Ok(RegistryError::InvalidPop))
    );
}

#[test]
fn identity_pubkey_rejected() {
    let (env, client, v) = setup();
    let r = reg(&v, "makerOnStellarTestnet");
    let neg = &v["negative"]["identityPubkey"];

    assert_eq!(
        client.try_register(
            &bn::<32>(&env, &r["account"]),
            &OwnerAuth::Stellar(maker_owner(&env, &v)),
            &bn::<96>(&env, &neg["uncompressed"]),
            &bn::<192>(&env, &r["pop"]),
            &0,
        ),
        Err(Ok(RegistryError::IdentityKey))
    );
}

#[test]
fn pop_signed_with_wrong_dst_rejected() {
    let (env, client, v) = setup();
    let r = reg(&v, "makerOnStellarTestnet");
    let neg = &v["negative"]["popWrongDst"];

    assert_eq!(
        client.try_register(
            &bn::<32>(&env, &r["account"]),
            &OwnerAuth::Stellar(maker_owner(&env, &v)),
            &bn::<96>(&env, &r["pkNative"]),
            &bn::<192>(&env, &neg["pop"]),
            &0,
        ),
        Err(Ok(RegistryError::InvalidPop))
    );
}

#[test]
fn stellar_owner_that_is_not_the_account_rejected() {
    let (env, client, v) = setup();
    let r = reg(&v, "makerOnStellarTestnet");

    assert_eq!(
        client.try_register(
            &bn::<32>(&env, &r["account"]),
            &OwnerAuth::Stellar(Address::generate(&env)),
            &bn::<96>(&env, &r["pkNative"]),
            &bn::<192>(&env, &r["pop"]),
            &0,
        ),
        Err(Ok(RegistryError::OwnerMismatch))
    );
}

#[test]
fn evm_owner_sig_by_wrong_signer_rejected() {
    let (env, client, v) = setup();
    let r = reg(&v, "bridgerOnStellarTestnet");
    let e = &oa(&v, BRIDGER)["register"][0];

    // Flip the recovery parity: recovers a different key → different address.
    let mut bad = bn::<65>(&env, &e["sig"]).to_array();
    bad[64] = if bad[64] == 27 { 28 } else { 27 };

    assert_eq!(
        client.try_register(
            &bn::<32>(&env, &r["account"]),
            &signed_with(
                &env,
                legs_of(&env, e),
                OwnerSig::Secp256k1(BytesN::from_array(&env, &bad))
            ),
            &bn::<96>(&env, &r["pkNative"]),
            &bn::<192>(&env, &r["pop"]),
            &0,
        ),
        Err(Ok(RegistryError::OwnerMismatch))
    );
}

#[test]
fn revoke_unregistered_account_rejected() {
    let (env, client, v) = setup();
    let r = reg(&v, "makerOnStellarTestnet");

    assert_eq!(
        client.try_revoke(
            &bn::<32>(&env, &r["account"]),
            &OwnerAuth::Stellar(maker_owner(&env, &v)),
            &0
        ),
        Err(Ok(RegistryError::NotRegistered))
    );
}

// =============================================================================
// I-NEW-RV: revoke blocked while the account has open positions
// =============================================================================

#[contract]
pub struct MockGuard;

#[contractimpl]
impl MockGuard {
    pub fn has_open_positions(_env: Env, _account: BytesN<32>) -> bool {
        true
    }
}

/// A wired guard that reports no positions.
#[contract]
pub struct IdleGuard;

#[contractimpl]
impl IdleGuard {
    pub fn has_open_positions(_env: Env, _account: BytesN<32>) -> bool {
        false
    }
}

#[test]
fn revoke_blocked_while_in_flight() {
    let (env, client, v) = setup();
    let r = reg(&v, "makerOnStellarTestnet");
    let account = bn::<32>(&env, &r["account"]);
    let owner = maker_owner(&env, &v);

    client.register(
        &account,
        &OwnerAuth::Stellar(owner.clone()),
        &bn::<96>(&env, &r["pkNative"]),
        &bn::<192>(&env, &r["pop"]),
        &0,
    );

    let guard = env.register(MockGuard, ());
    client.set_position_guards(&soroban_sdk::vec![&env, guard]);

    assert_eq!(
        client.try_revoke(&account, &OwnerAuth::Stellar(owner), &1),
        Err(Ok(RegistryError::AccountInFlight))
    );
}

#[test]
fn first_registration_ignores_busy_guards() {
    let (env, client, v) = setup();
    let r = reg(&v, "makerOnStellarTestnet");
    let account = bn::<32>(&env, &r["account"]);
    let owner = maker_owner(&env, &v);

    let guard = env.register(MockGuard, ());
    client.set_position_guards(&soroban_sdk::vec![&env, guard]);

    client.register(
        &account,
        &OwnerAuth::Stellar(owner),
        &bn::<96>(&env, &r["pkNative"]),
        &bn::<192>(&env, &r["pop"]),
        &0,
    );
    assert_eq!(
        client.commitment_at(&account, &0),
        bn::<32>(&env, &r["commitment"])
    );
    // and a second (additive) slot too
    assert_eq!(register_slot(&env, &client, &v, MAKER, 1), 1);
}

/// Pause brakes register/revoke; retirement (the incident lever) still lands.
#[test]
fn pause_blocks_register_and_revoke_but_not_retirement() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    let owner = maker_owner(&env, &v);
    register_slot(&env, &client, &v, MAKER, 0);

    client.pause();
    let r1 = slot_reg(&v, MAKER, 1);
    assert_eq!(
        client.try_register(
            &account,
            &OwnerAuth::Stellar(owner.clone()),
            &bn::<96>(&env, &r1["pkNative"]),
            &bn::<192>(&env, &r1["pop"]),
            &1
        ),
        Err(Ok(RegistryError::ContractPaused))
    );
    assert_eq!(
        client.try_revoke(&account, &OwnerAuth::Stellar(owner.clone()), &1),
        Err(Ok(RegistryError::ContractPaused))
    );
    set_valid_until(&env, &client, &v, MAKER, 0, true);
    assert_eq!(
        client.try_commitment_at(&account, &0),
        Err(Ok(RegistryError::SlotExpired))
    );

    client.unpause();
    assert_eq!(register_slot(&env, &client, &v, MAKER, 1), 1);
}

#[test]
fn has_usable_slot_follows_validity() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    assert!(!client.has_usable_slot(&account));
    register_slot(&env, &client, &v, MAKER, 0);
    assert!(client.has_usable_slot(&account));
    set_valid_until(&env, &client, &v, MAKER, 0, false); // in grace
    assert!(client.has_usable_slot(&account));
    env.ledger().set_timestamp(grace_ts(&v));
    assert!(!client.has_usable_slot(&account));
    register_slot(&env, &client, &v, MAKER, 1);
    assert!(client.has_usable_slot(&account));
}

#[test]
fn two_step_admin_transfer() {
    let (env, client, _v) = setup();

    assert_eq!(
        client.try_accept_admin(),
        Err(Ok(RegistryError::NotPendingAdmin))
    );

    let next = Address::generate(&env);
    client.transfer_admin(&next);
    client.accept_admin();
    assert_eq!(client.admin(), next);
}

// =============================================================================
// Slots: additive register, monotonic ids, cap + prune, key reuse
// =============================================================================

#[test]
fn additive_register_assigns_monotonic_slot_ids() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, BRIDGER);
    for i in 0..3u32 {
        assert_eq!(register_slot(&env, &client, &v, BRIDGER, i as usize), i);
        assert_eq!(
            client.commitment_at(&account, &i),
            slot_commitment(&env, &v, BRIDGER, i as usize)
        );
    }
    assert_eq!(client.nonce_of(&account), 3);
    assert_eq!(client.live_slots(&account).len(), 3);
    assert_eq!(
        client.commitment_at(&account, &0),
        slot_commitment(&env, &v, BRIDGER, 0)
    );
    let slot = client.lookup(&account, &0).unwrap();
    assert_eq!(slot.valid_until, 0);
    assert_eq!(slot.registered_at, T0);
}

#[test]
fn sixth_slot_reverts_registry_full() {
    let (env, client, v) = setup();
    for i in 0..5 {
        register_slot(&env, &client, &v, MAKER, i);
    }
    let r = slot_reg(&v, MAKER, 5);
    assert_eq!(
        client.try_register(
            &slot_account(&env, &v, MAKER),
            &OwnerAuth::Stellar(maker_owner(&env, &v)),
            &bn::<96>(&env, &r["pkNative"]),
            &bn::<192>(&env, &r["pop"]),
            &5,
        ),
        Err(Ok(RegistryError::RegistryFull))
    );
}

/// A slot past valid_until + GRACE_PERIOD is pruned to make room; its id is never reissued.
#[test]
fn register_at_cap_prunes_expired_slot() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    idle_guard(&env, &client);
    for i in 0..5 {
        register_slot(&env, &client, &v, MAKER, i);
    }
    set_valid_until(&env, &client, &v, MAKER, 2, true); // valid_until = 1, expired at the kill (D14)
    env.ledger().set_timestamp(T0 + 1);
    // D17: the guard is wired and reports no positions, so no order can need the dead slot's
    // history — pruned at once.

    assert_eq!(register_slot(&env, &client, &v, MAKER, 5), 5);
    assert_eq!(client.lookup(&account, &2), None);
    assert_eq!(client.live_slots(&account).len(), 5);
    assert_eq!(client.next_slot_id(&account), 6);
}

/// #422 D14: our own retirement names `valid_until = 1`; the slot expired at the kill, not in 1970.
#[test]
fn any_slot_expired_within_a_kill_expires_at_the_kill() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    register_slot(&env, &client, &v, MAKER, 0);
    env.ledger().set_timestamp(T0 + 100);
    set_valid_until(&env, &client, &v, MAKER, 0, true);
    assert!(
        client.any_slot_expired_within(&account, &(T0 + 100), &(T0 + 100)),
        "the kill's own second"
    );
    assert!(client.any_slot_expired_within(&account, &(T0 + 50), &(T0 + 150)));
    assert!(
        !client.any_slot_expired_within(&account, &0, &(T0 + 99)),
        "before the kill: no"
    );
    assert!(
        !client.any_slot_expired_within(&account, &(T0 + 101), &u64::MAX),
        "after it: no"
    );
}

/// #422 D14: a shorten made before `from`, naming a date inside `[from, to]`, expires at the date.
#[test]
fn any_slot_expired_within_an_early_shorten_expires_at_its_date() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    register_slot(&env, &client, &v, MAKER, 0);
    set_valid_until(&env, &client, &v, MAKER, 0, false); // at T0, naming grace_ts
    let g = grace_ts(&v);
    assert!(
        client.any_slot_expired_within(&account, &(T0 + 1), &g),
        "the date, not the shorten"
    );
    assert!(!client.any_slot_expired_within(&account, &(T0 + 1), &(g - 1)));
}

/// #422 D17: while a guard reports positions a dead slot keeps its place for the grace — an open
/// order's cancel may still ask about it — and leaves once the grace is over regardless.
#[test]
fn register_at_cap_keeps_a_dead_slot_while_in_flight_until_the_grace() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    busy_guard(&env, &client);
    for i in 0..5 {
        register_slot(&env, &client, &v, MAKER, i);
    }
    set_valid_until(&env, &client, &v, MAKER, 2, true);
    env.ledger().set_timestamp(T0 + 1);
    let r = slot_reg(&v, MAKER, 5);
    assert_eq!(
        client.try_register(
            &account,
            &signed(&env, &oa(&v, MAKER)["register"][5]),
            &bn::<96>(&env, &r["pkNative"]),
            &bn::<192>(&env, &r["pop"]),
            &5,
        ),
        Err(Ok(RegistryError::RegistryFull))
    );
    env.ledger().set_timestamp(T0 + 30 * 86_400 + 1);
    assert_eq!(register_slot(&env, &client, &v, MAKER, 5), 5);
    assert_eq!(client.lookup(&account, &2), None);
}

/// #422 D17b: with no guard wired there is nobody to ask, so a dead slot keeps its place for the grace.
#[test]
fn register_at_cap_no_guard_wired_keeps_a_dead_slot_until_the_grace() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    for i in 0..5 {
        register_slot(&env, &client, &v, MAKER, i);
    }
    set_valid_until(&env, &client, &v, MAKER, 2, true);
    env.ledger().set_timestamp(T0 + 1);
    let r = slot_reg(&v, MAKER, 5);
    assert_eq!(
        client.try_register(
            &account,
            &signed(&env, &oa(&v, MAKER)["register"][5]),
            &bn::<96>(&env, &r["pkNative"]),
            &bn::<192>(&env, &r["pop"]),
            &5,
        ),
        Err(Ok(RegistryError::RegistryFull))
    );
    env.ledger().set_timestamp(T0 + 30 * 86_400 + 1);
    assert_eq!(register_slot(&env, &client, &v, MAKER, 5), 5);
    assert_eq!(client.lookup(&account, &2), None);
}

/// #422 D14b: a shorten on a slot that already died cannot move its death later — a re-kill after
/// an order's window must not erase an expiry inside it.
#[test]
fn set_valid_until_recorded_expiry_only_moves_earlier() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    register_slot(&env, &client, &v, MAKER, 0);
    set_valid_until(&env, &client, &v, MAKER, 0, false); // at T0, naming grace_ts
    let g = grace_ts(&v);
    env.ledger().set_timestamp(g + 100);
    set_valid_until(&env, &client, &v, MAKER, 0, true); // a kill to 1, after the slot died at g
    assert!(
        client.any_slot_expired_within(&account, &g, &g),
        "still died at g"
    );
    assert!(
        !client.any_slot_expired_within(&account, &(g + 1), &u64::MAX),
        "not at the re-kill"
    );
}

/// In-grace slots still count toward the cap and are not pruned.
#[test]
fn in_grace_slot_is_not_pruned() {
    let (env, client, v) = setup();
    for i in 0..5 {
        register_slot(&env, &client, &v, MAKER, i);
    }
    set_valid_until(&env, &client, &v, MAKER, 0, false); // grace_ts, in the future
    let r = slot_reg(&v, MAKER, 5);
    assert_eq!(
        client.try_register(
            &slot_account(&env, &v, MAKER),
            &OwnerAuth::Stellar(maker_owner(&env, &v)),
            &bn::<96>(&env, &r["pkNative"]),
            &bn::<192>(&env, &r["pop"]),
            &5,
        ),
        Err(Ok(RegistryError::RegistryFull))
    );
}

/// The T1 "re-register the same key at nonce 1" vector is now a reuse: rejected.
#[test]
fn reused_key_rejected() {
    let (env, client, v) = setup();
    let r = reg(&v, MAKER);
    let rot = &r["registerAtNonce1"];
    let account = bn::<32>(&env, &r["account"]);
    let owner = maker_owner(&env, &v);
    client.register(
        &account,
        &OwnerAuth::Stellar(owner.clone()),
        &bn::<96>(&env, &r["pkNative"]),
        &bn::<192>(&env, &r["pop"]),
        &0,
    );
    assert_eq!(
        client.try_register(
            &account,
            &OwnerAuth::Stellar(owner),
            &bn::<96>(&env, &rot["pkNative"]),
            &bn::<192>(&env, &rot["pop"]),
            &1,
        ),
        Err(Ok(RegistryError::KeyPreviouslyUsed))
    );
    assert!(client.is_used(&account, &bn::<32>(&env, &r["commitment"])));
}

/// A retired key stays used: it cannot re-enter a slot.
#[test]
fn reused_key_rejected_after_retirement() {
    let (env, client, v) = setup();
    let r = reg(&v, MAKER);
    let rot = &r["registerAtNonce1"];
    let account = bn::<32>(&env, &r["account"]);
    let owner = maker_owner(&env, &v);
    client.register(
        &account,
        &OwnerAuth::Stellar(owner.clone()),
        &bn::<96>(&env, &r["pkNative"]),
        &bn::<192>(&env, &r["pop"]),
        &0,
    );
    set_valid_until(&env, &client, &v, MAKER, 0, true);
    assert_eq!(
        client.try_register(
            &account,
            &OwnerAuth::Stellar(owner),
            &bn::<96>(&env, &rot["pkNative"]),
            &bn::<192>(&env, &rot["pop"]),
            &1,
        ),
        Err(Ok(RegistryError::KeyPreviouslyUsed))
    );
}

/// revoke drops every slot; the next registration continues the id sequence.
#[test]
fn revoke_clears_all_slots_and_next_id_keeps_advancing() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    register_slot(&env, &client, &v, MAKER, 0);
    client.revoke(&account, &OwnerAuth::Stellar(maker_owner(&env, &v)), &1);
    assert_eq!(client.live_slots(&account).len(), 0);

    assert_eq!(register_slot(&env, &client, &v, MAKER, 2), 1); // nonce 2, fresh key -> slot 1
    assert_eq!(client.live_slots(&account).len(), 1);
    assert_eq!(client.next_slot_id(&account), 2);
    assert_eq!(client.lookup(&account, &0), None);
}

// =============================================================================
// set_valid_until: shorten-only, nonce-free, use-time expiry
// =============================================================================

#[test]
fn set_valid_until_retires_immediately() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, BRIDGER);
    register_slot(&env, &client, &v, BRIDGER, 0);
    let nonce_before = client.nonce_of(&account);

    set_valid_until(&env, &client, &v, BRIDGER, 0, true);

    assert_eq!(
        client.try_commitment_at(&account, &0),
        Err(Ok(RegistryError::SlotExpired))
    );
    assert_eq!(client.lookup(&account, &0).unwrap().valid_until, 1); // history kept
    assert_eq!(client.nonce_of(&account), nonce_before); // nonce-free
}

#[test]
fn set_valid_until_grace_boundary() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    register_slot(&env, &client, &v, MAKER, 0);
    set_valid_until(&env, &client, &v, MAKER, 0, false);
    let g = grace_ts(&v);

    env.ledger().set_timestamp(g - 1);
    assert_eq!(
        client.commitment_at(&account, &0),
        slot_commitment(&env, &v, MAKER, 0)
    );
    env.ledger().set_timestamp(g);
    assert_eq!(
        client.try_commitment_at(&account, &0),
        Err(Ok(RegistryError::SlotExpired))
    );
}

#[test]
fn set_valid_until_shorten_only_and_never_zero() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, BRIDGER);
    register_slot(&env, &client, &v, BRIDGER, 0);
    assert_eq!(
        client.try_set_valid_until(
            &account,
            &svu_owner(&env, &v, BRIDGER, 0, true),
            &fingerprint(&env, &v, BRIDGER, 0),
            &0
        ),
        Err(Ok(RegistryError::BadValidUntil))
    );
    set_valid_until(&env, &client, &v, BRIDGER, 0, true); // -> 1
    assert_eq!(
        client.try_set_valid_until(
            &account,
            &svu_owner(&env, &v, BRIDGER, 0, false),
            &fingerprint(&env, &v, BRIDGER, 0),
            &grace_ts(&v)
        ),
        Err(Ok(RegistryError::BadValidUntil))
    );
}

#[test]
fn set_valid_until_unknown_slot_rejected() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, BRIDGER);
    register_slot(&env, &client, &v, BRIDGER, 0);
    assert_eq!(
        client.try_set_valid_until(
            &account,
            &svu_owner(&env, &v, BRIDGER, 1, true),
            &fingerprint(&env, &v, BRIDGER, 1),
            &1
        ),
        Err(Ok(RegistryError::NoSuchSlot))
    );
}

#[test]
fn set_valid_until_sig_bound_to_key_value_and_signer() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, BRIDGER);
    register_slot(&env, &client, &v, BRIDGER, 0);
    register_slot(&env, &client, &v, BRIDGER, 1);
    let fp0 = fingerprint(&env, &v, BRIDGER, 0);
    // key-0 signature replayed against key 1
    assert_eq!(
        client.try_set_valid_until(
            &account,
            &svu_owner(&env, &v, BRIDGER, 0, true),
            &fingerprint(&env, &v, BRIDGER, 1),
            &1
        ),
        Err(Ok(RegistryError::OwnerMismatch))
    );
    // value-1 signature used for a different value
    assert_eq!(
        client.try_set_valid_until(&account, &svu_owner(&env, &v, BRIDGER, 0, true), &fp0, &2),
        Err(Ok(RegistryError::OwnerMismatch))
    );
    // parity flipped -> different recovered signer
    let e = &oa(&v, BRIDGER)["retire"][0];
    let mut bad = bn::<65>(&env, &e["sig"]).to_array();
    bad[64] = if bad[64] == 27 { 28 } else { 27 };
    assert_eq!(
        client.try_set_valid_until(
            &account,
            &signed_with(
                &env,
                Vec::new(&env),
                OwnerSig::Secp256k1(BytesN::from_array(&env, &bad))
            ),
            &fp0,
            &1
        ),
        Err(Ok(RegistryError::OwnerMismatch))
    );
}

/// A retirement signed before later writes still lands (no nonce), and replay is a no-op.
#[test]
fn pre_signed_retirement_survives_later_writes_and_replay_is_noop() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, BRIDGER);
    register_slot(&env, &client, &v, BRIDGER, 0);
    let pre_signed = svu_owner(&env, &v, BRIDGER, 0, true);

    register_slot(&env, &client, &v, BRIDGER, 1); // rotation
    set_valid_until(&env, &client, &v, BRIDGER, 1, false); // another retirement, other slot
    let nonce = client.nonce_of(&account);

    let fp0 = fingerprint(&env, &v, BRIDGER, 0);
    client.set_valid_until(&account, &pre_signed, &fp0, &1);
    assert_eq!(
        client.try_commitment_at(&account, &0),
        Err(Ok(RegistryError::SlotExpired))
    );

    assert_eq!(
        client.try_set_valid_until(&account, &pre_signed, &fp0, &1), // replay
        Err(Ok(RegistryError::BadValidUntil))
    );
    assert_eq!(client.nonce_of(&account), nonce);
    assert_eq!(
        client.commitment_at(&account, &1),
        slot_commitment(&env, &v, BRIDGER, 1)
    );
}

// =============================================================================
// T-01 / T-04: guards never gate retirement or additive register; PoP per slot
// =============================================================================

/// T-01: with the account in flight, retirement and a new slot both succeed.
#[test]
fn t01_retire_and_register_while_in_flight() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    register_slot(&env, &client, &v, MAKER, 0);
    busy_guard(&env, &client);

    set_valid_until(&env, &client, &v, MAKER, 0, true);
    assert_eq!(
        client.try_commitment_at(&account, &0),
        Err(Ok(RegistryError::SlotExpired))
    );

    assert_eq!(register_slot(&env, &client, &v, MAKER, 1), 1);
    assert_eq!(
        client.commitment_at(&account, &1),
        slot_commitment(&env, &v, MAKER, 1)
    );
}

#[test]
fn t01_evm_home_retire_and_register_while_in_flight() {
    let (env, client, v) = setup();
    register_slot(&env, &client, &v, BRIDGER, 0);
    busy_guard(&env, &client);
    set_valid_until(&env, &client, &v, BRIDGER, 0, true);
    assert_eq!(register_slot(&env, &client, &v, BRIDGER, 1), 1);
}

/// T-04: a second slot needs its own PoP; a PoP bound to another nonce/key fails.
#[test]
fn t04_second_slot_needs_fresh_pop() {
    let (env, client, v) = setup();
    register_slot(&env, &client, &v, BRIDGER, 0);
    let r1 = slot_reg(&v, BRIDGER, 1);
    let r0 = slot_reg(&v, BRIDGER, 0);
    assert_eq!(
        client.try_register(
            &slot_account(&env, &v, BRIDGER),
            &signed(&env, &oa(&v, BRIDGER)["register"][1]),
            &bn::<96>(&env, &r1["pkNative"]),
            &bn::<192>(&env, &r0["pop"]), // slot-0 PoP
            &1,
        ),
        Err(Ok(RegistryError::InvalidPop))
    );
}

// =============================================================================
// 2.6: the ed25519 owner signs the fixed text (SEP-53) — also the maker's pre-signed kill switch
// =============================================================================

/// Sign `text` the way a Stellar wallet does (SEP-53: sha256(prefix ‖ text)), with any ed25519 key.
fn sep53_sign_text(env: &Env, text: &str, sk: &[u8; 32]) -> BytesN<64> {
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    let mut msg = b"Stellar Signed Message:\n".to_vec();
    msg.extend_from_slice(text.as_bytes());
    let payload = Sha256::digest(&msg);
    let sig = SigningKey::from_bytes(sk).sign(&payload);
    BytesN::from_array(env, &sig.to_bytes())
}

/// Sign an EIP-712 digest the way an EVM wallet does: r ‖ s ‖ v, v = 27/28.
fn secp_sign(env: &Env, digest: &[u8; 32], sk: &[u8]) -> BytesN<65> {
    let key = k256::ecdsa::SigningKey::from_slice(sk).unwrap();
    let (sig, rec) = key.sign_prehash_recoverable(digest).unwrap();
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig.to_bytes());
    out[64] = rec.to_byte() + 27;
    BytesN::from_array(env, &out)
}

fn maker_wallet_sk(v: &serde_json::Value) -> [u8; 32] {
    hexval(&v["keys"]["makerWallet"]["sk"]).try_into().unwrap()
}

fn text_of(e: &serde_json::Value) -> &str {
    e["text"].as_str().unwrap()
}

/// The panic a failing call raises, as text. A bad ed25519 signature traps in the host; the
/// generated `try_` client folds that into `InvokeError::Abort`, so the type is only visible here.
fn panic_message(f: impl FnOnce()) -> std::string::String {
    let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
        .expect_err("the call should trap");
    payload
        .downcast_ref::<std::string::String>()
        .cloned()
        .or_else(|| {
            payload
                .downcast_ref::<&str>()
                .map(|m| std::string::String::from(*m))
        })
        .unwrap_or_default()
}

/// The exact host error the relayer's `isPermanentRevert` keys on (`Error(Crypto`).
const CRYPTO_TRAP: &str = "HostError: Error(Crypto, InvalidInput)";

fn assert_crypto_trap(f: impl FnOnce(), what: &str) {
    let msg = panic_message(f);
    assert!(
        msg.starts_with(CRYPTO_TRAP),
        "{what}: wanted a Crypto trap, got: {msg}"
    );
}

/// The vector's SEP-53 retirement (the generator's signature, not this test's) retires the slot.
#[test]
fn sep53_vector_retires_the_makers_slot() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    register_slot(&env, &client, &v, MAKER, 0);
    let e = &oa(&v, MAKER)["retire"][0];
    assert_eq!(e["scheme"], "sep53");
    client.set_valid_until(
        &account,
        &signed(&env, e),
        &fingerprint(&env, &v, MAKER, 0),
        &1,
    );
    assert_eq!(
        client.try_commitment_at(&account, &0),
        Err(Ok(RegistryError::SlotExpired))
    );
}

/// Any SEP-53 wallet's output lands: a fresh signature by the maker's key over the vector's text.
#[test]
fn sep53_fresh_signature_over_the_text_verifies() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    let sk = maker_wallet_sk(&v);
    let r0 = slot_reg(&v, MAKER, 0);
    let e0 = &oa(&v, MAKER)["register"][0];
    client.register(
        &account,
        &signed_with(
            &env,
            legs_of(&env, e0),
            OwnerSig::Sep53(sep53_sign_text(&env, text_of(e0), &sk)),
        ),
        &bn::<96>(&env, &r0["pkNative"]),
        &bn::<192>(&env, &r0["pop"]),
        &0,
    );
    let e = &oa(&v, MAKER)["retire"][1]; // (key 0, graceTs)
    client.set_valid_until(
        &account,
        &signed_with(
            &env,
            Vec::new(&env),
            OwnerSig::Sep53(sep53_sign_text(&env, text_of(e), &sk)),
        ),
        &fingerprint(&env, &v, MAKER, 0),
        &grace_ts(&v),
    );
    assert_eq!(
        client.lookup(&account, &0).unwrap().valid_until,
        grace_ts(&v)
    );
    let e1 = &oa(&v, MAKER)["revoke"][1];
    client.revoke(
        &account,
        &signed_with(
            &env,
            legs_of(&env, e1),
            OwnerSig::Sep53(sep53_sign_text(&env, text_of(e1), &sk)),
        ),
        &1,
    );
    assert_eq!(client.live_slots(&account).len(), 0);
}

/// A stranger's key over the same text traps in the host's ed25519 verify: nothing changes.
#[test]
fn sep53_wrong_key_traps_and_changes_nothing() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    register_slot(&env, &client, &v, MAKER, 0);
    let sig = sep53_sign_text(&env, text_of(&oa(&v, MAKER)["retire"][0]), &[7u8; 32]);
    assert_crypto_trap(
        || {
            client.set_valid_until(
                &account,
                &signed_with(&env, Vec::new(&env), OwnerSig::Sep53(sig)),
                &fingerprint(&env, &v, MAKER, 0),
                &1,
            );
        },
        "a stranger's retirement",
    );
    assert_eq!(client.lookup(&account, &0).unwrap().valid_until, 0);
}

#[test]
fn register_stellar_home_account_via_sep53() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    assert_eq!(register_slot(&env, &client, &v, MAKER, 0), 0);
    assert_eq!(
        client.commitment_at(&account, &0),
        slot_commitment(&env, &v, MAKER, 0)
    );
    assert_eq!(client.nonce_of(&account), 1);
}

#[test]
fn revoke_stellar_home_account_via_sep53() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    register_slot(&env, &client, &v, MAKER, 0);
    client.revoke(&account, &signed(&env, &oa(&v, MAKER)["revoke"][1]), &1);
    assert_eq!(
        client.try_commitment_at(&account, &0),
        Err(Ok(RegistryError::NoSuchSlot))
    );
    assert_eq!(client.nonce_of(&account), 2);
}

/// The message kind is bound: a register signature (with its own legs at nonce 1) is not a revoke.
#[test]
fn sep53_register_signature_does_not_authorise_the_revoke() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    register_slot(&env, &client, &v, MAKER, 0);
    let replayed = signed(&env, &oa(&v, MAKER)["register"][1]); // legs at nonce 1, a RegisterKey
    assert_crypto_trap(
        || {
            client.revoke(&account, &replayed, &1);
        },
        "a register signature presented as a revoke",
    );
    assert_eq!(client.nonce_of(&account), 1);
    assert_eq!(client.live_slots(&account).len(), 1);
}

#[test]
fn sep53_signature_bound_to_key_and_value() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    register_slot(&env, &client, &v, MAKER, 0);
    register_slot(&env, &client, &v, MAKER, 1);
    let key0_retire = svu_owner(&env, &v, MAKER, 0, true);
    assert_crypto_trap(
        || {
            client.set_valid_until(&account, &key0_retire, &fingerprint(&env, &v, MAKER, 1), &1);
        },
        "key 1 under key 0's retirement",
    );
    assert_crypto_trap(
        || {
            client.set_valid_until(
                &account,
                &key0_retire,
                &fingerprint(&env, &v, MAKER, 0),
                &grace_ts(&v),
            );
        },
        "another value under value 1's signature",
    );
    assert_eq!(client.lookup(&account, &0).unwrap().valid_until, 0);
    assert_eq!(client.lookup(&account, &1).unwrap().valid_until, 0);
}

// =============================================================================
// 2.6 plan §4: every refusal, both signature schemes
// =============================================================================

/// One signature registers on both registries: the vector's legs name Sepolia and this chain.
#[test]
fn one_signature_names_both_registries() {
    let (_env, _client, v) = setup();
    for who in [MAKER, BRIDGER] {
        let legs = oa(&v, who)["register"][0]["legs"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(legs.len(), 2);
        assert_eq!(legs[0]["chainId"], v["chains"]["sepolia"]["chainId"]);
        assert_eq!(legs[1]["chainId"], v["chains"]["stellarTestnet"]["chainId"]);
    }
}

/// A single-leg signature naming only this registry is enough here.
#[test]
fn a_signature_naming_only_this_registry_registers() {
    let (env, client, v) = setup();
    for who in [MAKER, BRIDGER] {
        let r = slot_reg(&v, who, 0);
        assert_eq!(
            client.register(
                &slot_account(&env, &v, who),
                &signed(&env, &oa(&v, who)["onlyStellarLeg"]),
                &bn::<96>(&env, &r["pkNative"]),
                &bn::<192>(&env, &r["pop"]),
                &0,
            ),
            0
        );
    }
}

/// Refusal: a signature over a different leg set (another registry's nonce moved, or a leg added).
#[test]
fn a_signature_over_a_different_leg_set_is_refused() {
    let (env, client, v) = setup();
    for who in [MAKER, BRIDGER] {
        let e = &oa(&v, who)["register"][0];
        let r = slot_reg(&v, who, 0);
        let account = slot_account(&env, &v, who);
        let mut moved = legs_of(&env, e);
        let mut sepolia = moved.get(0).unwrap();
        sepolia.nonce += 1;
        moved.set(0, sepolia);
        let mut added = legs_of(&env, e);
        added.push_back(KeyLeg {
            chain_id: 84532,
            registry: BytesN::from_array(&env, &[0x33; 32]),
            nonce: 0,
        });
        for legs in [moved, added] {
            let auth = signed_with(&env, legs, sig_of(&env, e));
            let (pk, pop) = (bn::<96>(&env, &r["pkNative"]), bn::<192>(&env, &r["pop"]));
            if who == BRIDGER {
                assert_eq!(
                    client.try_register(&account, &auth, &pk, &pop, &0),
                    Err(Ok(RegistryError::OwnerMismatch))
                );
            } else {
                assert_crypto_trap(
                    || {
                        client.register(&account, &auth, &pk, &pop, &0);
                    },
                    "sep53 over another leg set",
                );
            }
        }
        assert_eq!(client.nonce_of(&account), 0);
    }
}

/// Refusal: `legs` without this registry's own leg (a valid signature naming only the EVM leg).
#[test]
fn legs_without_the_own_leg_are_refused() {
    let (env, client, v) = setup();
    for who in [MAKER, BRIDGER] {
        let r = slot_reg(&v, who, 0);
        assert_eq!(
            client.try_register(
                &slot_account(&env, &v, who),
                &signed(&env, &oa(&v, who)["onlySepoliaLeg"]),
                &bn::<96>(&env, &r["pkNative"]),
                &bn::<192>(&env, &r["pop"]),
                &0,
            ),
            Err(Ok(RegistryError::LegMismatch))
        );
    }
}

/// Refusal: this registry's own leg twice, under a valid signature over exactly those legs.
#[test]
fn the_own_leg_twice_is_refused() {
    let (env, client, v) = setup();
    for who in [MAKER, BRIDGER] {
        let r = slot_reg(&v, who, 0);
        assert_eq!(
            client.try_register(
                &slot_account(&env, &v, who),
                &signed(&env, &oa(&v, who)["duplicateLegs"]),
                &bn::<96>(&env, &r["pkNative"]),
                &bn::<192>(&env, &r["pop"]),
                &0,
            ),
            Err(Ok(RegistryError::LegMismatch))
        );
    }
}

/// Refusal: a stale nonce. The owner really signed a revoke at nonce 0; once the nonce is 1 its leg
/// is no longer this registry's, whatever `nonce` the caller passes.
#[test]
fn a_stale_nonce_is_refused() {
    let (env, client, v) = setup();
    for who in [MAKER, BRIDGER] {
        let account = slot_account(&env, &v, who);
        register_slot(&env, &client, &v, who, 0);
        let stale = signed(&env, &oa(&v, who)["revoke"][0]);
        assert_eq!(
            client.try_revoke(&account, &stale, &1),
            Err(Ok(RegistryError::LegMismatch))
        );
        assert_eq!(
            client.try_revoke(&account, &stale, &0),
            Err(Ok(RegistryError::BadNonce))
        );
        assert_eq!(client.live_slots(&account).len(), 1);
    }
}

/// Refusal: a text with one byte changed. The maker signed a text one byte off the one the
/// registry rebuilds from the call's arguments.
#[test]
fn a_text_with_one_byte_changed_is_refused() {
    let (env, client, v) = setup();
    let n = &v["ownerAuth"]["negative"]["tamperedText"];
    let real = &oa(&v, MAKER)["register"][0];
    assert_eq!(n["signedText"].as_str().unwrap().len(), text_of(real).len());
    let r = slot_reg(&v, MAKER, 0);
    let auth = signed_with(
        &env,
        legs_of(&env, real),
        OwnerSig::Sep53(bn::<64>(&env, &n["sig"])),
    );
    assert_crypto_trap(
        || {
            client.register(
                &slot_account(&env, &v, MAKER),
                &auth,
                &bn::<96>(&env, &r["pkNative"]),
                &bn::<192>(&env, &r["pop"]),
                &0,
            );
        },
        "a one-byte-off text",
    );
    assert_eq!(client.nonce_of(&slot_account(&env, &v, MAKER)), 0);
}

/// Refusal: a secp256k1 signature on an ed25519 (non-padded) account. The signature is valid and its
/// signer is the account's low 20 bytes: only the padding rule refuses it.
#[test]
fn a_secp256k1_signature_on_an_ed25519_account_is_refused() {
    let (env, client, v) = setup();
    let n = &v["ownerAuth"]["negative"]["secpOnNonEvmAccount"];
    assert_eq!(
        client.try_register(
            &bn::<32>(&env, &n["account"]),
            &signed(&env, n),
            &bn::<96>(&env, &n["stellarTestnet"]["pkNative"]),
            &bn::<192>(&env, &n["stellarTestnet"]["pop"]),
            &0,
        ),
        Err(Ok(RegistryError::OwnerMismatch))
    );
}

/// Refusal: an ed25519 signature on an EVM-shaped (padded) account, register and retire.
#[test]
fn an_ed25519_signature_on_an_evm_account_is_refused() {
    let (env, client, v) = setup();
    let n = &v["ownerAuth"]["negative"]["sep53OnEvmAccount"];
    let r = slot_reg(&v, BRIDGER, 0);
    let account = slot_account(&env, &v, BRIDGER);
    assert_eq!(bn::<32>(&env, &n["account"]), account);
    assert_eq!(
        client.try_register(
            &account,
            &signed(&env, n),
            &bn::<96>(&env, &r["pkNative"]),
            &bn::<192>(&env, &r["pop"]),
            &0
        ),
        Err(Ok(RegistryError::OwnerMismatch))
    );
    register_slot(&env, &client, &v, BRIDGER, 0);
    let sig = sep53_sign_text(
        &env,
        text_of(&oa(&v, BRIDGER)["retire"][0]),
        &maker_wallet_sk(&v),
    );
    assert_eq!(
        client.try_set_valid_until(
            &account,
            &signed_with(&env, Vec::new(&env), OwnerSig::Sep53(sig)),
            &fingerprint(&env, &v, BRIDGER, 0),
            &1
        ),
        Err(Ok(RegistryError::OwnerMismatch))
    );
}

/// A retirement names no legs: one that carries any is refused, even when the signature is sound.
#[test]
fn a_retirement_with_legs_is_refused() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, BRIDGER);
    register_slot(&env, &client, &v, BRIDGER, 0);
    let e = &oa(&v, BRIDGER)["retire"][0];
    let auth = signed_with(
        &env,
        legs_of(&env, &oa(&v, BRIDGER)["register"][0]),
        sig_of(&env, e),
    );
    assert_eq!(
        client.try_set_valid_until(&account, &auth, &fingerprint(&env, &v, BRIDGER, 0), &1),
        Err(Ok(RegistryError::LegMismatch))
    );
}

/// A valid signature for a key the account already used still hits KeyPreviouslyUsed.
#[test]
fn reused_key_rejected_under_a_valid_signature() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    register_slot(&env, &client, &v, MAKER, 0);
    let rot = &reg(&v, MAKER)["registerAtNonce1"]; // the same key's PoP at nonce 1
    assert_eq!(
        client.try_register(
            &account,
            &signed(&env, &oa(&v, MAKER)["reuseKey0AtNonce1"]),
            &bn::<96>(&env, &rot["pkNative"]),
            &bn::<192>(&env, &rot["pop"]),
            &1
        ),
        Err(Ok(RegistryError::KeyPreviouslyUsed))
    );
}

// =============================================================================
// 2.6: the builders equal the vectors byte for byte
// =============================================================================

fn message_of(env: &Env, e: &serde_json::Value) -> KeyMessage {
    let fp = || bn::<32>(env, &e["keyCommitment"]);
    match e["kind"].as_str().unwrap() {
        "register" => KeyMessage::Register {
            fingerprint: fp(),
            nonce: 0,
        },
        "revoke" => KeyMessage::Revoke { nonce: 0 },
        _ => KeyMessage::Retire {
            fingerprint: fp(),
            valid_until: e["validUntil"].as_str().unwrap().parse().unwrap(),
        },
    }
}

#[test]
fn text_and_struct_hash_match_every_vector() {
    let (env, _client, v) = setup();
    let mut entries = std::vec::Vec::new();
    for who in ["maker", "bridger"] {
        let a = &v["ownerAuth"][who];
        for k in ["register", "revoke", "retire"] {
            entries.extend(a[k].as_array().unwrap().iter().cloned());
        }
        for k in [
            "reuseKey0AtNonce1",
            "onlySepoliaLeg",
            "onlyStellarLeg",
            "duplicateLegs",
        ] {
            entries.push(a[k].clone());
        }
    }
    for k in ["secpOnNonEvmAccount", "sep53OnEvmAccount"] {
        entries.push(v["ownerAuth"]["negative"][k].clone());
    }
    assert!(entries.len() > 50);
    for e in &entries {
        let account = bn::<32>(&env, &e["account"]);
        let legs = legs_of(&env, e);
        let msg = message_of(&env, e);
        let text = owner::text(&env, &account, &legs, &msg);
        let mut buf = std::vec![0u8; text.len() as usize];
        text.copy_into_slice(&mut buf);
        assert_eq!(std::str::from_utf8(&buf).unwrap(), text_of(e));
        assert_eq!(
            owner::struct_hash(&env, &account, &legs, &msg).to_vec(),
            hexval(&e["structHash"])
        );
    }
}

#[test]
fn constants_match_the_vectors() {
    let (env, _client, v) = setup();
    let m = &v["ownerAuth"]["_meta"];
    let k = |s: &str| {
        env.crypto()
            .keccak256(&Bytes::from_slice(&env, s.as_bytes()))
            .to_array()
            .to_vec()
    };
    assert_eq!(
        owner::KEY_LEG_TYPEHASH.to_vec(),
        k(m["typeStrings"]["keyLeg"].as_str().unwrap())
    );
    assert_eq!(
        owner::REGISTER_KEY_TYPEHASH.to_vec(),
        k(m["typeStrings"]["registerKey"].as_str().unwrap())
    );
    assert_eq!(
        owner::REVOKE_KEYS_TYPEHASH.to_vec(),
        k(m["typeStrings"]["revokeKeys"].as_str().unwrap())
    );
    assert_eq!(
        owner::RETIRE_KEY_TYPEHASH.to_vec(),
        k(m["typeStrings"]["retireKey"].as_str().unwrap())
    );
    let mut dom = std::vec::Vec::new();
    dom.extend_from_slice(&proofbridge_core::eip712::DOMAIN_TYPEHASH_MIN);
    dom.extend_from_slice(&k("ProofBridge Keys"));
    dom.extend_from_slice(&k("2"));
    let sep = env
        .crypto()
        .keccak256(&Bytes::from_slice(&env, &dom))
        .to_array()
        .to_vec();
    assert_eq!(owner::KEYS_DOMAIN_SEPARATOR.to_vec(), sep);
    assert_eq!(sep, hexval(&m["domainSeparator"]));
}

/// D2: the padded 96-byte key hashes to the vector fingerprint, which is the EVM commitment.
#[test]
fn key_fingerprint_is_the_evm_commitment() {
    let (env, _client, v) = setup();
    for who in [MAKER, BRIDGER] {
        let evm = if who == MAKER {
            "makerOnSepolia"
        } else {
            "bridgerOnSepolia"
        };
        for i in 0..6 {
            let pk = bn::<96>(&env, &slot_reg(&v, who, i)["pkNative"]);
            let fp = owner::key_fingerprint(&env, &pk);
            assert_eq!(fp, fingerprint(&env, &v, who, i));
            assert_eq!(fp, bn::<32>(&env, &slot_reg(&v, evm, i)["commitment"]));
            assert_ne!(
                fp,
                slot_commitment(&env, &v, who, i),
                "storage keeps the native commitment"
            );
        }
    }
}

/// A secp256k1 signature built here over the vector digest lands: the EIP-712 rule is the wallet's.
#[test]
fn a_fresh_secp256k1_signature_over_the_vector_digest_registers() {
    let (env, client, v) = setup();
    let e = &oa(&v, BRIDGER)["register"][2];
    let digest: [u8; 32] = hexval(&e["digest"]).try_into().unwrap();
    let sig = secp_sign(&env, &digest, &hexval(&v["keys"]["bridgerWallet"]["sk"]));
    let r = slot_reg(&v, BRIDGER, 2);
    let account = slot_account(&env, &v, BRIDGER);
    register_slot(&env, &client, &v, BRIDGER, 0);
    register_slot(&env, &client, &v, BRIDGER, 1);
    client.register(
        &account,
        &signed_with(&env, legs_of(&env, e), OwnerSig::Secp256k1(sig)),
        &bn::<96>(&env, &r["pkNative"]),
        &bn::<192>(&env, &r["pop"]),
        &2,
    );
    assert_eq!(
        client.slot_of_key(&account, &fingerprint(&env, &v, BRIDGER, 2)),
        Some(2)
    );
}

/// The fingerprint map follows the slots: a key maps to its slot, a pruned or revoked key to none.
#[test]
fn slot_of_key_follows_registration_and_revoke() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    assert_eq!(
        client.slot_of_key(&account, &fingerprint(&env, &v, MAKER, 0)),
        None
    );
    register_slot(&env, &client, &v, MAKER, 0);
    assert_eq!(
        client.slot_of_key(&account, &fingerprint(&env, &v, MAKER, 0)),
        Some(0)
    );
    client.revoke(&account, &OwnerAuth::Stellar(maker_owner(&env, &v)), &1);
    assert_eq!(
        client.slot_of_key(&account, &fingerprint(&env, &v, MAKER, 0)),
        None
    );
    assert_eq!(register_slot(&env, &client, &v, MAKER, 2), 1);
    assert_eq!(
        client.slot_of_key(&account, &fingerprint(&env, &v, MAKER, 2)),
        Some(1)
    );
    // the retired-then-revoked key's retirement now finds no slot
    assert_eq!(
        client.try_set_valid_until(
            &account,
            &svu_owner(&env, &v, MAKER, 0, true),
            &fingerprint(&env, &v, MAKER, 0),
            &1
        ),
        Err(Ok(RegistryError::NoSuchSlot))
    );
}

#[test]
fn position_guards_view_follows_set_position_guards() {
    let (env, client, _) = setup();
    assert_eq!(client.position_guards().len(), 0);
    let guard = Address::generate(&env);
    client.set_position_guards(&soroban_sdk::vec![&env, guard.clone()]);
    assert_eq!(client.position_guards(), soroban_sdk::vec![&env, guard]);
}

/// #422 D12: the escrow's question, answered directly — did any slot expire in [from, to].
#[test]
fn any_slot_expired_within_reads_the_slots_expiries() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    register_slot(&env, &client, &v, MAKER, 0);
    assert!(
        !client.any_slot_expired_within(&account, &0, &u64::MAX),
        "no expiry: never"
    );
    set_valid_until(&env, &client, &v, MAKER, 0, false);
    let g = grace_ts(&v);
    assert!(
        client.any_slot_expired_within(&account, &g, &g),
        "the boundary is inclusive"
    );
    assert!(client.any_slot_expired_within(&account, &(g - 100), &(g + 100)));
    assert!(
        !client.any_slot_expired_within(&account, &(g + 1), &(g + 100)),
        "after: no"
    );
    assert!(
        !client.any_slot_expired_within(&account, &0, &(g - 1)),
        "before: no"
    );
}

/// C-13: the escrows and the verifier read this registry on every lock and unlock, so each read
/// and write entry point keeps the instance alive. Each step ages the instance past the threshold
/// first, so a step that stopped extending is caught by name.
#[test]
fn read_and_write_entry_points_extend_the_instance_ttl() {
    use proofbridge_core::ttl::{INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD};
    use soroban_sdk::testutils::storage::Instance as _;

    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    register_slot(&env, &client, &v, MAKER, 0);

    let ttl = || env.as_contract(&client.address, || env.storage().instance().get_ttl());
    let age = || {
        let by = ttl() - INSTANCE_LIFETIME_THRESHOLD + 1;
        env.ledger().with_mut(|l| l.sequence_number += by);
        assert!(
            ttl() < INSTANCE_LIFETIME_THRESHOLD,
            "set-up: the instance is due"
        );
    };
    let steps: [(&str, &dyn Fn()); 5] = [
        ("has_usable_slot", &|| {
            assert!(client.has_usable_slot(&account))
        }),
        ("any_slot_expired_within", &|| {
            client.any_slot_expired_within(&account, &0, &T0);
        }),
        ("lookup", &|| assert!(client.lookup(&account, &0).is_some())),
        ("commitment_at", &|| {
            client.commitment_at(&account, &0);
        }),
        ("register", &|| {
            register_slot(&env, &client, &v, MAKER, 1);
        }),
    ];
    for (name, step) in steps {
        age();
        step();
        assert_eq!(
            ttl(),
            INSTANCE_BUMP_AMOUNT,
            "{name} did not extend the instance"
        );
    }
}

// ---- soak batch D (C-19): every reachable error, named ----

/// A second `initialize` is refused; the chain id stays.
#[test]
fn initialize_twice_is_already_initialized() {
    let (env, client, _) = setup();
    assert_eq!(
        client.try_initialize(&Address::generate(&env), &7),
        Err(Ok(RegistryError::AlreadyInitialized))
    );
    assert_eq!(client.chain_id(), CHAIN_ID);
}

/// Before `initialize`, every write path refuses.
#[test]
fn an_uninitialized_registry_is_not_initialized() {
    let env = Env::default();
    env.mock_all_auths();
    let client = BlsKeyRegistryClient::new(&env, &env.register(BlsKeyRegistry, ()));
    let v = vectors();
    let r = reg(&v, "makerOnStellarTestnet");
    let account = bn::<32>(&env, &r["account"]);
    let owner = OwnerAuth::Stellar(maker_owner(&env, &v));
    let e = Some(Ok(RegistryError::NotInitialized));
    assert_eq!(
        client
            .try_register(
                &account,
                &owner,
                &bn::<96>(&env, &r["pkNative"]),
                &bn::<192>(&env, &r["pop"]),
                &0
            )
            .err(),
        e
    );
    assert_eq!(
        client
            .try_set_valid_until(&account, &owner, &BytesN::from_array(&env, &[0; 32]), &1)
            .err(),
        e
    );
    assert_eq!(client.try_revoke(&account, &owner, &0).err(), e);
    assert_eq!(
        client
            .try_set_position_guards(&soroban_sdk::vec![&env])
            .err(),
        e
    );
}
