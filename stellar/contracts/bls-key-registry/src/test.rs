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

fn sig65(env: &Env, owner_sig: &serde_json::Value) -> BytesN<65> {
    let mut out = [0u8; 65];
    out[..32].copy_from_slice(&hexval(&owner_sig["sig"]["r"]));
    out[32..64].copy_from_slice(&hexval(&owner_sig["sig"]["s"]));
    out[64] = owner_sig["sig"]["v"].as_u64().unwrap() as u8;
    BytesN::from_array(env, &out)
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

fn owner_for(
    env: &Env,
    v: &serde_json::Value,
    who: &str,
    owner_sig: &serde_json::Value,
) -> OwnerAuth {
    if who == MAKER {
        OwnerAuth::Stellar(maker_owner(env, v))
    } else {
        OwnerAuth::Evm(sig65(env, owner_sig))
    }
}

/// Registers slot vector i for `who` at nonce i; returns the slot id.
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
        &owner_for(env, v, who, &r["ownerSig"]),
        &bn::<96>(env, &r["pkNative"]),
        &bn::<192>(env, &r["pop"]),
        &(i as u64),
    )
}

fn slot_commitment(env: &Env, v: &serde_json::Value, who: &str, i: usize) -> BytesN<32> {
    bn::<32>(env, &slot_reg(v, who, i)["commitment"])
}

fn grace_ts(v: &serde_json::Value) -> u64 {
    v["slots"]["graceTs"].as_str().unwrap().parse().unwrap()
}

/// `slots.<who>.setValidUntil[]` is (slotId, validUntil) x {1, graceTs}: index = slotId*2 + (retire ? 0 : 1).
fn svu_owner(env: &Env, v: &serde_json::Value, who: &str, slot_id: u32, retire: bool) -> OwnerAuth {
    let e = &v["slots"][who]["setValidUntil"][(slot_id as usize) * 2 + if retire { 0 } else { 1 }];
    owner_for(env, v, who, &e["ownerSig"])
}

fn set_valid_until(
    env: &Env,
    client: &BlsKeyRegistryClient,
    v: &serde_json::Value,
    who: &str,
    slot_id: u32,
    retire: bool,
) {
    client.set_valid_until(
        &slot_account(env, v, who),
        &svu_owner(env, v, who, slot_id, retire),
        &slot_id,
        &if retire { 1 } else { grace_ts(v) },
    );
}

fn busy_guard(env: &Env, client: &BlsKeyRegistryClient) {
    let guard = env.register(MockGuard, ());
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
fn register_evm_home_account_via_personal_sign() {
    let (env, client, v) = setup();
    let r = reg(&v, "bridgerOnStellarTestnet");

    client.register(
        &bn::<32>(&env, &r["account"]),
        &OwnerAuth::Evm(sig65(&env, &r["ownerSig"])),
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
    let r = reg(&v, "bridgerOnStellarTestnet");
    let account = bn::<32>(&env, &r["account"]);

    client.register(
        &account,
        &OwnerAuth::Evm(sig65(&env, &r["ownerSig"])),
        &bn::<96>(&env, &r["pkNative"]),
        &bn::<192>(&env, &r["pop"]),
        &0,
    );
    client.revoke(
        &account,
        &OwnerAuth::Evm(sig65(&env, &r["revokeAtNonce1"]["ownerSig"])),
        &1,
    );

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

    // Flip the recovery parity: recovers a different key → different address.
    let mut bad = sig65(&env, &r["ownerSig"]).to_array();
    bad[64] = if bad[64] == 27 { 28 } else { 27 };

    assert_eq!(
        client.try_register(
            &bn::<32>(&env, &r["account"]),
            &OwnerAuth::Evm(BytesN::from_array(&env, &bad)),
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
    for i in 0..5 {
        register_slot(&env, &client, &v, MAKER, i);
    }
    set_valid_until(&env, &client, &v, MAKER, 2, true); // valid_until = 1, past grace already
    env.ledger().set_timestamp(T0 + 1);

    assert_eq!(register_slot(&env, &client, &v, MAKER, 5), 5);
    assert_eq!(client.lookup(&account, &2), None);
    assert_eq!(client.live_slots(&account).len(), 5);
    assert_eq!(client.next_slot_id(&account), 6);
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
        client.try_set_valid_until(&account, &svu_owner(&env, &v, BRIDGER, 0, true), &0, &0),
        Err(Ok(RegistryError::BadValidUntil))
    );
    set_valid_until(&env, &client, &v, BRIDGER, 0, true); // -> 1
    assert_eq!(
        client.try_set_valid_until(
            &account,
            &svu_owner(&env, &v, BRIDGER, 0, false),
            &0,
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
        client.try_set_valid_until(&account, &svu_owner(&env, &v, BRIDGER, 1, true), &1, &1),
        Err(Ok(RegistryError::NoSuchSlot))
    );
}

#[test]
fn set_valid_until_sig_bound_to_slot_value_and_signer() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, BRIDGER);
    register_slot(&env, &client, &v, BRIDGER, 0);
    register_slot(&env, &client, &v, BRIDGER, 1);
    // slot-0 signature replayed against slot 1
    assert_eq!(
        client.try_set_valid_until(&account, &svu_owner(&env, &v, BRIDGER, 0, true), &1, &1),
        Err(Ok(RegistryError::OwnerMismatch))
    );
    // value-1 signature used for a different value
    assert_eq!(
        client.try_set_valid_until(&account, &svu_owner(&env, &v, BRIDGER, 0, true), &0, &2),
        Err(Ok(RegistryError::OwnerMismatch))
    );
    // parity flipped -> different recovered signer
    let mut bad = match svu_owner(&env, &v, BRIDGER, 0, true) {
        OwnerAuth::Evm(sig) => sig.to_array(),
        _ => unreachable!(),
    };
    bad[64] = if bad[64] == 27 { 28 } else { 27 };
    assert_eq!(
        client.try_set_valid_until(
            &account,
            &OwnerAuth::Evm(BytesN::from_array(&env, &bad)),
            &0,
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

    client.set_valid_until(&account, &pre_signed, &0, &1);
    assert_eq!(
        client.try_commitment_at(&account, &0),
        Err(Ok(RegistryError::SlotExpired))
    );

    assert_eq!(
        client.try_set_valid_until(&account, &pre_signed, &0, &1), // replay
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
            &owner_for(&env, &v, BRIDGER, &r1["ownerSig"]),
            &bn::<96>(&env, &r1["pkNative"]),
            &bn::<192>(&env, &r0["pop"]), // slot-0 PoP
            &1,
        ),
        Err(Ok(RegistryError::InvalidPop))
    );
}
