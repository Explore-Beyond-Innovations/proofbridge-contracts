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

/// The vector says how the owner signed: the maker registers by `require_auth` and retires by a
/// detached SEP-53 signature (#404); the bridger always signs with its EVM key.
fn owner_for(
    env: &Env,
    v: &serde_json::Value,
    who: &str,
    owner_sig: &serde_json::Value,
) -> OwnerAuth {
    if who == MAKER {
        if owner_sig["scheme"] == "sep53-ed25519" {
            OwnerAuth::Sep53(bn::<64>(env, &owner_sig["sig"]))
        } else {
            OwnerAuth::Stellar(maker_owner(env, v))
        }
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

// =============================================================================
// #404: the detached ed25519 owner-auth (`Sep53`) — the maker's pre-signed kill switch
// =============================================================================

/// Sign `digest` the way a Stellar wallet does (SEP-53: sha256(prefix ‖ lowercase 0x-hex)),
/// with the vector maker's ed25519 key or a stranger's.
fn sep53_sign(env: &Env, digest: &[u8; 32], sk: &[u8; 32]) -> BytesN<64> {
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    let mut msg = b"Stellar Signed Message:\n".to_vec();
    msg.extend_from_slice(std::format!("0x{}", hex::encode(digest)).as_bytes());
    let payload = Sha256::digest(&msg);
    let sig = SigningKey::from_bytes(sk).sign(&payload);
    BytesN::from_array(env, &sig.to_bytes())
}

fn maker_wallet_sk(v: &serde_json::Value) -> [u8; 32] {
    hexval(&v["keys"]["makerWallet"]["sk"]).try_into().unwrap()
}

fn digest32(v: &serde_json::Value) -> [u8; 32] {
    hexval(v).try_into().unwrap()
}

/// The vectors' Soroban `setValidUntil` entries carry `sep53-ed25519` signatures for the maker,
/// so every `set_valid_until` case above already runs under `Sep53`; this pins the bytes.
#[test]
fn sep53_vector_retires_the_makers_slot() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    register_slot(&env, &client, &v, MAKER, 0);
    let e = &v["slots"][MAKER]["setValidUntil"][0];
    assert_eq!(e["ownerSig"]["scheme"], "sep53-ed25519");
    client.set_valid_until(
        &account,
        &OwnerAuth::Sep53(bn::<64>(&env, &e["ownerSig"]["sig"])),
        &0,
        &1,
    );
    assert_eq!(
        client.try_commitment_at(&account, &0),
        Err(Ok(RegistryError::SlotExpired))
    );
}

/// The message rule is the EVM registry's byte for byte: a fresh signature by the maker's key
/// over the vector's digest verifies, so any SEP-53 wallet's output lands.
#[test]
fn sep53_fresh_signature_over_the_digest_verifies() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    register_slot(&env, &client, &v, MAKER, 0);
    let e = &v["slots"][MAKER]["setValidUntil"][1]; // (slot 0, graceTs)
    let sig = sep53_sign(&env, &digest32(&e["digest"]), &maker_wallet_sk(&v));
    client.set_valid_until(&account, &OwnerAuth::Sep53(sig), &0, &grace_ts(&v));
    assert_eq!(
        client.lookup(&account, &0).unwrap().valid_until,
        grace_ts(&v)
    );
}

/// A stranger's key over the same digest traps in the host's ed25519 verify (D3): nothing
/// changes on-chain, and the relayer treats the trap as a permanent revert.
#[test]
fn sep53_wrong_key_traps_and_changes_nothing() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    register_slot(&env, &client, &v, MAKER, 0);
    let e = &v["slots"][MAKER]["setValidUntil"][0];
    let stranger = [7u8; 32];
    let sig = sep53_sign(&env, &digest32(&e["digest"]), &stranger);
    let msg = panic_message(|| {
        client.set_valid_until(&account, &OwnerAuth::Sep53(sig), &0, &1);
    });
    assert!(
        msg.starts_with(CRYPTO_TRAP),
        "a bad ed25519 signature is a host Crypto trap, got: {msg}"
    );
    assert_eq!(client.lookup(&account, &0).unwrap().valid_until, 0);
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

/// A signature bound to slot 0 / value 1 does not retire slot 1 or set another value.
/// The other legal path for a Stellar-home owner (#404): a detached SEP-53 signature rather than
/// `require_auth`, which is what lets the relayer submit on the tenant's behalf. Same account and
/// the same digests as `makerOnStellarTestnet` — only the authorisation differs. The signature is
/// the generator's, not one this test builds, so it is the cross-implementation check.
const MAKER_SEP53: &str = "makerSep53OnStellarTestnet";

fn sep53_sig(env: &Env, node: &serde_json::Value) -> BytesN<64> {
    bn::<64>(env, &node["ownerSig"]["sig"])
}

fn register_via_sep53(
    env: &Env,
    client: &BlsKeyRegistryClient,
    v: &serde_json::Value,
) -> (BytesN<32>, serde_json::Value) {
    let r = reg(v, MAKER_SEP53);
    let account = bn::<32>(env, &r["account"]);
    client.register(
        &account,
        &OwnerAuth::Sep53(sep53_sig(env, &r)),
        &bn::<96>(env, &r["pkNative"]),
        &bn::<192>(env, &r["pop"]),
        &0,
    );
    (account, r)
}

#[test]
fn register_stellar_home_account_via_sep53() {
    let (env, client, v) = setup();
    let (account, r) = register_via_sep53(&env, &client, &v);

    assert_eq!(
        client.commitment_at(&account, &0),
        bn::<32>(&env, &r["commitment"])
    );
    assert_eq!(client.nonce_of(&account), 1);
}

#[test]
fn revoke_stellar_home_account_via_sep53() {
    let (env, client, v) = setup();
    let (account, r) = register_via_sep53(&env, &client, &v);

    // The revoke digest binds the bumped nonce, so this is a second, distinct signature.
    client.revoke(
        &account,
        &OwnerAuth::Sep53(sep53_sig(&env, &r["revokeAtNonce1"])),
        &1,
    );

    assert_eq!(
        client.try_commitment_at(&account, &0),
        Err(Ok(RegistryError::NoSuchSlot))
    );
    assert_eq!(client.nonce_of(&account), 2);
}

/// The replay a pre-signed kill switch has to survive: a revoke signature the owner really did
/// produce, for the same account and the same tag, but bound to the previous nonce. Isolating the
/// nonce is the point — replaying the *register* signature instead would differ in both the tag
/// and the nonce and so could not tell the two bindings apart.
#[test]
fn sep53_revoke_signature_does_not_replay_across_nonces() {
    let (env, client, v) = setup();
    let (account, r) = register_via_sep53(&env, &client, &v);
    let stale = sep53_sig(&env, &r["staleRevokeSigAtNonce0"]);

    let msg = panic_message(|| {
        client.revoke(&account, &OwnerAuth::Sep53(stale), &1);
    });
    assert!(
        msg.starts_with(CRYPTO_TRAP),
        "a revoke signature bound to nonce 0 must not authorise nonce 1, got: {msg}"
    );

    // And the refusal left nothing behind.
    assert_eq!(
        client.commitment_at(&account, &0),
        bn::<32>(&env, &r["commitment"])
    );
    assert_eq!(client.nonce_of(&account), 1);
}

/// The tag half of the same binding: a register signature is not a revoke signature.
#[test]
fn sep53_register_signature_does_not_authorise_the_revoke() {
    let (env, client, v) = setup();
    let (account, r) = register_via_sep53(&env, &client, &v);
    let replayed = sep53_sig(&env, &r);

    let msg = panic_message(|| {
        client.revoke(&account, &OwnerAuth::Sep53(replayed), &1);
    });
    assert!(
        msg.starts_with(CRYPTO_TRAP),
        "the register signature must not authorise a revoke, got: {msg}"
    );

    assert_eq!(
        client.commitment_at(&account, &0),
        bn::<32>(&env, &r["commitment"])
    );
    assert_eq!(client.nonce_of(&account), 1);
}

#[test]
fn sep53_signature_bound_to_slot_and_value() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    register_slot(&env, &client, &v, MAKER, 0);
    register_slot(&env, &client, &v, MAKER, 1);
    let e = &v["slots"][MAKER]["setValidUntil"][0];
    let sig = bn::<64>(&env, &e["ownerSig"]["sig"]);
    let other_slot = panic_message(|| {
        client.set_valid_until(&account, &OwnerAuth::Sep53(sig.clone()), &1, &1);
    });
    assert!(
        other_slot.starts_with(CRYPTO_TRAP),
        "slot 1 under slot 0's signature: {other_slot}"
    );
    let other_value = panic_message(|| {
        client.set_valid_until(&account, &OwnerAuth::Sep53(sig), &0, &grace_ts(&v));
    });
    assert!(
        other_value.starts_with(CRYPTO_TRAP),
        "another value under value 1's signature: {other_value}"
    );
    assert_eq!(client.lookup(&account, &0).unwrap().valid_until, 0);
    assert_eq!(client.lookup(&account, &1).unwrap().valid_until, 0);
}

/// The shape rule mirrors the EVM path: a padded-EVM account is never an ed25519 key.
#[test]
fn sep53_refuses_a_padded_evm_account() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, BRIDGER);
    register_slot(&env, &client, &v, BRIDGER, 0);
    let e = &v["slots"][BRIDGER]["setValidUntil"][0];
    let sig = sep53_sign(&env, &digest32(&e["digest"]), &maker_wallet_sk(&v));
    assert_eq!(
        client.try_set_valid_until(&account, &OwnerAuth::Sep53(sig), &0, &1),
        Err(Ok(RegistryError::OwnerMismatch))
    );
}

/// `register` and `revoke` take the same dispatch, so a Stellar-home owner can be relayed there
/// too: detached signatures over the vector's registration and revoke digests.
#[test]
fn sep53_registers_and_revokes_by_detached_signature() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    let sk = maker_wallet_sk(&v);
    let r0 = slot_reg(&v, MAKER, 0);
    client.register(
        &account,
        &OwnerAuth::Sep53(sep53_sign(&env, &digest32(&r0["regDigest"]), &sk)),
        &bn::<96>(&env, &r0["pkNative"]),
        &bn::<192>(&env, &r0["pop"]),
        &0,
    );
    assert_eq!(client.nonce_of(&account), 1);
    // revoke at nonce 1: the digest the vectors record on registration 1
    let r1 = slot_reg(&v, MAKER, 1);
    client.revoke(
        &account,
        &OwnerAuth::Sep53(sep53_sign(&env, &digest32(&r1["revokeDigest"]), &sk)),
        &1,
    );
    assert!(client.try_commitment_at(&account, &0).is_err());
}

#[test]
fn position_guards_view_follows_set_position_guards() {
    let (env, client, _) = setup();
    assert_eq!(client.position_guards().len(), 0);
    let guard = Address::generate(&env);
    client.set_position_guards(&soroban_sdk::vec![&env, guard.clone()]);
    assert_eq!(client.position_guards(), soroban_sdk::vec![&env, guard]);
}

/// #422: a shorten to the past stamps the kill; a rotation's future date does not.
#[test]
fn set_valid_until_stamps_a_kill_but_not_a_rotation() {
    let (env, client, v) = setup();
    let account = slot_account(&env, &v, MAKER);
    register_slot(&env, &client, &v, MAKER, 0);
    assert_eq!(client.last_retired_at(&account), 0);
    set_valid_until(&env, &client, &v, MAKER, 0, false);
    assert_eq!(
        client.last_retired_at(&account),
        0,
        "a rotation is not a kill"
    );
    env.ledger().set_timestamp(T0 + 5);
    set_valid_until(&env, &client, &v, MAKER, 0, true);
    assert_eq!(client.last_retired_at(&account), T0 + 5);
}
