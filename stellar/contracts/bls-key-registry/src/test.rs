//! Vector-driven tests; the EVM registry suite consumes the same JSON.

#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::{contract, contractimpl, testutils::Address as _, Env, String as SString};

const VECTORS: &str = include_str!("../../../../test-vectors/bls-encodings.json");

// The vectors bind the Soroban registry to chain 1000002 + this dummy id.
const REGISTRY_ID: [u8; 32] = [0x22; 32];
const CHAIN_ID: u128 = 1_000_002;

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
        client.key_of(&bn::<32>(&env, &r["account"])),
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
        client.key_of(&bn::<32>(&env, &r["account"])),
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
        client.try_key_of(&account),
        Err(Ok(RegistryError::NotRegistered))
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
        client.try_key_of(&account),
        Err(Ok(RegistryError::NotRegistered))
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
fn rotation_gated_like_revoke() {
    let (env, client, v) = setup();
    let r = reg(&v, "makerOnStellarTestnet");
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

    let guard = env.register(MockGuard, ());
    client.set_position_guards(&soroban_sdk::vec![&env, guard]);

    assert_eq!(
        client.try_register(
            &account,
            &OwnerAuth::Stellar(owner.clone()),
            &bn::<96>(&env, &rot["pkNative"]),
            &bn::<192>(&env, &rot["pop"]),
            &1,
        ),
        Err(Ok(RegistryError::AccountInFlight))
    );

    client.set_position_guards(&soroban_sdk::vec![&env]);
    client.register(
        &account,
        &OwnerAuth::Stellar(owner),
        &bn::<96>(&env, &rot["pkNative"]),
        &bn::<192>(&env, &rot["pop"]),
        &1,
    );
    assert_eq!(client.nonce_of(&account), 2);
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
    assert_eq!(client.key_of(&account), bn::<32>(&env, &r["commitment"]));
}

#[test]
fn pause_blocks_register_and_revoke_until_unpause() {
    let (env, client, v) = setup();
    let r = reg(&v, "makerOnStellarTestnet");
    let account = bn::<32>(&env, &r["account"]);
    let owner = maker_owner(&env, &v);

    client.pause();
    assert_eq!(
        client.try_register(
            &account,
            &OwnerAuth::Stellar(owner.clone()),
            &bn::<96>(&env, &r["pkNative"]),
            &bn::<192>(&env, &r["pop"]),
            &0
        ),
        Err(Ok(RegistryError::ContractPaused))
    );
    assert_eq!(
        client.try_revoke(&account, &OwnerAuth::Stellar(owner.clone()), &0),
        Err(Ok(RegistryError::ContractPaused))
    );

    client.unpause();
    client.register(
        &account,
        &OwnerAuth::Stellar(owner),
        &bn::<96>(&env, &r["pkNative"]),
        &bn::<192>(&env, &r["pop"]),
        &0,
    );
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
