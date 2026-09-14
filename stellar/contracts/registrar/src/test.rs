//! 2.1b (#324), T-67a: the registrar appends a domain-4 leaf only after the account's own
//! authorization passes, only while it is a manager on the MerkleManager, and never twice for the
//! same epoch.

#![cfg(test)]

extern crate std;

use super::*;
use proofbridge_core::cross_contract::REG_LEAF_TAG;
use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env};

/// The destination the leaf is minted for: the vectors' Stellar registry.
const DST_CHAIN: u128 = 1_000_002;

struct F {
    env: Env,
    client: RegistrarClient<'static>,
    mm: Address,
}

fn setup() -> F {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let mm = env.register(merkle_manager::ProofBridgeMerkleManagerContract, ());
    let mmc = merkle_manager::ProofBridgeMerkleManagerContractClient::new(&env, &mm);
    mmc.initialize(&admin);
    let id = env.register(Registrar, ());
    let client = RegistrarClient::new(&env, &id);
    client.initialize(&mm);
    mmc.set_manager(&id, &true);
    F { env, client, mm }
}

fn width(f: &F) -> u128 {
    merkle_manager::ProofBridgeMerkleManagerContractClient::new(&f.env, &f.mm).get_width()
}

fn commitment(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0xC0; 32])
}

fn dst_registry(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0x22; 32])
}

fn leaf(f: &F, account: &Address, epoch: u64) -> BytesN<32> {
    f.client.register_leaf(
        account,
        &commitment(&f.env),
        &epoch,
        &DST_CHAIN,
        &dst_registry(&f.env),
    )
}

#[test]
fn initialize_twice_errors() {
    let f = setup();
    assert_eq!(
        f.client.try_initialize(&f.mm),
        Err(Ok(RegistrarError::AlreadyInitialized))
    );
    assert_eq!(f.client.merkle_manager(), Some(f.mm.clone()));
}

// --- the subject --------------------------------------------------------------

#[test]
fn subject_is_the_tagged_registration_message() {
    let f = setup();
    let account32 = BytesN::from_array(&f.env, &[0xAC; 32]);
    let c = commitment(&f.env);
    let mut chain = [0u8; 32];
    chain[16..].copy_from_slice(&DST_CHAIN.to_be_bytes());
    let mut epoch = [0u8; 32];
    epoch[24..].copy_from_slice(&7u64.to_be_bytes());
    let mut data = Bytes::from_slice(&f.env, &REG_LEAF_TAG);
    data.extend_from_slice(&chain);
    data.extend_from_slice(&[0x22; 32]);
    data.extend_from_slice(&account32.to_array());
    data.extend_from_slice(&c.to_array());
    data.extend_from_slice(&epoch);
    let expected: BytesN<32> = f.env.crypto().keccak256(&data).to_bytes();
    assert_eq!(
        f.client
            .subject_of(&account32, &c, &7, &DST_CHAIN, &dst_registry(&f.env)),
        expected
    );
    let tag: BytesN<32> = f
        .env
        .crypto()
        .keccak256(&Bytes::from_slice(
            &f.env,
            b"ProofBridge.BLSKeyRegistry.RegistrationLeaf.v1",
        ))
        .to_bytes();
    assert_eq!(tag.to_array(), REG_LEAF_TAG);
}

#[test]
fn subject_binds_the_destination() {
    let f = setup();
    let account32 = BytesN::from_array(&f.env, &[0xAC; 32]);
    let c = commitment(&f.env);
    let here = f
        .client
        .subject_of(&account32, &c, &7, &DST_CHAIN, &dst_registry(&f.env));
    // Another chain, or another registry on the same chain, is another leaf.
    assert_ne!(
        here,
        f.client
            .subject_of(&account32, &c, &7, &(DST_CHAIN + 1), &dst_registry(&f.env))
    );
    assert_ne!(
        here,
        f.client.subject_of(
            &account32,
            &c,
            &7,
            &DST_CHAIN,
            &BytesN::from_array(&f.env, &[0xBE; 32])
        )
    );
}

// --- authorization ------------------------------------------------------------

#[test]
fn own_auth_appends_domain4_leaf() {
    let f = setup();
    let account = Address::generate(&f.env);
    assert_eq!(width(&f), 0);

    let subject = leaf(&f, &account, 1);

    assert_eq!(width(&f), 1, "one leaf appended");
    let account32 = address_to_bytes32(&f.env, &account);
    assert_eq!(
        subject,
        f.client.subject_of(
            &account32,
            &commitment(&f.env),
            &1,
            &DST_CHAIN,
            &dst_registry(&f.env)
        )
    );
    assert_eq!(f.client.next_epoch(&account32), 2);
}

#[test]
fn without_the_accounts_auth_it_fails() {
    let f = setup();
    // Nothing is mocked for the account, so `require_auth` fails at the host.
    f.env.set_auths(&[]);
    let account = Address::generate(&f.env);
    assert!(f
        .client
        .try_register_leaf(
            &account,
            &commitment(&f.env),
            &1,
            &DST_CHAIN,
            &dst_registry(&f.env)
        )
        .is_err());
    assert_eq!(width(&f), 0);
}

#[test]
fn without_manager_role_it_fails() {
    let f = setup();
    let bare_id = f.env.register(Registrar, ());
    let bare = RegistrarClient::new(&f.env, &bare_id);
    bare.initialize(&f.mm);
    let account = Address::generate(&f.env);
    assert_eq!(
        bare.try_register_leaf(
            &account,
            &commitment(&f.env),
            &1,
            &DST_CHAIN,
            &dst_registry(&f.env)
        ),
        Err(Ok(RegistrarError::AppendFailed))
    );
    assert_eq!(width(&f), 0);
}

// --- epochs are strictly increasing per account (B2) ---------------------------

#[test]
fn first_leaf_may_use_epoch_zero() {
    let f = setup();
    let account = Address::generate(&f.env);
    leaf(&f, &account, 0);
    assert_eq!(
        f.client.next_epoch(&address_to_bytes32(&f.env, &account)),
        1
    );
}

#[test]
fn an_epoch_cannot_repeat_or_go_down() {
    let f = setup();
    let account = Address::generate(&f.env);
    leaf(&f, &account, 5);

    let stale = |epoch: u64| {
        f.client.try_register_leaf(
            &account,
            &commitment(&f.env),
            &epoch,
            &DST_CHAIN,
            &dst_registry(&f.env),
        )
    };
    assert_eq!(stale(5), Err(Ok(RegistrarError::StaleEpoch)));
    assert_eq!(stale(2), Err(Ok(RegistrarError::StaleEpoch)));

    // Gaps are fine; only the order is fixed.
    leaf(&f, &account, 9);
    assert_eq!(
        f.client.next_epoch(&address_to_bytes32(&f.env, &account)),
        10
    );
    assert_eq!(width(&f), 2);
}

#[test]
fn epochs_are_per_account() {
    let f = setup();
    let a = Address::generate(&f.env);
    let b = Address::generate(&f.env);
    leaf(&f, &a, 7);
    leaf(&f, &b, 0);
    assert_eq!(f.client.next_epoch(&address_to_bytes32(&f.env, &a)), 8);
    assert_eq!(f.client.next_epoch(&address_to_bytes32(&f.env, &b)), 1);
}
