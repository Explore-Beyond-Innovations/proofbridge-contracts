//! 2.1b (#324), T-67a: the registrar appends a domain-4 leaf only after the account's own
//! authorization passes, and only while it is a manager on the MerkleManager.

#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env};

struct F {
    env: Env,
    client: RegistrarClient<'static>,
    id: Address,
    mm: Address,
    admin: Address,
}

fn setup(mock_auths: bool) -> F {
    let env = Env::default();
    if mock_auths {
        env.mock_all_auths();
    }
    let admin = Address::generate(&env);
    let mm = env.register(merkle_manager::ProofBridgeMerkleManagerContract, ());
    let mmc = merkle_manager::ProofBridgeMerkleManagerContractClient::new(&env, &mm);
    // Admin auth for initialize / set_manager: mocked when requested, otherwise explicitly.
    if !mock_auths {
        env.mock_all_auths();
        mmc.initialize(&admin);
    }
    let id = env.register(Registrar, ());
    let client = RegistrarClient::new(&env, &id);
    if mock_auths {
        mmc.initialize(&admin);
    }
    client.initialize(&mm);
    mmc.set_manager(&id, &true);
    F {
        env,
        client,
        id,
        mm,
        admin,
    }
}

fn width(f: &F) -> u128 {
    merkle_manager::ProofBridgeMerkleManagerContractClient::new(&f.env, &f.mm).get_width()
}

fn commitment(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0xC0; 32])
}

#[test]
fn initialize_twice_errors() {
    let f = setup(true);
    assert_eq!(
        f.client.try_initialize(&f.mm),
        Err(Ok(RegistrarError::AlreadyInitialized))
    );
    assert_eq!(f.client.merkle_manager(), Some(f.mm.clone()));
}

#[test]
fn subject_is_keccak_of_packed_fields() {
    let f = setup(true);
    let account32 = BytesN::from_array(&f.env, &[0xAC; 32]);
    let c = commitment(&f.env);
    let mut data = Bytes::from_slice(&f.env, &account32.to_array());
    data.extend_from_slice(&c.to_array());
    data.extend_from_slice(&7u64.to_be_bytes());
    let expected: BytesN<32> = f.env.crypto().keccak256(&data).to_bytes();
    assert_eq!(f.client.subject_of(&account32, &c, &7), expected);
}

#[test]
fn own_auth_appends_domain4_leaf() {
    let f = setup(true);
    let account = Address::generate(&f.env);
    assert_eq!(width(&f), 0);

    let subject = f.client.register_leaf(&account, &commitment(&f.env), &1);

    assert_eq!(width(&f), 1, "one leaf appended");
    let account32 = address_to_bytes32(&f.env, &account);
    assert_eq!(
        subject,
        f.client.subject_of(&account32, &commitment(&f.env), &1)
    );
}

#[test]
fn without_the_accounts_auth_it_fails() {
    // Nothing is mocked for the account, so `require_auth` fails at the host.
    let f = setup(false);
    let env = &f.env;
    env.set_auths(&[]);
    let account = Address::generate(env);
    assert!(f
        .client
        .try_register_leaf(&account, &commitment(env), &1)
        .is_err());
    assert_eq!(width(&f), 0);
}

#[test]
fn without_manager_role_it_fails() {
    let f = setup(true);
    let bare_id = f.env.register(Registrar, ());
    let bare = RegistrarClient::new(&f.env, &bare_id);
    bare.initialize(&f.mm);
    let account = Address::generate(&f.env);
    assert_eq!(
        bare.try_register_leaf(&account, &commitment(&f.env), &1),
        Err(Ok(RegistrarError::AppendFailed))
    );
    assert_eq!(width(&f), 0);
    let _ = (&f.id, &f.admin);
}
