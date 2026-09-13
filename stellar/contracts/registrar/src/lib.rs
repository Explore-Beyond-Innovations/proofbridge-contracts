//! Registrar — the home-chain half of proof-carried registration (2.1b,
//! contracts/proof-carried-registration).
//!
//! A keyless account cannot sign a registration for the other chain, so it approves one *here*,
//! under its own `require_auth`, and the registrar appends a `REGISTERED` leaf to the home MMR.
//! The foreign registry then accepts the key on an inclusion proof of that leaf against an
//! anchored home-chain root. Nothing consumes the leaves until the registry's flag is turned on.
//!
//! Subject = `keccak256(account32 ‖ bls_commitment ‖ epoch)` with `epoch` as 8 big-endian bytes,
//! so both chains hash identical bytes.

#![no_std]

mod errors;
mod events;

#[cfg(test)]
mod test;

use soroban_sdk::{contract, contractimpl, symbol_short, Address, Bytes, BytesN, Env, Symbol};

use proofbridge_core::{
    cross_contract::{MerkleManagerClient, LEAF_DOMAIN_REGISTERED},
    eip712::address_to_bytes32,
    ttl,
};

pub use errors::RegistrarError;

const KEY_INIT: Symbol = symbol_short!("init");
const KEY_MM: Symbol = symbol_short!("mm");

#[contract]
pub struct Registrar;

#[contractimpl]
impl Registrar {
    pub fn initialize(env: Env, merkle_manager: Address) -> Result<(), RegistrarError> {
        if env.storage().instance().has(&KEY_INIT) {
            return Err(RegistrarError::AlreadyInitialized);
        }
        env.storage().instance().set(&KEY_INIT, &true);
        env.storage().instance().set(&KEY_MM, &merkle_manager);
        events::Initialized { merkle_manager }.publish(&env);
        ttl::extend_instance(&env);
        Ok(())
    }

    pub fn merkle_manager(env: Env) -> Option<Address> {
        env.storage().instance().get(&KEY_MM)
    }

    /// Append the registration leaf for `account` after its own authorization. The registrar must
    /// be a manager on the MerkleManager. Returns the leaf's subject.
    pub fn register_leaf(
        env: Env,
        account: Address,
        bls_commitment: BytesN<32>,
        epoch: u64,
    ) -> Result<BytesN<32>, RegistrarError> {
        let mm: Address = env
            .storage()
            .instance()
            .get(&KEY_MM)
            .ok_or(RegistrarError::NotInitialized)?;
        account.require_auth();

        let account32 = address_to_bytes32(&env, &account);
        let subject = Self::subject_of(
            env.clone(),
            account32.clone(),
            bls_commitment.clone(),
            epoch,
        );

        match MerkleManagerClient::new(&env, &mm).try_append_order_hash(
            &env.current_contract_address(),
            &subject,
            &LEAF_DOMAIN_REGISTERED,
        ) {
            Ok(Ok(true)) => {}
            _ => return Err(RegistrarError::AppendFailed),
        }

        events::RegistrationLeaf {
            account32,
            bls_commitment,
            epoch,
            subject: subject.clone(),
        }
        .publish(&env);
        ttl::extend_instance(&env);
        Ok(subject)
    }

    /// The leaf subject both chains derive: 32 + 32 + 8 bytes, `epoch` big-endian.
    pub fn subject_of(
        env: Env,
        account32: BytesN<32>,
        bls_commitment: BytesN<32>,
        epoch: u64,
    ) -> BytesN<32> {
        let mut data = Bytes::from_slice(&env, &account32.to_array());
        data.extend_from_slice(&bls_commitment.to_array());
        data.extend_from_slice(&epoch.to_be_bytes());
        env.crypto().keccak256(&data).to_bytes()
    }
}
