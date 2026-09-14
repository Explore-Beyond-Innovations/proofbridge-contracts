//! Registrar — the home-chain half of proof-carried registration (2.1b,
//! contracts/proof-carried-registration).
//!
//! A keyless account cannot sign a registration for the other chain, so it approves one *here*,
//! under its own `require_auth`, and the registrar appends a `REGISTERED` leaf to the home MMR.
//! The foreign registry then accepts the key on an inclusion proof of that leaf against an
//! anchored home-chain root. Nothing consumes the leaves until the registry's flag is turned on.
//!
//! The leaf is the message the account consents to, so it names the destination chain and registry
//! like every registry digest does (`proofbridge_core::cross_contract::registration_subject`): one
//! leaf, one registry. `epoch` is caller-chosen but strictly increasing per account, so the direct
//! path cannot append duplicates and an account's leaves are totally ordered for the
//! registration-leaf monitor.

#![no_std]

mod errors;
mod events;

#[cfg(test)]
mod test;

use soroban_sdk::{contract, contractimpl, symbol_short, Address, BytesN, Env, Symbol};

use proofbridge_core::{
    cross_contract::{registration_subject, MerkleManagerClient, LEAF_DOMAIN_REGISTERED},
    eip712::address_to_bytes32,
    ttl,
};

pub use errors::RegistrarError;

const KEY_INIT: Symbol = symbol_short!("init");
const KEY_MM: Symbol = symbol_short!("mm");
/// (KEY_NEXT, account32) -> u64: the lowest epoch the account's next leaf may carry (persistent).
const KEY_NEXT: Symbol = symbol_short!("next");

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

    /// Append the registration leaf for `account` after its own authorization. `epoch` must be at
    /// least `next_epoch(account)`; the leaf raises it to `epoch + 1`. The registrar must be a
    /// manager on the MerkleManager. Returns the leaf's subject.
    pub fn register_leaf(
        env: Env,
        account: Address,
        bls_commitment: BytesN<32>,
        epoch: u64,
        dst_chain_id: u128,
        dst_registry_id: BytesN<32>,
    ) -> Result<BytesN<32>, RegistrarError> {
        let mm: Address = env
            .storage()
            .instance()
            .get(&KEY_MM)
            .ok_or(RegistrarError::NotInitialized)?;
        account.require_auth();

        let account32 = address_to_bytes32(&env, &account);
        let key = (KEY_NEXT, account32.clone());
        let next: u64 = env.storage().persistent().get(&key).unwrap_or(0);
        if epoch < next {
            return Err(RegistrarError::StaleEpoch);
        }
        let bumped = epoch.checked_add(1).ok_or(RegistrarError::StaleEpoch)?;
        env.storage().persistent().set(&key, &bumped);
        ttl::extend_persistent(&env, &key);

        let subject = registration_subject(
            &env,
            dst_chain_id,
            &dst_registry_id,
            &account32,
            &bls_commitment,
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
            dst_chain_id,
            dst_registry_id,
            subject: subject.clone(),
        }
        .publish(&env);
        ttl::extend_instance(&env);
        Ok(subject)
    }

    /// The lowest epoch `account32`'s next leaf may carry.
    pub fn next_epoch(env: Env, account32: BytesN<32>) -> u64 {
        let key = (KEY_NEXT, account32);
        let next: u64 = env.storage().persistent().get(&key).unwrap_or(0);
        if next > 0 {
            ttl::extend_persistent(&env, &key);
        }
        next
    }

    /// The leaf subject both chains derive; see `registration_subject`.
    pub fn subject_of(
        env: Env,
        account32: BytesN<32>,
        bls_commitment: BytesN<32>,
        epoch: u64,
        dst_chain_id: u128,
        dst_registry_id: BytesN<32>,
    ) -> BytesN<32> {
        registration_subject(
            &env,
            dst_chain_id,
            &dst_registry_id,
            &account32,
            &bls_commitment,
            epoch,
        )
    }
}
