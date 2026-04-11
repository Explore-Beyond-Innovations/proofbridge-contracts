//! Cross-contract helpers for the AdManager contract
//!
//! Thin wrappers over proofbridge_core::cross_contract, specialized with
//! AdManagerError and chain_flag=1 (destination/ad chain).

pub use proofbridge_core::cross_contract::{
    get_merkle_root, get_merkle_root_at_index, get_merkle_width,
};

use soroban_sdk::{Address, Bytes, BytesN, Env};

use crate::errors::AdManagerError;

/// Append an order hash to the MerkleManager.
pub fn append_to_merkle(
    env: &Env,
    merkle_manager: &Address,
    order_hash: &BytesN<32>,
) -> Result<(), AdManagerError> {
    proofbridge_core::cross_contract::append_to_merkle(env, merkle_manager, order_hash)
}

/// Verify a ZK proof via cross-contract call to the Verifier contract.
pub fn verify_proof(
    env: &Env,
    verifier: &Address,
    public_inputs: &Bytes,
    proof_bytes: &Bytes,
) -> Result<(), AdManagerError> {
    proofbridge_core::cross_contract::verify_proof(env, verifier, public_inputs, proof_bytes)
}

/// Build public inputs for the ZK proof verification.
/// Uses chain_flag=1 for destination/ad chain.
pub fn build_public_inputs(
    env: &Env,
    merkle_manager: &Address,
    nullifier_hash: &BytesN<32>,
    target_root: &BytesN<32>,
    order_hash: &BytesN<32>,
) -> Bytes {
    proofbridge_core::cross_contract::build_public_inputs(
        env,
        merkle_manager,
        nullifier_hash,
        target_root,
        order_hash,
        1, // destination/ad chain
    )
}
