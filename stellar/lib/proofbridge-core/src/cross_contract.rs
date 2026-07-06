//! Cross-contract client definitions and helpers for MerkleManager and Verifier.
//!
//! Defines typed `#[contractclient]` traits so contracts can call
//! MerkleManager and Verifier without raw `env.invoke_contract`.

use soroban_sdk::{contractclient, Address, Bytes, BytesN, Env};

use crate::errors::ProofBridgeError;

// =============================================================================
// Client Traits
// =============================================================================

/// Typed interface for cross-contract calls to the MerkleManager contract.
#[allow(dead_code)]
#[contractclient(name = "MerkleManagerClient")]
pub trait MerkleManagerInterface {
    fn append_order_hash(env: Env, manager: Address, order_hash: BytesN<32>, side: u32) -> bool;
    fn get_root(env: Env) -> BytesN<32>;
    fn get_root_at_index(env: Env, leaf_index: u128) -> BytesN<32>;
    fn get_width(env: Env) -> u128;
    fn field_mod(env: Env, order_hash: BytesN<32>) -> BytesN<32>;
}

/// Typed interface for cross-contract calls to the Verifier contract.
#[allow(dead_code)]
#[contractclient(name = "VerifierClient")]
pub trait VerifierInterface {
    fn verify_proof(env: Env, public_inputs: Bytes, proof_bytes: Bytes);
}

/// Typed interface for the pluggable root-authentication seam.
#[allow(dead_code)]
#[contractclient(name = "RootVerifierClient")]
pub trait RootVerifierInterface {
    fn is_root_valid(env: Env, source_chain_id: u128, root: BytesN<32>, metadata: Bytes) -> bool;
}

// =============================================================================
// MerkleManager Helpers
// =============================================================================

/// Append an order hash to the MerkleManager.
pub fn append_to_merkle<E: ProofBridgeError>(
    env: &Env,
    merkle_manager: &Address,
    order_hash: &BytesN<32>,
    side: u32,
) -> Result<(), E> {
    let client = MerkleManagerClient::new(env, merkle_manager);
    client
        .try_append_order_hash(&env.current_contract_address(), order_hash, &side)
        .map_err(|_| E::merkle_append_failed())?
        .map_err(|_| E::merkle_append_failed())?;
    Ok(())
}

/// Get the current root from MerkleManager.
pub fn get_merkle_root(env: &Env, merkle_manager: &Address) -> BytesN<32> {
    MerkleManagerClient::new(env, merkle_manager).get_root()
}

/// Get a historical root from MerkleManager at a specific width.
pub fn get_merkle_root_at_index(env: &Env, merkle_manager: &Address, index: u128) -> BytesN<32> {
    MerkleManagerClient::new(env, merkle_manager).get_root_at_index(&index)
}

/// Get the current width (leaf count) from MerkleManager.
pub fn get_merkle_width(env: &Env, merkle_manager: &Address) -> u128 {
    MerkleManagerClient::new(env, merkle_manager).get_width()
}

/// Apply BN254 field modulus to a hash via MerkleManager.
pub fn get_field_mod(env: &Env, merkle_manager: &Address, order_hash: &BytesN<32>) -> BytesN<32> {
    MerkleManagerClient::new(env, merkle_manager).field_mod(order_hash)
}

// =============================================================================
// Verifier Helper
// =============================================================================

/// Verify a ZK proof via cross-contract call to the Verifier contract.
pub fn verify_proof<E: ProofBridgeError>(
    env: &Env,
    verifier: &Address,
    public_inputs: &Bytes,
    proof_bytes: &Bytes,
) -> Result<(), E> {
    let client = VerifierClient::new(env, verifier);
    client
        .try_verify_proof(public_inputs, proof_bytes)
        .map_err(|_| E::invalid_proof())?
        .map_err(|_| E::invalid_proof())?;
    Ok(())
}

// =============================================================================
// Proof Construction
// =============================================================================

/// Build public inputs for the ZK proof verification.
///
/// The public inputs are ordered as:
/// - nullifier_hash (32 bytes)
/// - order_hash_mod (32 bytes) - order hash with BN254 field modulus applied
/// - target_root (32 bytes)
/// - chain_flag (32 bytes) - 0 for source/order chain, 1 for destination/ad chain
///
/// Total: 128 bytes (4 x 32-byte field elements)
pub fn build_public_inputs(
    env: &Env,
    merkle_manager: &Address,
    nullifier_hash: &BytesN<32>,
    target_root: &BytesN<32>,
    order_hash: &BytesN<32>,
    chain_flag_value: u8,
) -> Bytes {
    let order_hash_mod = get_field_mod(env, merkle_manager, order_hash);

    // Chain flag as bytes32 (big-endian)
    let mut chain_flag = [0u8; 32];
    chain_flag[31] = chain_flag_value;

    let mut inputs = Bytes::new(env);
    inputs.append(&Bytes::from_slice(env, &nullifier_hash.to_array()));
    inputs.append(&Bytes::from_slice(env, &order_hash_mod.to_array()));
    inputs.append(&Bytes::from_slice(env, &target_root.to_array()));
    inputs.append(&Bytes::from_slice(env, &chain_flag));

    inputs
}

// =============================================================================
// RootVerifier Helpers
// =============================================================================

/// Gate 2: metadata = maker(32) || bridger(32) || cosig_data, accounts from
/// the hash-bound order params.
pub fn is_root_valid(
    env: &Env,
    module: &Address,
    source_chain_id: u128,
    root: &BytesN<32>,
    maker: &BytesN<32>,
    bridger: &BytesN<32>,
    cosig_data: &Bytes,
) -> bool {
    let mut metadata = Bytes::from_slice(env, &maker.to_array());
    metadata.extend_from_slice(&bridger.to_array());
    metadata.append(cosig_data);
    RootVerifierClient::new(env, module).is_root_valid(&source_chain_id, root, &metadata)
}
