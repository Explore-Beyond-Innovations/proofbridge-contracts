#![cfg(test)]
//! Verifier contract tests.
//!
//! **IMPORTANT**: These tests must be run with `--test-threads=1` due to
//! global state in the UltraHonk verifier backends. The backends use global
//! static variables to store the Soroban Env reference, and parallel test
//! execution can cause tests to use stale Env references.
//!
//! Run tests with: `cargo test -p verifier -- --test-threads=1`

extern crate std;

use soroban_sdk::{Bytes, Env};
use ultrahonk_soroban_verifier::PROOF_BYTES;

use crate::{ProofBridgeVerifierContract, ProofBridgeVerifierContractClient};

// =============================================================================
// Constructor Validation Tests
// =============================================================================

/// Test that the contract constructor validates VK bytes.
///
/// Note: When a contract has __constructor, it MUST be called with valid arguments.
/// You cannot deploy the contract without providing the VK bytes - this is the
/// security benefit of using __constructor over initialize().
#[test]
#[should_panic(expected = "Invalid verification key bytes")]
fn test_constructor_rejects_invalid_vk() {
    let env = Env::default();

    // Create invalid VK bytes (not a valid verification key)
    let invalid_vk_bytes = Bytes::from_slice(&env, &[1u8; 100]);

    // This should panic because the VK bytes are invalid
    let _contract_id = env.register(ProofBridgeVerifierContract, (invalid_vk_bytes,));
}

/// Test that the contract rejects empty VK bytes.
#[test]
#[should_panic(expected = "Invalid verification key bytes")]
fn test_constructor_rejects_empty_vk() {
    let env = Env::default();

    // Empty VK bytes
    let empty_vk_bytes = Bytes::new(&env);

    // This should panic because the VK bytes are empty/invalid
    let _contract_id = env.register(ProofBridgeVerifierContract, (empty_vk_bytes,));
}

// =============================================================================
// Simple Circuit Verification Tests
// =============================================================================
//
// The simple_circuit is a basic Noir circuit that asserts x != y.
// Circuit: fn main(x: Field, y: pub Field) { assert(x != y); }
// Prover inputs: x = 1, y = 2
//
// To regenerate the test artifacts:
//   cd contracts/verifier/tests && ./build_circuits.sh

/// Simple circuit test artifacts
const SIMPLE_VK: &[u8] = include_bytes!("../tests/simple_circuit/target/vk");
const SIMPLE_PROOF: &[u8] = include_bytes!("../tests/simple_circuit/target/proof");
const SIMPLE_PUBLIC_INPUTS: &[u8] = include_bytes!("../tests/simple_circuit/target/public_inputs");

/// Helper to create a verifier contract with the simple circuit VK
fn setup_simple_circuit_verifier<'a>(env: &'a Env) -> ProofBridgeVerifierContractClient<'a> {
    let vk_bytes = Bytes::from_slice(env, SIMPLE_VK);
    let contract_id = env.register(ProofBridgeVerifierContract, (vk_bytes,));
    ProofBridgeVerifierContractClient::new(env, &contract_id)
}

/// Test that simple_circuit proof verification succeeds with valid inputs
#[test]
fn test_simple_circuit_verification_succeeds() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();

    // Verify proof size matches expected
    assert_eq!(
        SIMPLE_PROOF.len(),
        PROOF_BYTES,
        "Proof size mismatch: expected {}, got {}",
        PROOF_BYTES,
        SIMPLE_PROOF.len()
    );

    // Setup verifier with VK
    let client = setup_simple_circuit_verifier(&env);

    // Prepare inputs
    let public_inputs = Bytes::from_slice(&env, SIMPLE_PUBLIC_INPUTS);
    let proof_bytes = Bytes::from_slice(&env, SIMPLE_PROOF);

    // Verify - should succeed (panics on failure)
    client.verify_proof(&public_inputs, &proof_bytes);
}

/// Test that the VK is correctly stored and retrievable
#[test]
fn test_simple_circuit_vk_stored() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();

    let client = setup_simple_circuit_verifier(&env);

    // Get stored VK
    let stored_vk = client.get_vk();
    assert!(stored_vk.is_some(), "VK should be stored");

    let stored_vk_bytes = stored_vk.unwrap();
    assert_eq!(
        stored_vk_bytes.len() as usize,
        SIMPLE_VK.len(),
        "Stored VK length should match"
    );
}

/// Test that verification fails with wrong proof
#[test]
fn test_simple_circuit_wrong_proof_fails() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();

    let client = setup_simple_circuit_verifier(&env);

    let public_inputs = Bytes::from_slice(&env, SIMPLE_PUBLIC_INPUTS);

    // Create an invalid proof (all zeros, correct size)
    let invalid_proof = Bytes::from_slice(&env, &[0u8; PROOF_BYTES]);

    // Verify - should fail
    let result = client.try_verify_proof(&public_inputs, &invalid_proof);
    assert!(
        result.is_err(),
        "Verification should fail with invalid proof"
    );
}

/// Test that verification fails with wrong public inputs
#[test]
fn test_simple_circuit_wrong_public_inputs_fails() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();

    let client = setup_simple_circuit_verifier(&env);

    // Use different public inputs (32 bytes of zeros instead of actual value)
    let wrong_public_inputs = Bytes::from_slice(&env, &[0u8; 32]);
    let proof_bytes = Bytes::from_slice(&env, SIMPLE_PROOF);

    // Verify - should fail
    let result = client.try_verify_proof(&wrong_public_inputs, &proof_bytes);
    assert!(
        result.is_err(),
        "Verification should fail with wrong public inputs"
    );
}

/// Test that verification fails with wrong size proof
#[test]
fn test_simple_circuit_wrong_proof_size_fails() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();

    let client = setup_simple_circuit_verifier(&env);

    let public_inputs = Bytes::from_slice(&env, SIMPLE_PUBLIC_INPUTS);

    // Create a proof with wrong size
    let wrong_size_proof = Bytes::from_slice(&env, &[1u8; 100]);

    // Verify - should fail with ProofParseError
    let result = client.try_verify_proof(&public_inputs, &wrong_size_proof);
    assert!(
        result.is_err(),
        "Verification should fail with wrong proof size"
    );
}
