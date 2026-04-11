//! UltraHonk Verifier Contract for Stellar/Soroban
//!
//! This contract wraps the UltraHonk proof verifier with an immutable verification key.
//! The verification key is set at deployment time via the constructor and cannot be changed.
//!
//! ## Usage
//!
//! 1. Deploy the contract with `__constructor(vk_bytes)` - VK is set immutably
//! 2. Call `verify_proof(public_inputs, proof_bytes)` to verify proofs
//!
//! The verification key is stored on-chain at deployment and cannot be updated.

#![no_std]
use soroban_sdk::{contract, contracterror, contractimpl, symbol_short, Bytes, Env, Symbol};
use ultrahonk_soroban_verifier::{utils::load_vk_from_bytes, UltraHonkVerifier, PROOF_BYTES};

// =============================================================================
// Error Types
// =============================================================================

#[contracterror]
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VerifierError {
    /// Failed to parse verification key bytes
    VkParseError = 1,
    /// Failed to parse proof bytes
    ProofParseError = 2,
    /// Proof verification failed
    VerificationFailed = 3,
    /// Verification key not set (constructor not called properly)
    VkNotSet = 4,
}

// =============================================================================
// Contract Definition
// =============================================================================

/// UltraHonk Verifier Contract
///
/// Stores an immutable verification key and verifies UltraHonk proofs.
#[contract]
pub struct ProofBridgeVerifierContract;

#[contractimpl]
impl ProofBridgeVerifierContract {
    // =========================================================================
    // Storage Keys
    // =========================================================================

    fn key_vk() -> Symbol {
        symbol_short!("vk")
    }

    // =========================================================================
    // Constructor
    // =========================================================================

    /// Contract constructor - sets the verification key immutably at deployment.
    ///
    /// This function is called automatically during contract deployment and
    /// cannot be called again. The verification key is stored permanently.
    ///
    /// # Arguments
    /// * `vk_bytes` - The serialized verification key bytes
    ///
    /// # Panics
    /// * If the verification key cannot be parsed
    pub fn __constructor(env: Env, vk_bytes: Bytes) {
        if load_vk_from_bytes(&vk_bytes).is_none() {
            panic!("Invalid verification key bytes");
        }

        // Store the verification key immutably
        env.storage().instance().set(&Self::key_vk(), &vk_bytes);
    }

    // =========================================================================
    // Verification
    // =========================================================================

    /// Verify an UltraHonk proof using the stored verification key.
    ///
    /// # Arguments
    /// * `public_inputs` - The public inputs as concatenated 32-byte chunks
    /// * `proof_bytes` - The proof bytes
    ///
    /// # Errors
    /// * `VkNotSet` - Contract not initialized
    /// * `ProofParseError` - Invalid proof format
    /// * `VerificationFailed` - Proof verification failed
    pub fn verify_proof(
        env: Env,
        public_inputs: Bytes,
        proof_bytes: Bytes,
    ) -> Result<(), VerifierError> {
        // Validate proof size
        if proof_bytes.len() as usize != PROOF_BYTES {
            return Err(VerifierError::ProofParseError);
        }

        // Get stored verification key
        let vk_bytes: Bytes = env
            .storage()
            .instance()
            .get(&Self::key_vk())
            .ok_or(VerifierError::VkNotSet)?;

        // Deserialize verification key bytes
        let verifier =
            UltraHonkVerifier::new(&env, &vk_bytes).map_err(|_| VerifierError::VkParseError)?;

        // Verify the proof
        verifier
            .verify(&proof_bytes, &public_inputs)
            .map_err(|_| VerifierError::VerificationFailed)?;

        Ok(())
    }

    // =========================================================================
    // View Functions
    // =========================================================================

    /// Get the stored verification key bytes.
    ///
    /// The VK is always set at deployment via constructor, so this should
    /// never return None for a properly deployed contract.
    pub fn get_vk(env: Env) -> Option<Bytes> {
        env.storage().instance().get(&Self::key_vk())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod test;
