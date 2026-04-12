#![cfg(test)]

extern crate std;

// =============================================================================
// EIP-712 Tests
// =============================================================================

mod eip712_tests {
    use crate::eip712::{
        domain_separator_proofbridge, keccak256, DOMAIN_TYPEHASH_MIN, NAME_HASH, ORDER_TYPEHASH,
        VERSION_HASH,
    };

    #[test]
    fn test_keccak256_empty() {
        let hash = keccak256(&[]);
        assert_eq!(
            hex::encode(hash),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn test_keccak256_hello() {
        let hash = keccak256(b"hello");
        assert_eq!(
            hex::encode(hash),
            "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        );
    }

    #[test]
    fn test_domain_typehash() {
        let computed = keccak256(b"EIP712Domain(string name,string version)");
        assert_eq!(computed, DOMAIN_TYPEHASH_MIN);
    }

    #[test]
    fn test_version_hash() {
        let computed = keccak256(b"1");
        assert_eq!(computed, VERSION_HASH);
    }

    #[test]
    fn test_name_hash() {
        let computed = keccak256(b"Proofbridge");
        assert_eq!(computed, NAME_HASH);
    }

    #[test]
    fn test_order_typehash() {
        let type_string = "Order(bytes32 orderChainToken,bytes32 adChainToken,uint256 amount,bytes32 bridger,uint256 orderChainId,bytes32 orderPortal,bytes32 orderRecipient,uint256 adChainId,bytes32 adManager,string adId,bytes32 adCreator,bytes32 adRecipient,uint256 salt)";
        let computed = keccak256(type_string.as_bytes());
        assert_eq!(computed, ORDER_TYPEHASH);
    }

    #[test]
    fn test_domain_separator() {
        let domain_sep = domain_separator_proofbridge();
        assert_eq!(domain_sep.len(), 32);
    }
}

// =============================================================================
// Auth Tests
// =============================================================================

mod auth_tests {
    use crate::auth;
    use soroban_sdk::{BytesN, Env};

    #[test]
    fn test_is_zero_bytes32() {
        let env = Env::default();
        let zero = BytesN::from_array(&env, &[0u8; 32]);
        assert!(auth::is_zero_bytes32(&zero));

        let non_zero = BytesN::from_array(&env, &[1u8; 32]);
        assert!(!auth::is_zero_bytes32(&non_zero));

        let mut almost_zero = [0u8; 32];
        almost_zero[31] = 1;
        let almost = BytesN::from_array(&env, &almost_zero);
        assert!(!auth::is_zero_bytes32(&almost));
    }

    #[test]
    fn test_hash_request_deterministic() {
        let env = Env::default();
        let auth_token = BytesN::from_array(&env, &[0xAA; 32]);
        let contract_addr = BytesN::from_array(&env, &[0xBB; 32]);

        let hash1 = auth::hash_request(
            &env,
            &auth_token,
            1000,
            "testAction",
            &[1, 2, 3],
            42,
            &contract_addr,
        );
        let hash2 = auth::hash_request(
            &env,
            &auth_token,
            1000,
            "testAction",
            &[1, 2, 3],
            42,
            &contract_addr,
        );
        assert_eq!(hash1, hash2, "Same inputs must produce same hash");
    }

    #[test]
    fn test_hash_request_different_actions() {
        let env = Env::default();
        let auth_token = BytesN::from_array(&env, &[0xAA; 32]);
        let contract_addr = BytesN::from_array(&env, &[0xBB; 32]);

        let hash1 =
            auth::hash_request(&env, &auth_token, 1000, "createAd", &[], 42, &contract_addr);
        let hash2 = auth::hash_request(&env, &auth_token, 1000, "fundAd", &[], 42, &contract_addr);
        assert_ne!(
            hash1, hash2,
            "Different actions must produce different hashes"
        );
    }

    #[test]
    fn test_hash_request_different_tokens() {
        let env = Env::default();
        let token1 = BytesN::from_array(&env, &[0xAA; 32]);
        let token2 = BytesN::from_array(&env, &[0xBB; 32]);
        let contract_addr = BytesN::from_array(&env, &[0xCC; 32]);

        let hash1 = auth::hash_request(&env, &token1, 1000, "test", &[], 42, &contract_addr);
        let hash2 = auth::hash_request(&env, &token2, 1000, "test", &[], 42, &contract_addr);
        assert_ne!(
            hash1, hash2,
            "Different auth tokens must produce different hashes"
        );
    }

    #[test]
    fn test_hash_request_different_chain_ids() {
        let env = Env::default();
        let auth_token = BytesN::from_array(&env, &[0xAA; 32]);
        let contract_addr = BytesN::from_array(&env, &[0xBB; 32]);

        let hash1 = auth::hash_request(&env, &auth_token, 1000, "test", &[], 1, &contract_addr);
        let hash2 = auth::hash_request(&env, &auth_token, 1000, "test", &[], 2, &contract_addr);
        assert_ne!(
            hash1, hash2,
            "Different chain IDs must produce different hashes"
        );
    }
}

// =============================================================================
// Ed25519 Signature Tests
// =============================================================================

mod ed25519_tests {
    use crate::auth;
    use ed25519_dalek::{Signer, SigningKey};
    use soroban_sdk::{BytesN, Env};

    #[test]
    fn test_ed25519_verify_valid_signature() {
        let env = Env::default();

        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        let message = [0xABu8; 32];
        let message_bytes = BytesN::from_array(&env, &message);

        let signature = signing_key.sign(&message);
        let sig_bytes = BytesN::from_array(&env, &signature.to_bytes());

        let pub_bytes = BytesN::from_array(&env, &verifying_key.to_bytes());

        // Should not panic
        auth::verify_ed25519_signature(&env, &pub_bytes, &message_bytes, &sig_bytes);
    }

    #[test]
    #[should_panic]
    fn test_ed25519_verify_invalid_signature_panics() {
        let env = Env::default();

        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        let message = [0xABu8; 32];
        let message_bytes = BytesN::from_array(&env, &message);

        // Sign a DIFFERENT message
        let wrong_message = [0xCDu8; 32];
        let wrong_signature = signing_key.sign(&wrong_message);
        let sig_bytes = BytesN::from_array(&env, &wrong_signature.to_bytes());

        let pub_bytes = BytesN::from_array(&env, &verifying_key.to_bytes());

        // Should panic
        auth::verify_ed25519_signature(&env, &pub_bytes, &message_bytes, &sig_bytes);
    }

    #[test]
    fn test_get_signer_address_roundtrip() {
        let env = Env::default();

        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        let pub_bytes = BytesN::from_array(&env, &verifying_key.to_bytes());

        let address = auth::get_signer_address(&env, &pub_bytes);

        let roundtrip = crate::eip712::address_to_bytes32(&env, &address);
        assert_eq!(
            roundtrip, pub_bytes,
            "Address roundtrip should preserve public key bytes"
        );
    }
}
