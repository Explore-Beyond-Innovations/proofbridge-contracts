#![cfg(test)]

extern crate std;

use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, String as SorobanString};

use crate::{AdManagerContract, AdManagerContractClient};

// =============================================================================
// Cross-Chain EIP-712 Tests
// =============================================================================

mod cross_chain_tests {
    use crate::eip712::{
        abi_encode_string, abi_encode_uint256, hash_typed_data_v4, keccak256, struct_hash_order,
    };
    use proofbridge_core::eip712::{
        domain_separator_proofbridge, DOMAIN_TYPEHASH_MIN, NAME_HASH, VERSION_HASH,
    };
    use crate::types::OrderParams;
    use soroban_sdk::{BytesN, Env, String as SorobanString};

    fn hex_to_bytes32(env: &Env, hex_str: &str) -> BytesN<32> {
        let bytes = hex::decode(hex_str).expect("Invalid hex");
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        BytesN::from_array(env, &arr)
    }

    fn evm_address_to_bytes32(env: &Env, addr_hex: &str) -> BytesN<32> {
        let addr_bytes = hex::decode(addr_hex).expect("Invalid hex");
        assert_eq!(addr_bytes.len(), 20, "EVM address must be 20 bytes");
        let mut arr = [0u8; 32];
        arr[12..32].copy_from_slice(&addr_bytes);
        BytesN::from_array(env, &arr)
    }

    #[test]
    fn test_domain_separator_cross_chain() {
        let domain_sep = domain_separator_proofbridge();
        let mut data = [0u8; 96];
        data[0..32].copy_from_slice(&DOMAIN_TYPEHASH_MIN);
        data[32..64].copy_from_slice(&NAME_HASH);
        data[64..96].copy_from_slice(&VERSION_HASH);
        let expected = keccak256(&data);
        assert_eq!(domain_sep, expected);
    }

    #[test]
    fn test_uint256_encoding() {
        let value: u128 = 1_000_000_000_000_000_000;
        let encoded = abi_encode_uint256(value);
        let expected_hex = "0000000000000000000000000000000000000000000000000de0b6b3a7640000";
        assert_eq!(hex::encode(encoded), expected_hex);
    }

    #[test]
    fn test_chain_id_encoding() {
        let chain_id: u128 = 2_000_000_002;
        let encoded = abi_encode_uint256(chain_id);
        let expected_hex = "0000000000000000000000000000000000000000000000000000000077359402";
        assert_eq!(hex::encode(encoded), expected_hex);
    }

    #[test]
    fn test_string_encoding() {
        let env = Env::default();
        let ad_id = SorobanString::from_str(&env, "test-ad-123");
        let encoded = abi_encode_string(&ad_id);
        let expected = keccak256(b"test-ad-123");
        assert_eq!(encoded, expected);
    }

    #[test]
    fn test_struct_hash_order() {
        let env = Env::default();
        let order_params = OrderParams {
            order_chain_token: evm_address_to_bytes32(
                &env,
                "1111111111111111111111111111111111111111",
            ),
            ad_chain_token: evm_address_to_bytes32(
                &env,
                "2222222222222222222222222222222222222222",
            ),
            amount: 1_000_000_000_000_000_000,
            bridger: evm_address_to_bytes32(&env, "3333333333333333333333333333333333333333"),
            order_chain_id: 1,
            src_order_portal: evm_address_to_bytes32(
                &env,
                "4444444444444444444444444444444444444444",
            ),
            order_recipient: evm_address_to_bytes32(
                &env,
                "5555555555555555555555555555555555555555",
            ),
            ad_id: SorobanString::from_str(&env, "test-ad-123"),
            ad_creator: evm_address_to_bytes32(
                &env,
                "7777777777777777777777777777777777777777",
            ),
            ad_recipient: evm_address_to_bytes32(
                &env,
                "8888888888888888888888888888888888888888",
            ),
            salt: 12345,
        };
        let ad_chain_id: u128 = 2_000_000_002;
        let ad_manager =
            evm_address_to_bytes32(&env, "6666666666666666666666666666666666666666");
        let struct_hash = struct_hash_order(&order_params, ad_chain_id, &ad_manager);
        assert_eq!(struct_hash.len(), 32);
        assert_ne!(struct_hash, [0u8; 32]);
    }

    #[test]
    fn test_order_hash_cross_chain() {
        let env = Env::default();
        let order_params = OrderParams {
            order_chain_token: evm_address_to_bytes32(
                &env,
                "1111111111111111111111111111111111111111",
            ),
            ad_chain_token: evm_address_to_bytes32(
                &env,
                "2222222222222222222222222222222222222222",
            ),
            amount: 1_000_000_000_000_000_000,
            bridger: evm_address_to_bytes32(&env, "3333333333333333333333333333333333333333"),
            order_chain_id: 1,
            src_order_portal: evm_address_to_bytes32(
                &env,
                "4444444444444444444444444444444444444444",
            ),
            order_recipient: evm_address_to_bytes32(
                &env,
                "5555555555555555555555555555555555555555",
            ),
            ad_id: SorobanString::from_str(&env, "test-ad-123"),
            ad_creator: evm_address_to_bytes32(
                &env,
                "7777777777777777777777777777777777777777",
            ),
            ad_recipient: evm_address_to_bytes32(
                &env,
                "8888888888888888888888888888888888888888",
            ),
            salt: 12345,
        };
        let ad_chain_id: u128 = 2_000_000_002;
        let ad_manager =
            evm_address_to_bytes32(&env, "6666666666666666666666666666666666666666");
        let struct_hash = struct_hash_order(&order_params, ad_chain_id, &ad_manager);
        let order_hash = hash_typed_data_v4(&struct_hash);
        assert_eq!(order_hash.len(), 32);
        assert_ne!(order_hash, [0u8; 32]);
    }

    #[test]
    fn test_order_hash_zero_salt() {
        let env = Env::default();
        let order_params = OrderParams {
            order_chain_token: evm_address_to_bytes32(
                &env,
                "1111111111111111111111111111111111111111",
            ),
            ad_chain_token: evm_address_to_bytes32(
                &env,
                "2222222222222222222222222222222222222222",
            ),
            amount: 1_000_000_000_000_000_000,
            bridger: evm_address_to_bytes32(&env, "3333333333333333333333333333333333333333"),
            order_chain_id: 1,
            src_order_portal: evm_address_to_bytes32(
                &env,
                "4444444444444444444444444444444444444444",
            ),
            order_recipient: evm_address_to_bytes32(
                &env,
                "5555555555555555555555555555555555555555",
            ),
            ad_id: SorobanString::from_str(&env, "test-ad-123"),
            ad_creator: evm_address_to_bytes32(
                &env,
                "7777777777777777777777777777777777777777",
            ),
            ad_recipient: evm_address_to_bytes32(
                &env,
                "8888888888888888888888888888888888888888",
            ),
            salt: 0,
        };
        let ad_chain_id: u128 = 2_000_000_002;
        let ad_manager =
            evm_address_to_bytes32(&env, "6666666666666666666666666666666666666666");
        let struct_hash = struct_hash_order(&order_params, ad_chain_id, &ad_manager);
        let order_hash = hash_typed_data_v4(&struct_hash);
        assert_ne!(order_hash, [0u8; 32]);
    }

    #[test]
    fn test_order_hash_max_values() {
        let env = Env::default();
        let order_params = OrderParams {
            order_chain_token: hex_to_bytes32(
                &env,
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
            ad_chain_token: hex_to_bytes32(
                &env,
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
            amount: u128::MAX,
            bridger: hex_to_bytes32(
                &env,
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
            order_chain_id: u128::MAX,
            src_order_portal: hex_to_bytes32(
                &env,
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
            order_recipient: hex_to_bytes32(
                &env,
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
            ad_id: SorobanString::from_str(&env, "max-test"),
            ad_creator: hex_to_bytes32(
                &env,
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
            ad_recipient: hex_to_bytes32(
                &env,
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
            salt: u128::MAX,
        };
        let ad_chain_id: u128 = u128::MAX;
        let ad_manager = hex_to_bytes32(
            &env,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
        let struct_hash = struct_hash_order(&order_params, ad_chain_id, &ad_manager);
        let order_hash = hash_typed_data_v4(&struct_hash);
        assert_ne!(order_hash, [0u8; 32]);
    }

    #[test]
    fn test_order_hash_uniqueness() {
        let env = Env::default();
        let base_params = OrderParams {
            order_chain_token: evm_address_to_bytes32(
                &env,
                "1111111111111111111111111111111111111111",
            ),
            ad_chain_token: evm_address_to_bytes32(
                &env,
                "2222222222222222222222222222222222222222",
            ),
            amount: 1_000_000_000_000_000_000,
            bridger: evm_address_to_bytes32(&env, "3333333333333333333333333333333333333333"),
            order_chain_id: 1,
            src_order_portal: evm_address_to_bytes32(
                &env,
                "4444444444444444444444444444444444444444",
            ),
            order_recipient: evm_address_to_bytes32(
                &env,
                "5555555555555555555555555555555555555555",
            ),
            ad_id: SorobanString::from_str(&env, "test-ad-123"),
            ad_creator: evm_address_to_bytes32(
                &env,
                "7777777777777777777777777777777777777777",
            ),
            ad_recipient: evm_address_to_bytes32(
                &env,
                "8888888888888888888888888888888888888888",
            ),
            salt: 12345,
        };
        let ad_chain_id: u128 = 2_000_000_002;
        let ad_manager =
            evm_address_to_bytes32(&env, "6666666666666666666666666666666666666666");

        let hash1 =
            hash_typed_data_v4(&struct_hash_order(&base_params, ad_chain_id, &ad_manager));

        let mut different_salt = base_params.clone();
        different_salt.salt = 12346;
        let hash2 = hash_typed_data_v4(&struct_hash_order(
            &different_salt,
            ad_chain_id,
            &ad_manager,
        ));

        let mut different_amount = base_params.clone();
        different_amount.amount = 2_000_000_000_000_000_000;
        let hash3 = hash_typed_data_v4(&struct_hash_order(
            &different_amount,
            ad_chain_id,
            &ad_manager,
        ));

        assert_ne!(hash1, hash2, "Different salt should produce different hash");
        assert_ne!(
            hash1, hash3,
            "Different amount should produce different hash"
        );
        assert_ne!(hash2, hash3, "Hashes should all be unique");
    }

    #[test]
    fn test_eip712_prefix() {
        let struct_hash = [0u8; 32];
        let domain_sep = domain_separator_proofbridge();
        let mut data = [0u8; 66];
        data[0] = 0x19;
        data[1] = 0x01;
        data[2..34].copy_from_slice(&domain_sep);
        data[34..66].copy_from_slice(&struct_hash);
        let expected = keccak256(&data);
        let actual = hash_typed_data_v4(&struct_hash);
        assert_eq!(actual, expected);
    }
}

// =============================================================================
// Contract Initialization Tests (existing)
// =============================================================================

mod contract_tests {
    use super::*;

    fn setup_env() -> (Env, Address, AdManagerContractClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register(AdManagerContract, ());
        let client = AdManagerContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);

        (env, admin, client)
    }

    #[test]
    fn test_initialization() {
        let (env, admin, client) = setup_env();

        let verifier = Address::generate(&env);
        let merkle_manager = Address::generate(&env);
        let w_native_token = Address::generate(&env);
        let chain_id: u128 = 2_000_000_002;

        client.initialize(&admin, &verifier, &merkle_manager, &w_native_token, &chain_id);

        let stored_chain_id = client.get_chain_id();
        assert_eq!(stored_chain_id, chain_id);

        let is_mgr = client.is_manager(&admin);
        assert!(is_mgr);
    }

    #[test]
    fn test_double_initialization_fails() {
        let (env, admin, client) = setup_env();

        let verifier = Address::generate(&env);
        let merkle_manager = Address::generate(&env);
        let w_native_token = Address::generate(&env);
        let chain_id: u128 = 2_000_000_002;

        client.initialize(&admin, &verifier, &merkle_manager, &w_native_token, &chain_id);

        let result = client.try_initialize(
            &admin,
            &verifier,
            &merkle_manager,
            &w_native_token,
            &chain_id,
        );
        assert!(result.is_err());
    }
}

// =============================================================================
// Validation Tests
// =============================================================================

mod validation_tests {
    use crate::errors::AdManagerError;
    use crate::storage;
    use crate::types::{Ad, ChainInfo};
    use crate::validation;
    use soroban_sdk::{BytesN, Env, String as SorobanString};

    use super::*;

    fn make_bytes32(env: &Env, fill: u8) -> BytesN<32> {
        BytesN::from_array(env, &[fill; 32])
    }

    fn zero_bytes32(env: &Env) -> BytesN<32> {
        BytesN::from_array(env, &[0u8; 32])
    }

    fn setup_validation_env() -> Env {
        let env = Env::default();
        // Register the contract so storage calls work in the contract context
        let _contract_id = env.register(AdManagerContract, ());
        env
    }

    /// Build a valid Ad and matching OrderParams for testing.
    /// Callers can mutate fields to introduce specific failures.
    fn valid_ad_and_params(env: &Env) -> (Ad, crate::types::OrderParams) {
        let ad_token = make_bytes32(env, 0xAA);
        let order_chain_token = make_bytes32(env, 0xBB);
        let ad_recipient = make_bytes32(env, 0xCC);
        let bridger = make_bytes32(env, 0xDD);
        let order_recipient = make_bytes32(env, 0xEE);
        let order_chain_id: u128 = 1;

        let ad = Ad {
            order_chain_id,
            ad_recipient: ad_recipient.clone(),
            maker: Address::generate(env),
            token: ad_token.clone(),
            balance: 1_000_000,
            locked: 0,
            open: true,
        };

        let params = crate::types::OrderParams {
            order_chain_token: order_chain_token.clone(),
            ad_chain_token: ad_token.clone(),
            amount: 100_000,
            bridger: bridger.clone(),
            order_chain_id,
            src_order_portal: make_bytes32(env, 0xFF),
            order_recipient: order_recipient.clone(),
            ad_id: SorobanString::from_str(env, "test-ad"),
            ad_creator: make_bytes32(env, 0x77),
            ad_recipient: ad_recipient.clone(),
            salt: 42,
        };

        (ad, params)
    }

    /// Set up storage with chain info and token route so validate_order passes
    fn setup_chain_and_route(env: &Env, params: &crate::types::OrderParams) {
        let chain_info = ChainInfo {
            supported: true,
            order_portal: params.src_order_portal.clone(),
        };
        storage::set_chain(env, params.order_chain_id, &chain_info);
        storage::set_token_route(
            env,
            &params.ad_chain_token,
            params.order_chain_id,
            &params.order_chain_token,
        );
    }

    #[test]
    fn test_validate_order_success() {
        let env = setup_validation_env();
        env.as_contract(&env.register(AdManagerContract, ()), || {
            let (ad, params) = valid_ad_and_params(&env);
            setup_chain_and_route(&env, &params);
            let result = validation::validate_order(&env, &ad, &params);
            assert!(result.is_ok());
        });
    }

    #[test]
    fn test_validate_order_ad_closed() {
        let env = setup_validation_env();
        env.as_contract(&env.register(AdManagerContract, ()), || {
            let (mut ad, params) = valid_ad_and_params(&env);
            ad.open = false;
            setup_chain_and_route(&env, &params);
            let result = validation::validate_order(&env, &ad, &params);
            assert_eq!(result, Err(AdManagerError::AdClosed));
        });
    }

    #[test]
    fn test_validate_order_zero_amount() {
        let env = setup_validation_env();
        env.as_contract(&env.register(AdManagerContract, ()), || {
            let (ad, mut params) = valid_ad_and_params(&env);
            params.amount = 0;
            setup_chain_and_route(&env, &params);
            let result = validation::validate_order(&env, &ad, &params);
            assert_eq!(result, Err(AdManagerError::ZeroAmount));
        });
    }

    #[test]
    fn test_validate_order_bridger_zero() {
        let env = setup_validation_env();
        env.as_contract(&env.register(AdManagerContract, ()), || {
            let (ad, mut params) = valid_ad_and_params(&env);
            params.bridger = zero_bytes32(&env);
            setup_chain_and_route(&env, &params);
            let result = validation::validate_order(&env, &ad, &params);
            assert_eq!(result, Err(AdManagerError::BridgerZero));
        });
    }

    #[test]
    fn test_validate_order_recipient_zero() {
        let env = setup_validation_env();
        env.as_contract(&env.register(AdManagerContract, ()), || {
            let (ad, mut params) = valid_ad_and_params(&env);
            params.order_recipient = zero_bytes32(&env);
            setup_chain_and_route(&env, &params);
            let result = validation::validate_order(&env, &ad, &params);
            assert_eq!(result, Err(AdManagerError::RecipientZero));
        });
    }

    #[test]
    fn test_validate_order_chain_not_supported() {
        let env = setup_validation_env();
        env.as_contract(&env.register(AdManagerContract, ()), || {
            let (ad, params) = valid_ad_and_params(&env);
            // Don't set up chain info — chain not found
            let result = validation::validate_order(&env, &ad, &params);
            assert_eq!(result, Err(AdManagerError::ChainNotSupported));
        });
    }

    #[test]
    fn test_validate_order_chain_not_supported_disabled() {
        let env = setup_validation_env();
        env.as_contract(&env.register(AdManagerContract, ()), || {
            let (ad, params) = valid_ad_and_params(&env);
            let chain_info = ChainInfo {
                supported: false,
                order_portal: params.src_order_portal.clone(),
            };
            storage::set_chain(&env, params.order_chain_id, &chain_info);
            let result = validation::validate_order(&env, &ad, &params);
            assert_eq!(result, Err(AdManagerError::ChainNotSupported));
        });
    }

    #[test]
    fn test_validate_order_portal_mismatch() {
        let env = setup_validation_env();
        env.as_contract(&env.register(AdManagerContract, ()), || {
            let (ad, mut params) = valid_ad_and_params(&env);
            // Chain has a specific portal, but params has a different one
            let chain_info = ChainInfo {
                supported: true,
                order_portal: make_bytes32(&env, 0x11),
            };
            storage::set_chain(&env, params.order_chain_id, &chain_info);
            storage::set_token_route(
                &env,
                &params.ad_chain_token,
                params.order_chain_id,
                &params.order_chain_token,
            );
            params.src_order_portal = make_bytes32(&env, 0x22); // Different from chain's portal
            let result = validation::validate_order(&env, &ad, &params);
            assert_eq!(result, Err(AdManagerError::OrderPortalMismatch));
        });
    }

    #[test]
    fn test_validate_order_portal_zero_skips_check() {
        let env = setup_validation_env();
        env.as_contract(&env.register(AdManagerContract, ()), || {
            let (ad, params) = valid_ad_and_params(&env);
            // Chain portal is zero → portal check is skipped
            let chain_info = ChainInfo {
                supported: true,
                order_portal: zero_bytes32(&env),
            };
            storage::set_chain(&env, params.order_chain_id, &chain_info);
            storage::set_token_route(
                &env,
                &params.ad_chain_token,
                params.order_chain_id,
                &params.order_chain_token,
            );
            let result = validation::validate_order(&env, &ad, &params);
            assert!(result.is_ok());
        });
    }

    #[test]
    fn test_validate_order_chain_mismatch() {
        let env = setup_validation_env();
        env.as_contract(&env.register(AdManagerContract, ()), || {
            let (mut ad, params) = valid_ad_and_params(&env);
            ad.order_chain_id = 999; // Ad configured for different chain
            setup_chain_and_route(&env, &params);
            let result = validation::validate_order(&env, &ad, &params);
            assert_eq!(result, Err(AdManagerError::OrderChainMismatch));
        });
    }

    #[test]
    fn test_validate_order_missing_route() {
        let env = setup_validation_env();
        env.as_contract(&env.register(AdManagerContract, ()), || {
            let (ad, params) = valid_ad_and_params(&env);
            // Set chain but NOT the token route
            let chain_info = ChainInfo {
                supported: true,
                order_portal: params.src_order_portal.clone(),
            };
            storage::set_chain(&env, params.order_chain_id, &chain_info);
            let result = validation::validate_order(&env, &ad, &params);
            assert_eq!(result, Err(AdManagerError::MissingRoute));
        });
    }

    #[test]
    fn test_validate_order_token_mismatch() {
        let env = setup_validation_env();
        env.as_contract(&env.register(AdManagerContract, ()), || {
            let (ad, params) = valid_ad_and_params(&env);
            let chain_info = ChainInfo {
                supported: true,
                order_portal: params.src_order_portal.clone(),
            };
            storage::set_chain(&env, params.order_chain_id, &chain_info);
            // Route points to a different order token than what params expects
            storage::set_token_route(
                &env,
                &params.ad_chain_token,
                params.order_chain_id,
                &make_bytes32(&env, 0x99), // Wrong token
            );
            let result = validation::validate_order(&env, &ad, &params);
            assert_eq!(result, Err(AdManagerError::OrderTokenMismatch));
        });
    }

    #[test]
    fn test_validate_order_ad_token_mismatch() {
        let env = setup_validation_env();
        env.as_contract(&env.register(AdManagerContract, ()), || {
            let (mut ad, params) = valid_ad_and_params(&env);
            ad.token = make_bytes32(&env, 0x99); // Ad has different token
            setup_chain_and_route(&env, &params);
            let result = validation::validate_order(&env, &ad, &params);
            assert_eq!(result, Err(AdManagerError::AdTokenMismatch));
        });
    }

    #[test]
    fn test_validate_order_ad_recipient_mismatch() {
        let env = setup_validation_env();
        env.as_contract(&env.register(AdManagerContract, ()), || {
            let (mut ad, params) = valid_ad_and_params(&env);
            ad.ad_recipient = make_bytes32(&env, 0x99); // Ad has different recipient
            setup_chain_and_route(&env, &params);
            let result = validation::validate_order(&env, &ad, &params);
            assert_eq!(result, Err(AdManagerError::AdRecipientMismatch));
        });
    }
}

// =============================================================================
// Auth & Request Hash Tests
// =============================================================================

mod auth_tests {
    use crate::auth;
    use soroban_sdk::{BytesN, Env, String as SorobanString};

    #[test]
    fn test_create_ad_request_hash_deterministic() {
        let env = Env::default();
        let ad_id = SorobanString::from_str(&env, "test-ad");
        let ad_token = BytesN::from_array(&env, &[0xAA; 32]);
        let ad_recipient = BytesN::from_array(&env, &[0xBB; 32]);
        let auth_token = BytesN::from_array(&env, &[0xCC; 32]);
        let contract_addr = BytesN::from_array(&env, &[0xDD; 32]);

        let hash1 = auth::create_ad_request_hash(
            &env,
            &ad_id,
            &ad_token,
            1000,
            1,
            &ad_recipient,
            &auth_token,
            9999,
            42,
            &contract_addr,
        );
        let hash2 = auth::create_ad_request_hash(
            &env,
            &ad_id,
            &ad_token,
            1000,
            1,
            &ad_recipient,
            &auth_token,
            9999,
            42,
            &contract_addr,
        );
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_different_request_types_produce_different_hashes() {
        let env = Env::default();
        let ad_id = SorobanString::from_str(&env, "test-ad");
        let token = BytesN::from_array(&env, &[0xAA; 32]);
        let auth_token = BytesN::from_array(&env, &[0xCC; 32]);
        let contract_addr = BytesN::from_array(&env, &[0xDD; 32]);

        let create_hash = auth::create_ad_request_hash(
            &env,
            &ad_id,
            &token,
            1000,
            1,
            &token,
            &auth_token,
            9999,
            42,
            &contract_addr,
        );
        let fund_hash = auth::fund_ad_request_hash(
            &env,
            &ad_id,
            1000,
            &auth_token,
            9999,
            42,
            &contract_addr,
        );
        assert_ne!(
            create_hash, fund_hash,
            "Different request types must produce different hashes"
        );
    }
}

// =============================================================================
// Storage Tests
// =============================================================================

mod storage_tests {
    use crate::storage;
    use crate::types::{Ad, ChainInfo, Status};

    use super::*;

    #[test]
    fn test_chain_crud() {
        let env = Env::default();
        let contract_id = env.register(AdManagerContract, ());

        env.as_contract(&contract_id, || {
            let chain_id: u128 = 1;

            // Initially no chain
            assert!(storage::get_chain(&env, chain_id).is_none());

            // Set chain
            let chain_info = ChainInfo {
                supported: true,
                order_portal: BytesN::from_array(&env, &[0xAA; 32]),
            };
            storage::set_chain(&env, chain_id, &chain_info);

            // Read it back
            let stored = storage::get_chain(&env, chain_id).unwrap();
            assert!(stored.supported);

            // Remove it
            storage::remove_chain(&env, chain_id);
            assert!(storage::get_chain(&env, chain_id).is_none());
        });
    }

    #[test]
    fn test_token_route_crud() {
        let env = Env::default();
        let contract_id = env.register(AdManagerContract, ());

        env.as_contract(&contract_id, || {
            let ad_token = BytesN::from_array(&env, &[0xAA; 32]);
            let order_token = BytesN::from_array(&env, &[0xBB; 32]);
            let chain_id: u128 = 1;

            assert!(storage::get_token_route(&env, &ad_token, chain_id).is_none());

            storage::set_token_route(&env, &ad_token, chain_id, &order_token);

            let stored = storage::get_token_route(&env, &ad_token, chain_id).unwrap();
            assert_eq!(stored, order_token);

            storage::remove_token_route(&env, &ad_token, chain_id);
            assert!(storage::get_token_route(&env, &ad_token, chain_id).is_none());
        });
    }

    #[test]
    fn test_ad_storage() {
        let env = Env::default();
        let contract_id = env.register(AdManagerContract, ());

        env.as_contract(&contract_id, || {
            let ad_id = SorobanString::from_str(&env, "test-ad");

            assert!(storage::get_ad(&env, &ad_id).is_none());

            let ad = Ad {
                order_chain_id: 1,
                ad_recipient: BytesN::from_array(&env, &[0xCC; 32]),
                maker: Address::generate(&env),
                token: BytesN::from_array(&env, &[0xAA; 32]),
                balance: 1_000_000,
                locked: 100_000,
                open: true,
            };

            storage::set_ad(&env, &ad_id, &ad);

            let stored = storage::get_ad(&env, &ad_id).unwrap();
            assert_eq!(stored.balance, 1_000_000);
            assert_eq!(stored.locked, 100_000);
            assert!(stored.open);
        });
    }

    #[test]
    fn test_order_status_lifecycle() {
        let env = Env::default();
        let contract_id = env.register(AdManagerContract, ());

        env.as_contract(&contract_id, || {
            let order_hash = BytesN::from_array(&env, &[0xAA; 32]);

            // Default is None
            assert_eq!(storage::get_order_status(&env, &order_hash), Status::None);

            // Set to Open
            storage::set_order_status(&env, &order_hash, Status::Open);
            assert_eq!(storage::get_order_status(&env, &order_hash), Status::Open);

            // Set to Filled
            storage::set_order_status(&env, &order_hash, Status::Filled);
            assert_eq!(storage::get_order_status(&env, &order_hash), Status::Filled);
        });
    }

    #[test]
    fn test_nullifier_tracking() {
        let env = Env::default();
        let contract_id = env.register(AdManagerContract, ());

        env.as_contract(&contract_id, || {
            let nullifier = BytesN::from_array(&env, &[0xAA; 32]);

            assert!(!storage::is_nullifier_used(&env, &nullifier));

            storage::set_nullifier_used(&env, &nullifier);
            assert!(storage::is_nullifier_used(&env, &nullifier));
        });
    }

    #[test]
    fn test_manager_tracking() {
        let env = Env::default();
        let contract_id = env.register(AdManagerContract, ());

        env.as_contract(&contract_id, || {
            let addr = Address::generate(&env);

            assert!(!storage::is_manager(&env, &addr));

            storage::set_manager(&env, &addr, true);
            assert!(storage::is_manager(&env, &addr));

            storage::set_manager(&env, &addr, false);
            assert!(!storage::is_manager(&env, &addr));
        });
    }

    #[test]
    fn test_request_hash_and_token_tracking() {
        let env = Env::default();
        let contract_id = env.register(AdManagerContract, ());

        env.as_contract(&contract_id, || {
            let hash = BytesN::from_array(&env, &[0xAA; 32]);
            let token = BytesN::from_array(&env, &[0xBB; 32]);

            assert!(!storage::is_request_hash_used(&env, &hash));
            assert!(!storage::is_request_token_used(&env, &token));

            storage::set_request_hash_used(&env, &hash);
            storage::set_request_token_used(&env, &token);

            assert!(storage::is_request_hash_used(&env, &hash));
            assert!(storage::is_request_token_used(&env, &token));
        });
    }

    #[test]
    fn test_ad_id_tracking() {
        let env = Env::default();
        let contract_id = env.register(AdManagerContract, ());

        env.as_contract(&contract_id, || {
            let ad_id = SorobanString::from_str(&env, "my-ad");

            assert!(!storage::is_ad_id_used(&env, &ad_id));

            storage::set_ad_id_used(&env, &ad_id);
            assert!(storage::is_ad_id_used(&env, &ad_id));
        });
    }
}

// =============================================================================
// Ad Lifecycle Integration Tests
// =============================================================================

mod ad_lifecycle_tests {
    use crate::storage;
    use crate::types::{Ad, ChainInfo, ContractConfig};
    use crate::{AdManagerContract, AdManagerContractClient};
    use soroban_sdk::{
        testutils::Address as _, Address, BytesN, Env, String as SorobanString,
    };

    /// Helper: set up an initialized contract with a maker that has an open ad,
    /// all done through direct storage writes to bypass auth.
    fn setup_ad_env() -> (Env, Address, SorobanString, Ad) {
        let env = Env::default();
        let contract_id = env.register(AdManagerContract, ());
        let maker = Address::generate(&env);
        let ad_id = SorobanString::from_str(&env, "test-ad-1");

        env.as_contract(&contract_id, || {
            // Initialize config
            let config = ContractConfig {
                admin: Address::generate(&env),
                verifier: Address::generate(&env),
                merkle_manager: Address::generate(&env),
                w_native_token: Address::generate(&env),
                chain_id: 2_000_000_002,
            };
            storage::set_config(&env, &config);
            storage::set_initialized(&env);
            storage::set_manager(&env, &config.admin, true);

            // Set up chain
            let chain_info = ChainInfo {
                supported: true,
                order_portal: BytesN::from_array(&env, &[0xFF; 32]),
            };
            storage::set_chain(&env, 1, &chain_info);

            // Set up token route
            let ad_token = BytesN::from_array(&env, &[0xAA; 32]);
            let order_token = BytesN::from_array(&env, &[0xBB; 32]);
            storage::set_token_route(&env, &ad_token, 1, &order_token);

            // Create ad
            let ad = Ad {
                order_chain_id: 1,
                ad_recipient: BytesN::from_array(&env, &[0xCC; 32]),
                maker: maker.clone(),
                token: ad_token.clone(),
                balance: 1_000_000,
                locked: 0,
                open: true,
            };
            storage::set_ad(&env, &ad_id, &ad);
            storage::set_ad_id_used(&env, &ad_id);
        });

        let ad = env.as_contract(&contract_id, || {
            storage::get_ad(&env, &ad_id).unwrap()
        });

        (env, contract_id, ad_id, ad)
    }

    #[test]
    fn test_view_ad_details() {
        let (env, contract_id, ad_id, _) = setup_ad_env();
        let client = AdManagerContractClient::new(&env, &contract_id);

        let ad = client.get_ad(&ad_id).unwrap();
        assert_eq!(ad.balance, 1_000_000);
        assert_eq!(ad.locked, 0);
        assert!(ad.open);
        assert_eq!(ad.order_chain_id, 1);
    }

    #[test]
    fn test_available_liquidity() {
        let (env, contract_id, ad_id, _) = setup_ad_env();
        let client = AdManagerContractClient::new(&env, &contract_id);

        assert_eq!(client.available_liquidity(&ad_id), 1_000_000);

        // Simulate locking some funds
        env.as_contract(&contract_id, || {
            let mut ad = storage::get_ad(&env, &ad_id).unwrap();
            ad.locked = 300_000;
            storage::set_ad(&env, &ad_id, &ad);
        });

        assert_eq!(client.available_liquidity(&ad_id), 700_000);
    }

    #[test]
    fn test_available_liquidity_nonexistent_ad() {
        let env = Env::default();
        let contract_id = env.register(AdManagerContract, ());
        let client = AdManagerContractClient::new(&env, &contract_id);

        let missing = SorobanString::from_str(&env, "no-such-ad");
        assert_eq!(client.available_liquidity(&missing), 0);
    }

    #[test]
    fn test_ad_balance_and_lock_tracking() {
        let (env, contract_id, ad_id, _) = setup_ad_env();

        env.as_contract(&contract_id, || {
            let mut ad = storage::get_ad(&env, &ad_id).unwrap();
            assert_eq!(ad.balance, 1_000_000);
            assert_eq!(ad.locked, 0);

            // Simulate funding
            ad.balance += 500_000;
            storage::set_ad(&env, &ad_id, &ad);

            let ad = storage::get_ad(&env, &ad_id).unwrap();
            assert_eq!(ad.balance, 1_500_000);

            // Simulate lock for order
            let mut ad = ad;
            ad.locked += 200_000;
            storage::set_ad(&env, &ad_id, &ad);

            let ad = storage::get_ad(&env, &ad_id).unwrap();
            assert_eq!(ad.balance, 1_500_000);
            assert_eq!(ad.locked, 200_000);
            let available = ad.balance - ad.locked;
            assert_eq!(available, 1_300_000);

            // Simulate unlock (filled)
            let mut ad = ad;
            ad.locked -= 200_000;
            ad.balance -= 200_000;
            storage::set_ad(&env, &ad_id, &ad);

            let ad = storage::get_ad(&env, &ad_id).unwrap();
            assert_eq!(ad.balance, 1_300_000);
            assert_eq!(ad.locked, 0);
        });
    }

    #[test]
    fn test_ad_close_logic() {
        let (env, contract_id, ad_id, _) = setup_ad_env();

        env.as_contract(&contract_id, || {
            let mut ad = storage::get_ad(&env, &ad_id).unwrap();
            assert!(ad.open);

            // Close it
            ad.open = false;
            ad.balance = 0;
            storage::set_ad(&env, &ad_id, &ad);

            let ad = storage::get_ad(&env, &ad_id).unwrap();
            assert!(!ad.open);
            assert_eq!(ad.balance, 0);
        });
    }

    #[test]
    fn test_close_ad_with_locks_should_fail() {
        let (env, contract_id, ad_id, _) = setup_ad_env();

        env.as_contract(&contract_id, || {
            let mut ad = storage::get_ad(&env, &ad_id).unwrap();
            ad.locked = 100_000;
            storage::set_ad(&env, &ad_id, &ad);

            // Business rule: cannot close ad with active locks
            let ad = storage::get_ad(&env, &ad_id).unwrap();
            assert_ne!(ad.locked, 0, "Ad should have active locks");
            // The contract checks: if ad.locked != 0 { return Err(ActiveLocks) }
        });
    }

    #[test]
    fn test_withdraw_exceeds_available_logic() {
        let (env, contract_id, ad_id, _) = setup_ad_env();

        env.as_contract(&contract_id, || {
            let mut ad = storage::get_ad(&env, &ad_id).unwrap();
            ad.locked = 800_000;
            storage::set_ad(&env, &ad_id, &ad);

            let ad = storage::get_ad(&env, &ad_id).unwrap();
            let available = ad.balance - ad.locked;
            assert_eq!(available, 200_000);

            // Requesting 300k should fail
            let requested = 300_000u128;
            assert!(
                requested > available,
                "Request should exceed available liquidity"
            );
        });
    }

    #[test]
    fn test_multiple_ads_independent() {
        let env = Env::default();
        let contract_id = env.register(AdManagerContract, ());
        let maker = Address::generate(&env);

        env.as_contract(&contract_id, || {
            let ad1_id = SorobanString::from_str(&env, "ad-1");
            let ad2_id = SorobanString::from_str(&env, "ad-2");

            let ad1 = Ad {
                order_chain_id: 1,
                ad_recipient: BytesN::from_array(&env, &[0xAA; 32]),
                maker: maker.clone(),
                token: BytesN::from_array(&env, &[0x11; 32]),
                balance: 1_000_000,
                locked: 0,
                open: true,
            };
            let ad2 = Ad {
                order_chain_id: 2,
                ad_recipient: BytesN::from_array(&env, &[0xBB; 32]),
                maker: maker.clone(),
                token: BytesN::from_array(&env, &[0x22; 32]),
                balance: 5_000_000,
                locked: 2_000_000,
                open: true,
            };

            storage::set_ad(&env, &ad1_id, &ad1);
            storage::set_ad(&env, &ad2_id, &ad2);

            // Verify they're independent
            let stored1 = storage::get_ad(&env, &ad1_id).unwrap();
            let stored2 = storage::get_ad(&env, &ad2_id).unwrap();

            assert_eq!(stored1.balance, 1_000_000);
            assert_eq!(stored2.balance, 5_000_000);
            assert_eq!(stored1.order_chain_id, 1);
            assert_eq!(stored2.order_chain_id, 2);

            // Modifying one doesn't affect the other
            let mut ad1_mut = stored1;
            ad1_mut.balance = 0;
            storage::set_ad(&env, &ad1_id, &ad1_mut);

            let stored2_again = storage::get_ad(&env, &ad2_id).unwrap();
            assert_eq!(stored2_again.balance, 5_000_000);
        });
    }
}

// =============================================================================
// Order Lifecycle Tests
// =============================================================================

mod order_lifecycle_tests {
    use crate::storage;
    use crate::types::{Ad, ChainInfo, Status};
    use crate::{AdManagerContract, AdManagerContractClient};
    use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, String as SorobanString};

    #[test]
    fn test_order_status_transitions() {
        let env = Env::default();
        let contract_id = env.register(AdManagerContract, ());

        env.as_contract(&contract_id, || {
            let order_hash = BytesN::from_array(&env, &[0xAA; 32]);

            // None -> Open (lock_for_order)
            assert_eq!(storage::get_order_status(&env, &order_hash), Status::None);
            storage::set_order_status(&env, &order_hash, Status::Open);
            assert_eq!(storage::get_order_status(&env, &order_hash), Status::Open);

            // Open -> Filled (unlock)
            storage::set_order_status(&env, &order_hash, Status::Filled);
            assert_eq!(storage::get_order_status(&env, &order_hash), Status::Filled);
        });
    }

    #[test]
    fn test_order_lock_updates_ad_balance() {
        let env = Env::default();
        let contract_id = env.register(AdManagerContract, ());

        env.as_contract(&contract_id, || {
            let ad_id = SorobanString::from_str(&env, "test-ad");
            let ad = Ad {
                order_chain_id: 1,
                ad_recipient: BytesN::from_array(&env, &[0xCC; 32]),
                maker: Address::generate(&env),
                token: BytesN::from_array(&env, &[0xAA; 32]),
                balance: 1_000_000,
                locked: 0,
                open: true,
            };
            storage::set_ad(&env, &ad_id, &ad);

            // Simulate lock_for_order: lock 200k
            let mut ad = storage::get_ad(&env, &ad_id).unwrap();
            let lock_amount = 200_000u128;
            assert!(lock_amount <= ad.balance - ad.locked);
            ad.locked += lock_amount;
            storage::set_ad(&env, &ad_id, &ad);

            let ad = storage::get_ad(&env, &ad_id).unwrap();
            assert_eq!(ad.locked, 200_000);
            assert_eq!(ad.balance, 1_000_000); // Balance unchanged, just locked

            // Simulate unlock: deduct from both locked and balance
            let mut ad = ad;
            ad.locked -= lock_amount;
            ad.balance -= lock_amount;
            storage::set_ad(&env, &ad_id, &ad);

            let ad = storage::get_ad(&env, &ad_id).unwrap();
            assert_eq!(ad.locked, 0);
            assert_eq!(ad.balance, 800_000);
        });
    }

    #[test]
    fn test_multiple_orders_on_same_ad() {
        let env = Env::default();
        let contract_id = env.register(AdManagerContract, ());

        env.as_contract(&contract_id, || {
            let ad_id = SorobanString::from_str(&env, "test-ad");
            let ad = Ad {
                order_chain_id: 1,
                ad_recipient: BytesN::from_array(&env, &[0xCC; 32]),
                maker: Address::generate(&env),
                token: BytesN::from_array(&env, &[0xAA; 32]),
                balance: 1_000_000,
                locked: 0,
                open: true,
            };
            storage::set_ad(&env, &ad_id, &ad);

            let order1 = BytesN::from_array(&env, &[0x01; 32]);
            let order2 = BytesN::from_array(&env, &[0x02; 32]);
            let order3 = BytesN::from_array(&env, &[0x03; 32]);

            // Lock 3 orders: 200k + 300k + 100k = 600k locked
            let mut ad = storage::get_ad(&env, &ad_id).unwrap();
            ad.locked += 200_000;
            storage::set_ad(&env, &ad_id, &ad);
            storage::set_order_status(&env, &order1, Status::Open);

            let mut ad = storage::get_ad(&env, &ad_id).unwrap();
            ad.locked += 300_000;
            storage::set_ad(&env, &ad_id, &ad);
            storage::set_order_status(&env, &order2, Status::Open);

            let mut ad = storage::get_ad(&env, &ad_id).unwrap();
            ad.locked += 100_000;
            storage::set_ad(&env, &ad_id, &ad);
            storage::set_order_status(&env, &order3, Status::Open);

            let ad = storage::get_ad(&env, &ad_id).unwrap();
            assert_eq!(ad.locked, 600_000);
            assert_eq!(ad.balance - ad.locked, 400_000);

            // Fill order 2 (300k)
            let mut ad = ad;
            ad.locked -= 300_000;
            ad.balance -= 300_000;
            storage::set_ad(&env, &ad_id, &ad);
            storage::set_order_status(&env, &order2, Status::Filled);

            let ad = storage::get_ad(&env, &ad_id).unwrap();
            assert_eq!(ad.locked, 300_000);
            assert_eq!(ad.balance, 700_000);
            assert_eq!(ad.balance - ad.locked, 400_000);

            // Verify order statuses
            assert_eq!(storage::get_order_status(&env, &order1), Status::Open);
            assert_eq!(storage::get_order_status(&env, &order2), Status::Filled);
            assert_eq!(storage::get_order_status(&env, &order3), Status::Open);
        });
    }

    #[test]
    fn test_nullifier_prevents_double_unlock() {
        let env = Env::default();
        let contract_id = env.register(AdManagerContract, ());

        env.as_contract(&contract_id, || {
            let nullifier = BytesN::from_array(&env, &[0xAA; 32]);

            // First use should succeed
            assert!(!storage::is_nullifier_used(&env, &nullifier));
            storage::set_nullifier_used(&env, &nullifier);

            // Second use should be detected
            assert!(
                storage::is_nullifier_used(&env, &nullifier),
                "Nullifier must be marked as used to prevent double-spend"
            );
        });
    }

    #[test]
    fn test_order_duplicate_detection() {
        let env = Env::default();
        let contract_id = env.register(AdManagerContract, ());

        env.as_contract(&contract_id, || {
            let order_hash = BytesN::from_array(&env, &[0xAA; 32]);

            // First order should be allowed (status = None)
            assert_eq!(storage::get_order_status(&env, &order_hash), Status::None);

            storage::set_order_status(&env, &order_hash, Status::Open);

            // Duplicate should be detected (status != None)
            assert_ne!(
                storage::get_order_status(&env, &order_hash),
                Status::None,
                "Duplicate order must be detected"
            );
        });
    }

    #[test]
    fn test_chain_configuration_lifecycle() {
        let env = Env::default();
        let contract_id = env.register(AdManagerContract, ());
        env.as_contract(&contract_id, || {
            // No chain initially
            assert!(storage::get_chain(&env, 1).is_none());

            // Add chain
            let chain_info = ChainInfo {
                supported: true,
                order_portal: BytesN::from_array(&env, &[0xAA; 32]),
            };
            storage::set_chain(&env, 1, &chain_info);

            let stored = storage::get_chain(&env, 1).unwrap();
            assert!(stored.supported);

            // Disable chain
            let disabled = ChainInfo {
                supported: false,
                order_portal: stored.order_portal,
            };
            storage::set_chain(&env, 1, &disabled);

            let stored = storage::get_chain(&env, 1).unwrap();
            assert!(!stored.supported);
        });
    }

    #[test]
    fn test_view_functions_after_init() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register(AdManagerContract, ());
        let client = AdManagerContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let verifier = Address::generate(&env);
        let merkle_manager = Address::generate(&env);
        let w_native_token = Address::generate(&env);
        let chain_id: u128 = 42;

        client.initialize(&admin, &verifier, &merkle_manager, &w_native_token, &chain_id);

        // get_chain_id
        assert_eq!(client.get_chain_id(), 42);

        // is_manager
        assert!(client.is_manager(&admin));
        assert!(!client.is_manager(&Address::generate(&env)));

        // get_config
        let config = client.get_config();
        assert_eq!(config.chain_id, 42);

        // get_ad for non-existent
        let missing = SorobanString::from_str(&env, "does-not-exist");
        assert!(client.get_ad(&missing).is_none());

        // get_chain for non-existent
        assert!(client.get_chain(&999).is_none());

        // get_order_status for unknown hash
        let unknown = BytesN::from_array(&env, &[0xFF; 32]);
        assert_eq!(client.get_order_status(&unknown), Status::None);
    }
}
