#![cfg(test)]

extern crate std;

use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, String as SorobanString};

use crate::{OrderPortalContract, OrderPortalContractClient};

// =============================================================================
// Contract Initialization Tests
// =============================================================================

mod contract_tests {
    use super::*;

    fn setup_env() -> (Env, Address, OrderPortalContractClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register(OrderPortalContract, ());
        let client = OrderPortalContractClient::new(&env, &contract_id);
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

        assert!(client.is_initialized());
        assert!(client.is_manager(&admin));
        assert_eq!(client.get_chain_id(), chain_id);
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

    #[test]
    fn test_view_functions_after_init() {
        let (env, admin, client) = setup_env();

        let verifier = Address::generate(&env);
        let merkle_manager = Address::generate(&env);
        let w_native_token = Address::generate(&env);
        let chain_id: u128 = 42;

        client.initialize(&admin, &verifier, &merkle_manager, &w_native_token, &chain_id);

        assert_eq!(client.get_chain_id(), 42);
        assert!(client.is_manager(&admin));
        assert!(!client.is_manager(&Address::generate(&env)));

        let config = client.get_config();
        assert_eq!(config.chain_id, 42);

        assert!(client.get_chain(&999).is_none());

        let unknown = BytesN::from_array(&env, &[0xFF; 32]);
        assert_eq!(
            client.get_order_status(&unknown),
            crate::types::Status::None
        );
    }
}

// =============================================================================
// Validation Tests
// =============================================================================

mod validation_tests {
    use crate::errors::OrderPortalError;
    use crate::storage;
    use crate::types::ChainInfo;
    use crate::validation;

    use super::*;

    fn make_bytes32(env: &Env, fill: u8) -> BytesN<32> {
        BytesN::from_array(env, &[fill; 32])
    }

    fn zero_bytes32(env: &Env) -> BytesN<32> {
        BytesN::from_array(env, &[0u8; 32])
    }

    fn valid_params(env: &Env) -> crate::types::OrderParams {
        let order_chain_token = make_bytes32(env, 0xAA);
        let ad_chain_token = make_bytes32(env, 0xBB);
        let ad_manager = make_bytes32(env, 0xCC);
        let bridger = make_bytes32(env, 0xDD);
        let order_recipient = make_bytes32(env, 0xEE);
        let ad_recipient = make_bytes32(env, 0xFF);
        let ad_chain_id: u128 = 1;

        crate::types::OrderParams {
            order_chain_token,
            ad_chain_token,
            amount: 100_000,
            bridger,
            order_recipient,
            ad_chain_id,
            ad_manager,
            ad_id: SorobanString::from_str(env, "test-ad"),
            ad_creator: make_bytes32(env, 0x77),
            ad_recipient,
            salt: 42,
        }
    }

    fn setup_chain_and_route(env: &Env, params: &crate::types::OrderParams) {
        let chain_info = ChainInfo {
            supported: true,
            ad_manager: params.ad_manager.clone(),
        };
        storage::set_chain(env, params.ad_chain_id, &chain_info);
        storage::set_token_route(
            env,
            &params.order_chain_token,
            params.ad_chain_id,
            &params.ad_chain_token,
        );
    }

    #[test]
    fn test_validate_order_success() {
        let env = Env::default();
        env.as_contract(&env.register(OrderPortalContract, ()), || {
            let params = valid_params(&env);
            setup_chain_and_route(&env, &params);
            let result = validation::validate_order(&env, &params);
            assert!(result.is_ok());
        });
    }

    #[test]
    fn test_validate_order_zero_amount() {
        let env = Env::default();
        env.as_contract(&env.register(OrderPortalContract, ()), || {
            let mut params = valid_params(&env);
            params.amount = 0;
            setup_chain_and_route(&env, &params);
            let result = validation::validate_order(&env, &params);
            assert_eq!(result, Err(OrderPortalError::ZeroAmount));
        });
    }

    #[test]
    fn test_validate_order_invalid_ad_recipient() {
        let env = Env::default();
        env.as_contract(&env.register(OrderPortalContract, ()), || {
            let mut params = valid_params(&env);
            params.ad_recipient = zero_bytes32(&env);
            setup_chain_and_route(&env, &params);
            let result = validation::validate_order(&env, &params);
            assert_eq!(result, Err(OrderPortalError::InvalidAdRecipient));
        });
    }

    #[test]
    fn test_validate_order_chain_not_supported() {
        let env = Env::default();
        env.as_contract(&env.register(OrderPortalContract, ()), || {
            let params = valid_params(&env);
            // Don't set up chain — not found
            let result = validation::validate_order(&env, &params);
            assert_eq!(result, Err(OrderPortalError::AdChainNotSupported));
        });
    }

    #[test]
    fn test_validate_order_chain_disabled() {
        let env = Env::default();
        env.as_contract(&env.register(OrderPortalContract, ()), || {
            let params = valid_params(&env);
            let chain_info = ChainInfo {
                supported: false,
                ad_manager: params.ad_manager.clone(),
            };
            storage::set_chain(&env, params.ad_chain_id, &chain_info);
            let result = validation::validate_order(&env, &params);
            assert_eq!(result, Err(OrderPortalError::AdChainNotSupported));
        });
    }

    #[test]
    fn test_validate_order_ad_manager_mismatch() {
        let env = Env::default();
        env.as_contract(&env.register(OrderPortalContract, ()), || {
            let params = valid_params(&env);
            let chain_info = ChainInfo {
                supported: true,
                ad_manager: make_bytes32(&env, 0x11), // Different from params
            };
            storage::set_chain(&env, params.ad_chain_id, &chain_info);
            let result = validation::validate_order(&env, &params);
            assert_eq!(result, Err(OrderPortalError::AdManagerMismatch));
        });
    }

    #[test]
    fn test_validate_order_missing_route() {
        let env = Env::default();
        env.as_contract(&env.register(OrderPortalContract, ()), || {
            let params = valid_params(&env);
            // Set chain but not route
            let chain_info = ChainInfo {
                supported: true,
                ad_manager: params.ad_manager.clone(),
            };
            storage::set_chain(&env, params.ad_chain_id, &chain_info);
            let result = validation::validate_order(&env, &params);
            assert_eq!(result, Err(OrderPortalError::MissingRoute));
        });
    }

    #[test]
    fn test_validate_order_ad_token_mismatch() {
        let env = Env::default();
        env.as_contract(&env.register(OrderPortalContract, ()), || {
            let params = valid_params(&env);
            let chain_info = ChainInfo {
                supported: true,
                ad_manager: params.ad_manager.clone(),
            };
            storage::set_chain(&env, params.ad_chain_id, &chain_info);
            // Route points to wrong ad token
            storage::set_token_route(
                &env,
                &params.order_chain_token,
                params.ad_chain_id,
                &make_bytes32(&env, 0x99),
            );
            let result = validation::validate_order(&env, &params);
            assert_eq!(result, Err(OrderPortalError::AdTokenMismatch));
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
    fn test_create_order_request_hash_deterministic() {
        let env = Env::default();
        let ad_id = SorobanString::from_str(&env, "test-ad");
        let order_hash = BytesN::from_array(&env, &[0xAA; 32]);
        let auth_token = BytesN::from_array(&env, &[0xBB; 32]);
        let contract_addr = BytesN::from_array(&env, &[0xCC; 32]);

        let hash1 = auth::create_order_request_hash(
            &env, &ad_id, &order_hash, &auth_token, 9999, 42, &contract_addr,
        );
        let hash2 = auth::create_order_request_hash(
            &env, &ad_id, &order_hash, &auth_token, 9999, 42, &contract_addr,
        );
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_different_request_types_produce_different_hashes() {
        let env = Env::default();
        let ad_id = SorobanString::from_str(&env, "test-ad");
        let order_hash = BytesN::from_array(&env, &[0xAA; 32]);
        let target_root = BytesN::from_array(&env, &[0xDD; 32]);
        let auth_token = BytesN::from_array(&env, &[0xBB; 32]);
        let contract_addr = BytesN::from_array(&env, &[0xCC; 32]);

        let create_hash = auth::create_order_request_hash(
            &env, &ad_id, &order_hash, &auth_token, 9999, 42, &contract_addr,
        );
        let unlock_hash = auth::unlock_order_request_hash(
            &env,
            &ad_id,
            &order_hash,
            &target_root,
            &auth_token,
            9999,
            42,
            &contract_addr,
        );
        assert_ne!(create_hash, unlock_hash);
    }
}

// =============================================================================
// Storage Tests
// =============================================================================

mod storage_tests {
    use crate::storage;
    use crate::types::{ChainInfo, Status};

    use super::*;

    #[test]
    fn test_chain_crud() {
        let env = Env::default();
        let contract_id = env.register(OrderPortalContract, ());

        env.as_contract(&contract_id, || {
            let chain_id: u128 = 1;
            assert!(storage::get_chain(&env, chain_id).is_none());

            let chain_info = ChainInfo {
                supported: true,
                ad_manager: BytesN::from_array(&env, &[0xAA; 32]),
            };
            storage::set_chain(&env, chain_id, &chain_info);

            let stored = storage::get_chain(&env, chain_id).unwrap();
            assert!(stored.supported);

            storage::remove_chain(&env, chain_id);
            assert!(storage::get_chain(&env, chain_id).is_none());
        });
    }

    #[test]
    fn test_token_route_crud() {
        let env = Env::default();
        let contract_id = env.register(OrderPortalContract, ());

        env.as_contract(&contract_id, || {
            let order_token = BytesN::from_array(&env, &[0xAA; 32]);
            let ad_token = BytesN::from_array(&env, &[0xBB; 32]);
            let chain_id: u128 = 1;

            assert!(storage::get_token_route(&env, &order_token, chain_id).is_none());

            storage::set_token_route(&env, &order_token, chain_id, &ad_token);

            let stored = storage::get_token_route(&env, &order_token, chain_id).unwrap();
            assert_eq!(stored, ad_token);

            storage::remove_token_route(&env, &order_token, chain_id);
            assert!(storage::get_token_route(&env, &order_token, chain_id).is_none());
        });
    }

    #[test]
    fn test_order_status_lifecycle() {
        let env = Env::default();
        let contract_id = env.register(OrderPortalContract, ());

        env.as_contract(&contract_id, || {
            let order_hash = BytesN::from_array(&env, &[0xAA; 32]);

            assert_eq!(storage::get_order_status(&env, &order_hash), Status::None);

            storage::set_order_status(&env, &order_hash, Status::Open);
            assert_eq!(storage::get_order_status(&env, &order_hash), Status::Open);

            storage::set_order_status(&env, &order_hash, Status::Filled);
            assert_eq!(storage::get_order_status(&env, &order_hash), Status::Filled);
        });
    }

    #[test]
    fn test_nullifier_tracking() {
        let env = Env::default();
        let contract_id = env.register(OrderPortalContract, ());

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
        let contract_id = env.register(OrderPortalContract, ());

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
        let contract_id = env.register(OrderPortalContract, ());

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
}

// =============================================================================
// Order Lifecycle Tests
// =============================================================================

mod order_lifecycle_tests {
    use crate::storage;
    use crate::types::Status;

    use super::*;

    #[test]
    fn test_order_status_transitions() {
        let env = Env::default();
        let contract_id = env.register(OrderPortalContract, ());

        env.as_contract(&contract_id, || {
            let order_hash = BytesN::from_array(&env, &[0xAA; 32]);

            // None -> Open (create_order)
            assert_eq!(storage::get_order_status(&env, &order_hash), Status::None);
            storage::set_order_status(&env, &order_hash, Status::Open);
            assert_eq!(storage::get_order_status(&env, &order_hash), Status::Open);

            // Open -> Filled (unlock)
            storage::set_order_status(&env, &order_hash, Status::Filled);
            assert_eq!(storage::get_order_status(&env, &order_hash), Status::Filled);
        });
    }

    #[test]
    fn test_nullifier_prevents_double_unlock() {
        let env = Env::default();
        let contract_id = env.register(OrderPortalContract, ());

        env.as_contract(&contract_id, || {
            let nullifier = BytesN::from_array(&env, &[0xAA; 32]);

            assert!(!storage::is_nullifier_used(&env, &nullifier));
            storage::set_nullifier_used(&env, &nullifier);
            assert!(
                storage::is_nullifier_used(&env, &nullifier),
                "Nullifier must be marked as used to prevent double-spend"
            );
        });
    }

    #[test]
    fn test_order_duplicate_detection() {
        let env = Env::default();
        let contract_id = env.register(OrderPortalContract, ());

        env.as_contract(&contract_id, || {
            let order_hash = BytesN::from_array(&env, &[0xAA; 32]);

            assert_eq!(storage::get_order_status(&env, &order_hash), Status::None);
            storage::set_order_status(&env, &order_hash, Status::Open);
            assert_ne!(
                storage::get_order_status(&env, &order_hash),
                Status::None,
                "Duplicate order must be detected"
            );
        });
    }

    #[test]
    fn test_multiple_independent_orders() {
        let env = Env::default();
        let contract_id = env.register(OrderPortalContract, ());

        env.as_contract(&contract_id, || {
            let order1 = BytesN::from_array(&env, &[0x01; 32]);
            let order2 = BytesN::from_array(&env, &[0x02; 32]);
            let order3 = BytesN::from_array(&env, &[0x03; 32]);

            storage::set_order_status(&env, &order1, Status::Open);
            storage::set_order_status(&env, &order2, Status::Open);
            storage::set_order_status(&env, &order3, Status::Open);

            // Fill order 2 only
            storage::set_order_status(&env, &order2, Status::Filled);

            assert_eq!(storage::get_order_status(&env, &order1), Status::Open);
            assert_eq!(storage::get_order_status(&env, &order2), Status::Filled);
            assert_eq!(storage::get_order_status(&env, &order3), Status::Open);
        });
    }

    #[test]
    fn test_chain_configuration_lifecycle() {
        let env = Env::default();
        let contract_id = env.register(OrderPortalContract, ());

        env.as_contract(&contract_id, || {
            assert!(storage::get_chain(&env, 1).is_none());

            let chain_info = crate::types::ChainInfo {
                supported: true,
                ad_manager: BytesN::from_array(&env, &[0xAA; 32]),
            };
            storage::set_chain(&env, 1, &chain_info);
            assert!(storage::get_chain(&env, 1).unwrap().supported);

            let disabled = crate::types::ChainInfo {
                supported: false,
                ad_manager: chain_info.ad_manager,
            };
            storage::set_chain(&env, 1, &disabled);
            assert!(!storage::get_chain(&env, 1).unwrap().supported);
        });
    }

    #[test]
    fn test_get_dest_token() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register(OrderPortalContract, ());
        let client = OrderPortalContractClient::new(&env, &contract_id);

        let order_token = BytesN::from_array(&env, &[0xAA; 32]);
        let zero = BytesN::from_array(&env, &[0u8; 32]);

        // Non-existent returns zero
        assert_eq!(client.get_dest_token(&order_token, &1), zero);

        // After setting a route
        env.as_contract(&contract_id, || {
            let ad_token = BytesN::from_array(&env, &[0xBB; 32]);
            storage::set_token_route(&env, &order_token, 1, &ad_token);
        });

        let result = client.get_dest_token(&order_token, &1);
        assert_eq!(result, BytesN::from_array(&env, &[0xBB; 32]));
    }
}
