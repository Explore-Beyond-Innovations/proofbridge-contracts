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

        client.initialize(
            &admin,
            &verifier,
            &merkle_manager,
            &w_native_token,
            &chain_id,
        );

        assert!(client.is_initialized());
        assert_eq!(client.get_chain_id(), chain_id);
    }

    #[test]
    fn test_double_initialization_fails() {
        let (env, admin, client) = setup_env();

        let verifier = Address::generate(&env);
        let merkle_manager = Address::generate(&env);
        let w_native_token = Address::generate(&env);
        let chain_id: u128 = 2_000_000_002;

        client.initialize(
            &admin,
            &verifier,
            &merkle_manager,
            &w_native_token,
            &chain_id,
        );

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

        client.initialize(
            &admin,
            &verifier,
            &merkle_manager,
            &w_native_token,
            &chain_id,
        );

        assert_eq!(client.get_chain_id(), 42);

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
            salt: soroban_sdk::U256::from_u128(env, 42),
            order_decimals: 7,
            ad_decimals: 7,
            deadline: 4_102_444_800,
            ad_settlement_signer: make_bytes32(env, 0x77),
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
    fn test_bytes32_to_account_address_rejects_zero() {
        let env = Env::default();
        let zero = zero_bytes32(&env);
        // Direct call into the refactored helper — zero bytes must surface as
        // the typed contract-specific error, not a panic.
        let result: Result<Address, OrderPortalError> =
            proofbridge_core::token::bytes32_to_account_address(&env, &zero);
        assert_eq!(result, Err(OrderPortalError::InvalidAccountAddress));
    }

    #[test]
    fn test_bytes32_to_account_address_decodes_non_zero() {
        let env = Env::default();
        let bytes = make_bytes32(&env, 0xAB);
        let result: Result<Address, OrderPortalError> =
            proofbridge_core::token::bytes32_to_account_address(&env, &bytes);
        assert!(result.is_ok(), "any non-zero 32-byte pubkey must decode");
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

// 17-field EIP-712 order-hash parity (T-19, T-66) against the frozen 2.5b fixture; the same file
// drives the EVM and relayer suites.
mod order_hash_parity {
    extern crate std;
    use crate::eip712::{hash_order, keccak256, struct_hash_order, ORDER_TYPEHASH};
    use crate::types::OrderParams;
    use soroban_sdk::{Bytes, BytesN, Env, String as SorobanString, U256};

    const V: &str = include_str!("../../../../test-vectors/order-hash-v2.json");

    fn arr32(hex_str: &str) -> [u8; 32] {
        let b = hex::decode(hex_str.trim_start_matches("0x")).expect("invalid hex");
        let mut a = [0u8; 32];
        a.copy_from_slice(&b);
        a
    }

    fn bn32(env: &Env, hex_str: &str) -> BytesN<32> {
        BytesN::from_array(env, &arr32(hex_str))
    }

    fn u256(env: &Env, hex_str: &str) -> U256 {
        U256::from_be_bytes(env, &Bytes::from_array(env, &arr32(hex_str)))
    }

    #[test]
    fn typehash_is_the_fixture_string() {
        let j: serde_json::Value = serde_json::from_str(V).unwrap();
        let type_string = j["_meta"]["orderTypeString"].as_str().unwrap();
        assert_eq!(keccak256(type_string.as_bytes()), ORDER_TYPEHASH);
        assert_eq!(
            ORDER_TYPEHASH,
            arr32(j["_meta"]["orderTypehash"].as_str().unwrap())
        );
    }

    #[test]
    fn every_vector_hashes_as_frozen() {
        let env = Env::default();
        let j: serde_json::Value = serde_json::from_str(V).unwrap();
        let vectors = j["vectors"].as_array().unwrap();
        assert_eq!(vectors.len() as u64, j["count"].as_u64().unwrap());
        assert!(vectors.len() >= 11, "vector set shrank");
        for v in vectors {
            let o = &v["order"];
            let s = |k: &str| o[k].as_str().unwrap();
            let params = OrderParams {
                order_chain_token: bn32(&env, s("orderChainToken")),
                ad_chain_token: bn32(&env, s("adChainToken")),
                amount: s("amount").parse::<u128>().unwrap(),
                bridger: bn32(&env, s("bridger")),
                order_recipient: bn32(&env, s("orderRecipient")),
                ad_chain_id: s("adChainId").parse::<u128>().unwrap(),
                ad_manager: bn32(&env, s("adManager")),
                ad_id: SorobanString::from_str(&env, s("adId")),
                ad_creator: bn32(&env, s("adCreator")),
                ad_recipient: bn32(&env, s("adRecipient")),
                salt: u256(&env, s("saltHex")),
                order_decimals: o["orderDecimals"].as_u64().unwrap() as u32,
                ad_decimals: o["adDecimals"].as_u64().unwrap() as u32,
                deadline: s("deadline").parse::<u64>().unwrap(),
                ad_settlement_signer: bn32(&env, s("adSettlementSigner")),
            };
            let order_chain_id = s("orderChainId").parse::<u128>().unwrap();
            let order_portal = bn32(&env, s("orderPortal"));
            let struct_hash = struct_hash_order(&params, order_chain_id, &order_portal.to_array());
            let digest = hash_order(&env, &params, order_chain_id, &order_portal);
            let name = v["name"].as_str().unwrap();
            assert_eq!(
                struct_hash,
                arr32(v["expected"]["structHash"].as_str().unwrap()),
                "{}",
                name
            );
            assert_eq!(
                digest.to_array(),
                arr32(v["expected"]["orderHash"].as_str().unwrap()),
                "{}",
                name
            );
        }
    }

    // The rejects can't be represented in the Soroban types, so they can never be hashed here.
    #[test]
    fn rejects_do_not_fit_the_types() {
        let j: serde_json::Value = serde_json::from_str(V).unwrap();
        let r = j["rejects"].as_array().unwrap();
        assert_eq!(r[0]["field"], "amount");
        assert!(r[0]["value"].as_str().unwrap().parse::<u128>().is_err());
        assert_eq!(r[1]["field"], "deadline");
        assert!(r[1]["value"].as_str().unwrap().parse::<u64>().is_err());
    }
}
