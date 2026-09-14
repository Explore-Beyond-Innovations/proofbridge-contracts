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
        let type_string = "Order(bytes32 orderChainToken,bytes32 adChainToken,uint256 amount,bytes32 bridger,uint256 orderChainId,bytes32 orderPortal,bytes32 orderRecipient,uint256 adChainId,bytes32 adManager,string adId,bytes32 adCreator,bytes32 adRecipient,uint256 salt,uint8 orderDecimals,uint8 adDecimals,uint256 deadline,bytes32 adSettlementSigner)";
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
}

// =============================================================================
// Route timing (2.3e D6)
// =============================================================================

mod timing_tests {
    use crate::timing::{validate, MIN_BUFFER};
    use crate::types::RouteTiming;

    fn t(
        min_window: u64,
        buffer: u64,
        margin: u64,
        long_backstop: u64,
        claim_stagger: u64,
    ) -> RouteTiming {
        RouteTiming {
            min_window,
            buffer,
            margin,
            long_backstop,
            claim_stagger,
        }
    }

    #[test]
    fn validation_matrix() {
        assert_eq!(validate(&t(0, MIN_BUFFER - 1, 0, 86_400, 0)), Err(1));
        assert_eq!(validate(&t(3_600, 3_600, 3_600, 86_400, 0)), Err(2));
        assert_eq!(validate(&t(0, 7_200, 0, 3_600, 0)), Err(3));
        assert_eq!(validate(&t(1_800, 3_600, 0, 86_400, 1_800)), Err(4));
        assert_eq!(validate(&t(60, 3_600, 120, 86_400, 0)), Err(5));
        // The D6 defaults, the smallest legal set, and the stagger switched off with a zero window.
        assert_eq!(validate(&t(3_600, 7_200, 120, 259_200, 1_800)), Ok(()));
        assert_eq!(validate(&t(0, MIN_BUFFER, 0, MIN_BUFFER, 0)), Ok(()));
    }
}
