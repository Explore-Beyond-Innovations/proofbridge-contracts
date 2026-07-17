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
        let type_string = "Order(bytes32 orderChainToken,bytes32 adChainToken,uint256 amount,bytes32 bridger,uint256 orderChainId,bytes32 orderPortal,bytes32 orderRecipient,uint256 adChainId,bytes32 adManager,string adId,bytes32 adCreator,bytes32 adRecipient,uint256 salt,uint8 orderDecimals,uint8 adDecimals)";
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
