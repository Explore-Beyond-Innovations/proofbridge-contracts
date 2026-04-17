//! EIP-712 compatible hashing for cross-chain order identification
//!
//! This module implements EIP-712 typed data hashing to ensure order hashes
//! computed on Stellar match those computed on EVM chains.
//!
//! IMPORTANT: This is critical for cross-chain interoperability. The order hash
//! must be byte-for-byte identical on both EVM and Stellar.

use sha3::{Digest, Keccak256};
use soroban_sdk::{Address, BytesN, Env, String};

// =============================================================================
// EIP-712 Constants
// =============================================================================

/// Precomputed: keccak256("EIP712Domain(string name,string version)")
pub const DOMAIN_TYPEHASH_MIN: [u8; 32] = [
    0xb0, 0x39, 0x48, 0x44, 0x63, 0x34, 0xeb, 0x9b, 0x21, 0x96, 0xd5, 0xeb, 0x16, 0x6f, 0x69, 0xb9,
    0xd4, 0x94, 0x03, 0xeb, 0x4a, 0x12, 0xf3, 0x6d, 0xe8, 0xd3, 0xf9, 0xf3, 0xcb, 0x8e, 0x15, 0xc3,
];

/// Precomputed: keccak256("Order(bytes32 orderChainToken,bytes32 adChainToken,uint256 amount,bytes32 bridger,uint256 orderChainId,bytes32 orderPortal,bytes32 orderRecipient,uint256 adChainId,bytes32 adManager,string adId,bytes32 adCreator,bytes32 adRecipient,uint256 salt,uint8 orderDecimals,uint8 adDecimals)")
pub const ORDER_TYPEHASH: [u8; 32] = [
    0x14, 0x68, 0x39, 0x16, 0x00, 0x7e, 0xcb, 0x1a, 0x2b, 0x77, 0x2b, 0xfd, 0x1c, 0x31, 0x26, 0x34,
    0x0f, 0x16, 0xb7, 0xe1, 0xda, 0x0d, 0x2f, 0x95, 0x5b, 0x8c, 0xa2, 0x85, 0x57, 0x1e, 0x06, 0xe4,
];

/// Precomputed: keccak256("Proofbridge")
pub const NAME_HASH: [u8; 32] = [
    0xce, 0xa4, 0xb9, 0x0a, 0xb1, 0x14, 0xe5, 0x57, 0xc0, 0x15, 0x2d, 0xf0, 0xf3, 0x01, 0x09, 0x06,
    0xc4, 0x89, 0xb3, 0xad, 0xc1, 0x81, 0x4c, 0xfd, 0xf1, 0x75, 0x5c, 0xe9, 0x28, 0xce, 0x35, 0x9c,
];

/// Precomputed: keccak256("1")
pub const VERSION_HASH: [u8; 32] = [
    0xc8, 0x9e, 0xfd, 0xaa, 0x54, 0xc0, 0xf2, 0x0c, 0x7a, 0xdf, 0x61, 0x28, 0x82, 0xdf, 0x09, 0x50,
    0xf5, 0xa9, 0x51, 0x63, 0x7e, 0x03, 0x07, 0xcd, 0xcb, 0x4c, 0x67, 0x2f, 0x29, 0x8b, 0x8b, 0xc6,
];

// =============================================================================
// Keccak256 Implementation
// =============================================================================

/// Keccak256 hash function using sha3 crate
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// =============================================================================
// ABI Encoding Functions
// =============================================================================

/// ABI encode an address as bytes32 (already padded in our case)
/// EVM addresses are 20 bytes, stored as 32 bytes with 12 leading zeros.
/// Stellar addresses in BytesN<32> are already 32 bytes.
pub fn abi_encode_address(addr: &BytesN<32>) -> [u8; 32] {
    addr.to_array()
}

/// ABI encode a uint256 (u128 extended to 32 bytes, big-endian)
pub fn abi_encode_uint256(value: u128) -> [u8; 32] {
    let mut buf = [0u8; 32];
    // u128 is 16 bytes, so it goes in the last 16 bytes (big-endian)
    buf[16..32].copy_from_slice(&value.to_be_bytes());
    buf
}

/// ABI encode a string by hashing it (EIP-712 string encoding)
pub fn abi_encode_string(s: &String) -> [u8; 32] {
    let len = s.len() as usize;
    let mut buf = [0u8; 1024]; // Support strings up to 1KB
    if len > 0 && len <= buf.len() {
        s.copy_into_slice(&mut buf[..len]);
    }
    keccak256(&buf[..len])
}

// =============================================================================
// Domain Separator
// =============================================================================

/// Compute the minimal EIP-712 domain separator (name, version only)
///
/// domainSeparator = keccak256(abi.encode(
///     DOMAIN_TYPEHASH_MIN,
///     keccak256(bytes("Proofbridge")),
///     keccak256(bytes("1"))
/// ))
pub fn domain_separator_proofbridge() -> [u8; 32] {
    // Concatenate: DOMAIN_TYPEHASH_MIN || NAME_HASH || VERSION_HASH
    let mut data = [0u8; 96]; // 32 * 3
    data[0..32].copy_from_slice(&DOMAIN_TYPEHASH_MIN);
    data[32..64].copy_from_slice(&NAME_HASH);
    data[64..96].copy_from_slice(&VERSION_HASH);
    keccak256(&data)
}

// =============================================================================
// Final Hash (EIP-712 Typed Data Hash)
// =============================================================================

/// Compute the final EIP-712 typed data hash
///
/// digest = keccak256("\x19\x01" || domainSeparator || structHash)
pub fn hash_typed_data_v4(struct_hash: &[u8; 32]) -> [u8; 32] {
    let domain_sep = domain_separator_proofbridge();

    // Total: 2 + 32 + 32 = 66 bytes
    let mut data = [0u8; 66];

    // EIP-712 prefix: "\x19\x01"
    data[0] = 0x19;
    data[1] = 0x01;

    // Domain separator
    data[2..34].copy_from_slice(&domain_sep);

    // Struct hash
    data[34..66].copy_from_slice(struct_hash);

    keccak256(&data)
}

// =============================================================================
// Address Conversion Helpers
// =============================================================================

/// Convert a Stellar Address to BytesN<32> for cross-chain storage
///
/// Handles both contract addresses (C...) and account addresses (G...).
pub fn address_to_bytes32(env: &Env, addr: &Address) -> BytesN<32> {
    use stellar_strkey::{ed25519::PublicKey, Contract};

    let addr_str = addr.to_string();
    let len = addr_str.len() as usize;
    let mut str_buf = [0u8; 256];
    addr_str.copy_into_slice(&mut str_buf[..len]);
    let addr_str_slice = core::str::from_utf8(&str_buf[..len]).unwrap();

    let mut buf = [0u8; 32];
    if addr_str_slice.starts_with('C') {
        if let Ok(contract) = Contract::from_string(addr_str_slice) {
            buf = contract.0;
        }
    } else if addr_str_slice.starts_with('G') {
        if let Ok(pubkey) = PublicKey::from_string(addr_str_slice) {
            buf = pubkey.0;
        }
    }

    BytesN::from_array(env, &buf)
}

/// Convert contract address to BytesN<32>
pub fn contract_address_to_bytes32(env: &Env) -> BytesN<32> {
    address_to_bytes32(env, &env.current_contract_address())
}

// =============================================================================
// Tests
