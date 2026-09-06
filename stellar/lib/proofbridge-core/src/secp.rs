//! secp256k1 recovery to an EVM address, the one derivation the registry and the
//! agent account share.

use soroban_sdk::{crypto::Hash, Bytes, BytesN, Env};

/// Recover the 20-byte EVM address that signed `digest`. Accepts the recovery id
/// as 0/1 or 27/28; anything else is `None`. Malformed signatures trap in the host.
pub fn recover_evm_address(
    env: &Env,
    digest: &Hash<32>,
    sig: &BytesN<64>,
    recovery_id: u32,
) -> Option<[u8; 20]> {
    let v = if recovery_id >= 27 {
        recovery_id - 27
    } else {
        recovery_id
    };
    if v > 1 {
        return None;
    }
    let pk = env.crypto().secp256k1_recover(digest, sig, v).to_array();
    let hash = env
        .crypto()
        .keccak256(&Bytes::from_slice(env, &pk[1..]))
        .to_array();
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    Some(addr)
}

/// The universal 32-byte account id of an EVM address: left-padded with zeros.
pub fn evm_address_to_bytes32(env: &Env, addr: &[u8; 20]) -> BytesN<32> {
    let mut id = [0u8; 32];
    id[12..].copy_from_slice(addr);
    BytesN::from_array(env, &id)
}
