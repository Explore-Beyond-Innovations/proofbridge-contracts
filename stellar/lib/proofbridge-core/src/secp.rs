//! secp256k1 recovery to an EVM address, the one derivation the registry and the
//! agent account share.

use soroban_sdk::{crypto::Hash, Bytes, BytesN, Env};

/// secp256k1 group order n, big-endian.
const SECP_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
/// floor(n / 2), big-endian: the largest low s.
const SECP_HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// The one owner-signature rule (2.6 D1): v in {0, 1, 27, 28}, 0 < r < n, 0 < s <= n/2.
pub fn secp_sig_acceptable(sig: &[u8; 64], recovery_id: u32) -> Option<u32> {
    let v = match recovery_id {
        0 | 1 => recovery_id,
        27 | 28 => recovery_id - 27,
        _ => return None,
    };
    let (r, s) = (&sig[..32], &sig[32..]);
    let zero = [0u8; 32];
    if r == &zero[..] || r >= &SECP_N[..] || s == &zero[..] || s > &SECP_HALF_N[..] {
        return None;
    }
    Some(v)
}

/// Recover the 20-byte EVM address that signed `digest` under `secp_sig_acceptable`; anything it
/// refuses (bad v, high s, r or s out of range) is `None`, never a host trap.
pub fn recover_evm_address(
    env: &Env,
    digest: &Hash<32>,
    sig: &BytesN<64>,
    recovery_id: u32,
) -> Option<[u8; 20]> {
    let v = secp_sig_acceptable(&sig.to_array(), recovery_id)?;
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

#[cfg(test)]
mod test {
    use super::*;

    fn be(hex32: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&hex32[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    fn sig(r: [u8; 32], s: [u8; 32]) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&r);
        out[32..].copy_from_slice(&s);
        out
    }

    #[test]
    fn test_rule_v_and_s() {
        let one = be("0000000000000000000000000000000000000000000000000000000000000001");
        let half = SECP_HALF_N;
        let mut above = half;
        above[31] += 1;
        assert_eq!(secp_sig_acceptable(&sig(one, one), 0), Some(0));
        assert_eq!(secp_sig_acceptable(&sig(one, one), 28), Some(1));
        for v in [2u32, 26, 29, 255] {
            assert_eq!(secp_sig_acceptable(&sig(one, one), v), None, "v {v}");
        }
        assert_eq!(
            secp_sig_acceptable(&sig(one, half), 27),
            Some(0),
            "n/2 is low"
        );
        assert_eq!(secp_sig_acceptable(&sig(one, above), 27), None, "high s");
        assert_eq!(secp_sig_acceptable(&sig([0u8; 32], one), 27), None, "r = 0");
        assert_eq!(secp_sig_acceptable(&sig(one, [0u8; 32]), 27), None, "s = 0");
        assert_eq!(secp_sig_acceptable(&sig(SECP_N, one), 27), None, "r = n");
    }
}
