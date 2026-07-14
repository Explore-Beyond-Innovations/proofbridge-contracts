//! Vector-driven tests; the EVM verifier suite consumes the same JSON.

#![cfg(test)]

extern crate std;

use super::*;
use bls_key_registry::{BlsKeyRegistry, BlsKeyRegistryClient, OwnerAuth};
use soroban_sdk::{testutils::Address as _, Env, String as SString};

const VECTORS: &str = include_str!("../../../../test-vectors/bls-encodings.json");

const REGISTRY_ID: [u8; 32] = [0x22; 32];
const CHAIN_ID: u128 = 1_000_002;

fn vectors() -> serde_json::Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn hexval(v: &serde_json::Value) -> std::vec::Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

fn bn<const N: usize>(env: &Env, v: &serde_json::Value) -> BytesN<N> {
    BytesN::from_array(env, &hexval(v).as_slice().try_into().unwrap())
}

struct Setup {
    env: Env,
    verifier: CounterpartyVerifierClient<'static>,
    v: serde_json::Value,
    order_chain_id: u128,
    ad_chain_id: u128,
    order_chain_root: BytesN<32>,
    ad_chain_root: BytesN<32>,
}

fn setup() -> Setup {
    let env = Env::default();
    env.mock_all_auths();
    let v = vectors();

    // Registry at the exact contract id the vector digests bind.
    let strkey = stellar_strkey::Contract(REGISTRY_ID).to_string();
    let at = Address::from_string(&SString::from_str(&env, &strkey));
    let registry_addr = env.register_at(&at, BlsKeyRegistry, ());
    let registry = BlsKeyRegistryClient::new(&env, &registry_addr);
    registry.initialize(&Address::generate(&env), &CHAIN_ID);

    for who in ["makerOnStellarTestnet", "bridgerOnStellarTestnet"] {
        let r = &v["registration"][who];
        let owner = if who.starts_with("maker") {
            let pk = hexval(&v["keys"]["makerWallet"]["pk"]);
            let g = stellar_strkey::ed25519::PublicKey(pk.try_into().unwrap()).to_string();
            OwnerAuth::Stellar(Address::from_string(&SString::from_str(&env, &g)))
        } else {
            let sig = &r["ownerSig"]["sig"];
            let mut out = [0u8; 65];
            out[..32].copy_from_slice(&hexval(&sig["r"]));
            out[32..64].copy_from_slice(&hexval(&sig["s"]));
            out[64] = sig["v"].as_u64().unwrap() as u8;
            OwnerAuth::Evm(BytesN::from_array(&env, &out))
        };
        registry.register(
            &bn::<32>(&env, &r["account"]),
            &owner,
            &bn::<96>(&env, &r["pkNative"]),
            &bn::<192>(&env, &r["pop"]),
            &0,
        );
    }

    let verifier_addr = env.register(CounterpartyVerifier, ());
    let verifier = CounterpartyVerifierClient::new(&env, &verifier_addr);
    verifier.initialize(&registry_addr);

    let auth = &v["settlement"]["auth"];
    Setup {
        order_chain_id: auth["orderChainId"].as_str().unwrap().parse().unwrap(),
        ad_chain_id: auth["adChainId"].as_str().unwrap().parse().unwrap(),
        order_chain_root: bn::<32>(&env, &auth["orderChainRoot"]),
        ad_chain_root: bn::<32>(&env, &auth["adChainRoot"]),
        env,
        verifier,
        v,
    }
}

impl Setup {
    fn metadata(&self) -> Bytes {
        self.metadata_with(
            &hexval(&self.v["keys"]["makerBls"]["pk"]["uncompressed"]),
            &hexval(&self.v["settlement"]["aggSig"]["uncompressed"]),
        )
    }

    fn metadata_with(&self, pk_maker: &[u8], agg_sig: &[u8]) -> Bytes {
        let v = &self.v;
        let auth = &v["settlement"]["auth"];
        let mut out = std::vec::Vec::new();
        out.extend_from_slice(&hexval(
            &v["registration"]["makerOnStellarTestnet"]["account"],
        ));
        out.extend_from_slice(&hexval(
            &v["registration"]["bridgerOnStellarTestnet"]["account"],
        ));
        out.push(1u8);
        out.extend_from_slice(&self.order_chain_id.to_be_bytes());
        out.extend_from_slice(&self.ad_chain_id.to_be_bytes());
        out.extend_from_slice(&hexval(&auth["orderHash"]));
        out.extend_from_slice(&hexval(&auth["orderChainRoot"]));
        out.extend_from_slice(&hexval(&auth["adChainRoot"]));
        out.extend_from_slice(pk_maker);
        out.extend_from_slice(&hexval(&v["keys"]["bridgerBls"]["pk"]["uncompressed"]));
        out.extend_from_slice(agg_sig);
        assert_eq!(out.len(), 577);
        Bytes::from_slice(&self.env, &out)
    }
}

// Epic done-when: the aggregate pairing check (2 registry lookups + BLS
// verify over the settlement digest) must clear well under 2s wall-clock.
#[test]
fn pairing_verification_under_two_seconds() {
    let s = setup();
    let start = std::time::Instant::now();
    const RUNS: u32 = 10;
    for _ in 0..RUNS {
        assert!(s
            .verifier
            .is_root_valid(&s.order_chain_id, &s.order_chain_root, &s.metadata()));
    }
    let per_call = start.elapsed() / RUNS;
    std::println!("is_root_valid wall-clock: {per_call:?} per call");
    assert!(
        per_call < std::time::Duration::from_secs(2),
        "pairing check exceeded 2s: {per_call:?}"
    );
}

#[test]
fn order_chain_root_is_valid() {
    let s = setup();
    assert!(s
        .verifier
        .is_root_valid(&s.order_chain_id, &s.order_chain_root, &s.metadata()));
}

#[test]
fn ad_chain_root_is_valid() {
    let s = setup();
    assert!(s
        .verifier
        .is_root_valid(&s.ad_chain_id, &s.ad_chain_root, &s.metadata()));
}

#[test]
fn root_not_matching_auth_fails() {
    let s = setup();
    assert!(!s
        .verifier
        .is_root_valid(&s.order_chain_id, &s.ad_chain_root, &s.metadata()));
}

#[test]
fn unknown_source_chain_fails() {
    let s = setup();
    assert!(!s
        .verifier
        .is_root_valid(&424_242, &s.order_chain_root, &s.metadata()));
}

#[test]
fn wrong_version_fails() {
    let s = setup();
    let m = s.metadata();
    let mut raw = [0u8; 577];
    m.copy_into_slice(&mut raw);
    raw[64] = 2;
    let m2 = Bytes::from_slice(&s.env, &raw);
    assert!(!s
        .verifier
        .is_root_valid(&s.order_chain_id, &s.order_chain_root, &m2));
}

#[test]
fn bad_length_fails() {
    let s = setup();
    let short = Bytes::from_slice(&s.env, &[1u8; 100]);
    assert!(!s
        .verifier
        .is_root_valid(&s.order_chain_id, &s.order_chain_root, &short));
}

#[test]
fn pk_not_matching_commitment_fails() {
    let s = setup();
    // bridger's key presented as the maker's
    let m = s.metadata_with(
        &hexval(&s.v["keys"]["bridgerBls"]["pk"]["uncompressed"]),
        &hexval(&s.v["settlement"]["aggSig"]["uncompressed"]),
    );
    assert!(!s
        .verifier
        .is_root_valid(&s.order_chain_id, &s.order_chain_root, &m));
}

#[test]
fn unregistered_account_fails() {
    let s = setup();
    let registry = BlsKeyRegistryClient::new(&s.env, &s.verifier.registry());
    let maker_pk = hexval(&s.v["keys"]["makerWallet"]["pk"]);
    let g = stellar_strkey::ed25519::PublicKey(maker_pk.clone().try_into().unwrap()).to_string();
    let owner = OwnerAuth::Stellar(Address::from_string(&SString::from_str(&s.env, &g)));
    registry.revoke(
        &BytesN::from_array(&s.env, &maker_pk.try_into().unwrap()),
        &owner,
        &1,
    );

    assert!(!s
        .verifier
        .is_root_valid(&s.order_chain_id, &s.order_chain_root, &s.metadata()));
}

#[test]
fn single_signature_is_not_the_aggregate() {
    let s = setup();
    let m = s.metadata_with(
        &hexval(&s.v["keys"]["makerBls"]["pk"]["uncompressed"]),
        &hexval(&s.v["settlement"]["sigMaker"]["uncompressed"]),
    );
    assert!(!s
        .verifier
        .is_root_valid(&s.order_chain_id, &s.order_chain_root, &m));
}

#[test]
fn tampered_root_in_auth_fails() {
    let s = setup();
    let m = s.metadata();
    let mut raw = [0u8; 577];
    m.copy_into_slice(&mut raw);
    raw[160] ^= 0x01; // last byte of order_chain_root (offset 129..161)
    let m2 = Bytes::from_slice(&s.env, &raw);
    let mut tampered = [0u8; 32];
    tampered.copy_from_slice(&raw[129..161]);
    let tampered_root = BytesN::from_array(&s.env, &tampered);
    // root matches the (tampered) auth, but the aggSig was made over the real one
    assert!(!s
        .verifier
        .is_root_valid(&s.order_chain_id, &tampered_root, &m2));
}
