//! Vector-driven tests; the EVM verifier suite consumes the same JSON.

#![cfg(test)]

extern crate std;

use super::*;
use bls_key_registry::{
    BlsKeyRegistry, BlsKeyRegistryClient, KeyLeg, OwnerAuth, OwnerSig, SignedOwner,
};
use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    Env, String as SString,
};

const VECTORS: &str = include_str!("../../../../test-vectors/bls-encodings.json");

const REGISTRY_ID: [u8; 32] = [0x22; 32];
const CHAIN_ID: u128 = 1_000_002;
const T0: u64 = 1_700_000_000;
const METADATA_LEN: usize = 750;
/// The envelope before v4 (signer, bridger, order hash) and v3's module data (no leg nullifiers).
const V3_METADATA_LEN: usize = 649;
const SIDE_ORDER: u8 = 0;
const SIDE_AD: u8 = 1;

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
    env.ledger().set_timestamp(T0);
    let v = vectors();

    // Registry at the exact contract id the vector digests bind.
    let strkey = stellar_strkey::Contract(REGISTRY_ID).to_string();
    let at = Address::from_string(&SString::from_str(&env, &strkey));
    let registry_addr = env.register_at(&at, BlsKeyRegistry, ());
    let registry = BlsKeyRegistryClient::new(&env, &registry_addr);
    registry.initialize(
        &Address::generate(&env),
        &CHAIN_ID,
        &SString::from_str(&env, "testnet"),
    );

    for who in ["makerOnStellarTestnet", "bridgerOnStellarTestnet"] {
        let r = &v["registration"][who];
        let owner = if who.starts_with("maker") {
            let pk = hexval(&v["keys"]["makerWallet"]["pk"]);
            let g = stellar_strkey::ed25519::PublicKey(pk.try_into().unwrap()).to_string();
            OwnerAuth::Stellar(Address::from_string(&SString::from_str(&env, &g)))
        } else {
            // 2.6: the bridger's one signature, whose legs name this registry at nonce 0
            let e = &v["ownerAuth"]["bridger"]["register"][0];
            let mut legs = soroban_sdk::Vec::new(&env);
            for l in e["legs"].as_array().unwrap() {
                legs.push_back(KeyLeg {
                    chain_id: l["chainId"].as_str().unwrap().parse().unwrap(),
                    registry: bn::<32>(&env, &l["registry"]),
                    nonce: l["nonce"].as_str().unwrap().parse().unwrap(),
                });
            }
            OwnerAuth::Signed(SignedOwner {
                legs,
                sig: OwnerSig::Secp256k1(bn::<65>(&env, &e["sig"])),
            })
        };
        registry.register(
            &bn::<32>(&env, &r["account"]),
            &owner,
            &bn::<96>(&env, &r["pkNative"]),
            &bn::<192>(&env, &r["pop"]),
            &0,
            // the bridger's signed deadline (`_meta.deadline.register`); require_auth takes any in range
            &v["ownerAuth"]["_meta"]["deadline"]["register"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap(),
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
    /// The ad leg's unlock: side AD, its nullifier, checked against the order chain's root.
    fn metadata(&self) -> Bytes {
        self.metadata_with(
            &hexval(&self.v["keys"]["makerBls"]["pk"]["uncompressed"]),
            &hexval(&self.v["settlement"]["aggSig"]["uncompressed"]),
        )
    }

    fn metadata_with(&self, pk_maker: &[u8], agg_sig: &[u8]) -> Bytes {
        self.metadata_slots(0, 0, pk_maker, agg_sig)
    }

    /// Both parties' settlement keys sit in slot 0; the slot hints are calldata, not hash-bound.
    fn metadata_slots(
        &self,
        maker_slot: u32,
        bridger_slot: u32,
        pk_maker: &[u8],
        agg_sig: &[u8],
    ) -> Bytes {
        let mut out = self.envelope(SIDE_AD, &self.ad_leg());
        out.extend_from_slice(&self.module_data(maker_slot, bridger_slot, pk_maker, agg_sig));
        assert_eq!(out.len(), METADATA_LEN);
        Bytes::from_slice(&self.env, &out)
    }

    /// One leg's unlock under the vector aggregate: `side` and the nullifier the escrow consumes.
    fn metadata_leg(&self, side: u8, nullifier: &[u8]) -> Bytes {
        let mut out = self.envelope(side, nullifier);
        out.extend_from_slice(&self.module_data(
            0,
            0,
            &hexval(&self.v["keys"]["makerBls"]["pk"]["uncompressed"]),
            &hexval(&self.v["settlement"]["aggSig"]["uncompressed"]),
        ));
        Bytes::from_slice(&self.env, &out)
    }

    /// What the escrow vouches for: the vector parties, the vector auth's own order (the order the
    /// escrow would be unlocking), no pin, the nullifier it consumes and its side.
    fn envelope(&self, side: u8, nullifier: &[u8]) -> std::vec::Vec<u8> {
        let v = &self.v;
        let mut out = std::vec::Vec::new();
        out.extend_from_slice(&hexval(
            &v["registration"]["makerOnStellarTestnet"]["account"],
        ));
        out.extend_from_slice(&hexval(
            &v["registration"]["bridgerOnStellarTestnet"]["account"],
        ));
        out.extend_from_slice(&hexval(&v["settlement"]["auth"]["orderHash"]));
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(nullifier);
        out.push(side);
        out
    }

    /// The v4 module data over the vector auth.
    fn module_data(
        &self,
        maker_slot: u32,
        bridger_slot: u32,
        pk_maker: &[u8],
        agg_sig: &[u8],
    ) -> std::vec::Vec<u8> {
        let v = &self.v;
        let auth = &v["settlement"]["auth"];
        let mut out = std::vec![4u8];
        out.extend_from_slice(&self.order_chain_id.to_be_bytes());
        out.extend_from_slice(&self.ad_chain_id.to_be_bytes());
        out.extend_from_slice(&hexval(&auth["orderHash"]));
        out.extend_from_slice(&hexval(&auth["orderChainRoot"]));
        out.extend_from_slice(&hexval(&auth["adChainRoot"]));
        out.extend_from_slice(&hexval(&auth["makerKeyCommitment"]));
        out.extend_from_slice(&self.ad_leg());
        out.extend_from_slice(&self.order_leg());
        out.extend_from_slice(&maker_slot.to_be_bytes());
        out.extend_from_slice(&bridger_slot.to_be_bytes());
        out.extend_from_slice(pk_maker);
        out.extend_from_slice(&hexval(&v["keys"]["bridgerBls"]["pk"]["uncompressed"]));
        out.extend_from_slice(agg_sig);
        out
    }

    fn ad_leg(&self) -> std::vec::Vec<u8> {
        hexval(&self.v["settlement"]["auth"]["adLegNullifier"])
    }

    fn order_leg(&self) -> std::vec::Vec<u8> {
        hexval(&self.v["settlement"]["auth"]["orderLegNullifier"])
    }

    fn registry(&self) -> BlsKeyRegistryClient<'static> {
        BlsKeyRegistryClient::new(&self.env, &self.verifier.registry())
    }

    fn maker_owner(&self) -> OwnerAuth {
        let pk = hexval(&self.v["keys"]["makerWallet"]["pk"]);
        let g = stellar_strkey::ed25519::PublicKey(pk.try_into().unwrap()).to_string();
        OwnerAuth::Stellar(Address::from_string(&SString::from_str(&self.env, &g)))
    }

    fn maker_account(&self) -> BytesN<32> {
        bn::<32>(
            &self.env,
            &self.v["registration"]["makerOnStellarTestnet"]["account"],
        )
    }

    /// slots.makerOnStellarTestnet.registrations[i] at nonce i (slot 0 = the settlement key).
    fn register_maker_slot(&self, i: usize) -> u32 {
        let r = &self.v["slots"]["makerOnStellarTestnet"]["registrations"][i];
        self.registry().register(
            &self.maker_account(),
            &self.maker_owner(),
            &bn::<96>(&self.env, &r["pkNative"]),
            &bn::<192>(&self.env, &r["pop"]),
            &(i as u64),
            &(self.env.ledger().timestamp() + 3_600), // require_auth: any deadline within 7 days
        )
    }

    /// Retires the key in slots registration `i` (named by its fingerprint, 2.6).
    fn set_maker_valid_until(&self, i: u32, valid_until: u64) {
        let fp = &self.v["ownerAuth"]["maker"]["register"][i as usize]["keyCommitment"];
        self.registry().set_valid_until(
            &self.maker_account(),
            &self.maker_owner(),
            &bn::<32>(&self.env, fp),
            &valid_until,
        );
    }

    fn grace_ts(&self) -> u64 {
        self.v["slots"]["graceTs"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap()
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

/// The order leg's unlock (side ORDER, its nullifier) is checked against the ad chain's root.
#[test]
fn ad_chain_root_is_valid() {
    let s = setup();
    assert!(s.verifier.is_root_valid(
        &s.ad_chain_id,
        &s.ad_chain_root,
        &s.metadata_leg(SIDE_ORDER, &s.order_leg())
    ));
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
    let mut raw = [0u8; METADATA_LEN];
    m.copy_into_slice(&mut raw);
    for old in [1u8, 2, 3] {
        raw[133] = old; // a retired version byte on the current layout
        let m2 = Bytes::from_slice(&s.env, &raw);
        assert!(!s
            .verifier
            .is_root_valid(&s.order_chain_id, &s.order_chain_root, &m2));
    }
}

/// #433: the co-signature names one order. An escrow unlocking any other order puts that order's
/// hash in the envelope, and the verifier must refuse even though keys, roots and signature all hold.
#[test]
fn envelope_order_hash_not_the_signed_one_fails() {
    let s = setup();
    let m = s.metadata();
    let mut raw = [0u8; METADATA_LEN];
    m.copy_into_slice(&mut raw);
    raw[64..96].copy_from_slice(&[0x42u8; 32]); // another order
    let m2 = Bytes::from_slice(&s.env, &raw);
    assert!(!s
        .verifier
        .is_root_valid(&s.order_chain_id, &s.order_chain_root, &m2));
    // Control: the same bytes with the signed order hash back in place verify.
    assert!(s
        .verifier
        .is_root_valid(&s.order_chain_id, &s.order_chain_root, &m));
}

/// #433: the pre-binding layout (no envelope order hash) is refused outright, never misread.
#[test]
fn old_layout_without_the_order_hash_fails() {
    let s = setup();
    let m = s.metadata();
    let mut raw = std::vec![0u8; METADATA_LEN];
    m.copy_into_slice(&mut raw);
    raw.drain(64..96);
    assert_eq!(raw.len(), METADATA_LEN - 32);
    let m = Bytes::from_slice(&s.env, &raw);
    assert!(!s
        .verifier
        .is_root_valid(&s.order_chain_id, &s.order_chain_root, &m));
}

/// The version-3 layout (the three-field envelope, an auth without leg nullifiers) is refused by
/// length, never misread as v4 with shifted fields — with the v3 version byte, or the v4 one.
#[test]
fn v3_layout_without_the_leg_nullifiers_fails() {
    let s = setup();
    let mut raw = s.envelope(SIDE_AD, &s.ad_leg());
    raw.truncate(96); // signer, bridger, order hash
    let mut module = s.module_data(
        0,
        0,
        &hexval(&s.v["keys"]["makerBls"]["pk"]["uncompressed"]),
        &hexval(&s.v["settlement"]["aggSig"]["uncompressed"]),
    );
    module.drain(161..225); // the two leg nullifiers
    module[0] = 3;
    raw.extend_from_slice(&module);
    assert_eq!(raw.len(), V3_METADATA_LEN);
    for version in [3u8, 4] {
        raw[96] = version;
        let m = Bytes::from_slice(&s.env, &raw);
        assert!(!s
            .verifier
            .is_root_valid(&s.order_chain_id, &s.order_chain_root, &m));
    }
}

// ---- v4: the co-signed auth names each leg's nullifier ----

/// An unlock consuming any nullifier but the one co-signed for its leg is refused.
#[test]
fn other_nullifier_fails() {
    let s = setup();
    let invented = [0x42u8; 32];
    assert!(s.verifier.is_root_valid(
        &s.order_chain_id,
        &s.order_chain_root,
        &s.metadata_leg(SIDE_AD, &s.ad_leg())
    ));
    assert!(!s.verifier.is_root_valid(
        &s.order_chain_id,
        &s.order_chain_root,
        &s.metadata_leg(SIDE_AD, &invented)
    ));
    assert!(!s.verifier.is_root_valid(
        &s.ad_chain_id,
        &s.ad_chain_root,
        &s.metadata_leg(SIDE_ORDER, &invented)
    ));
}

/// Each leg's nullifier settles only its own leg.
#[test]
fn other_legs_nullifier_fails() {
    let s = setup();
    assert!(!s.verifier.is_root_valid(
        &s.order_chain_id,
        &s.order_chain_root,
        &s.metadata_leg(SIDE_AD, &s.order_leg())
    ));
    assert!(!s.verifier.is_root_valid(
        &s.ad_chain_id,
        &s.ad_chain_root,
        &s.metadata_leg(SIDE_ORDER, &s.ad_leg())
    ));
}

/// The side must agree with the root it names: side AD against the ad chain's root fails even
/// with the ad leg's nullifier, and side ORDER against the order chain's root.
#[test]
fn side_disagrees_with_the_root_fails() {
    let s = setup();
    assert!(!s.verifier.is_root_valid(
        &s.ad_chain_id,
        &s.ad_chain_root,
        &s.metadata_leg(SIDE_AD, &s.ad_leg())
    ));
    assert!(!s.verifier.is_root_valid(
        &s.order_chain_id,
        &s.order_chain_root,
        &s.metadata_leg(SIDE_ORDER, &s.order_leg())
    ));
}

#[test]
fn unknown_side_fails() {
    let s = setup();
    assert!(!s.verifier.is_root_valid(
        &s.order_chain_id,
        &s.order_chain_root,
        &s.metadata_leg(2, &s.ad_leg())
    ));
}

/// The vector's v4 Soroban metadata (both entries) verifies here byte for byte: the envelope, the
/// offsets and the 288-byte preimage agree with the generator.
#[test]
fn metadata_v4_vectors_verify() {
    let s = setup();
    for e in s.v["settlement"]["metadataV4"].as_array().unwrap() {
        if e["makerSlotId"] != "0" || e["bridgerSlotId"] != "0" {
            continue; // the asymmetric hints name slots this registry does not hold
        }
        let side: u8 = e["side"].as_str().unwrap().parse().unwrap();
        let (chain, root) = if side == SIDE_AD {
            (s.order_chain_id, s.order_chain_root.clone())
        } else {
            (s.ad_chain_id, s.ad_chain_root.clone())
        };
        let m = Bytes::from_slice(&s.env, &hexval(&e["sorobanMetadata"]));
        assert_eq!(m.len() as usize, METADATA_LEN);
        assert!(s.verifier.is_root_valid(&chain, &root, &m));
    }
}

/// #469: the bridger's half aggregated with another live maker key. The pairing holds, the slot is
/// live and its commitment matches the key used, the roots and order are right — and it must still
/// fail, because the signed auth names a different maker key. The control keeps the golden pair
/// verifying in the same registry state.
#[test]
fn re_paired_under_another_maker_key_fails() {
    let s = setup();
    let alt = s.register_maker_slot(1);
    let re_paired = s.metadata_slots(
        alt,
        0,
        &hexval(&s.v["settlement"]["rePaired"]["pkAlt"]["uncompressed"]),
        &hexval(&s.v["settlement"]["rePaired"]["aggSig"]["uncompressed"]),
    );
    assert!(!s
        .verifier
        .is_root_valid(&s.order_chain_id, &s.order_chain_root, &re_paired));
    assert!(s
        .verifier
        .is_root_valid(&s.order_chain_id, &s.order_chain_root, &s.metadata()));
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
    let mut raw = [0u8; METADATA_LEN];
    m.copy_into_slice(&mut raw);
    raw[229] ^= 0x01; // last byte of order_chain_root (offset 198..230)
    let m2 = Bytes::from_slice(&s.env, &raw);
    let mut tampered = [0u8; 32];
    tampered.copy_from_slice(&raw[198..230]);
    let tampered_root = BytesN::from_array(&s.env, &tampered);
    // root matches the (tampered) auth, but the aggSig was made over the real one
    assert!(!s
        .verifier
        .is_root_valid(&s.order_chain_id, &tampered_root, &m2));
}

// =============================================================================
// T-02: slot hints + use-time validity
// =============================================================================

/// Rotation: the old slot keeps verifying through its grace window, then stops.
#[test]
fn t02_old_slot_in_grace_settles_then_expires() {
    let s = setup();
    s.register_maker_slot(1); // new key in slot 1
    let g = s.grace_ts();
    s.set_maker_valid_until(0, g); // old slot valid until grace_ts

    assert!(s
        .verifier
        .is_root_valid(&s.order_chain_id, &s.order_chain_root, &s.metadata()));
    s.env.ledger().set_timestamp(g - 1);
    assert!(s
        .verifier
        .is_root_valid(&s.order_chain_id, &s.order_chain_root, &s.metadata()));
    s.env.ledger().set_timestamp(g);
    assert!(!s
        .verifier
        .is_root_valid(&s.order_chain_id, &s.order_chain_root, &s.metadata()));
}

/// Citing the wrong slot for a key fails on commitment mismatch.
#[test]
fn t02_wrong_slot_hint_fails() {
    let s = setup();
    s.register_maker_slot(1);
    let pk_maker = hexval(&s.v["keys"]["makerBls"]["pk"]["uncompressed"]);
    let agg_sig = hexval(&s.v["settlement"]["aggSig"]["uncompressed"]);
    for (m, b) in [(1u32, 0u32), (0, 1), (9, 0)] {
        assert!(!s.verifier.is_root_valid(
            &s.order_chain_id,
            &s.order_chain_root,
            &s.metadata_slots(m, b, &pk_maker, &agg_sig)
        ));
    }
}

/// A retired slot fails immediately; a pruned slot fails as missing, with no state change.
#[test]
fn t02_retired_then_pruned_slot_fails() {
    let s = setup();
    s.set_maker_valid_until(0, 1);
    assert!(!s
        .verifier
        .is_root_valid(&s.order_chain_id, &s.order_chain_root, &s.metadata()));

    for i in 1..5 {
        s.register_maker_slot(i);
    }
    // #422 D14: the kill expired the slot at the kill, not in 1970; it is prunable 30 days later.
    s.env.ledger().set_timestamp(T0 + 30 * 86_400 + 1);
    s.register_maker_slot(5); // at cap: prunes slot 0
    assert_eq!(s.registry().lookup(&s.maker_account(), &0), None);
    assert!(!s
        .verifier
        .is_root_valid(&s.order_chain_id, &s.order_chain_root, &s.metadata()));
    assert_eq!(s.registry().live_slots(&s.maker_account()).len(), 5);
}

/// C-13: every unlock reads the registry address from this module's instance and the key
/// commitments through the registry's, so one `is_root_valid` keeps both instances alive.
#[test]
fn is_root_valid_extends_its_own_and_the_registrys_instance_ttl() {
    use proofbridge_core::ttl::{INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD};
    use soroban_sdk::testutils::storage::Instance as _;

    let s = setup();
    let registry = s.verifier.registry();
    let ttl = |at: &Address| {
        s.env
            .as_contract(at, || s.env.storage().instance().get_ttl())
    };
    let age = ttl(&s.verifier.address).max(ttl(&registry)) - INSTANCE_LIFETIME_THRESHOLD + 1;
    s.env.ledger().with_mut(|l| l.sequence_number += age);
    assert!(
        ttl(&s.verifier.address) < INSTANCE_LIFETIME_THRESHOLD,
        "set-up: verifier due"
    );
    assert!(
        ttl(&registry) < INSTANCE_LIFETIME_THRESHOLD,
        "set-up: registry due"
    );

    assert!(s
        .verifier
        .is_root_valid(&s.order_chain_id, &s.order_chain_root, &s.metadata()));
    assert_eq!(
        ttl(&s.verifier.address),
        INSTANCE_BUMP_AMOUNT,
        "verifier instance not extended"
    );
    assert_eq!(
        ttl(&registry),
        INSTANCE_BUMP_AMOUNT,
        "registry instance not extended"
    );
}

// ---- soak batch D (C-19): every reachable error, named ----

/// A second `initialize` is refused, and the registry the module reads does not move.
#[test]
fn initialize_twice_is_already_initialized() {
    let s = setup();
    let before = s.verifier.registry();
    assert_eq!(
        s.verifier.try_initialize(&Address::generate(&s.env)),
        Err(Ok(VerifierError::AlreadyInitialized))
    );
    assert_eq!(s.verifier.registry(), before);
}

/// A registry that answers `commitment_at` with whatever the test stored for the account, so the
/// verifier's slot check can be shown a value the real registry no longer writes.
mod stub_registry {
    use soroban_sdk::{contract, contractimpl, BytesN, Env};

    #[contract]
    pub struct StubRegistry;

    #[contractimpl]
    impl StubRegistry {
        pub fn set(env: Env, account: BytesN<32>, commitment: BytesN<32>) {
            env.storage().instance().set(&account, &commitment);
        }

        pub fn commitment_at(env: Env, account: BytesN<32>, _slot_id: u32) -> BytesN<32> {
            env.storage().instance().get(&account).unwrap()
        }
    }
}

/// The stub-backed verifier and the two accounts' 96-byte keys.
fn stub_setup(
    s: &Setup,
) -> (
    CounterpartyVerifierClient<'static>,
    stub_registry::StubRegistryClient<'static>,
) {
    let stub_addr = s.env.register(stub_registry::StubRegistry, ());
    let stub = stub_registry::StubRegistryClient::new(&s.env, &stub_addr);
    let verifier_addr = s.env.register(CounterpartyVerifier, ());
    let verifier = CounterpartyVerifierClient::new(&s.env, &verifier_addr);
    verifier.initialize(&stub_addr);
    (verifier, stub)
}

fn party(s: &Setup, who: &str) -> (BytesN<32>, BytesN<96>) {
    let r = &s.v["registration"][std::format!("{who}OnStellarTestnet")];
    (
        bn::<32>(&s.env, &r["account"]),
        bn::<96>(&s.env, &r["pkNative"]),
    )
}

fn keccak96(env: &Env, pk: &BytesN<96>) -> BytesN<32> {
    env.crypto()
        .keccak256(&Bytes::from_slice(env, &pk.to_array()))
        .to_bytes()
}

/// One key commitment: a slot holding keccak of the EIP-2537 form settles; the same slot holding
/// the hash of the 96-byte form (the old Soroban storage) does not, for either party.
#[test]
fn slot_check_reads_the_eip2537_commitment_not_the_96_byte_hash() {
    let s = setup();
    let (verifier, stub) = stub_setup(&s);
    let (maker, pk_maker) = party(&s, "maker");
    let (bridger, pk_bridger) = party(&s, "bridger");
    let valid = || verifier.is_root_valid(&s.order_chain_id, &s.order_chain_root, &s.metadata());

    stub.set(&maker, &key_commitment(&s.env, &pk_maker));
    stub.set(&bridger, &key_commitment(&s.env, &pk_bridger));
    assert!(valid(), "the EIP-2537 commitment settles");

    stub.set(&maker, &keccak96(&s.env, &pk_maker));
    assert!(!valid(), "a maker slot holding the 96-byte hash fails");

    stub.set(&maker, &key_commitment(&s.env, &pk_maker));
    stub.set(&bridger, &keccak96(&s.env, &pk_bridger));
    assert!(!valid(), "a bridger slot holding the 96-byte hash fails");
}

/// The slot's commitment, the auth's maker key and the registry vector are one value.
#[test]
fn the_slot_commitment_is_the_auths_maker_key() {
    let s = setup();
    let (maker, pk_maker) = party(&s, "maker");
    let registry = BlsKeyRegistryClient::new(&s.env, &s.verifier.registry());
    let stored = registry.commitment_at(&maker, &0);
    assert_eq!(stored, key_commitment(&s.env, &pk_maker));
    assert_eq!(
        stored,
        bn::<32>(&s.env, &s.v["settlement"]["auth"]["makerKeyCommitment"])
    );
}
