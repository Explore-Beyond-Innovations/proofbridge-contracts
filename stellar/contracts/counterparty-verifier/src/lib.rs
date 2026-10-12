//! CounterpartyVerifier — module C behind the RootVerifier seam.
//! A root is valid iff it equals the SettlementAuth's root for the source
//! chain and both parties' aggregate BLS signature over the auth verifies
//! against their registered keys.

#![no_std]

mod errors;

use soroban_sdk::{
    bytesn, contract, contractclient, contractimpl,
    crypto::bls12_381::{Bls12381G1Affine as G1Affine, Bls12381G2Affine as G2Affine},
    symbol_short, vec, Address, Bytes, BytesN, Env, Symbol,
};

use errors::VerifierError;
use proofbridge_core::cross_contract::key_commitment;

/// The pluggable root-authentication seam every module implements.
#[contractclient(name = "RootVerifierClient")]
pub trait RootVerifier {
    fn is_root_valid(env: Env, source_chain_id: u128, root: BytesN<32>, metadata: Bytes) -> bool;
}

#[contractclient(name = "KeyRegistryClient")]
pub trait KeyRegistry {
    fn commitment_at(env: Env, account: BytesN<32>, slot_id: u32) -> BytesN<32>;
}

pub const DST_SIG: &str = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// keccak256("ProofBridge.Settlement.v1")
const SETTLE_TAG: [u8; 32] = [
    0x3d, 0x7b, 0xf6, 0xa3, 0x86, 0xb1, 0xa0, 0x85, 0x77, 0xb2, 0x87, 0xb9, 0xc9, 0x6a, 0x47, 0xad,
    0x90, 0x91, 0x51, 0x65, 0xc3, 0x07, 0x5b, 0x0d, 0x77, 0x65, 0xff, 0x24, 0x7a, 0x04, 0x6d, 0xf5,
];

const METADATA_VERSION: u8 = 4;
/// The envelope: settlement_signer(32) || bridger(32) || order_hash(32) (#433) || pinned_slot(4) ||
/// nullifier_hash(32) || side(1) = 133, then moduleData: version(1) || chainIds(2*16) ||
/// orderHash/roots(3*32) || makerKeyCommitment(32) (#469) || adLegNullifier(32) ||
/// orderLegNullifier(32) || slotIds(2*4) || pks(2*96) || aggSig(192) = 617. 750 in all.
const METADATA_LEN: u32 = 750;
const VERSION_OFFSET: u32 = 133;
/// The escrow's leg: the ad manager consumes the AD leaf (1), the order portal the ORDER leaf (0).
const SIDE_ORDER: u8 = 0;
const SIDE_AD: u8 = 1;
/// The order leg's envelope pin: no slot pinned (the auth's named maker key binds it).
const UNPINNED: u32 = u32::MAX;

const KEY_INIT: Symbol = symbol_short!("init");
const KEY_REGISTRY: Symbol = symbol_short!("registry");

#[contract]
pub struct CounterpartyVerifier;

#[contractimpl]
impl CounterpartyVerifier {
    pub fn initialize(env: Env, registry: Address) -> Result<(), VerifierError> {
        if env.storage().instance().has(&KEY_INIT) {
            return Err(VerifierError::AlreadyInitialized);
        }
        env.storage().instance().set(&KEY_INIT, &true);
        env.storage().instance().set(&KEY_REGISTRY, &registry);
        proofbridge_core::ttl::extend_instance(&env);
        Ok(())
    }

    pub fn registry(env: Env) -> Address {
        env.storage().instance().get(&KEY_REGISTRY).unwrap()
    }

    pub fn is_root_valid(
        env: Env,
        source_chain_id: u128,
        root: BytesN<32>,
        metadata: Bytes,
    ) -> bool {
        // C-13: the registry address lives in instance storage and every unlock reads it.
        proofbridge_core::ttl::extend_instance(&env);
        if metadata.len() != METADATA_LEN || metadata.get(VERSION_OFFSET) != Some(METADATA_VERSION)
        {
            return false;
        }
        let m = Metadata::decode(&env, &metadata);
        // #433: the parties co-signed one order. A signature over another order between the same two
        // parties, under the same roots, is not consent to this one.
        if m.order_hash != m.envelope_order_hash {
            return false;
        }

        // The escrow's side picks the leg: its source chain, its root and the nullifier the parties
        // signed for it. A side that disagrees with the root it names, or any other nullifier, fails.
        let (leg_chain, leg_root, leg_nullifier) = match m.side {
            SIDE_AD => (m.order_chain_id, &m.order_chain_root, &m.ad_leg_nullifier),
            SIDE_ORDER => (m.ad_chain_id, &m.ad_chain_root, &m.order_leg_nullifier),
            _ => return false,
        };
        if source_chain_id != leg_chain || root != *leg_root || m.nullifier_hash != *leg_nullifier {
            return false;
        }
        // Plan 12 C: on the ad leg the lock pinned the maker's co-signing slot; only that slot's key
        // settles there. The order leg sends the unpinned sentinel and is bound by the named key.
        if m.pinned_slot != UNPINNED && m.signer_slot_id != m.pinned_slot {
            return false;
        }

        // One commitment per key (keccak of the EIP-2537 form): the registry stores it and the
        // signed auth names it, so the maker's key is hashed once for both checks.
        let signer_commitment = key_commitment(&env, &m.pk_signer);
        // #469: the bridger signed for one maker key. The bridger's half aggregated with any other
        // live key of the maker's is a valid pairing but not consent; only the named key settles.
        if m.maker_key_commitment != signer_commitment {
            return false;
        }
        let registry: Address = env.storage().instance().get(&KEY_REGISTRY).unwrap();
        let client = KeyRegistryClient::new(&env, &registry);
        if !commitment_matches(
            &client,
            &m.settlement_signer,
            m.signer_slot_id,
            &signer_commitment,
        ) || !commitment_matches(
            &client,
            &m.bridger,
            m.bridger_slot_id,
            &key_commitment(&env, &m.pk_bridger),
        ) {
            return false;
        }

        verify_aggregate(&env, &m)
    }
}

struct Metadata {
    order_chain_id: u128,
    ad_chain_id: u128,
    order_hash: BytesN<32>,
    order_chain_root: BytesN<32>,
    ad_chain_root: BytesN<32>,
    maker_key_commitment: BytesN<32>,
    ad_leg_nullifier: BytesN<32>,
    order_leg_nullifier: BytesN<32>,
    settlement_signer: BytesN<32>,
    bridger: BytesN<32>,
    envelope_order_hash: BytesN<32>,
    pinned_slot: u32,
    nullifier_hash: BytesN<32>,
    side: u8,
    signer_slot_id: u32,
    bridger_slot_id: u32,
    pk_signer: BytesN<96>,
    pk_bridger: BytesN<96>,
    agg_sig: BytesN<192>,
}

impl Metadata {
    /// Envelope: settlement_signer(0) || bridger(32) || order_hash(64) (#433) || pinned_slot(96) ||
    /// nullifier_hash(100) || side(132), then the module data: version(133) || orderChainId(134) ||
    /// adChainId(150) || orderHash(166) || orderChainRoot(198) || adChainRoot(230) ||
    /// makerKeyCommitment(262) (#469) || adLegNullifier(294) || orderLegNullifier(326) ||
    /// signerSlotId(358) || bridgerSlotId(362) || pkSigner(366) || pkBridger(462) || aggSig(558)
    fn decode(env: &Env, b: &Bytes) -> Metadata {
        Metadata {
            settlement_signer: BytesN::from_array(env, &arr::<32>(b, 0)),
            bridger: BytesN::from_array(env, &arr::<32>(b, 32)),
            envelope_order_hash: BytesN::from_array(env, &arr::<32>(b, 64)),
            pinned_slot: u32::from_be_bytes(arr::<4>(b, 96)),
            nullifier_hash: BytesN::from_array(env, &arr::<32>(b, 100)),
            side: b.get(132).unwrap_or(u8::MAX),
            order_chain_id: u128::from_be_bytes(arr::<16>(b, 134)),
            ad_chain_id: u128::from_be_bytes(arr::<16>(b, 150)),
            order_hash: BytesN::from_array(env, &arr::<32>(b, 166)),
            order_chain_root: BytesN::from_array(env, &arr::<32>(b, 198)),
            ad_chain_root: BytesN::from_array(env, &arr::<32>(b, 230)),
            maker_key_commitment: BytesN::from_array(env, &arr::<32>(b, 262)),
            ad_leg_nullifier: BytesN::from_array(env, &arr::<32>(b, 294)),
            order_leg_nullifier: BytesN::from_array(env, &arr::<32>(b, 326)),
            signer_slot_id: u32::from_be_bytes(arr::<4>(b, 358)),
            bridger_slot_id: u32::from_be_bytes(arr::<4>(b, 362)),
            pk_signer: BytesN::from_array(env, &arr::<96>(b, 366)),
            pk_bridger: BytesN::from_array(env, &arr::<96>(b, 462)),
            agg_sig: BytesN::from_array(env, &arr::<192>(b, 558)),
        }
    }
}

fn arr<const N: usize>(b: &Bytes, offset: u32) -> [u8; N] {
    let mut out = [0u8; N];
    b.slice(offset..offset + N as u32).copy_into_slice(&mut out);
    out
}

/// The registry stores each key's commitment; the full key travels here and is hashed by the
/// caller. A missing, pruned or expired slot errors in the registry and fails the root here.
fn commitment_matches(
    client: &KeyRegistryClient,
    account: &BytesN<32>,
    slot_id: u32,
    commitment: &BytesN<32>,
) -> bool {
    matches!(client.try_commitment_at(account, &slot_id), Ok(Ok(c)) if c == *commitment)
}

/// e(pkM + pkB, H(preimage)) == e(G1, aggSig)
fn verify_aggregate(env: &Env, m: &Metadata) -> bool {
    let bls = env.crypto().bls12_381();

    let neg_g1 = G1Affine::from_bytes(bytesn!(
        env,
        0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca
    ));

    let pk_agg = bls.g1_add(
        &G1Affine::from_bytes(m.pk_signer.clone()),
        &G1Affine::from_bytes(m.pk_bridger.clone()),
    );
    let agg_sig = G2Affine::from_bytes(m.agg_sig.clone());

    // SETTLE_TAG || orderChainId(32) || adChainId(32) || orderHash || roots || makerKeyCommitment ||
    // adLegNullifier || orderLegNullifier — 288 B
    let mut preimage = Bytes::from_slice(env, &SETTLE_TAG);
    preimage.extend_from_slice(&pad32_u128(m.order_chain_id));
    preimage.extend_from_slice(&pad32_u128(m.ad_chain_id));
    preimage.extend_from_slice(&m.order_hash.to_array());
    preimage.extend_from_slice(&m.order_chain_root.to_array());
    preimage.extend_from_slice(&m.ad_chain_root.to_array());
    preimage.extend_from_slice(&m.maker_key_commitment.to_array());
    preimage.extend_from_slice(&m.ad_leg_nullifier.to_array());
    preimage.extend_from_slice(&m.order_leg_nullifier.to_array());

    let dst = Bytes::from_slice(env, DST_SIG.as_bytes());
    let msg_g2 = bls.hash_to_g2(&preimage, &dst);

    bls.pairing_check(vec![env, pk_agg, neg_g1], vec![env, msg_g2, agg_sig])
}

fn pad32_u128(v: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&v.to_be_bytes());
    out
}

#[cfg(test)]
mod test;
