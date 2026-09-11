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

const METADATA_VERSION: u8 = 2;
/// settlement_signer(32) || bridger(32) || moduleData: version(1) || chainIds(2*16)
/// || orderHash/roots(3*32) || slotIds(2*4) || pks(2*96) || aggSig(192)
const METADATA_LEN: u32 = 585;

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
        if metadata.len() != METADATA_LEN || metadata.get(64) != Some(METADATA_VERSION) {
            return false;
        }
        let m = Metadata::decode(&env, &metadata);

        // The relevant root: the source chain's root inside the signed auth.
        if source_chain_id == m.order_chain_id {
            if root != m.order_chain_root {
                return false;
            }
        } else if source_chain_id == m.ad_chain_id {
            if root != m.ad_chain_root {
                return false;
            }
        } else {
            return false;
        }

        let registry: Address = env.storage().instance().get(&KEY_REGISTRY).unwrap();
        let client = KeyRegistryClient::new(&env, &registry);
        if !commitment_matches(
            &env,
            &client,
            &m.settlement_signer,
            m.signer_slot_id,
            &m.pk_signer,
        ) || !commitment_matches(&env, &client, &m.bridger, m.bridger_slot_id, &m.pk_bridger)
        {
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
    settlement_signer: BytesN<32>,
    bridger: BytesN<32>,
    signer_slot_id: u32,
    bridger_slot_id: u32,
    pk_signer: BytesN<96>,
    pk_bridger: BytesN<96>,
    agg_sig: BytesN<192>,
}

impl Metadata {
    /// settlement_signer(0) || bridger(32) || version(64) || orderChainId(65) ||
    /// adChainId(81) || orderHash(97) || orderChainRoot(129) ||
    /// adChainRoot(161) || signerSlotId(193) || bridgerSlotId(197) ||
    /// pkSigner(201) || pkBridger(297) || aggSig(393)
    fn decode(env: &Env, b: &Bytes) -> Metadata {
        Metadata {
            settlement_signer: BytesN::from_array(env, &arr::<32>(b, 0)),
            bridger: BytesN::from_array(env, &arr::<32>(b, 32)),
            order_chain_id: u128::from_be_bytes(arr::<16>(b, 65)),
            ad_chain_id: u128::from_be_bytes(arr::<16>(b, 81)),
            order_hash: BytesN::from_array(env, &arr::<32>(b, 97)),
            order_chain_root: BytesN::from_array(env, &arr::<32>(b, 129)),
            ad_chain_root: BytesN::from_array(env, &arr::<32>(b, 161)),
            signer_slot_id: u32::from_be_bytes(arr::<4>(b, 193)),
            bridger_slot_id: u32::from_be_bytes(arr::<4>(b, 197)),
            pk_signer: BytesN::from_array(env, &arr::<96>(b, 201)),
            pk_bridger: BytesN::from_array(env, &arr::<96>(b, 297)),
            agg_sig: BytesN::from_array(env, &arr::<192>(b, 393)),
        }
    }
}

fn arr<const N: usize>(b: &Bytes, offset: u32) -> [u8; N] {
    let mut out = [0u8; N];
    b.slice(offset..offset + N as u32).copy_into_slice(&mut out);
    out
}

/// The registry stores keccak commitments; the full keys travel here. A missing,
/// pruned or expired slot errors in the registry and fails the root here.
fn commitment_matches(
    env: &Env,
    client: &KeyRegistryClient,
    account: &BytesN<32>,
    slot_id: u32,
    pk: &BytesN<96>,
) -> bool {
    match client.try_commitment_at(account, &slot_id) {
        Ok(Ok(commitment)) => {
            let hash: BytesN<32> = env
                .crypto()
                .keccak256(&Bytes::from_slice(env, &pk.to_array()))
                .to_bytes();
            commitment == hash
        }
        _ => false,
    }
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

    // SETTLE_TAG || orderChainId(32) || adChainId(32) || orderHash || roots — 192 B
    let mut preimage = Bytes::from_slice(env, &SETTLE_TAG);
    preimage.extend_from_slice(&pad32_u128(m.order_chain_id));
    preimage.extend_from_slice(&pad32_u128(m.ad_chain_id));
    preimage.extend_from_slice(&m.order_hash.to_array());
    preimage.extend_from_slice(&m.order_chain_root.to_array());
    preimage.extend_from_slice(&m.ad_chain_root.to_array());

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
