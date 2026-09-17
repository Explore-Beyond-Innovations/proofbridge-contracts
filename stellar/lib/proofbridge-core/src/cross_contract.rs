//! Cross-contract client definitions and helpers for MerkleManager and Verifier.
//!
//! Defines typed `#[contractclient]` traits so contracts can call
//! MerkleManager and Verifier without raw `env.invoke_contract`.

use soroban_sdk::{contractclient, crypto::bn254::Bn254Fr, Address, Bytes, BytesN, Env};

use crate::errors::ProofBridgeError;

// =============================================================================
// Client Traits
// =============================================================================

/// Typed interface for cross-contract calls to the MerkleManager contract.
#[allow(dead_code)]
#[contractclient(name = "MerkleManagerClient")]
pub trait MerkleManagerInterface {
    fn append_order_hash(env: Env, manager: Address, order_hash: BytesN<32>, side: u32) -> bool;
    fn get_root(env: Env) -> BytesN<32>;
    fn get_root_at_index(env: Env, leaf_index: u128) -> BytesN<32>;
    fn get_width(env: Env) -> u128;
    fn field_mod(env: Env, order_hash: BytesN<32>) -> BytesN<32>;
}

/// Typed interface for the DisputeManager module (2.3g).
///
/// The escrow's whole dependency on it, and the direction is one-way: the escrow calls in, the
/// module never calls back. `escrow` is passed so the module can `require_auth` it — the host then
/// proves the caller's identity, which is why there is no address to spoof.
#[allow(dead_code)]
#[contractclient(name = "DisputeManagerClient")]
pub trait DisputeManagerInterface {
    fn open_dispute(
        env: Env,
        escrow: Address,
        order_hash: BytesN<32>,
        amount: u128,
        peer_chain_id: u128,
        filer: Address,
        evidence: BytesN<32>,
    ) -> u128;
    fn settle_bond(env: Env, escrow: Address, order_hash: BytesN<32>, filer_was_counterparty: bool);
    fn outcome_of(
        env: Env,
        order_hash: BytesN<32>,
    ) -> (crate::types::DisputeOutcome, bool, Option<Address>);
    fn is_disputed(env: Env, order_hash: BytesN<32>) -> bool;
}

/// Typed interface for cross-contract calls to the Verifier contract.
#[allow(dead_code)]
#[contractclient(name = "VerifierClient")]
pub trait VerifierInterface {
    fn verify_proof(env: Env, public_inputs: Bytes, proof_bytes: Bytes);
}

/// Typed interface for the pluggable root-authentication seam.
#[allow(dead_code)]
#[contractclient(name = "RootVerifierClient")]
pub trait RootVerifierInterface {
    fn is_root_valid(env: Env, source_chain_id: u128, root: BytesN<32>, metadata: Bytes) -> bool;
}

/// The authenticator for unilateral-event proofs (2.3f): is this root of the source chain
/// notarized and past its delay? Consumers never learn who signs. `anchored_at` (0 when not
/// anchored) lets a consumer that needs a longer age than the route's delay apply its own.
#[allow(dead_code)]
#[contractclient(name = "RootAnchorClient")]
pub trait RootAnchorInterface {
    fn is_anchored(env: Env, source_chain_id: u128, root: BytesN<32>) -> bool;
    fn anchored_at(env: Env, source_chain_id: u128, root: BytesN<32>) -> u64;
}

/// The one registry read the escrows make (2.3c D2): a live, unexpired key slot.
#[allow(dead_code)]
#[contractclient(name = "KeyRegistryClient")]
pub trait KeyRegistryInterface {
    fn has_usable_slot(env: Env, account: BytesN<32>) -> bool;
}

// =============================================================================
// MerkleManager Helpers
// =============================================================================

/// Append an order hash to the MerkleManager.
pub fn append_to_merkle<E: ProofBridgeError>(
    env: &Env,
    merkle_manager: &Address,
    order_hash: &BytesN<32>,
    side: u32,
) -> Result<(), E> {
    let client = MerkleManagerClient::new(env, merkle_manager);
    client
        .try_append_order_hash(&env.current_contract_address(), order_hash, &side)
        .map_err(|_| E::merkle_append_failed())?
        .map_err(|_| E::merkle_append_failed())?;
    Ok(())
}

/// Get the current root from MerkleManager.
pub fn get_merkle_root(env: &Env, merkle_manager: &Address) -> BytesN<32> {
    MerkleManagerClient::new(env, merkle_manager).get_root()
}

/// Get a historical root from MerkleManager at a specific width.
pub fn get_merkle_root_at_index(env: &Env, merkle_manager: &Address, index: u128) -> BytesN<32> {
    MerkleManagerClient::new(env, merkle_manager).get_root_at_index(&index)
}

/// Get the current width (leaf count) from MerkleManager.
pub fn get_merkle_width(env: &Env, merkle_manager: &Address) -> u128 {
    MerkleManagerClient::new(env, merkle_manager).get_width()
}

/// Apply BN254 field modulus to a hash via MerkleManager.
pub fn get_field_mod(env: &Env, merkle_manager: &Address, order_hash: &BytesN<32>) -> BytesN<32> {
    MerkleManagerClient::new(env, merkle_manager).field_mod(order_hash)
}

// =============================================================================
// Verifier Helper
// =============================================================================

/// Verify a ZK proof via cross-contract call to the Verifier contract.
pub fn verify_proof<E: ProofBridgeError>(
    env: &Env,
    verifier: &Address,
    public_inputs: &Bytes,
    proof_bytes: &Bytes,
) -> Result<(), E> {
    let client = VerifierClient::new(env, verifier);
    client
        .try_verify_proof(public_inputs, proof_bytes)
        .map_err(|_| E::invalid_proof())?
        .map_err(|_| E::invalid_proof())?;
    Ok(())
}

// =============================================================================
// Proof Construction
// =============================================================================

/// Build public inputs for the ZK proof verification.
///
/// The public inputs are ordered as:
/// - nullifier_hash (32 bytes)
/// - order_hash_mod (32 bytes) - order hash with BN254 field modulus applied
/// - target_root (32 bytes)
/// - chain_flag (32 bytes) - 0 for source/order chain, 1 for destination/ad chain
///
/// Total: 128 bytes (4 x 32-byte field elements)
pub fn build_public_inputs(
    env: &Env,
    merkle_manager: &Address,
    nullifier_hash: &BytesN<32>,
    target_root: &BytesN<32>,
    order_hash: &BytesN<32>,
    chain_flag_value: u8,
) -> Bytes {
    let order_hash_mod = get_field_mod(env, merkle_manager, order_hash);

    // Chain flag as bytes32 (big-endian)
    let mut chain_flag = [0u8; 32];
    chain_flag[31] = chain_flag_value;

    let mut inputs = Bytes::new(env);
    inputs.append(&Bytes::from_slice(env, &nullifier_hash.to_array()));
    inputs.append(&Bytes::from_slice(env, &order_hash_mod.to_array()));
    inputs.append(&Bytes::from_slice(env, &target_root.to_array()));
    inputs.append(&Bytes::from_slice(env, &chain_flag));

    inputs
}

/// What an MMR leaf records, and the proof's last public input. ORDER/AD are deposits (the side
/// the leaf is unlocked on) and prove the trade secret; the rest are event claims and prove none.
/// Always a contract constant, never an argument. Mirrors `Side` in proofbridge-mmr.
pub const LEAF_DOMAIN_ORDER: u32 = 0;
pub const LEAF_DOMAIN_AD: u32 = 1;
pub const LEAF_DOMAIN_CANCEL: u32 = 2;
pub const LEAF_DOMAIN_SETTLED: u32 = 3;
pub const LEAF_DOMAIN_REGISTERED: u32 = 4;

/// `x mod r` for BN254's scalar field: what the MMR hashes as a leaf's data (the MerkleManager's
/// own `field_mod`). Local, so a consumer with no MerkleManager needs no reference to build inputs.
pub fn field_mod(data: &BytesN<32>) -> BytesN<32> {
    Bn254Fr::from_bytes(data.clone()).to_bytes()
}

/// Public inputs for an event claim: `[0, subject % p, target_root, domain]` (128 bytes). No secret,
/// so the nullifier is zero; `domain` is a `LEAF_DOMAIN_*` event constant fixed by the caller.
pub fn build_event_public_inputs(
    env: &Env,
    target_root: &BytesN<32>,
    subject: &BytesN<32>,
    domain: u32,
) -> Bytes {
    let subject_mod = field_mod(subject);

    let mut domain_word = [0u8; 32];
    domain_word[28..].copy_from_slice(&domain.to_be_bytes());

    let mut inputs = Bytes::new(env);
    inputs.append(&Bytes::from_slice(env, &[0u8; 32]));
    inputs.append(&Bytes::from_slice(env, &subject_mod.to_array()));
    inputs.append(&Bytes::from_slice(env, &target_root.to_array()));
    inputs.append(&Bytes::from_slice(env, &domain_word));
    inputs
}

/// keccak256("ProofBridge.BLSKeyRegistry.RegistrationLeaf.v1")
pub const REG_LEAF_TAG: [u8; 32] = [
    0x11, 0x4c, 0xb0, 0xbc, 0xa6, 0xcb, 0x0f, 0x15, 0xf0, 0x56, 0x60, 0xd6, 0x36, 0x69, 0xbc, 0x00,
    0xcb, 0xd1, 0xd4, 0x2f, 0xc7, 0xac, 0xe7, 0xdf, 0x9d, 0x09, 0x16, 0xb6, 0xff, 0x9a, 0x66, 0x86,
];

/// The subject of a `REGISTERED` leaf (2.1b): the registration an account consents to on its home
/// chain, shaped like the registry's `reg_digest` — it binds the destination chain and registry, so
/// one leaf is good for exactly one registry — with `epoch` in the nonce slot. Byte-identical to
/// `RegistrationSubject.subject` on EVM:
/// `keccak256(TAG ‖ dst_chain_id ‖ dst_registry_id ‖ account32 ‖ bls_commitment ‖ epoch)`, every
/// field 32 bytes big-endian.
pub fn registration_subject(
    env: &Env,
    dst_chain_id: u128,
    dst_registry_id: &BytesN<32>,
    account32: &BytesN<32>,
    bls_commitment: &BytesN<32>,
    epoch: u64,
) -> BytesN<32> {
    let mut chain = [0u8; 32];
    chain[16..].copy_from_slice(&dst_chain_id.to_be_bytes());
    let mut epoch_word = [0u8; 32];
    epoch_word[24..].copy_from_slice(&epoch.to_be_bytes());

    let mut data = Bytes::from_slice(env, &REG_LEAF_TAG);
    data.extend_from_slice(&chain);
    data.extend_from_slice(&dst_registry_id.to_array());
    data.extend_from_slice(&account32.to_array());
    data.extend_from_slice(&bls_commitment.to_array());
    data.extend_from_slice(&epoch_word);
    env.crypto().keccak256(&data).to_bytes()
}

// =============================================================================
// RootVerifier Helpers
// =============================================================================

/// The root verifier's envelope: `settlement_signer(32) || bridger(32) || cosig_data`. Slot 0 is the
/// account whose settlement key the verifier resolves: the order's `ad_settlement_signer`.
pub fn is_root_valid(
    env: &Env,
    module: &Address,
    source_chain_id: u128,
    root: &BytesN<32>,
    settlement_signer: &BytesN<32>,
    bridger: &BytesN<32>,
    cosig_data: &Bytes,
) -> bool {
    let mut metadata = Bytes::from_slice(env, &settlement_signer.to_array());
    metadata.extend_from_slice(&bridger.to_array());
    metadata.append(cosig_data);
    RootVerifierClient::new(env, module).is_root_valid(&source_chain_id, root, &metadata)
}

// =============================================================================
// RootAnchor Helpers
// =============================================================================

/// True iff the anchor module has notarized `root` for `source_chain_id` and its delay has passed.
/// A failed call (a mis-wired address, a trap) is a typed `false`, never a host error on the
/// consumer's refund path.
pub fn is_anchored(env: &Env, anchor: &Address, source_chain_id: u128, root: &BytesN<32>) -> bool {
    matches!(
        RootAnchorClient::new(env, anchor).try_is_anchored(&source_chain_id, root),
        Ok(Ok(true))
    )
}

// =============================================================================
// KeyRegistry Helpers
// =============================================================================

/// True iff `account` holds at least one live, unexpired key slot in the registry.
pub fn has_usable_slot(env: &Env, registry: &Address, account: &BytesN<32>) -> bool {
    KeyRegistryClient::new(env, registry).has_usable_slot(account)
}
