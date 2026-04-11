//! Merkle Mountain Range (MMR) implementation with Poseidon2 hashing.
//!
//! This is a port of the Solidity MMRPoseidon2.sol library.
//! Indexing is 1-based (not 0-based) to match the EVM implementation.

use soroban_poseidon::poseidon2_hash;
use soroban_sdk::{
    crypto::{bn254::Fr, BnScalar},
    Bytes, BytesN, Env, Vec, U256,
};

use crate::storage;

// =============================================================================
// Field Operations
// =============================================================================

/// Apply BN254 field modulus to a hash.
/// Reduces dataHash into the BN254 scalar field using the SDK's Fr type,
/// mirroring Solidity's `_fieldMod`: `bytes32(uint256(dataHash) % Field.PRIME)`.
pub fn field_mod(_env: &Env, data_hash: &BytesN<32>) -> BytesN<32> {
    Fr::from_bytes(data_hash.clone()).to_bytes()
}

// =============================================================================
// Poseidon2 Hashing
// =============================================================================
//
// All hashes use T=4 (rate=3) regardless of input count. This is intentional
// for cross-chain compatibility: the EVM Poseidon2Lib (ported from Noir) uses a
// fixed T=4 permutation for hash_1, hash_2, and hash_3 alike. Different T
// values produce different round constants and matrix diagonals, so using T=3
// for 2-input hashes would break EVM parity.

/// Hash a leaf node: Poseidon2(index, dataHash)
pub fn hash_leaf(env: &Env, index: u128, data_hash: &BytesN<32>) -> BytesN<32> {
    let mut inputs: Vec<U256> = Vec::new(env);
    inputs.push_back(u128_to_u256(env, index));
    inputs.push_back(bytes32_to_u256(env, data_hash));

    let result: U256 = poseidon2_hash::<4, BnScalar>(env, &inputs);
    u256_to_bytes32(env, &result)
}

/// Hash a branch node: Poseidon2(index, left, right)
pub fn hash_branch(env: &Env, index: u128, left: &BytesN<32>, right: &BytesN<32>) -> BytesN<32> {
    let mut inputs: Vec<U256> = Vec::new(env);
    inputs.push_back(u128_to_u256(env, index));
    inputs.push_back(bytes32_to_u256(env, left));
    inputs.push_back(bytes32_to_u256(env, right));

    let result: U256 = poseidon2_hash::<4, BnScalar>(env, &inputs);
    u256_to_bytes32(env, &result)
}

/// Compute peak bagging: fold peaks into a single root.
pub fn peak_bagging(env: &Env, width: u128, peaks: &Vec<BytesN<32>>) -> BytesN<32> {
    if width == 0 {
        return BytesN::from_array(env, &[0u8; 32]);
    }

    let size = calc_size(width);
    assert!(num_of_peaks(width) == peaks.len(), "MMR: bad peak count");
    let size_u256 = u128_to_u256(env, size);

    // Fold: acc = H(acc, peak[i])
    let mut acc: U256 = size_u256.clone();

    for i in 0..peaks.len() {
        let peak = peaks.get(i).unwrap();
        let mut inputs: Vec<U256> = Vec::new(env);
        inputs.push_back(acc.clone());
        inputs.push_back(bytes32_to_u256(env, &peak));
        acc = poseidon2_hash::<4, BnScalar>(&env, &inputs);
    }

    // Final bind: H(size, acc)
    let mut final_inputs: Vec<U256> = Vec::new(env);
    final_inputs.push_back(size_u256);
    final_inputs.push_back(acc);
    let result = poseidon2_hash::<4, BnScalar>(&env, &final_inputs);
    u256_to_bytes32(env, &result)
}

// =============================================================================
// MMR Pure Functions
// =============================================================================

/// Calculate MMR size from width (leaf count).
/// size = (width << 1) - popcount(width)
pub fn calc_size(width: u128) -> u128 {
    (width << 1) - num_of_peaks(width) as u128
}

/// Count the number of peaks (popcount of width).
pub fn num_of_peaks(width: u128) -> u32 {
    let mut bits = width;
    let mut count = 0u32;
    while bits > 0 {
        count += 1;
        bits &= bits - 1; // Clear lowest set bit
    }
    count
}

/// Get peak indexes for a given width.
pub fn get_peak_indexes(env: &Env, width: u128) -> Vec<u128> {
    let num_peaks = num_of_peaks(width);
    let mut peak_indexes: Vec<u128> = Vec::new(env);

    if width == 0 {
        return peak_indexes;
    }

    // Compute max height
    let mut max_height: u32 = 1;
    while (1u128 << max_height) <= width {
        max_height += 1;
    }

    let mut running_size: u128 = 0;
    for i in (1..=max_height).rev() {
        if (width & (1u128 << (i - 1))) != 0 {
            running_size = running_size + (1u128 << i) - 1;
            peak_indexes.push_back(running_size);
        }
    }

    // Verify count matches
    assert!(peak_indexes.len() == num_peaks);

    peak_indexes
}

/// Get the leaf index for a given width.
/// Width is 1-indexed count of leaves.
pub fn get_leaf_index(width: u128) -> u128 {
    if width % 2 == 1 {
        calc_size(width)
    } else {
        calc_size(width - 1) + 1
    }
}

/// Get the height of a node at a given index.
pub fn height_at(index: u128) -> u8 {
    let mut reduced_index = index;
    let mut peak_index: u128 = 0;
    let mut height: u8 = 0;

    while reduced_index > peak_index {
        reduced_index -= (1u128 << height) - 1;
        height = mountain_height(reduced_index);
        peak_index = (1u128 << height) - 1;
    }

    height - (peak_index - reduced_index) as u8
}

/// Check if an index is a leaf node.
pub fn is_leaf(index: u128) -> bool {
    height_at(index) == 1
}
/// Get the children of a node at a given index.
pub fn get_children(index: u128) -> (u128, u128) {
    let h = height_at(index);
    let left = index - (1u128 << (h - 1));
    let right = index - 1;
    assert!(left != right, "Not a parent node");
    (left, right)
}

/// Calculate the mountain height for a given size.
fn mountain_height(size: u128) -> u8 {
    let mut height: u8 = 1;
    while (1u128 << height) <= size + height as u128 {
        height += 1;
    }
    height - 1
}

// =============================================================================
// MMR Append Operation
// =============================================================================

/// Append a new leaf to the MMR.
/// Returns the new leaf index.
pub fn append(env: &Env, data_hash: &BytesN<32>) -> u128 {
    // Apply field modulus
    let data_hash_mod = field_mod(env, data_hash);

    // Increment width
    let width = storage::get_width(env) + 1;
    storage::set_width(env, width);

    // Calculate leaf index
    let leaf_index = get_leaf_index(width);

    // Hash leaf node: Poseidon2(index, value)
    let leaf_node = hash_leaf(env, leaf_index, &data_hash_mod);

    // Store leaf hash
    storage::set_node_hash(env, leaf_index, &leaf_node);

    // Get peak indexes
    let peak_indexes = get_peak_indexes(env, width);

    // Update size
    let size = calc_size(width);
    storage::set_size(env, size);

    // Get or create node hashes for all peaks
    let mut peaks: Vec<BytesN<32>> = Vec::new(env);
    for i in 0..peak_indexes.len() {
        let peak_idx = peak_indexes.get(i).unwrap();
        let peak_hash = get_or_create_node(env, peak_idx, size);
        peaks.push_back(peak_hash);
    }

    // Compute new root via peak bagging
    let new_root = peak_bagging(env, width, &peaks);
    storage::set_root(env, &new_root);

    // Store root in history
    storage::set_root_at_width(env, width, &new_root);

    leaf_index
}

/// Get or create a node hash at the given index.
/// Recursively computes branch hashes if not cached.
fn get_or_create_node(env: &Env, index: u128, size: u128) -> BytesN<32> {
    assert!(index <= size, "Index out of bounds");

    // Check if already cached
    if let Some(cached) = storage::get_node_hash(env, index) {
        if cached != BytesN::from_array(env, &[0u8; 32]) {
            return cached;
        }
    }

    // Not cached - must be a branch node, compute from children
    let (left_idx, right_idx) = get_children(index);
    let left_hash = get_or_create_node(env, left_idx, size);
    let right_hash = get_or_create_node(env, right_idx, size);

    let branch_hash = hash_branch(env, index, &left_hash, &right_hash);
    storage::set_node_hash(env, index, &branch_hash);

    branch_hash
}

// =============================================================================
// Peak Query
// =============================================================================

/// Return all current peak hashes (same order as in peak bagging).
pub fn get_peaks(env: &Env) -> Vec<BytesN<32>> {
    let width = storage::get_width(env);
    let peak_idxs = get_peak_indexes(env, width);
    let mut peaks: Vec<BytesN<32>> = Vec::new(env);
    for i in 0..peak_idxs.len() {
        let idx = peak_idxs.get(i).unwrap();
        let hash =
            storage::get_node_hash(env, idx).unwrap_or(BytesN::from_array(env, &[0u8; 32]));
        peaks.push_back(hash);
    }
    peaks
}

// =============================================================================
// Proof Generation & Verification
// =============================================================================

/// Build a Merkle inclusion proof for a leaf at `index`.
/// Returns (root, width, peak_bag, siblings).
pub fn get_merkle_proof(
    env: &Env,
    index: u128,
) -> (BytesN<32>, u128, Vec<BytesN<32>>, Vec<BytesN<32>>) {
    let size = storage::get_size(env);
    assert!(index <= size, "MMR: index out of range");
    assert!(is_leaf(index), "MMR: not a leaf");

    let root = storage::get_root(env);
    let width = storage::get_width(env);

    let peak_idxs = get_peak_indexes(env, width);
    let mut peak_bag: Vec<BytesN<32>> = Vec::new(env);
    let mut cursor: u128 = 0;

    for i in 0..peak_idxs.len() {
        let peak_idx = peak_idxs.get(i).unwrap();
        let hash =
            storage::get_node_hash(env, peak_idx).unwrap_or(BytesN::from_array(env, &[0u8; 32]));
        peak_bag.push_back(hash);
        if peak_idx >= index && cursor == 0 {
            cursor = peak_idx;
        }
    }
    assert!(cursor != 0, "MMR: peak not found");

    // Descend from peak to leaf, recording siblings
    let h = height_at(cursor);
    let mut siblings: Vec<BytesN<32>> = Vec::new(env);
    // Pre-fill with zeros (h-1 entries)
    for _ in 0..(h - 1) {
        siblings.push_back(BytesN::from_array(env, &[0u8; 32]));
    }

    let mut cur = cursor;
    let mut level = h;
    while cur != index {
        level -= 1;
        let (left, right) = get_children(cur);
        let (next, sibling_idx) = if index <= left {
            (left, right)
        } else {
            (right, left)
        };
        let sibling_hash =
            storage::get_node_hash(env, sibling_idx).unwrap_or(BytesN::from_array(env, &[0u8; 32]));
        siblings.set(level as u32 - 1, sibling_hash);
        cur = next;
    }

    (root, width, peak_bag, siblings)
}

/// Stateless inclusion proof verification (mirrors EVM `verifyInclusion`).
pub fn verify_inclusion(
    env: &Env,
    root: &BytesN<32>,
    width: u128,
    index: u128,
    value_hash: &BytesN<32>,
    peak_bag: &Vec<BytesN<32>>,
    siblings: &Vec<BytesN<32>>,
) -> bool {
    assert!(calc_size(width) >= index, "MMR: index out of bounds");

    // Root must equal bagged peak hash
    let bagged = peak_bagging(env, width, peak_bag);
    assert!(root == &bagged, "MMR: bad root");

    // Find target peak and starting cursor
    let peak_idxs = get_peak_indexes(env, width);
    let mut target_peak = BytesN::from_array(env, &[0u8; 32]);
    let mut cursor: u128 = 0;
    for i in 0..peak_idxs.len() {
        let peak_idx = peak_idxs.get(i).unwrap();
        if peak_idx >= index {
            target_peak = peak_bag.get(i).unwrap();
            cursor = peak_idx;
            break;
        }
    }
    let zero = BytesN::from_array(env, &[0u8; 32]);
    assert!(target_peak != zero, "MMR: no peak for index");

    // Walk DOWN from peak to leaf, recording path
    // Mirrors EVM: h starts at siblings.length + 1, pre-decrements each iteration
    let sib_len = siblings.len();
    let path_len = sib_len + 1;
    let mut path: Vec<u128> = Vec::new(env);
    for _ in 0..path_len {
        path.push_back(0);
    }

    let mut h = path_len; // EVM: uint8 h = uint8(siblings.length) + 1
    loop {
        h -= 1; // EVM: path[--h] = cursor
        path.set(h, cursor);
        if cursor == index {
            break;
        }
        let (l, r) = get_children(cursor);
        cursor = if index > l { r } else { l };
    }

    // Walk UP recomputing hashes
    let mut node = BytesN::from_array(env, &[0u8; 32]);
    while h < path_len {
        cursor = path.get(h).unwrap();
        if h == 0 {
            // Leaf
            node = hash_leaf(env, cursor, value_hash);
        } else {
            let prev = path.get(h - 1).unwrap();
            let sibling = siblings.get(h - 1).unwrap();
            if cursor - 1 == prev {
                // Sibling is on the left
                node = hash_branch(env, cursor, &sibling, &node);
            } else {
                // Sibling is on the right
                node = hash_branch(env, cursor, &node, &sibling);
            }
        }
        h += 1;
    }

    assert!(node == target_peak, "MMR: bad peak hash");
    true
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Convert u128 to U256.
pub fn u128_to_u256(env: &Env, value: u128) -> U256 {
    U256::from_u128(env, value)
}

/// Convert BytesN<32> to U256 (big-endian).
pub fn bytes32_to_u256(env: &Env, bytes: &BytesN<32>) -> U256 {
    // Convert BytesN<32> to Bytes for U256::from_be_bytes
    let bytes_dynamic = Bytes::from_slice(env, &bytes.to_array());
    U256::from_be_bytes(env, &bytes_dynamic)
}

/// Convert U256 to BytesN<32> (big-endian).
pub fn u256_to_bytes32(_env: &Env, value: &U256) -> BytesN<32> {
    value.to_be_bytes().try_into().unwrap()
}
