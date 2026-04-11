#![cfg(test)]

extern crate std;

use soroban_sdk::{testutils::Address as _, Address, BytesN, Env};

use crate::{mmr, ProofBridgeMerkleManagerContract, ProofBridgeMerkleManagerContractClient};

// =============================================================================
// Helper Functions
// =============================================================================

fn setup_contract<'a>(
    env: &'a Env,
) -> (ProofBridgeMerkleManagerContractClient<'a>, Address, Address) {
    let contract_id = env.register(ProofBridgeMerkleManagerContract, ());
    let client = ProofBridgeMerkleManagerContractClient::new(env, &contract_id);

    let admin = Address::generate(env);
    let manager = Address::generate(env);

    (client, admin, manager)
}

// =============================================================================
// Pure Function Tests
// =============================================================================

#[test]
fn test_calc_size() {
    // Test calc_size matches EVM implementation
    // size = (width << 1) - popcount(width)
    assert_eq!(mmr::calc_size(0), 0);
    assert_eq!(mmr::calc_size(1), 1); // 2 - 1 = 1
    assert_eq!(mmr::calc_size(2), 3); // 4 - 1 = 3
    assert_eq!(mmr::calc_size(3), 4); // 6 - 2 = 4
    assert_eq!(mmr::calc_size(4), 7); // 8 - 1 = 7
    assert_eq!(mmr::calc_size(5), 8); // 10 - 2 = 8
    assert_eq!(mmr::calc_size(6), 10); // 12 - 2 = 10
    assert_eq!(mmr::calc_size(7), 11); // 14 - 3 = 11
    assert_eq!(mmr::calc_size(8), 15); // 16 - 1 = 15
}

#[test]
fn test_num_of_peaks() {
    // Popcount of width
    assert_eq!(mmr::num_of_peaks(0), 0);
    assert_eq!(mmr::num_of_peaks(1), 1); // 0b0001
    assert_eq!(mmr::num_of_peaks(2), 1); // 0b0010
    assert_eq!(mmr::num_of_peaks(3), 2); // 0b0011
    assert_eq!(mmr::num_of_peaks(4), 1); // 0b0100
    assert_eq!(mmr::num_of_peaks(5), 2); // 0b0101
    assert_eq!(mmr::num_of_peaks(6), 2); // 0b0110
    assert_eq!(mmr::num_of_peaks(7), 3); // 0b0111
    assert_eq!(mmr::num_of_peaks(8), 1); // 0b1000
}

#[test]
fn test_get_leaf_index() {
    // Leaf index for given width
    assert_eq!(mmr::get_leaf_index(1), 1);
    assert_eq!(mmr::get_leaf_index(2), 2);
    assert_eq!(mmr::get_leaf_index(3), 4);
    assert_eq!(mmr::get_leaf_index(4), 5);
    assert_eq!(mmr::get_leaf_index(5), 8);
    assert_eq!(mmr::get_leaf_index(6), 9);
    assert_eq!(mmr::get_leaf_index(7), 11);
    assert_eq!(mmr::get_leaf_index(8), 12);
}

#[test]
fn test_get_peak_indexes() {
    let env = Env::default();

    // Width 1: peak at 1
    let peaks1 = mmr::get_peak_indexes(&env, 1);
    assert_eq!(peaks1.len(), 1);
    assert_eq!(peaks1.get(0).unwrap(), 1);

    // Width 2: peak at 3
    let peaks2 = mmr::get_peak_indexes(&env, 2);
    assert_eq!(peaks2.len(), 1);
    assert_eq!(peaks2.get(0).unwrap(), 3);

    // Width 3: peaks at 3, 4
    let peaks3 = mmr::get_peak_indexes(&env, 3);
    assert_eq!(peaks3.len(), 2);
    assert_eq!(peaks3.get(0).unwrap(), 3);
    assert_eq!(peaks3.get(1).unwrap(), 4);

    // Width 4: peak at 7
    let peaks4 = mmr::get_peak_indexes(&env, 4);
    assert_eq!(peaks4.len(), 1);
    assert_eq!(peaks4.get(0).unwrap(), 7);

    // Width 5: peaks at 7, 8
    let peaks5 = mmr::get_peak_indexes(&env, 5);
    assert_eq!(peaks5.len(), 2);
    assert_eq!(peaks5.get(0).unwrap(), 7);
    assert_eq!(peaks5.get(1).unwrap(), 8);
}

#[test]
fn test_height_at() {
    // Height of node at index (1 = leaf)
    assert_eq!(mmr::height_at(1), 1); // leaf
    assert_eq!(mmr::height_at(2), 1); // leaf
    assert_eq!(mmr::height_at(3), 2); // parent of 1,2
    assert_eq!(mmr::height_at(4), 1); // leaf
    assert_eq!(mmr::height_at(5), 1); // leaf
    assert_eq!(mmr::height_at(6), 2); // parent of 4,5
    assert_eq!(mmr::height_at(7), 3); // parent of 3,6
}

#[test]
fn test_is_leaf() {
    assert!(mmr::is_leaf(1));
    assert!(mmr::is_leaf(2));
    assert!(!mmr::is_leaf(3)); // branch
    assert!(mmr::is_leaf(4));
    assert!(mmr::is_leaf(5));
    assert!(!mmr::is_leaf(6)); // branch
    assert!(!mmr::is_leaf(7)); // branch
}

// =============================================================================
// Contract Tests
// =============================================================================

#[test]
fn test_initialize() {
    let env = Env::default();
    let (client, admin, _) = setup_contract(&env);

    // Initialize
    client.initialize(&admin);

    // Check state
    assert!(client.is_initialized());
    assert_eq!(client.get_admin(), Some(admin));
    assert_eq!(client.get_width(), 0);
    assert_eq!(client.get_size(), 0);
}

#[test]
fn test_double_initialize_fails() {
    let env = Env::default();
    let (client, admin, _) = setup_contract(&env);

    // First initialize should succeed
    client.initialize(&admin);

    // Second initialize should fail with AlreadyInitialized error
    let result = client.try_initialize(&admin);
    assert!(result.is_err());
}

#[test]
fn test_set_manager() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, manager) = setup_contract(&env);

    client.initialize(&admin);

    // Set manager
    client.set_manager(&manager, &true);

    // Check
    assert!(client.is_manager(&manager));

    // Unset manager
    client.set_manager(&manager, &false);
    assert!(!client.is_manager(&manager));
}

#[test]
fn test_field_mod() {
    let env = Env::default();
    let (client, admin, _) = setup_contract(&env);

    client.initialize(&admin);

    // Test with a hash that's smaller than the prime (should stay the same)
    let small_hash = BytesN::from_array(&env, &[0u8; 32]);
    let result = client.field_mod(&small_hash);
    assert_eq!(result, small_hash);

    // Test with max hash (all 0xFF) - should be reduced
    let max_hash = BytesN::from_array(&env, &[0xFF; 32]);
    let reduced = client.field_mod(&max_hash);
    // Result should be different from input since it's reduced
    assert_ne!(reduced, max_hash);
}

#[test]
fn test_append_order_hash() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, manager) = setup_contract(&env);

    // Initialize and set manager
    client.initialize(&admin);
    client.set_manager(&manager, &true);

    // Initial state
    assert_eq!(client.get_width(), 0);
    assert_eq!(client.get_size(), 0);

    // Append first order hash
    let hash1 = BytesN::from_array(&env, &[1u8; 32]);
    let result = client.append_order_hash(&manager, &hash1);
    assert!(result);

    // Check state after first append
    assert_eq!(client.get_width(), 1);
    assert_eq!(client.get_size(), 1);

    // Root should not be zero
    let root1 = client.get_root();
    assert_ne!(root1, BytesN::from_array(&env, &[0u8; 32]));

    // Root should be stored in history
    let historical_root = client.get_root_at_index(&1);
    assert_eq!(historical_root, root1);

    // Append second order hash
    let hash2 = BytesN::from_array(&env, &[2u8; 32]);
    client.append_order_hash(&manager, &hash2);

    // Check state after second append
    assert_eq!(client.get_width(), 2);
    assert_eq!(client.get_size(), 3); // MMR size for 2 leaves is 3

    // Root should change
    let root2 = client.get_root();
    assert_ne!(root2, root1);
}

#[test]
fn test_append_not_manager_fails() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, manager) = setup_contract(&env);

    client.initialize(&admin);
    // Don't set manager

    let hash = BytesN::from_array(&env, &[1u8; 32]);
    let result = client.try_append_order_hash(&manager, &hash);
    assert!(result.is_err());
}

// =============================================================================
// Cross-Chain Verification Tests
// =============================================================================

/// Helper to create BytesN<32> from hex string (without 0x prefix)
fn hex_to_bytes32(env: &Env, hex_str: &str) -> BytesN<32> {
    let bytes = hex::decode(hex_str).expect("Invalid hex");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    BytesN::from_array(env, &arr)
}

/// Helper to create a zero-padded u256 from an integer (matching EVM zeroPadValue)
fn padded_int_to_bytes32(env: &Env, n: u64) -> BytesN<32> {
    let mut arr = [0u8; 32];
    // Big-endian: value goes in the last bytes
    arr[24..32].copy_from_slice(&n.to_be_bytes());
    BytesN::from_array(env, &arr)
}

/// Test BN254 scalar field reduction via Fr
#[test]
fn test_bn254_field_reduction() {
    // Verify that Fr reduces the BN254 scalar field modulus r to 0.
    // r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
    let env = Env::default();
    let prime = hex_to_bytes32(
        &env,
        "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
    );
    let reduced = mmr::field_mod(&env, &prime);
    assert_eq!(
        reduced,
        BytesN::from_array(&env, &[0u8; 32]),
        "Prime should reduce to 0"
    );
}

/// Test field_mod with known EVM values
#[test]
fn test_field_mod_cross_chain() {
    let env = Env::default();
    let (client, admin, _) = setup_contract(&env);
    client.initialize(&admin);

    // Test 1: Value less than prime should stay the same
    let small = hex_to_bytes32(
        &env,
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    let result1 = client.field_mod(&small);
    assert_eq!(result1, small, "Small value should not change");

    // Test 2: Value equal to prime should become 0
    let prime = hex_to_bytes32(
        &env,
        "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
    );
    let result2 = client.field_mod(&prime);
    let zero = BytesN::from_array(&env, &[0u8; 32]);
    assert_eq!(result2, zero, "Prime should reduce to 0");

    // Test 3: Value = prime + 1 should become 1
    let prime_plus_1 = hex_to_bytes32(
        &env,
        "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000002",
    );
    let result3 = client.field_mod(&prime_plus_1);
    let one = hex_to_bytes32(
        &env,
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    assert_eq!(result3, one, "Prime + 1 should reduce to 1");

    // Test 4: Max value (all 0xFF) should be reduced
    let max = BytesN::from_array(&env, &[0xFF; 32]);
    let result4 = client.field_mod(&max);
    assert_ne!(result4, max, "Max value should be reduced");
}

/// Test MMR pure functions match EVM implementation
#[test]
fn test_mmr_structure_cross_chain() {
    let env = Env::default();

    // These tests verify the MMR structure matches EVM exactly
    // The structure is critical for cross-chain verification

    // Test 1: Size calculation for various widths
    let test_cases = [
        (0u128, 0u128), // empty tree
        (1, 1),         // single leaf
        (2, 3),         // 2 leaves + 1 parent
        (3, 4),         // 3 leaves + 1 parent (2 peaks)
        (4, 7),         // 4 leaves in a complete binary tree
        (7, 11),        // 7 leaves (3 peaks)
        (8, 15),        // 8 leaves in complete binary tree
        (15, 26),       // 15 leaves (4 peaks)
        (16, 31),       // 16 leaves in complete binary tree
    ];

    for (width, expected_size) in test_cases {
        assert_eq!(
            mmr::calc_size(width),
            expected_size,
            "Size mismatch for width {}",
            width
        );
    }

    // Test 2: Verify peak indexes match EVM
    // For width=7, peaks should be at [7, 10, 11]
    let peaks_7 = mmr::get_peak_indexes(&env, 7);
    assert_eq!(peaks_7.len(), 3);
    assert_eq!(peaks_7.get(0).unwrap(), 7);
    assert_eq!(peaks_7.get(1).unwrap(), 10);
    assert_eq!(peaks_7.get(2).unwrap(), 11);

    // For width=15, peaks should be at [15, 22, 25, 26]
    let peaks_15 = mmr::get_peak_indexes(&env, 15);
    assert_eq!(peaks_15.len(), 4);
    assert_eq!(peaks_15.get(0).unwrap(), 15);
    assert_eq!(peaks_15.get(1).unwrap(), 22);
    assert_eq!(peaks_15.get(2).unwrap(), 25);
    assert_eq!(peaks_15.get(3).unwrap(), 26);
}

/// Test that multiple appends produce changing roots
#[test]
fn test_multiple_appends_cross_chain() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, manager) = setup_contract(&env);
    client.initialize(&admin);
    client.set_manager(&manager, &true);

    // Store roots after each append
    let mut roots: std::vec::Vec<BytesN<32>> = std::vec::Vec::new();
    let zero_root = BytesN::from_array(&env, &[0u8; 32]);

    // Append 10 elements (matching testMerkle.ts pattern)
    for i in 0..10u64 {
        let hash = padded_int_to_bytes32(&env, i);
        client.append_order_hash(&manager, &hash);

        let root = client.get_root();
        assert_ne!(
            root, zero_root,
            "Root should not be zero after append {}",
            i
        );

        // Each root should be different from previous
        if !roots.is_empty() {
            let last_root = roots.last().unwrap();
            assert_ne!(root, *last_root, "Root should change after append {}", i);
        }

        roots.push(root);
    }

    // Verify final state
    assert_eq!(client.get_width(), 10);
    assert_eq!(client.get_size(), mmr::calc_size(10));

    // Verify root history is stored correctly
    for (i, expected_root) in roots.iter().enumerate() {
        let stored_root = client.get_root_at_index(&((i + 1) as u128));
        assert_eq!(
            stored_root,
            *expected_root,
            "Root history mismatch at width {}",
            i + 1
        );
    }
}

/// Test that same inputs produce deterministic roots
#[test]
fn test_deterministic_roots() {
    let env1 = Env::default();
    let env2 = Env::default();
    env1.mock_all_auths();
    env2.mock_all_auths();

    // Create two separate contract instances
    let (client1, admin1, manager1) = setup_contract(&env1);
    let (client2, admin2, manager2) = setup_contract(&env2);

    client1.initialize(&admin1);
    client1.set_manager(&manager1, &true);
    client2.initialize(&admin2);
    client2.set_manager(&manager2, &true);

    // Append same sequence to both
    for i in 0..5u64 {
        let hash1 = padded_int_to_bytes32(&env1, i);
        let hash2 = padded_int_to_bytes32(&env2, i);
        client1.append_order_hash(&manager1, &hash1);
        client2.append_order_hash(&manager2, &hash2);
    }

    // Roots should be identical
    let root1 = client1.get_root();
    let root2 = client2.get_root();

    // Convert to arrays for comparison (different Env instances)
    assert_eq!(
        root1.to_array(),
        root2.to_array(),
        "Roots should be identical for same inputs"
    );
}

/// Test that different input order produces different roots
#[test]
fn test_root_depends_on_order() {
    let env1 = Env::default();
    let env2 = Env::default();
    env1.mock_all_auths();
    env2.mock_all_auths();

    let (client1, admin1, manager1) = setup_contract(&env1);
    let (client2, admin2, manager2) = setup_contract(&env2);

    client1.initialize(&admin1);
    client1.set_manager(&manager1, &true);
    client2.initialize(&admin2);
    client2.set_manager(&manager2, &true);

    // Append in order: 0, 1
    let hash0_1 = padded_int_to_bytes32(&env1, 0);
    let hash1_1 = padded_int_to_bytes32(&env1, 1);
    client1.append_order_hash(&manager1, &hash0_1);
    client1.append_order_hash(&manager1, &hash1_1);

    // Append in reverse order: 1, 0
    let hash1_2 = padded_int_to_bytes32(&env2, 1);
    let hash0_2 = padded_int_to_bytes32(&env2, 0);
    client2.append_order_hash(&manager2, &hash1_2);
    client2.append_order_hash(&manager2, &hash0_2);

    // Roots should be different
    let root1 = client1.get_root();
    let root2 = client2.get_root();
    assert_ne!(
        root1.to_array(),
        root2.to_array(),
        "Different order should produce different roots"
    );
}

// =============================================================================
// EVM Cross-Chain Compatibility Tests
// =============================================================================
// These tests verify that the Stellar MerkleManager produces identical outputs
// to the EVM MerkleManager for the same inputs.

/// Test exact cross-chain compatibility with EVM testMerkle.ts output
///
/// The EVM test script (testMerkle.ts) does:
/// 1. For i in 0..5: compute poseidon2Hash([hex(i)])
/// 2. Append each hash to MMR
/// 3. Record root after each append
///
/// This test uses the exact hashes from EVM as inputs and verifies
/// the Stellar MMR produces the same roots.
#[test]
fn test_cross_chain_mmr_evm_compatibility() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, manager) = setup_contract(&env);
    client.initialize(&admin);
    client.set_manager(&manager, &true);

    // These are the poseidon2 hashes of hex(0..4) from EVM testMerkle.ts
    // Input: zeroPadValue(toBeHex(i), 32) → poseidon2Hash([input])
    let evm_hashes = [
        "2710144414c3a5f2354f4c08d52ed655b9fe253b4bf12cb9ad3de693d9b1db11", // poseidon2(0x00...00)
        "168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373", // poseidon2(0x00...01)
        "10a1bcbc8042d777b9e26d836704377fdd79202b3b5db02f36eb70407c332b75", // poseidon2(0x00...02)
        "24177b4692df7493b626c0a03a9891e0ee5c514fbd5856964e810c5e9d03ebf2", // poseidon2(0x00...03)
        "0157eb7606c8121d046231c4fa78714a91ab2fd0690e9b1b0c848468ebd13dbc", // poseidon2(0x00...04)
    ];

    // Expected roots after each append from EVM testMerkle.ts
    let evm_roots = [
        "29ae820c971a4cfb1efa6ff17005b852121928021a9148ae0e972ba1b791babe", // after append 0
        "0c36410360add62088d4fe9b1b93a762b940c0554118e8371b3f70c200557292", // after append 1
        "103de6d9d2c45dc7e4975424e2a9926747527d428801f7bbba5408f443ea1d6d", // after append 2
        "0c753a881c3884ccd9a19d5f837aacd3a3598dac0311766ad9e1e97ecde6c552", // after append 3
        "01cdf4db8698b886693a0d948ce7ef7859e1cf4f9594b4efa4d070d1db0a436b", // after append 4
    ];

    // Append each hash and verify root matches EVM
    for (i, (hash_hex, expected_root_hex)) in evm_hashes.iter().zip(evm_roots.iter()).enumerate() {
        let order_hash = hex_to_bytes32(&env, hash_hex);
        client.append_order_hash(&manager, &order_hash);

        let actual_root = client.get_root();
        let expected_root = hex_to_bytes32(&env, expected_root_hex);

        let actual_hex = hex::encode(actual_root.to_array());
        assert_eq!(
            actual_root.to_array(),
            expected_root.to_array(),
            "Root mismatch after append {}: expected {} got {}",
            i,
            expected_root_hex,
            actual_hex
        );
    }

    // Verify final state matches EVM
    assert_eq!(client.get_width(), 5, "Width should be 5");
    assert_eq!(client.get_size(), 8, "Size should be 8"); // calc_size(5) = 8

    // Verify element indexes match EVM: [1, 2, 4, 5, 8]
    // This is implicit in the MMR structure - width 5 means:
    // - Leaf 1 at index 1
    // - Leaf 2 at index 2 (merges with 1 to form node 3)
    // - Leaf 3 at index 4
    // - Leaf 4 at index 5 (merges with 4 to form node 6, then 3+6 = 7)
    // - Leaf 5 at index 8
    assert_eq!(mmr::get_leaf_index(1), 1);
    assert_eq!(mmr::get_leaf_index(2), 2);
    assert_eq!(mmr::get_leaf_index(3), 4);
    assert_eq!(mmr::get_leaf_index(4), 5);
    assert_eq!(mmr::get_leaf_index(5), 8);
}

// =============================================================================
// Proof Verification Tests
// =============================================================================

/// Test proof generation and verification round-trip.
/// Mirrors the EVM TestMMRPoseidon.sol pattern: append items, get proof, verify.
#[test]
fn test_merkle_proof_round_trip() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, manager) = setup_contract(&env);
    client.initialize(&admin);
    client.set_manager(&manager, &true);

    // Append 10 items (matching EVM TestMMRPoseidon structure)
    //              15
    //       7             14
    //    3      6     10       13       18
    //  1  2   4  5   8  9    11  12   16  17
    let hashes: std::vec::Vec<BytesN<32>> =
        (0..10u64).map(|i| padded_int_to_bytes32(&env, i)).collect();

    for hash in &hashes {
        client.append_order_hash(&manager, hash);
    }

    assert_eq!(client.get_width(), 10);

    // Verify proof for every leaf
    let leaf_indexes: [u128; 10] = [1, 2, 4, 5, 8, 9, 11, 12, 16, 17];
    for (i, &leaf_idx) in leaf_indexes.iter().enumerate() {
        let (root, width, peak_bag, siblings) = client.get_merkle_proof(&leaf_idx);

        // The value_hash is field_mod(original_hash) since append applies field_mod
        let value_hash = client.field_mod(&hashes[i]);

        let valid =
            client.verify_inclusion(&root, &width, &leaf_idx, &value_hash, &peak_bag, &siblings);
        assert!(
            valid,
            "Proof verification failed for leaf index {}",
            leaf_idx
        );
    }
}

/// Test proof verification fails with wrong value hash.
#[test]
#[should_panic(expected = "MMR: bad peak hash")]
fn test_proof_fails_with_wrong_value() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, manager) = setup_contract(&env);
    client.initialize(&admin);
    client.set_manager(&manager, &true);

    let hash = padded_int_to_bytes32(&env, 42);
    client.append_order_hash(&manager, &hash);

    let (root, width, peak_bag, siblings) = client.get_merkle_proof(&1);

    // Use wrong value (must be a valid field element, i.e. < BN254 modulus)
    let wrong_value = padded_int_to_bytes32(&env, 999);
    client.verify_inclusion(&root, &width, &1, &wrong_value, &peak_bag, &siblings);
}
