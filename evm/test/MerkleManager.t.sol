// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {MerkleManager} from "src/MerkleManager.sol";
import {TwoStepAdmin} from "src/libraries/TwoStepAdmin.sol";
import {Poseidon2Yul_BN254 as Poseidon2Yul} from "@poseidon2/src/bn254/yul/Poseidon2Yul.sol";

/// A hasher that tries to write storage. Reached only through `staticcall`, so the write fails.
contract WritingHasher {
    uint256 public calls;

    fallback(bytes calldata) external returns (bytes memory) {
        calls++;
        return abi.encode(bytes32(uint256(1)));
    }
}

/// The manager list (one admin system), the append's staticcall assumption, and the kept debugging
/// helpers pinned to `proofbridge-mmr` through `test-vectors/t2-mmr.json` `proofParity`.
contract MerkleManagerTest is Test {
    MerkleManager internal mm;
    address internal admin = address(0xA11CE);
    address internal next = address(0xB0B);
    address internal escrow = address(0xE5C0);

    event ManagerSet(address indexed account, bool enabled);

    function setUp() public {
        mm = new MerkleManager(admin, address(new Poseidon2Yul()));
    }

    // ---------- the manager list ----------

    function test_onlyAManagerAppends() public {
        vm.prank(escrow);
        vm.expectRevert(abi.encodeWithSelector(MerkleManager.MerkleManager__NotManager.selector, escrow));
        mm.appendOrderHash(keccak256("o"), 0);

        vm.prank(admin);
        mm.setManager(escrow, true);
        assertTrue(mm.isManager(escrow));
        vm.prank(escrow);
        mm.appendOrderHash(keccak256("o"), 0);
        assertEq(mm.getWidth(), 1);
    }

    function test_setManagerIsAdminOnlyAndEmits() public {
        vm.prank(escrow);
        vm.expectRevert(TwoStepAdmin.NotAdmin.selector);
        mm.setManager(escrow, true);

        vm.expectEmit(true, false, false, true, address(mm));
        emit ManagerSet(escrow, true);
        vm.prank(admin);
        mm.setManager(escrow, true);
    }

    function test_disablingAManagerStopsItsAppends() public {
        vm.startPrank(admin);
        mm.setManager(escrow, true);
        mm.setManager(escrow, false);
        vm.stopPrank();
        assertFalse(mm.isManager(escrow));
        vm.prank(escrow);
        vm.expectRevert(abi.encodeWithSelector(MerkleManager.MerkleManager__NotManager.selector, escrow));
        mm.appendOrderHash(keccak256("o"), 0);
    }

    function test_setManagerRefusesTheZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(MerkleManager.MerkleManager__ZeroAddress.selector);
        mm.setManager(address(0), true);
    }

    /// The admin path is the two-step handover alone: after it, only the new admin edits the list.
    function test_afterAHandoverOnlyTheNewAdminSetsManagers() public {
        vm.prank(admin);
        mm.transferAdmin(next);
        vm.prank(next);
        mm.acceptAdmin();

        vm.prank(admin);
        vm.expectRevert(TwoStepAdmin.NotAdmin.selector);
        mm.setManager(escrow, true);

        vm.prank(next);
        mm.setManager(escrow, true);
        assertTrue(mm.isManager(escrow));
    }

    // ---------- the append makes no call that can write state ----------

    /// Why `appendOrderHash` carries no reentrancy guard: the hasher is reached by `staticcall`, so
    /// a hasher that writes (or re-enters to write) reverts the append instead.
    function test_aHasherThatWritesStateRevertsTheAppend() public {
        WritingHasher h = new WritingHasher();
        MerkleManager bad = new MerkleManager(admin, address(h));
        vm.prank(admin);
        bad.setManager(escrow, true);
        vm.prank(escrow);
        vm.expectRevert(bytes("MMR:HashFail"));
        bad.appendOrderHash(keccak256("o"), 0);
        assertEq(h.calls(), 0, "the write never landed");
    }

    // ---------- the debugging helpers, pinned to proofbridge-mmr ----------

    string internal json;

    function _appendParityLeaves() internal returns (uint256 n) {
        json = vm.readFile("../test-vectors/t2-mmr.json");
        n = abi.decode(vm.parseJson(json, ".proofParity.width"), (uint256));
        vm.prank(admin);
        mm.setManager(address(this), true);
        for (uint256 i = 0; i < n; i++) {
            string memory k = string.concat(".proofParity.leaves[", vm.toString(i), "]");
            bytes32 orderHash = vm.parseJsonBytes32(json, string.concat(k, ".orderHash"));
            uint256 side = vm.parseJsonUint(json, string.concat(k, ".side"));
            mm.appendOrderHash(orderHash, side);
        }
    }

    function _proof(uint256 j)
        internal
        view
        returns (uint256 index, bytes32 leaf, bytes32[] memory peaks, bytes32[] memory siblings)
    {
        string memory k = string.concat(".proofParity.proofs[", vm.toString(j), "]");
        index = vm.parseJsonUint(json, string.concat(k, ".elementIndex"));
        leaf = vm.parseJsonBytes32(json, string.concat(k, ".leaf"));
        peaks = vm.parseJsonBytes32Array(json, string.concat(k, ".peaks"));
        siblings = abi.decode(vm.parseJson(json, string.concat(k, ".siblings")), (bytes32[]));
    }

    /// For every leaf, `getMerkleProof` returns exactly `proofbridge-mmr`'s proof, and
    /// `verifyInclusionProof` accepts it.
    function test_proofViewEqualsProofbridgeMmrAndVerifies() public {
        uint256 n = _appendParityLeaves();
        bytes32 root = vm.parseJsonBytes32(json, ".proofParity.root");
        assertEq(mm.getRoot(), root, "root");
        assertEq(mm.getWidth(), n, "width");
        for (uint256 j = 0; j < n; j++) {
            (uint256 index, bytes32 leaf, bytes32[] memory peaks, bytes32[] memory siblings) = _proof(j);
            (bytes32 r, uint256 w, bytes32[] memory pb, bytes32[] memory sib) = mm.getMerkleProof(index);
            assertEq(r, root, "proof root");
            assertEq(w, n, "proof width");
            assertEq(pb, peaks, "peaks");
            assertEq(sib, siblings, "siblings");
            assertTrue(mm.verifyInclusionProof(r, w, index, leaf, pb, sib), "verifies");
        }
    }

    function test_verifyInclusionProofRejectsAWrongValueIndexOrSibling() public {
        _appendParityLeaves();
        (uint256 index, bytes32 leaf, bytes32[] memory peaks, bytes32[] memory siblings) = _proof(0);
        (bytes32 root, uint256 width,,) = mm.getMerkleProof(index);
        assertTrue(mm.verifyInclusionProof(root, width, index, leaf, peaks, siblings));

        (uint256 otherIndex, bytes32 otherLeaf,,) = _proof(1);

        vm.expectRevert(bytes("MMR:BadPeakHash"));
        mm.verifyInclusionProof(root, width, index, otherLeaf, peaks, siblings);

        vm.expectRevert(bytes("MMR:BadPeakHash"));
        mm.verifyInclusionProof(root, width, otherIndex, leaf, peaks, siblings);

        siblings[0] = bytes32(uint256(siblings[0]) ^ 1);
        vm.expectRevert(bytes("MMR:BadPeakHash"));
        mm.verifyInclusionProof(root, width, index, leaf, peaks, siblings);
    }
}
