// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {BLSKeyRegistryTest} from "./BLSKeyRegistry.t.sol";
import {BLSKeyRegistry} from "src/BLSKeyRegistry.sol";
import {RootAnchor} from "src/RootAnchor.sol";
import {IRootAnchor} from "src/interfaces/IRootAnchor.sol";
import {HonkVerifier, IVerifier} from "src/Verifier.sol";
import {MerkleManager, IMerkleManager} from "src/MerkleManager.sol";
import {Poseidon2Yul_BN254 as Poseidon2Yul} from "@poseidon2/src/bn254/yul/Poseidon2Yul.sol";

/// 2.1b (#324), T-67b/c: the registry's proof-accepting `register` path, tested against the real
/// `RootAnchor` (threshold 1, delay 0) and a live domain-4 proof. Ships flagged off.
contract ProofRegistrationTest is BLSKeyRegistryTest {
    uint256 internal constant SOURCE_CHAIN = 1_000_002;
    uint64 internal constant EPOCH = 0; // the vectors' nonce-0 POP doubles as the epoch-0 POP

    RootAnchor internal anchor;
    HonkVerifier internal honk;
    MerkleManager internal mm;

    bytes32 internal account;
    bytes internal pk;
    bytes internal pop;

    function _wire(bool enabled) internal {
        address[] memory signers = new address[](1);
        signers[0] = address(this);
        anchor = new RootAnchor(address(this), signers, 1);
        honk = new HonkVerifier();
        mm = new MerkleManager(address(this), address(new Poseidon2Yul()));
        registry.setProofRegistration(
            IRootAnchor(address(anchor)), IVerifier(address(honk)), IMerkleManager(address(mm)), enabled
        );

        account = reg32("makerOnSepolia", "account");
        pk = reg("makerOnSepolia", "pkNative");
        pop = reg("makerOnSepolia", "pop");
    }

    function _subject(bytes32 acct, bytes memory blsPk, uint64 epoch) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(acct, keccak256(blsPk), epoch));
    }

    /// A domain-4 inclusion proof for `subject`, built live by the event-claim generator.
    function _leafProof(bytes32 subject) internal returns (bytes memory proof, bytes32 root) {
        string[] memory a = new string[](5);
        a[0] = "npx";
        a[1] = "tsx";
        a[2] = "js-scripts/deposits/generateEventClaim.ts";
        a[3] = "4";
        a[4] = vm.toString(subject);
        bytes32[] memory pub;
        (proof, pub) = abi.decode(vm.ffi(a), (bytes, bytes32[]));
        root = pub[2];
    }

    function test_flagOff_reverts() public {
        _wire(false);
        vm.expectRevert(BLSKeyRegistry.ProofRegistrationDisabled.selector);
        registry.registerByProof(account, pk, pop, EPOCH, SOURCE_CHAIN, bytes32(0), "");
    }

    function test_enable_requiresEveryReference() public {
        vm.expectRevert(BLSKeyRegistry.ProofRegistrationRefsUnset.selector);
        registry.setProofRegistration(IRootAnchor(address(0)), IVerifier(address(1)), IMerkleManager(address(1)), true);
        // Disabled needs nothing.
        registry.setProofRegistration(IRootAnchor(address(0)), IVerifier(address(0)), IMerkleManager(address(0)), false);
    }

    function test_setProofRegistration_adminOnly() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(BLSKeyRegistry.NotAdmin.selector);
        registry.setProofRegistration(IRootAnchor(address(1)), IVerifier(address(1)), IMerkleManager(address(1)), true);
    }

    function test_anchoredLeafProof_registers() public {
        _wire(true);
        (bytes memory proof, bytes32 root) = _leafProof(_subject(account, pk, EPOCH));
        anchor.anchor(SOURCE_CHAIN, root, 1);

        vm.expectEmit(true, true, false, true);
        emit BLSKeyRegistry.KeyRegisteredByProof(account, 0, pk, EPOCH, SOURCE_CHAIN);
        uint32 slotId = registry.registerByProof(account, pk, pop, EPOCH, SOURCE_CHAIN, root, proof);

        assertEq(slotId, 0);
        assertEq(registry.commitmentAt(account, 0), keccak256(pk));
        assertTrue(registry.hasUsableSlot(account));
    }

    function test_unanchoredRoot_reverts() public {
        _wire(true);
        (bytes memory proof, bytes32 root) = _leafProof(_subject(account, pk, EPOCH));
        vm.expectRevert(abi.encodeWithSelector(BLSKeyRegistry.RootNotAnchored.selector, SOURCE_CHAIN, root));
        registry.registerByProof(account, pk, pop, EPOCH, SOURCE_CHAIN, root, proof);
    }

    function test_anchoredButInsideDelay_reverts() public {
        _wire(true);
        anchor.setAnchorDelay(SOURCE_CHAIN, 3600);
        (bytes memory proof, bytes32 root) = _leafProof(_subject(account, pk, EPOCH));
        anchor.anchor(SOURCE_CHAIN, root, 1);
        vm.expectRevert(abi.encodeWithSelector(BLSKeyRegistry.RootNotAnchored.selector, SOURCE_CHAIN, root));
        registry.registerByProof(account, pk, pop, EPOCH, SOURCE_CHAIN, root, proof);
    }

    function test_proofForAnotherSubject_reverts() public {
        _wire(true);
        // A valid POP for the bridger's key, but the leaf proof was built for the maker's subject.
        bytes32 other = reg32("bridgerOnSepolia", "account");
        bytes memory otherPk = reg("bridgerOnSepolia", "pkNative");
        bytes memory otherPop = reg("bridgerOnSepolia", "pop");
        (bytes memory proof, bytes32 root) = _leafProof(_subject(account, pk, EPOCH));
        anchor.anchor(SOURCE_CHAIN, root, 1);

        // The Honk verifier reverts (SumcheckFailed) on a proof for another subject rather than
        // returning false; either way no slot is added.
        vm.expectRevert();
        registry.registerByProof(other, otherPk, otherPop, EPOCH, SOURCE_CHAIN, root, proof);
        assertFalse(registry.hasUsableSlot(other));
    }

    function test_badPop_reverts() public {
        _wire(true);
        bytes memory otherPop = reg("bridgerOnSepolia", "pop");
        (bytes memory proof, bytes32 root) = _leafProof(_subject(account, pk, EPOCH));
        anchor.anchor(SOURCE_CHAIN, root, 1);

        vm.expectRevert(BLSKeyRegistry.InvalidPop.selector);
        registry.registerByProof(account, pk, otherPop, EPOCH, SOURCE_CHAIN, root, proof);
    }

    function test_replay_reverts_keyPreviouslyUsed() public {
        _wire(true);
        (bytes memory proof, bytes32 root) = _leafProof(_subject(account, pk, EPOCH));
        anchor.anchor(SOURCE_CHAIN, root, 1);
        registry.registerByProof(account, pk, pop, EPOCH, SOURCE_CHAIN, root, proof);

        vm.expectRevert(BLSKeyRegistry.KeyPreviouslyUsed.selector);
        registry.registerByProof(account, pk, pop, EPOCH, SOURCE_CHAIN, root, proof);
    }

    function test_enableIsAConfigCall_notARedeploy() public {
        _wire(false);
        (bytes memory proof, bytes32 root) = _leafProof(_subject(account, pk, EPOCH));
        anchor.anchor(SOURCE_CHAIN, root, 1);

        vm.expectRevert(BLSKeyRegistry.ProofRegistrationDisabled.selector);
        registry.registerByProof(account, pk, pop, EPOCH, SOURCE_CHAIN, root, proof);

        registry.setProofRegistration(
            IRootAnchor(address(anchor)), IVerifier(address(honk)), IMerkleManager(address(mm)), true
        );
        registry.registerByProof(account, pk, pop, EPOCH, SOURCE_CHAIN, root, proof);
        assertTrue(registry.hasUsableSlot(account));
    }
}
