// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {HonkVerifier} from "src/Verifier.sol";
import {MerkleManager, IMerkleManager} from "src/MerkleManager.sol";
import {Poseidon2Yul_BN254 as Poseidon2Yul} from "@poseidon2/src/bn254/yul/Poseidon2Yul.sol";
import {RequestAuth} from "src/libraries/RequestAuth.sol";
import {LeafDomain} from "src/libraries/LeafDomain.sol";

contract InputsHarness {
    IMerkleManager internal immutable mm;

    constructor(IMerkleManager _mm) {
        mm = _mm;
    }

    function deposit(bytes32 nullifier, bytes32 root, bytes32 orderHash, uint256 side)
        external
        view
        returns (bytes32[] memory)
    {
        return RequestAuth.buildPublicInputs(mm, nullifier, root, orderHash, side);
    }

    function eventClaim(bytes32 root, bytes32 subject, uint256 domain) external view returns (bytes32[] memory) {
        return RequestAuth.buildEventInputs(mm, root, subject, domain);
    }
}

/// Event claims go through the same circuit and the same verify as deposits; the contract-built
/// public inputs are what keep the two apart.
contract EventClaimTest is Test {
    uint256 constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    HonkVerifier internal verifier;
    InputsHarness internal inputs;
    bytes32 internal subject = bytes32(uint256(keccak256("proofbridge.event.claim")) % P);

    function setUp() public {
        verifier = new HonkVerifier();
        inputs = new InputsHarness(new MerkleManager(address(this), address(new Poseidon2Yul())));
    }

    function _eventClaim(uint256 domain) internal returns (bytes memory proof, bytes32 root) {
        string[] memory a = new string[](5);
        a[0] = "npx";
        a[1] = "tsx";
        a[2] = "js-scripts/deposits/generateEventClaim.ts";
        a[3] = vm.toString(domain);
        a[4] = vm.toString(subject);
        bytes32[] memory pub;
        (proof, pub) = abi.decode(vm.ffi(a), (bytes, bytes32[]));
        root = pub[2];
    }

    // bridger-side deposit (domain AD) for `subject`
    function _deposit() internal returns (bytes memory proof, bytes32[] memory pub) {
        string[] memory n = new string[](4);
        n[0] = "npx";
        n[1] = "tsx";
        n[2] = "js-scripts/deposits/getNullifierHash.ts";
        n[3] = vm.toString(subject);
        (, bytes32 nullifier, bytes32 secret) = abi.decode(vm.ffi(n), (bytes32, bytes32, bytes32));

        string[] memory g = new string[](8);
        g[0] = "npx";
        g[1] = "tsx";
        g[2] = "js-scripts/deposits/generateProof.ts";
        g[3] = vm.toString(nullifier);
        g[4] = vm.toString(subject);
        g[5] = "true";
        g[6] = vm.toString(secret);
        g[7] = vm.toString(subject);
        (proof, pub) = abi.decode(vm.ffi(g), (bytes, bytes32[]));
    }

    function test_eventClaim_verifiesForEveryEventDomain() public {
        uint256[3] memory domains = [LeafDomain.CANCEL, LeafDomain.SETTLED, LeafDomain.REGISTERED];
        for (uint256 i; i < 3; i++) {
            (bytes memory proof, bytes32 root) = _eventClaim(domains[i]);
            bytes32[] memory pub = inputs.eventClaim(root, subject, domains[i]);
            assertEq(pub[0], bytes32(0));
            assertEq(uint256(pub[3]), domains[i]);
            assertTrue(verifier.verify(proof, pub));
        }
    }

    function test_eventClaim_failsUnderAnotherDomain() public {
        (bytes memory proof, bytes32 root) = _eventClaim(LeafDomain.CANCEL);
        bytes32[] memory pub = inputs.eventClaim(root, subject, LeafDomain.SETTLED);
        vm.expectRevert();
        verifier.verify(proof, pub);
    }

    function test_eventClaim_failsForAnotherSubject() public {
        (bytes memory proof, bytes32 root) = _eventClaim(LeafDomain.CANCEL);
        bytes32[] memory pub = inputs.eventClaim(root, bytes32(uint256(subject) ^ 1), LeafDomain.CANCEL);
        vm.expectRevert();
        verifier.verify(proof, pub);
    }

    function test_eventClaim_failsWithANullifier() public {
        (bytes memory proof, bytes32 root) = _eventClaim(LeafDomain.CANCEL);
        bytes32[] memory pub = inputs.eventClaim(root, subject, LeafDomain.CANCEL);
        pub[0] = bytes32(uint256(1));
        vm.expectRevert();
        verifier.verify(proof, pub);
    }

    function test_eventClaim_cannotUnlockAsADeposit() public {
        (bytes memory proof, bytes32 root) = _eventClaim(LeafDomain.CANCEL);
        bytes32[] memory asDeposit = inputs.deposit(bytes32(0), root, subject, LeafDomain.AD);
        vm.expectRevert();
        verifier.verify(proof, asDeposit);
    }

    function test_depositProof_verifiesAndCannotPassAsAnEvent() public {
        (bytes memory proof, bytes32[] memory pub) = _deposit();
        assertTrue(verifier.verify(proof, inputs.deposit(pub[0], pub[2], subject, LeafDomain.AD)));
        bytes32[] memory asEvent = inputs.eventClaim(pub[2], subject, LeafDomain.CANCEL);
        vm.expectRevert();
        verifier.verify(proof, asEvent);
    }
}
