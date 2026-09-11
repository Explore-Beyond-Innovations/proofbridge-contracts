// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {HonkVerifier} from "src/Verifier.sol";

/// T-26: replays test-vectors/verifier-negative.json (2.3d D6) against the generated verifier. Each
/// vector is a real proof with byte patches; it must verify or fail exactly as recorded.
contract VerifierNegativeTest is Test {
    HonkVerifier internal verifier;
    string internal json;

    function setUp() public {
        verifier = new HonkVerifier();
        json = vm.readFile(string.concat(vm.projectRoot(), "/../test-vectors/verifier-negative.json"));
    }

    function _proof(string memory k) internal view returns (bytes memory proof) {
        string memory base = vm.parseJsonString(json, string.concat(k, ".base"));
        proof = vm.parseJsonBytes(json, string.concat(".bases.", base, ".proof"));
        uint256[] memory offsets = vm.parseJsonUintArray(json, string.concat(k, ".patchOffsets"));
        bytes32[] memory words = vm.parseJsonBytes32Array(json, string.concat(k, ".patchWords"));
        for (uint256 i; i < offsets.length; i++) {
            uint256 off = offsets[i];
            bytes32 w = words[i];
            assembly {
                mstore(add(add(proof, 32), off), w)
            }
        }
        uint256 len = vm.parseJsonUint(json, string.concat(k, ".proofLength"));
        require(len <= proof.length, "proofLength past the base proof");
        assembly {
            mstore(proof, len)
        }
    }

    function test_T26_everyVectorBehavesAsRecorded() public view {
        uint256 n = vm.parseJsonUint(json, ".count");
        assertGt(n, 0);
        for (uint256 i; i < n; i++) {
            string memory k = string.concat(".vectors[", vm.toString(i), "]");
            bytes memory proof = _proof(k);
            bytes32[] memory pub = vm.parseJsonBytes32Array(json, string.concat(k, ".publicInputs"));
            bool accepted;
            try verifier.verify(proof, pub) returns (bool ok) {
                accepted = ok;
            } catch {
                accepted = false;
            }
            bool expected =
                keccak256(bytes(vm.parseJsonString(json, string.concat(k, ".expect")))) == keccak256("accept");
            assertEq(accepted, expected, vm.parseJsonString(json, string.concat(k, ".name")));
        }
    }
}
