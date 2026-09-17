// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {FieldElement} from "src/libraries/FieldElement.sol";
import {RequestAuth} from "src/libraries/RequestAuth.sol";
import {LeafDomain} from "src/libraries/LeafDomain.sol";

/*//////////////////////////////////////////////////////////////
   2.3h / T-65 — canonical public inputs (residual 9)
//////////////////////////////////////////////////////////////*/

/// `vm.expectRevert` needs a frame below the cheatcode's, and an internal library call inlines into
/// the test's own. This puts the builders behind an external boundary so the revert is observable.
contract BuilderHarness {
    function deposit(bytes32 nullifierHash, bytes32 targetRoot, bytes32 orderHash) external pure {
        RequestAuth.buildPublicInputs(nullifierHash, targetRoot, orderHash, 0);
    }

    function event_(bytes32 targetRoot, bytes32 subject) external pure {
        RequestAuth.buildEventInputs(targetRoot, subject, LeafDomain.CANCEL);
    }
}

contract FieldElementTest is Test {
    BuilderHarness internal h = new BuilderHarness();

    uint256 internal constant PRIME = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    /// The constant is the MMR library's, not a second copy. If the fork ever changes it, this fails
    /// rather than the two silently disagreeing across a chain boundary.
    function test_primeIsTheMmrLibrarysOwn() public pure {
        assertEq(FieldElement.prime(), PRIME, "the field prime moved");
    }

    function test_boundary() public pure {
        assertTrue(FieldElement.isCanonical(bytes32(PRIME - 1)), "one below the prime is canonical");
        assertFalse(FieldElement.isCanonical(bytes32(PRIME)), "the prime itself is not");
        assertFalse(FieldElement.isCanonical(bytes32(type(uint256).max)), "nor is the maximum word");
    }

    /// The attack residual 9 names: `n` and `n + PRIME` reduce to the same field element, so the
    /// verifier sees one proof — but the escrow keys `nullifierUsed` on the raw bytes and sees two
    /// distinct nullifiers. The replay guard would stop guarding.
    function test_theAliasIsRejectedAtTheBuilder() public {
        bytes32 n = bytes32(uint256(12345));
        bytes32 alias_ = bytes32(uint256(12345) + PRIME);

        // Both reduce to the same element...
        assertEq(uint256(alias_) % PRIME, uint256(n) % PRIME, "they are aliases of one element");
        // ...but only the canonical one may be presented.
        h.deposit(n, bytes32(uint256(1)), bytes32(uint256(2)));
        vm.expectRevert(abi.encodeWithSelector(FieldElement.FieldElement__NonCanonical.selector, alias_));
        h.deposit(alias_, bytes32(uint256(1)), bytes32(uint256(2)));
    }

    /// The root is deliberately *not* checked here, and that is worth pinning rather than leaving
    /// to a reader's assumption. Every caller validates it before the builder runs — against the
    /// co-signed root on the deposit path, against the notary's anchored root on the event path —
    /// and both are equality comparisons with known-good stored data. Checking it again would buy
    /// nothing and would have forced a regeneration of the signed BLS encoding vectors, whose
    /// `orderChainRoot` is a synthetic placeholder rather than a real Poseidon2 output.
    function test_theRootIsNotCheckedBecauseItsCallersAlreadyDid() public view {
        bytes32 atPrime = bytes32(PRIME);
        h.deposit(bytes32(uint256(1)), atPrime, bytes32(uint256(2)));
        h.event_(atPrime, bytes32(uint256(2)));
    }

    /// The order hash is exempt on purpose: `_fieldMod` reduces it on the way in, so a non-canonical
    /// one is not an error, it is just reduced. Pinning that keeps someone from "fixing" it later.
    function test_theOrderHashIsReducedNotRejected() public pure {
        bytes32[] memory a = RequestAuth.buildPublicInputs(bytes32(0), bytes32(0), bytes32(uint256(7)), 0);
        bytes32[] memory b = RequestAuth.buildPublicInputs(bytes32(0), bytes32(0), bytes32(uint256(7) + PRIME), 0);
        assertEq(a[1], b[1], "the reduction makes the two order hashes one input");
    }

    /// The same bytes both chains must agree on, read from the shared vector rather than restated.
    /// This is the file `parity-fixture` regenerates and diffs, so the cases cannot drift from the
    /// generator, and the Soroban suite asserts the same rows.
    function test_canonicalityMatchesTheSharedVector() public {
        string memory v = vm.readFile("../test-vectors/verifier-negative.json");
        uint256 n = vm.parseJsonUint(v, ".canonicalityCount");
        assertEq(n, 5, "the case set shrank");

        uint256 rejected;
        for (uint256 i = 0; i < n; i++) {
            string memory at = string.concat(".canonicality[", vm.toString(i), "]");
            bytes32 value = vm.parseJsonBytes32(v, string.concat(at, ".value"));
            bool canonical = vm.parseJsonBool(v, string.concat(at, ".canonical"));
            assertEq(FieldElement.isCanonical(value), canonical, vm.parseJsonString(v, string.concat(at, ".name")));
            if (!canonical) {
                rejected++;
                vm.expectRevert(abi.encodeWithSelector(FieldElement.FieldElement__NonCanonical.selector, value));
                h.deposit(value, bytes32(uint256(1)), bytes32(uint256(2)));
            }
        }
        assertEq(rejected, 3, "every rejection case was actually driven");
    }

    function testFuzz_canonicalIffBelowThePrime(uint256 v) public pure {
        assertEq(FieldElement.isCanonical(bytes32(v)), v < PRIME);
    }
}
