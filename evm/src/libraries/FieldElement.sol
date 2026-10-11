// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {MMRPoseidon2} from "@solidity-mmr/MMRPoseidon2.sol";

/**
 * @title FieldElement
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice Canonicality for the BN254 scalar field: a 32-byte public input must be the unique
 *         representative of its field element, not one of the several that reduce to it (2.3h,
 *         residual 9).
 * @dev What this guards, and what it does not.
 *
 *      A non-canonical input is already refused by both shipped verifiers: the transcript hashes
 *      public inputs as given, so `n` and `n + PRIME` produce different challenges and a proof made
 *      for one fails for the other. `verifier-negative.json`'s `deposit/public-input-ge-r` vector
 *      pins that on both chains.
 *
 *      The nullifier is not a free calldata key either. On the co-signed unlock (metadata v4) the
 *      root verifier requires it to equal, byte for byte, the nullifier both parties signed for that
 *      leg, so an alias `n + PRIME` of the signed value fails the root check before any proof is read,
 *      whatever the ZK verifier does. The never-locked cancel consumes no nullifier at all.
 *
 *      So this check closes no hole. It refuses a malformed input locally, with a named error, before
 *      the verifier call, and it keeps every public input the escrows hand a verifier canonical if
 *      the verifier is ever ported (T3) to one that reduces instead of rejecting.
 *
 *      The order hash is exempt because it is already reduced by `_fieldMod` on the way in, so it is
 *      canonical by construction. Side flags and leaf domains are contract constants, never calldata.
 *
 *      `PRIME` is re-exported from the MMR library rather than restated. A second copy of a constant
 *      two chains have to agree on is the shape that produced both the inverted bond flag and the
 *      stale leaf-domain map; there is one source and this points at it.
 */
library FieldElement {
    /// @notice A public input at or above the field prime is not a canonical field element.
    error FieldElement__NonCanonical(bytes32 value);

    /// @notice BN254's scalar field modulus, as the MMR library defines it.
    function prime() internal pure returns (uint256) {
        return MMRPoseidon2.PRIME;
    }

    /// @notice Whether `value` is the canonical representative of its field element.
    function isCanonical(bytes32 value) internal pure returns (bool) {
        return uint256(value) < MMRPoseidon2.PRIME;
    }

    /// @notice Revert unless `value` is canonical.
    function requireCanonical(bytes32 value) internal pure {
        if (uint256(value) >= MMRPoseidon2.PRIME) revert FieldElement__NonCanonical(value);
    }
}
