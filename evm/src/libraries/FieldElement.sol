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
 * @dev Why this is here, and what it does *not* claim.
 *
 *      A non-canonical input is already refused by both shipped verifiers — the transcript
 *      hashes public inputs as given, so `n` and `n + PRIME` produce different challenges and a
 *      proof made for one fails for the other. `verifier-negative.json`'s `deposit/public-input-ge-r`
 *      vector pins exactly that, on both chains.
 *
 *      So this is defence in depth, not the closing of an open hole. It earns its place by not
 *      depending on verifier internals: it fails locally, cheaply, with a named error, and it keeps
 *      holding if the verifier is ever ported (T3) to one that reduces instead of rejecting. The
 *      escrow's `nullifierUsed` ledger keys on raw bytes, so a reducing verifier *would* turn one
 *      proof into unboundedly many nullifiers; this makes the escrow's guarantee independent of
 *      which verifier is underneath.
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
