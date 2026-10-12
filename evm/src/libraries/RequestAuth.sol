// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {MMRPoseidon2} from "@solidity-mmr/MMRPoseidon2.sol";
import {FieldElement} from "./FieldElement.sol";

/**
 * @title RequestAuth
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice Proof plumbing shared by OrderPortal and AdManager: assembles the
 *         public-input vector consumed by the zk verifier. The legacy
 *         pre-authorization helpers (request hashing, signer recovery, expiry
 *         checks) were removed at the 1.5 cutover; the only signature the
 *         contracts verify now is the BLS co-signature over the root-bound
 *         message, enforced via the root-verifier gate.
 */
library RequestAuth {
    /// @notice The envelope's pin on the order leg: no slot is pinned there, the verifier checks the
    ///         maker key the co-signed auth names instead (2.7 plan 12 D11).
    uint32 internal constant UNPINNED = type(uint32).max;

    /**
     * @notice Assemble the 4-element public-input vector for the zk verifier.
     * @dev Pure, like {buildEventInputs}: the reduction is the MMR library's own, the same one the
     *      MerkleManager's `fieldMod` returns, so there is no call to make. `EventClaim.t.sol` pins
     *      the two to each other.
     * @param nullifierHash One-time proof nullifier.
     * @param targetRoot Source-chain merkle root consumed by the proof.
     * @param orderHash EIP-712 order hash.
     * @param sideFlag Side indicator (1 = AdManager side, 0 = OrderPortal side).
     * @return inputs `[nullifierHash, orderHash % p, targetRoot, sideFlag]`.
     */
    function buildPublicInputs(bytes32 nullifierHash, bytes32 targetRoot, bytes32 orderHash, uint256 sideFlag)
        internal
        pure
        returns (bytes32[] memory inputs)
    {
        // A malformed nullifier is refused here, by name, before the verifier runs. It is not what
        // keeps a nullifier unique: on the co-signed unlock the root verifier has already required it
        // to equal the value both parties signed for this leg (an alias `n + p` fails that), and the
        // never-locked cancel consumes none. Both shipped verifiers reject a non-canonical input too;
        // see `FieldElement`. The root is checked against stored data before this runs on every path
        // (`_requireRootValid`, `_requireAnchored`), the order hash is reduced below, and the side
        // flag is a contract constant.
        FieldElement.requireCanonical(nullifierHash);

        inputs = new bytes32[](4);
        inputs[0] = nullifierHash;
        inputs[1] = MMRPoseidon2._fieldMod(orderHash);
        inputs[2] = targetRoot;
        inputs[3] = bytes32(sideFlag);
    }

    /**
     * @notice The root verifier's envelope:
     *         `(settlementSigner, bridger, orderHash, pinnedSlot, nullifierHash, side, cosigData)`: what the
     *         escrow vouches for. Slot 0 is the account whose settlement key the verifier resolves
     *         (`params.adSettlementSigner`, never `adCreator`); `orderHash` is the order the escrow is
     *         unlocking, which the co-signed auth must name (#433); `nullifierHash` is the nullifier the
     *         escrow is about to consume and `side` its leg, which the auth must have signed for that leg.
     *         `pinnedSlot` is the maker's co-signing slot the ad-chain order pinned at lock; the order leg
     *         passes `UNPINNED`.
     */
    function rootEnvelope(
        bytes32 settlementSigner,
        bytes32 bridger,
        bytes32 orderHash,
        uint32 pinnedSlot,
        bytes32 nullifierHash,
        uint8 side,
        bytes memory cosigData
    ) internal pure returns (bytes memory) {
        return abi.encode(settlementSigner, bridger, orderHash, pinnedSlot, nullifierHash, side, cosigData);
    }

    /**
     * @notice Assemble the public inputs for an event claim: no secret, so the nullifier is zero.
     * @dev Pure: the field reduction is the MMR library's own, so a consumer needs no MerkleManager.
     * @param targetRoot Source-chain merkle root the claim is proven against.
     * @param subject The leaf's subject (the order hash for cancel / settled, the registration subject).
     * @param domain A `LeafDomain` event constant (>= 2), fixed by the caller, never calldata.
     * @return inputs `[0, subject % p, targetRoot, domain]`.
     */
    function buildEventInputs(bytes32 targetRoot, bytes32 subject, uint256 domain)
        internal
        pure
        returns (bytes32[] memory inputs)
    {
        // Nothing to check: the event path's nullifier slot is a literal zero, and its root is
        // already anchored-checked by every caller before this runs. The subject is reduced below.
        inputs = new bytes32[](4);
        inputs[1] = MMRPoseidon2._fieldMod(subject);
        inputs[2] = targetRoot;
        inputs[3] = bytes32(domain);
    }
}
