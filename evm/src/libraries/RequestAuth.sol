// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {MMRPoseidon2} from "@solidity-mmr/MMRPoseidon2.sol";

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
        inputs = new bytes32[](4);
        inputs[0] = nullifierHash;
        inputs[1] = MMRPoseidon2._fieldMod(orderHash);
        inputs[2] = targetRoot;
        inputs[3] = bytes32(sideFlag);
    }

    /**
     * @notice The root verifier's envelope: `(settlementSigner, bridger, cosigData)`. Slot 0 is the account
     *         whose settlement key the verifier resolves: `params.adSettlementSigner`, never `adCreator`.
     */
    function rootEnvelope(bytes32 settlementSigner, bytes32 bridger, bytes memory cosigData)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(settlementSigner, bridger, cosigData);
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
        inputs = new bytes32[](4);
        inputs[1] = MMRPoseidon2._fieldMod(subject);
        inputs[2] = targetRoot;
        inputs[3] = bytes32(domain);
    }
}
