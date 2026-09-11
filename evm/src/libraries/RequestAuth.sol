// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IMerkleManager} from "../MerkleManager.sol";

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
     * @param merkleManager MerkleManager used to field-mod the order hash.
     * @param nullifierHash One-time proof nullifier.
     * @param targetRoot Source-chain merkle root consumed by the proof.
     * @param orderHash EIP-712 order hash.
     * @param sideFlag Side indicator (1 = AdManager side, 0 = OrderPortal side).
     * @return inputs `[nullifierHash, orderHash % p, targetRoot, sideFlag]`.
     */
    function buildPublicInputs(
        IMerkleManager merkleManager,
        bytes32 nullifierHash,
        bytes32 targetRoot,
        bytes32 orderHash,
        uint256 sideFlag
    ) internal view returns (bytes32[] memory inputs) {
        bytes32 orderHashMod = merkleManager.fieldMod(orderHash);
        inputs = new bytes32[](4);
        inputs[0] = nullifierHash;
        inputs[1] = orderHashMod;
        inputs[2] = targetRoot;
        inputs[3] = bytes32(sideFlag);
    }

    /**
     * @notice Assemble the public inputs for an event claim: no secret, so the nullifier is zero.
     * @param merkleManager MerkleManager used to field-mod the subject.
     * @param targetRoot Source-chain merkle root the claim is proven against.
     * @param subject The leaf's subject (the order hash for cancel / settled).
     * @param domain A `LeafDomain` event constant (>= 2), fixed by the caller, never calldata.
     * @return inputs `[0, subject % p, targetRoot, domain]`.
     */
    /**
     * @notice The root verifier's envelope: `(settlementSigner, bridger, cosigData)`. Slot 0 is the account
     *         whose settlement key the verifier resolves: `params.adSettlementSigner`, never `adCreator`.
     */
    function rootEnvelope(bytes32 settlementSigner, bytes32 bridger, bytes calldata cosigData)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(settlementSigner, bridger, cosigData);
    }

    function buildEventInputs(IMerkleManager merkleManager, bytes32 targetRoot, bytes32 subject, uint256 domain)
        internal
        view
        returns (bytes32[] memory inputs)
    {
        inputs = new bytes32[](4);
        inputs[1] = merkleManager.fieldMod(subject);
        inputs[2] = targetRoot;
        inputs[3] = bytes32(domain);
    }
}
