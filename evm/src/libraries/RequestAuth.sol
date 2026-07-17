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
}
