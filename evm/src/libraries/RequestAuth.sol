// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IMerkleManager} from "../MerkleManager.sol";

/**
 * @title RequestAuth
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice Pre-authorization and proof helpers shared by OrderPortal and
 *         AdManager. All helpers are stateless; concrete contracts keep the
 *         `requestTokens` / `requestHashes` mappings and call these helpers
 *         to compute digests, recover signers, and assemble proof public
 *         inputs.
 */
library RequestAuth {
    /// @notice Message digest is zero.
    error RequestAuth__InvalidMessage();
    /// @notice Deadline has passed.
    error RequestAuth__Expired();
    /// @notice ECDSA recovery returned the zero address.
    error RequestAuth__ZeroSigner();

    /**
     * @notice Hash a delegated-action request for pre-authorization.
     * @param authToken Unique token for this delegated action (replay guard).
     * @param timeToExpire Expiration time (unix timestamp).
     * @param action Action name (e.g. "createAd", "unlockOrder").
     * @param params Abi-encoded call parameters.
     * @param chainId Executing chain id.
     * @param verifyingContract Contract that will consume the signature.
     */
    function hashRequest(
        bytes32 authToken,
        uint256 timeToExpire,
        string memory action,
        bytes[] memory params,
        uint256 chainId,
        address verifyingContract
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(authToken, timeToExpire, action, params, chainId, verifyingContract));
    }

    /**
     * @notice Recover the ECDSA signer of an eth-signed message.
     * @dev Reverts if the digest is zero or recovery yields address(0).
     */
    function recoverSigner(bytes32 message, bytes memory signature) internal pure returns (address) {
        if (message == bytes32(0)) revert RequestAuth__InvalidMessage();
        address signer = ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(message), signature);
        if (signer == address(0)) revert RequestAuth__ZeroSigner();
        return signer;
    }

    /**
     * @notice Assert a deadline has not elapsed.
     * @dev Reverts with `RequestAuth__Expired` when stale.
     */
    function assertNotExpired(uint256 timeToExpire) internal view {
        if (block.timestamp > timeToExpire) revert RequestAuth__Expired();
    }

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
