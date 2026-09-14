// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/**
 * @title RegistrationSubject
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice The subject of a `REGISTERED` leaf (2.1b): the registration an account consents to on its home
 *         chain. Shaped like the registry's own `regDigest` — it binds the destination chain and registry,
 *         so one leaf is good for exactly one registry — with `epoch` in the nonce slot. Byte-identical on
 *         Soroban (`proofbridge_core::cross_contract::registration_subject`) and in the fixture generators.
 */
library RegistrationSubject {
    /// keccak256("ProofBridge.BLSKeyRegistry.RegistrationLeaf.v1")
    bytes32 internal constant TAG = 0x114cb0bca6cb0f15f05660d63669bc00cbd1d42fc7ace7df9d0916b6ff9a6686;

    /// @return keccak256(TAG ‖ dstChainId ‖ dstRegistryId ‖ account32 ‖ blsCommitment ‖ epoch), every field 32 bytes.
    function subject(uint256 dstChainId, bytes32 dstRegistryId, bytes32 account32, bytes32 blsCommitment, uint64 epoch)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            bytes.concat(TAG, bytes32(dstChainId), dstRegistryId, account32, blsCommitment, bytes32(uint256(epoch)))
        );
    }
}
