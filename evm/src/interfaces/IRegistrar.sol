// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IMerkleManager} from "./IMerkleManager.sol";

/**
 * @title IRegistrar — the home-chain half of proof-carried registration (2.1b).
 * @notice An account approves a registration here under its own authorization; the registrar
 *         appends the `REGISTERED` leaf the foreign registry later accepts by inclusion proof.
 */
interface IRegistrar {
    event RegistrationLeaf(
        bytes32 indexed account32,
        bytes32 indexed blsCommitment,
        uint64 epoch,
        uint256 dstChainId,
        bytes32 dstRegistryId,
        bytes32 subject
    );

    error Registrar__ZeroAddress();
    error Registrar__NotAccount();
    error Registrar__BadAuth();
    error Registrar__StaleEpoch(uint64 nextEpoch, uint64 given);
    error Registrar__AppendFailed();

    function registerLeaf(
        bytes32 account32,
        bytes32 blsCommitment,
        uint64 epoch,
        uint256 dstChainId,
        bytes32 dstRegistryId,
        bytes calldata sig
    ) external returns (bytes32 subject);

    function i_merkleManager() external view returns (IMerkleManager);
    function nextEpoch(bytes32 account32) external view returns (uint64);
    function subjectOf(
        bytes32 account32,
        bytes32 blsCommitment,
        uint64 epoch,
        uint256 dstChainId,
        bytes32 dstRegistryId
    ) external pure returns (bytes32);
    function leafDigest(
        bytes32 account32,
        bytes32 blsCommitment,
        uint64 epoch,
        uint256 dstChainId,
        bytes32 dstRegistryId
    ) external view returns (bytes32);
}
