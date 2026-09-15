// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/// @title IMerkleManager — the per-chain append-only MMR of order leaves.
/// @notice One leaf per escrow event (`LeafDomain`); the escrows append, everyone reads.
interface IMerkleManager {
    function getRoot() external view returns (bytes32);
    function getRootAtIndex(uint256 leafIndex) external view returns (bytes32);
    function getWidth() external view returns (uint256);
    function appendOrderHash(bytes32 orderHash, uint256 side) external returns (bool);
    function getSize() external view returns (uint256);
    function getNode(uint256 index) external view returns (bytes32);
    function getMerkleProof(uint256 index)
        external
        view
        returns (bytes32 root_, uint256 width_, bytes32[] memory peakBag, bytes32[] memory siblings);
    function verifyInclusionProof(
        bytes32 root_,
        uint256 width_,
        uint256 index,
        bytes32 valueHash,
        bytes32[] calldata peakBag,
        bytes32[] calldata siblings
    ) external view returns (bool);
    function fieldMod(bytes32 orderHash) external pure returns (bytes32 orderHashMod);
}
