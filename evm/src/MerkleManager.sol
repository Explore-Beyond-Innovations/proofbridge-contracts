// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {MMRPoseidon2} from "@solidity-mmr/MMRPoseidon2.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

interface IMerkleManager {
    function getRoot() external view returns (bytes32);
    function getRootAtIndex(uint256 leafIndex) external view returns (bytes32);
    function getWidth() external view returns (uint256);
    function appendOrderHash(bytes32 orderHash) external returns (bool);
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
    ) external pure returns (bool);
    function fieldMod(bytes32 orderHash) external pure returns (bytes32 orderHashMod);
}

/**
 * @title MerkleManager
 * @dev Manages all order hashes for ProofBridge protocol per chain
 */
contract MerkleManager is IMerkleManager, AccessControl, ReentrancyGuard {
    using MMRPoseidon2 for MMRPoseidon2.Tree;
    MMRPoseidon2.Tree _tree;

    // Mapping of width count to roothistory
    mapping(uint256 => bytes32) internal rootHistory;

    /// @notice Roles
    bytes32 public constant ADMIN_ROLE = DEFAULT_ADMIN_ROLE;
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");

    // Errors
    error MerkleManager__ZeroAddress();

    // Emitted event after each successful `append` operation
    event DepositHashAppended(
        uint256 indexed index, bytes32 indexed orderHash, uint256 width, uint256 size, bytes32 rootHash
    );

    // Role definition for admin
    constructor(address admin) {
        if (admin == address(0)) {
            revert MerkleManager__ZeroAddress();
        }
        _grantRole(ADMIN_ROLE, admin);
        _setRoleAdmin(MANAGER_ROLE, ADMIN_ROLE);
    }

    /**
     * @dev Appends a new deposit order to the tree.
     * Updates peaks, root, and mappings. Emits DepositHashAppended.
     * @param orderHash The hash of the order to append.
     */
    function appendOrderHash(bytes32 orderHash) external nonReentrant onlyRole(MANAGER_ROLE) returns (bool) {
        uint256 leafIndex = _tree.append(orderHash);
        bytes32 newRoot = _tree.getRoot();
        uint256 width = _tree.getWidth();

        rootHistory[width] = newRoot;

        emit DepositHashAppended(leafIndex, orderHash, width, _tree.getSize(), newRoot);
        return true;
    }

    // ========== READERS (VIEW) ==========
    /**
     * @dev Returns the root hash of the tree.
     * @return The latest root hash.
     */
    function getRoot() external view returns (bytes32) {
        return _tree.getRoot();
    }

    /**
     * @dev Return the root at a specific leaf index.
     * @param leafIndex The leaf index to retrieve the root for.
     * @return The root hash at the specified leaf index.
     */
    function getRootAtIndex(uint256 leafIndex) external view returns (bytes32) {
        return rootHistory[leafIndex];
    }

    /**
     * @dev Returns the number of leaves in the tree.
     * @return The latest leaves count.
     */
    function getWidth() external view returns (uint256) {
        return _tree.getWidth();
    }

    function getSize() external view returns (uint256) {
        return _tree.getSize();
    }

    function getNode(uint256 index) external view returns (bytes32) {
        return _tree.getNodeHash(index);
    }

    /**
     * @notice Returns peak bag + sibling path for a leaf index.
     * Used by off-chain relayers and by destination chain to claim.
     */
    function getMerkleProof(uint256 index)
        external
        view
        returns (bytes32 root_, uint256 width_, bytes32[] memory peakBag, bytes32[] memory siblings)
    {
        return _tree.getMerkleProof(index);
    }

    /**
     * @notice Stateless verification helper
     * This mirrors inclusionProof/verifyInclusion.
     */
    function verifyInclusionProof(
        bytes32 root_,
        uint256 width_,
        uint256 index,
        bytes32 valueHash,
        bytes32[] calldata peakBag,
        bytes32[] calldata siblings
    ) external pure returns (bool) {
        return MMRPoseidon2.verifyInclusion(root_, width_, index, valueHash, peakBag, siblings);
    }

    function fieldMod(bytes32 orderHash) external pure returns (bytes32 orderHashMod) {
        return MMRPoseidon2._fieldMod(orderHash);
    }
}
