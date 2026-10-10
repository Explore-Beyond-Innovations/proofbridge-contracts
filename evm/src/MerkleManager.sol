// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {MMRPoseidon2} from "@solidity-mmr/MMRPoseidon2.sol";
import {TwoStepAdmin} from "./libraries/TwoStepAdmin.sol";
import {IMerkleManager} from "./interfaces/IMerkleManager.sol";

/**
 * @title MerkleManager
 * @dev Manages all order hashes for ProofBridge protocol per chain. One admin (`TwoStepAdmin`) keeps
 *      the list of managers that may append: the escrows, and from proof registration's T3 flip the
 *      Registrar. No pause of its own: every escrow path that appends is gated by that escrow's
 *      pause; the Registrar, the one non-escrow appender, has none, and `setManager(registrar,
 *      false)` is its brake.
 */
contract MerkleManager is IMerkleManager, TwoStepAdmin {
    using MMRPoseidon2 for MMRPoseidon2.Tree;

    MMRPoseidon2.Tree _tree;

    // Mapping of width count to roothistory
    mapping(uint256 => bytes32) internal rootHistory;

    /// @notice Who may append: the escrows (and the Registrar once proof registration is on).
    mapping(address => bool) public isManager;

    // Errors
    error MerkleManager__ZeroAddress();
    error MerkleManager__NotManager(address caller);

    event ManagerSet(address indexed account, bool enabled);
    // Self-verifying core; width/size stay readable via the view functions.
    event DepositHashAppended(uint256 indexed index, bytes32 indexed orderHash, uint256 side, bytes32 newRoot);

    modifier onlyManager() {
        if (!isManager[msg.sender]) revert MerkleManager__NotManager(msg.sender);
        _;
    }

    constructor(address admin, address poseidon2Yul) {
        if (admin == address(0) || poseidon2Yul == address(0)) {
            revert MerkleManager__ZeroAddress();
        }
        _initAdmin(admin);
        _tree.setHasher(poseidon2Yul);
    }

    /// @notice Add (`enabled`) or remove an appender. Removing one stops its appends at once.
    function setManager(address account, bool enabled) external onlyAdmin {
        if (account == address(0)) revert MerkleManager__ZeroAddress();
        isManager[account] = enabled;
        emit ManagerSet(account, enabled);
    }

    /**
     * @dev Appends a new deposit order to the tree. The appended leaf is the side-bound value
     * poseidon2(orderHash, side) (see _encodeLeaf). Updates peaks, root, and mappings. Emits DepositHashAppended.
     * @param orderHash The hash of the order to append.
     * @param side The leaf's `ad_contract` - the side it is unlocked on (1 = ad, 0 = order); set by the caller.
     * No reentrancy guard: the only external call is the hasher `staticcall`. Restore one if a
     * non-static external call is ever added to the append path.
     */
    function appendOrderHash(bytes32 orderHash, uint256 side) external onlyManager {
        uint256 leafIndex = _tree.append(_encodeLeaf(orderHash, side));
        bytes32 newRoot = _tree.getRoot();
        uint256 width = _tree.getWidth();

        rootHistory[width] = newRoot;

        emit DepositHashAppended(leafIndex, orderHash, side, newRoot);
    }

    /**
     * @dev Leaf-side binding: value = poseidon2(orderHash mod p, side). `side` is the leaf's `ad_contract` -
     * the side it is unlocked on (1 = ad / 0 = order), NOT the contract that appends it (orders unlock on the
     * ad side, locks on the order side). MUST stay byte-identical to the circuit (`main.nr`) and the SDK
     * `encodeLeaf`, or roots diverge.
     */
    function _encodeLeaf(bytes32 orderHash, uint256 side) private view returns (bytes32) {
        return MMRPoseidon2.hash_2(_tree.hasher, uint256(MMRPoseidon2._fieldMod(orderHash)), side);
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

    /// @notice Debugging helper: one stored MMR node. Not a settlement or recovery path.
    function getNode(uint256 index) external view returns (bytes32) {
        return _tree.getNodeHash(index);
    }

    /**
     * @notice Debugging helper: peak bag + sibling path for the leaf at MMR position `index`, equal to
     * `proofbridge-mmr`'s proof for the same leaves. Not a settlement or recovery path: the relayer
     * builds proofs from its mirror, rebuilt from `DepositHashAppended` events.
     */
    function getMerkleProof(uint256 index)
        external
        view
        returns (bytes32 root_, uint256 width_, bytes32[] memory peakBag, bytes32[] memory siblings)
    {
        return _tree.getMerkleProof(index);
    }

    /**
     * @notice Debugging helper: stateless inclusion check (returns true or reverts). Nothing in the
     * settlement path calls it; real inclusion is checked inside the circuit.
     */
    function verifyInclusionProof(
        bytes32 root_,
        uint256 width_,
        uint256 index,
        bytes32 valueHash,
        bytes32[] calldata peakBag,
        bytes32[] calldata siblings
    ) external view returns (bool) {
        return MMRPoseidon2.verifyInclusion(_tree.hasher, root_, width_, index, valueHash, peakBag, siblings);
    }

    function fieldMod(bytes32 orderHash) external pure returns (bytes32 orderHashMod) {
        return MMRPoseidon2._fieldMod(orderHash);
    }
}
