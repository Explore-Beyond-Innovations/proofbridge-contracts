// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/**
 * @title IRootAnchor — the notary for unilateral-event proofs (2.3f).
 * @notice A signer set attests "the source chain's MMR root was `root` at ledger `ledgerSeq`"; the
 *         anchor becomes usable `anchorDelay[chainId]` later. Consumers only ever call `isAnchored`
 *         (and `anchoredAt` when they need a longer age); the writer is swapped up the ladder with
 *         `setSigners`, never by redeploying.
 */
interface IRootAnchor {
    struct Anchor {
        uint64 ledgerSeq;
        uint64 anchoredAt;
        uint32 approvals;
        uint32 setEpoch;
        uint32 gen;
    }

    event AnchorApproved(uint256 indexed chainId, bytes32 indexed root, address indexed signer, uint32 approvals);
    event Anchored(uint256 indexed chainId, bytes32 indexed root, uint64 ledgerSeq, uint64 anchoredAt);
    event AnchorRevoked(uint256 indexed chainId, bytes32 indexed root, uint32 gen);
    event SignersSet(address[] signers, uint32 threshold, uint32 epoch);
    event AnchorDelaySet(uint256 indexed chainId, uint64 delay);
    event MonotonicSet(bool monotonic);
    event LatestSeqReset(uint256 indexed chainId, uint64 seq);

    error RootAnchor__ZeroAddress();
    error RootAnchor__NotSigner();
    error RootAnchor__BadThreshold();
    error RootAnchor__DuplicateSigner(address signer);
    error RootAnchor__SeqNotMonotonic(uint64 latest, uint64 given);
    error RootAnchor__DelayTooLong(uint64 max, uint64 given);
    error RootAnchor__NoSuchAnchor();

    // consumer surface
    function isAnchored(uint256 sourceChainId, bytes32 root) external view returns (bool);
    /// @notice When the root reached its threshold; 0 when not anchored.
    function anchoredAt(uint256 sourceChainId, bytes32 root) external view returns (uint64);

    // notary
    function anchor(uint256 sourceChainId, bytes32 root, uint64 ledgerSeq) external;

    // admin
    function setSigners(address[] calldata signers_, uint32 threshold_) external;
    function revokeAnchor(uint256 sourceChainId, bytes32 root) external;
    function resetLatestSeq(uint256 sourceChainId, uint64 seq) external;
    function setAnchorDelay(uint256 sourceChainId, uint64 delay) external;
    function setMonotonic(bool monotonic_) external;
    function pause() external;
    function unpause() external;

    // views
    function anchorOf(uint256 sourceChainId, bytes32 root) external view returns (Anchor memory);
    function signers() external view returns (address[] memory);
    function isSigner(address account) external view returns (bool);
    function threshold() external view returns (uint32);
    function signerSetEpoch() external view returns (uint32);
    function anchorDelay(uint256 sourceChainId) external view returns (uint64);
    function monotonic() external view returns (bool);
    function latestSeq(uint256 sourceChainId) external view returns (uint64);
}
