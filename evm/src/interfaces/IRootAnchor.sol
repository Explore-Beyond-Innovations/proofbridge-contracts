// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/// @title IRootAnchor — the authenticator for unilateral-event proofs (2.3f).
/// @notice A consumer (the follower refund, proof-carried registration) asks one question: is this
///         root of the source chain notarized and past its delay? It never learns who signs, which
///         is what lets the writer be swapped up the ladder without touching the consumers.
///         `anchoredAt` lets a consumer that needs a longer age than the route's delay apply its own.
interface IRootAnchor {
    function isAnchored(uint256 sourceChainId, bytes32 root) external view returns (bool);
    /// @return The timestamp the root reached the threshold, or 0 if it is not anchored.
    function anchoredAt(uint256 sourceChainId, bytes32 root) external view returns (uint64);
}
