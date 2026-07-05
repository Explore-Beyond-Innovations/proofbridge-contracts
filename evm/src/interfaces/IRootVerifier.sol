// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/// @title IRootVerifier — the pluggable root-authentication seam.
/// @notice Unlock asks "is this root authentic for this source chain?" and
///         hands the module an opaque, module-specific metadata blob.
interface IRootVerifier {
    function isRootValid(uint256 sourceChainId, bytes32 root, bytes calldata metadata) external view returns (bool);
}
