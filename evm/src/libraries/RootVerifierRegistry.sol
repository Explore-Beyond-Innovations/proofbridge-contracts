// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IRootVerifier} from "../interfaces/IRootVerifier.sol";

/// @title RootVerifierRegistry — per-source-chain verification-module wiring.
/// @notice Inherited by the unlock contracts; the admin gating of
///         `_setRootVerifier` belongs to the inheritor.
abstract contract RootVerifierRegistry {
    mapping(uint256 => IRootVerifier) public rootVerifier;

    event RootVerifierSet(uint256 indexed chainId, address verifier);

    error NoRootVerifier(uint256 chainId);
    error RootNotValid(uint256 chainId, bytes32 root);

    function _setRootVerifier(uint256 chainId, address verifier) internal {
        rootVerifier[chainId] = IRootVerifier(verifier);
        emit RootVerifierSet(chainId, verifier);
    }

    function _requireRootValid(uint256 chainId, bytes32 root, bytes memory metadata) internal view {
        IRootVerifier v = rootVerifier[chainId];
        if (address(v) == address(0)) revert NoRootVerifier(chainId);
        if (!v.isRootValid(chainId, root, metadata)) revert RootNotValid(chainId, root);
    }
}
