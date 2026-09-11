// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IRootVerifier} from "./interfaces/IRootVerifier.sol";
import {BLS} from "./libraries/BLS.sol";
import {BLSKeyRegistry} from "./BLSKeyRegistry.sol";

/// @title CounterpartyVerifier — module C: the at-risk parties authenticate
///        the root by BLS co-signing one both-roots SettlementAuth.
/// @notice `root` is valid iff it equals the auth's root for `sourceChainId`
///         and both parties' aggregate signature over the auth verifies
///         against their registered keys.
contract CounterpartyVerifier is IRootVerifier {
    struct SettlementAuth {
        uint256 orderChainId;
        uint256 adChainId;
        bytes32 orderHash;
        bytes32 orderChainRoot;
        bytes32 adChainRoot;
    }

    /// metadata = abi.encode(settlementSigner, bridger, moduleData): slot 0 is the order's adSettlementSigner.
    /// moduleData = abi.encode(version, auth, signerSlotId, bridgerSlotId, pkSigner, pkBridger, aggSig)
    uint8 public constant METADATA_VERSION = 2;

    bytes32 private constant SETTLE_TAG = keccak256("ProofBridge.Settlement.v1");
    string public constant DST_SIG = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    BLSKeyRegistry public immutable registry;

    constructor(address registry_) {
        registry = BLSKeyRegistry(registry_);
    }

    function isRootValid(uint256 sourceChainId, bytes32 root, bytes calldata metadata) external view returns (bool) {
        (bytes32 settlementSigner, bytes32 bridger, bytes memory moduleData) =
            abi.decode(metadata, (bytes32, bytes32, bytes));
        // Version is the first word; check it before decoding a layout that may not be ours.
        if (!isCurrentVersion(moduleData)) return false;
        (
            ,
            SettlementAuth memory auth,
            uint32 signerSlotId,
            uint32 bridgerSlotId,
            bytes memory pkSigner,
            bytes memory pkBridger,
            bytes memory aggSig
        ) = abi.decode(moduleData, (uint8, SettlementAuth, uint32, uint32, bytes, bytes, bytes));

        if (pkSigner.length != 128 || pkBridger.length != 128 || aggSig.length != 256) return false;

        if (sourceChainId == auth.orderChainId) {
            if (root != auth.orderChainRoot) return false;
        } else if (sourceChainId == auth.adChainId) {
            if (root != auth.adChainRoot) return false;
        } else {
            return false;
        }

        if (
            !commitmentMatches(settlementSigner, signerSlotId, pkSigner)
                || !commitmentMatches(bridger, bridgerSlotId, pkBridger)
        ) {
            return false;
        }
        return verifyAggregate(auth, pkSigner, pkBridger, aggSig);
    }

    function isCurrentVersion(bytes memory moduleData) private pure returns (bool) {
        if (moduleData.length < 32) return false;
        uint256 word;
        assembly {
            word := mload(add(moduleData, 32))
        }
        return word == METADATA_VERSION;
    }

    function verifyAggregate(
        SettlementAuth memory auth,
        bytes memory pkSigner,
        bytes memory pkBridger,
        bytes memory aggSig
    ) private view returns (bool) {
        bytes memory preimage = bytes.concat(
            SETTLE_TAG,
            bytes32(auth.orderChainId),
            bytes32(auth.adChainId),
            auth.orderHash,
            auth.orderChainRoot,
            auth.adChainRoot
        );
        return BLS.verifyAggregate(pkSigner, pkBridger, BLS.hashToG2(preimage, bytes(DST_SIG)), aggSig);
    }

    /// The registry stores keccak commitments; the full keys travel here. A missing,
    /// pruned or expired slot reverts in the registry and fails the root here.
    function commitmentMatches(bytes32 account, uint32 slotId, bytes memory pk) private view returns (bool) {
        try registry.commitmentAt(account, slotId) returns (bytes32 commitment) {
            return commitment == keccak256(pk);
        } catch {
            return false;
        }
    }
}
