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
        /// #469: keccak256 of the maker key's EIP-2537 encoding — the one maker key this message pairs with.
        bytes32 makerKeyCommitment;
        /// The nullifier the ad leg's unlock consumes (`poseidon2(a, orderHash % p)`).
        bytes32 adLegNullifier;
        /// The nullifier the order leg's unlock consumes (`poseidon2(orderHash % p, b)`).
        bytes32 orderLegNullifier;
    }

    /// metadata = abi.encode(settlementSigner, bridger, orderHash, pinnedSlot, nullifierHash, side, moduleData):
    /// what the escrow vouches for. Slot 0 is the order's adSettlementSigner; orderHash is the order being
    /// unlocked (#433); nullifierHash and side are the nullifier the escrow is about to consume and its leg.
    /// moduleData = abi.encode(version, auth, signerSlotId, bridgerSlotId, pkSigner, pkBridger, aggSig);
    /// v4's auth names the maker key (#469) and each leg's nullifier.
    uint8 public constant METADATA_VERSION = 4;

    /// The escrow's leg: `AdManager` consumes the AD leaf (side 1), `OrderPortal` the ORDER leaf (side 0).
    uint8 private constant SIDE_ORDER = 0;
    uint8 private constant SIDE_AD = 1;
    /// The order leg's envelope pin: no slot pinned (the auth's named maker key binds it).
    uint32 private constant UNPINNED = type(uint32).max;

    bytes32 private constant SETTLE_TAG = keccak256("ProofBridge.Settlement.v1");
    string public constant DST_SIG = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    BLSKeyRegistry public immutable registry;

    constructor(address registry_) {
        registry = BLSKeyRegistry(registry_);
    }

    /// What the escrow vouches for, decoded from the metadata's head.
    struct Envelope {
        bytes32 settlementSigner;
        bytes32 bridger;
        bytes32 orderHash;
        uint32 pinnedSlot;
        bytes32 nullifierHash;
        uint8 side;
        bytes moduleData;
    }

    function isRootValid(uint256 sourceChainId, bytes32 root, bytes calldata metadata) external view returns (bool) {
        Envelope memory e = decodeEnvelope(metadata);
        // Version is the first word; check it before decoding a layout that may not be ours.
        if (!isCurrentVersion(e.moduleData)) return false;
        (
            ,
            SettlementAuth memory auth,
            uint32 signerSlotId,
            uint32 bridgerSlotId,
            bytes memory pkSigner,
            bytes memory pkBridger,
            bytes memory aggSig
        ) = abi.decode(e.moduleData, (uint8, SettlementAuth, uint32, uint32, bytes, bytes, bytes));

        if (pkSigner.length != 128 || pkBridger.length != 128 || aggSig.length != 256) return false;
        // #433: the parties co-signed one order. A signature over another order between the same two
        // parties, under the same roots, is not consent to this one.
        if (auth.orderHash != e.orderHash) return false;
        if (!legMatches(auth, sourceChainId, root, e.side, e.nullifierHash)) return false;
        // Plan 12 C: on the ad leg the lock pinned the maker's co-signing slot; only that slot's key
        // settles there. The order leg sends the unpinned sentinel and is bound by the named key below.
        if (e.pinnedSlot != UNPINNED && signerSlotId != e.pinnedSlot) return false;

        if (
            !commitmentMatches(e.settlementSigner, signerSlotId, pkSigner)
                || !commitmentMatches(e.bridger, bridgerSlotId, pkBridger)
        ) {
            return false;
        }
        // #469: the bridger signed for one maker key. The bridger's half aggregated with any other
        // live key of the maker's is a valid pairing but not consent; only the named key settles.
        if (auth.makerKeyCommitment != keccak256(pkSigner)) return false;
        return verifyAggregate(auth, pkSigner, pkBridger, aggSig);
    }

    function decodeEnvelope(bytes calldata metadata) private pure returns (Envelope memory e) {
        (e.settlementSigner, e.bridger, e.orderHash, e.pinnedSlot, e.nullifierHash, e.side, e.moduleData) =
            abi.decode(metadata, (bytes32, bytes32, bytes32, uint32, bytes32, uint8, bytes));
    }

    /// The escrow's side picks the leg: its source chain, its root and the nullifier the parties
    /// signed for it. A side that disagrees with the root it names, or any other nullifier, fails.
    function legMatches(
        SettlementAuth memory auth,
        uint256 sourceChainId,
        bytes32 root,
        uint8 side,
        bytes32 nullifierHash
    ) private pure returns (bool) {
        if (side == SIDE_AD) {
            return sourceChainId == auth.orderChainId && root == auth.orderChainRoot
                && nullifierHash == auth.adLegNullifier;
        }
        if (side == SIDE_ORDER) {
            return
                sourceChainId == auth.adChainId && root == auth.adChainRoot && nullifierHash == auth.orderLegNullifier;
        }
        return false;
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
            auth.adChainRoot,
            auth.makerKeyCommitment,
            auth.adLegNullifier,
            auth.orderLegNullifier
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
