// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {IBLSKeyRegistry} from "../interfaces/IBLSKeyRegistry.sol";

/**
 * @title KeyMessages
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice The owner's key messages, shared by both registries (2.6 plan 13, D1–D4): one signature over
 *         RegisterKey / RevokeKeys / RetireKey names every registry it is for. secp256k1 owners sign the
 *         EIP-712 form, ed25519 owners the fixed text (SEP-53). Byte-identical on Soroban
 *         (`bls-key-registry/src/owner.rs`) and in the bls-encodings package; pinned by the vectors.
 */
library KeyMessages {
    enum Kind {
        Register,
        Revoke,
        Retire
    }

    bytes32 internal constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version)");
    /// No chain id or contract: each leg binds its own (D3).
    bytes32 internal constant DOMAIN_SEPARATOR =
        keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256("ProofBridge Keys"), keccak256("2")));
    bytes32 internal constant KEY_LEG_TYPEHASH = keccak256("KeyLeg(uint256 chainId,bytes32 registry,uint256 nonce)");
    bytes32 internal constant REGISTER_KEY_TYPEHASH = keccak256(
        "RegisterKey(bytes32 account,bytes32 keyCommitment,KeyLeg[] legs)KeyLeg(uint256 chainId,bytes32 registry,uint256 nonce)"
    );
    bytes32 internal constant REVOKE_KEYS_TYPEHASH =
        keccak256("RevokeKeys(bytes32 account,KeyLeg[] legs)KeyLeg(uint256 chainId,bytes32 registry,uint256 nonce)");
    bytes32 internal constant RETIRE_KEY_TYPEHASH =
        keccak256("RetireKey(bytes32 account,bytes32 keyCommitment,uint64 validUntil)");

    /// EIP-712 array encoding: keccak256 of the concatenated element hashes.
    function legsHash(IBLSKeyRegistry.KeyLeg[] calldata legs) internal pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](legs.length);
        for (uint256 i = 0; i < legs.length; i++) {
            hashes[i] = keccak256(abi.encode(KEY_LEG_TYPEHASH, legs[i].chainId, legs[i].registry, legs[i].nonce));
        }
        return keccak256(abi.encodePacked(hashes));
    }

    function structHash(
        Kind kind,
        bytes32 account,
        bytes32 keyCommitment,
        IBLSKeyRegistry.KeyLeg[] calldata legs,
        uint64 validUntil
    ) internal pure returns (bytes32) {
        if (kind == Kind.Register) {
            return keccak256(abi.encode(REGISTER_KEY_TYPEHASH, account, keyCommitment, legsHash(legs)));
        }
        if (kind == Kind.Revoke) return keccak256(abi.encode(REVOKE_KEYS_TYPEHASH, account, legsHash(legs)));
        return keccak256(abi.encode(RETIRE_KEY_TYPEHASH, account, keyCommitment, validUntil));
    }

    /// What a secp256k1 owner signs.
    function digest(
        Kind kind,
        bytes32 account,
        bytes32 keyCommitment,
        IBLSKeyRegistry.KeyLeg[] calldata legs,
        uint64 validUntil
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(hex"1901", DOMAIN_SEPARATOR, structHash(kind, account, keyCommitment, legs, validUntil))
        );
    }

    /// What an ed25519 owner signs (D4): lines joined by "\n", no trailing newline, decimal numbers,
    /// full lowercase 0x hex, legs in the order signed.
    function text(
        Kind kind,
        bytes32 account,
        bytes32 keyCommitment,
        IBLSKeyRegistry.KeyLeg[] calldata legs,
        uint64 validUntil
    ) internal pure returns (bytes memory t) {
        if (kind == Kind.Register) {
            t = "ProofBridge: register a settlement key";
        } else if (kind == Kind.Revoke) {
            t = "ProofBridge: remove every settlement key";
        } else {
            t = "ProofBridge: retire a settlement key";
        }
        t = bytes.concat(t, "\n\nAccount: ", hex32(account));
        if (kind != Kind.Revoke) t = bytes.concat(t, "\nKey fingerprint: ", hex32(keyCommitment));
        t = bytes.concat(t, "\n");
        if (kind == Kind.Retire) {
            return bytes.concat(t, "\nValid until: ", bytes(Strings.toString(validUntil)));
        }
        for (uint256 i = 0; i < legs.length; i++) {
            t = bytes.concat(
                t,
                "\nChain ",
                bytes(Strings.toString(legs[i].chainId)),
                ", registry ",
                hex32(legs[i].registry),
                ", nonce ",
                bytes(Strings.toString(legs[i].nonce))
            );
        }
    }

    /// Lowercase "0x" + 64 hex.
    function hex32(bytes32 b) internal pure returns (bytes memory out) {
        bytes16 alphabet = "0123456789abcdef";
        out = new bytes(66);
        out[0] = "0";
        out[1] = "x";
        for (uint256 i = 0; i < 32; i++) {
            out[2 + i * 2] = alphabet[uint8(b[i]) >> 4];
            out[3 + i * 2] = alphabet[uint8(b[i]) & 0x0f];
        }
    }
}
