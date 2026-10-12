// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {IBLSKeyRegistry} from "../interfaces/IBLSKeyRegistry.sol";

/**
 * @title KeyMessages
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice The owner's key messages, shared by both registries (2.6 plan 13, D1–D4): one signature over
 *         RegisterKey / RevokeKeys / RetireKey / ApproveMaker / RepinOrder names every registry it is for. secp256k1 owners sign the
 *         EIP-712 form, ed25519 owners the fixed text (SEP-53). Byte-identical on Soroban
 *         (`bls-key-registry/src/owner.rs`) and in the bls-encodings package; pinned by the vectors.
 */
library KeyMessages {
    enum Kind {
        Register,
        Revoke,
        Retire,
        Cancel,
        ApproveMaker,
        Repin
    }

    bytes32 internal constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,bytes32 salt)");
    bytes32 internal constant KEY_LEG_TYPEHASH = keccak256("KeyLeg(uint256 chainId,bytes32 registry,uint256 nonce)");
    bytes32 internal constant REGISTER_KEY_TYPEHASH = keccak256(
        "RegisterKey(bytes32 account,bytes32 keyCommitment,KeyLeg[] legs,uint64 deadline)KeyLeg(uint256 chainId,bytes32 registry,uint256 nonce)"
    );
    bytes32 internal constant REVOKE_KEYS_TYPEHASH =
        keccak256("RevokeKeys(bytes32 account,KeyLeg[] legs)KeyLeg(uint256 chainId,bytes32 registry,uint256 nonce)");
    /// Review D2: moves the nonce and nothing else, so a pending registration dies and live keys stay.
    bytes32 internal constant CANCEL_PENDING_TYPEHASH =
        keccak256("CancelPending(bytes32 account,KeyLeg[] legs)KeyLeg(uint256 chainId,bytes32 registry,uint256 nonce)");
    bytes32 internal constant RETIRE_KEY_TYPEHASH =
        keccak256("RetireKey(bytes32 account,bytes32 keyCommitment,uint64 validUntil)");
    /// The account lets `maker` name it as an ad's settlement signer (`approved`), or withdraws that.
    bytes32 internal constant APPROVE_MAKER_TYPEHASH = keccak256(
        "ApproveMaker(bytes32 account,bytes32 maker,bool approved,KeyLeg[] legs,uint64 deadline)KeyLeg(uint256 chainId,bytes32 registry,uint256 nonce)"
    );

    /// The settlement signer moves an open order's co-signing pin from `fromSlot` to `toSlot`
    /// (the escrow applies it; 2.7 plan 12 D12).
    bytes32 internal constant REPIN_ORDER_TYPEHASH = keccak256(
        "RepinOrder(bytes32 account,bytes32 orderHash,uint32 fromSlot,uint32 toSlot,KeyLeg[] legs)KeyLeg(uint256 chainId,bytes32 registry,uint256 nonce)"
    );

    /// Review D3: the salt binds the environment the registry was deployed for.
    function salt(string memory env) internal pure returns (bytes32) {
        return keccak256(bytes.concat("proofbridge:", bytes(env)));
    }

    /// No chain id or contract (each leg binds its own); the salt binds the environment.
    function domainSeparator(bytes32 envSalt) internal pure returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256("ProofBridge Keys"), keccak256("2"), envSalt));
    }

    /// EIP-712 array encoding: keccak256 of the concatenated element hashes.
    function legsHash(IBLSKeyRegistry.KeyLeg[] calldata legs) internal pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](legs.length);
        for (uint256 i = 0; i < legs.length; i++) {
            hashes[i] = keccak256(abi.encode(KEY_LEG_TYPEHASH, legs[i].chainId, legs[i].registry, legs[i].nonce));
        }
        return keccak256(abi.encodePacked(hashes));
    }

    /// `time` is the register / approval deadline or the retirement's validUntil; revoke ignores it;
    /// a re-pin packs `fromSlot << 32 | toSlot` into it. `subject` is the key fingerprint, the maker
    /// for ApproveMaker, or the order hash for a re-pin; only ApproveMaker reads `approved`.
    function structHash(
        Kind kind,
        bytes32 account,
        bytes32 subject,
        IBLSKeyRegistry.KeyLeg[] calldata legs,
        uint64 time,
        bool approved
    ) internal pure returns (bytes32) {
        if (kind == Kind.ApproveMaker) {
            return keccak256(abi.encode(APPROVE_MAKER_TYPEHASH, account, subject, approved, legsHash(legs), time));
        }
        if (kind == Kind.Repin) {
            return keccak256(
                abi.encode(REPIN_ORDER_TYPEHASH, account, subject, uint32(time >> 32), uint32(time), legsHash(legs))
            );
        }
        if (kind == Kind.Register) {
            return keccak256(abi.encode(REGISTER_KEY_TYPEHASH, account, subject, legsHash(legs), time));
        }
        if (kind == Kind.Revoke) return keccak256(abi.encode(REVOKE_KEYS_TYPEHASH, account, legsHash(legs)));
        if (kind == Kind.Cancel) return keccak256(abi.encode(CANCEL_PENDING_TYPEHASH, account, legsHash(legs)));
        return keccak256(abi.encode(RETIRE_KEY_TYPEHASH, account, subject, time));
    }

    /// What a secp256k1 owner signs.
    function digest(
        bytes32 separator,
        Kind kind,
        bytes32 account,
        bytes32 subject,
        IBLSKeyRegistry.KeyLeg[] calldata legs,
        uint64 time,
        bool approved
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(hex"1901", separator, structHash(kind, account, subject, legs, time, approved))
        );
    }

    /// What an ed25519 owner signs (D4 + review D2/D3): lines joined by "\n", no trailing newline,
    /// decimal numbers, full lowercase 0x hex, legs in the order signed.
    function text(
        bytes memory env,
        Kind kind,
        bytes32 account,
        bytes32 subject,
        IBLSKeyRegistry.KeyLeg[] calldata legs,
        uint64 time,
        bool approved
    ) internal pure returns (bytes memory t) {
        if (kind == Kind.ApproveMaker) {
            t = approved
                ? bytes("ProofBridge: allow a maker to name this account as settlement signer")
                : bytes("ProofBridge: withdraw a maker's permission to name this account as settlement signer");
        } else if (kind == Kind.Register) {
            t = "ProofBridge: register a settlement key";
        } else if (kind == Kind.Revoke) {
            t = "ProofBridge: remove every settlement key";
        } else if (kind == Kind.Cancel) {
            t = "ProofBridge: cancel a pending key registration";
        } else if (kind == Kind.Repin) {
            t = "ProofBridge: move an order's settlement key to another slot";
        } else {
            t = "ProofBridge: retire a settlement key";
        }
        t = bytes.concat(t, "\n\nNetwork: ", env, "\nAccount: ", hex32(account));
        if (kind == Kind.Register || kind == Kind.Retire) {
            t = bytes.concat(t, "\nKey fingerprint: ", hex32(subject));
        } else if (kind == Kind.ApproveMaker) {
            t = bytes.concat(t, "\nMaker: ", hex32(subject));
        } else if (kind == Kind.Repin) {
            t = bytes.concat(
                t,
                "\nOrder: ",
                hex32(subject),
                "\nFrom slot: ",
                bytes(Strings.toString(uint32(time >> 32))),
                "\nTo slot: ",
                bytes(Strings.toString(uint32(time)))
            );
        }
        if (kind == Kind.Register || kind == Kind.ApproveMaker) {
            t = bytes.concat(t, "\nValid until: ", utc(time), " (", bytes(Strings.toString(time)), ")");
        }
        t = bytes.concat(t, "\n");
        if (kind == Kind.Retire) {
            return bytes.concat(t, "\nValid until: ", bytes(Strings.toString(time)));
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

    /// Unix seconds as "YYYY-MM-DD HH:MM:SS UTC" (civil-from-days, the same arithmetic as bls-encodings).
    function utc(uint256 t) internal pure returns (bytes memory) {
        uint256 sod = t % 86400;
        return bytes.concat(
            date(t / 86400), " ", pad(sod / 3600, 2), ":", pad((sod % 3600) / 60, 2), ":", pad(sod % 60, 2), " UTC"
        );
    }

    function date(uint256 days_) private pure returns (bytes memory) {
        uint256 z = days_ + 719468;
        uint256 era = z / 146097;
        uint256 doe = z - era * 146097;
        uint256 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        uint256 doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        uint256 mp = (5 * doy + 2) / 153;
        uint256 mo = mp < 10 ? mp + 3 : mp - 9;
        return bytes.concat(
            pad(yoe + era * 400 + (mo <= 2 ? 1 : 0), 4), "-", pad(mo, 2), "-", pad(doy - (153 * mp + 2) / 5 + 1, 2)
        );
    }

    /// Decimal, zero-padded to at least `width` digits.
    function pad(uint256 v, uint256 width) internal pure returns (bytes memory out) {
        out = bytes(Strings.toString(v));
        while (out.length < width) out = bytes.concat("0", out);
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
