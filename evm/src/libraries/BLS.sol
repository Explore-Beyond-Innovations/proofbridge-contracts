// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/// @title BLS12-381 helpers over the EIP-2537 precompiles.
/// @notice Min-pubkey mode: pubkeys G1 (128 B), signatures G2 (256 B).
///         hash-to-G2 per RFC 9380 (BLS12381G2_XMD:SHA-256_SSWU_RO).
library BLS {
    address internal constant G2_ADD = address(0x0d);
    address internal constant PAIRING = address(0x0f);
    address internal constant MAP_FP2_TO_G2 = address(0x11);
    address internal constant SHA256_PC = address(0x02);
    address internal constant MODEXP = address(0x05);

    /// Base field modulus p, split into two 32-byte words (48-byte value).
    bytes internal constant FP_MODULUS =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

    /// -G1 generator, EIP-2537 encoding.
    bytes internal constant NEG_G1 =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";

    error BlsPrecompileFailed();

    /// e(pk, H(msg)) == e(G1, sig) ⇔ pairing([pk, H(msg)], [-G1, sig]) == 1.
    /// `pk` 128 B, `sig` 256 B, both EIP-2537-encoded; the precompile
    /// subgroup-checks every input.
    function verifySingle(bytes memory pk, bytes memory msgG2, bytes memory sig) internal view returns (bool) {
        bytes memory input = bytes.concat(pk, msgG2, NEG_G1, sig);
        (bool ok, bytes memory out) = PAIRING.staticcall(input);
        if (!ok || out.length != 32) revert BlsPrecompileFailed();
        return out[31] == 0x01;
    }

    /// Same equation with an aggregate key: e(pkA + pkB, H(msg)) == e(G1, aggSig).
    /// Three pairs so the precompile subgroup-checks pkA and pkB individually.
    function verifyAggregate(bytes memory pkA, bytes memory pkB, bytes memory msgG2, bytes memory aggSig)
        internal
        view
        returns (bool)
    {
        bytes memory input = bytes.concat(pkA, msgG2, pkB, msgG2, NEG_G1, aggSig);
        (bool ok, bytes memory out) = PAIRING.staticcall(input);
        if (!ok || out.length != 32) revert BlsPrecompileFailed();
        return out[31] == 0x01;
    }

    /// RFC 9380 hash_to_curve for G2: expand_message_xmd(SHA-256) into two
    /// Fp2 elements, map each with the precompile (cofactor cleared), add.
    /// Returns the 256-byte EIP-2537 G2 point.
    function hashToG2(bytes memory message, bytes memory dst) internal view returns (bytes memory) {
        bytes memory uniform = expandMsgXmd(message, dst, 256);

        bytes memory fp2a = bytes.concat(reduceFp(slice64(uniform, 0)), reduceFp(slice64(uniform, 64)));
        bytes memory fp2b = bytes.concat(reduceFp(slice64(uniform, 128)), reduceFp(slice64(uniform, 192)));

        (bool okA, bytes memory pA) = MAP_FP2_TO_G2.staticcall(fp2a);
        (bool okB, bytes memory pB) = MAP_FP2_TO_G2.staticcall(fp2b);
        if (!okA || !okB) revert BlsPrecompileFailed();

        (bool okAdd, bytes memory point) = G2_ADD.staticcall(bytes.concat(pA, pB));
        if (!okAdd || point.length != 256) revert BlsPrecompileFailed();
        return point;
    }

    /// expand_message_xmd (RFC 9380 §5.3.1) with SHA-256, lenInBytes ≤ 8 * 32.
    function expandMsgXmd(bytes memory message, bytes memory dst, uint16 lenInBytes)
        internal
        pure
        returns (bytes memory out)
    {
        uint256 ell = (uint256(lenInBytes) + 31) / 32;
        bytes memory dstPrime = bytes.concat(dst, bytes1(uint8(dst.length)));
        bytes memory zPad = new bytes(64); // SHA-256 block size

        bytes32 b0 = sha256(bytes.concat(zPad, message, bytes2(lenInBytes), bytes1(0), dstPrime));
        bytes32 bi = sha256(bytes.concat(b0, bytes1(uint8(1)), dstPrime));

        out = bytes.concat(bi);
        for (uint256 i = 2; i <= ell; i++) {
            bi = sha256(bytes.concat(b0 ^ bi, bytes1(uint8(i)), dstPrime));
            out = bytes.concat(out, bi);
        }
        assembly {
            mstore(out, lenInBytes)
        }
    }

    /// Reduce a 64-byte big-endian integer mod p via the modexp precompile
    /// (exponent 1), returning the 64-byte padded Fp the G2 precompiles take.
    function reduceFp(bytes memory value64) internal view returns (bytes memory) {
        bytes memory input =
            bytes.concat(abi.encode(uint256(64), uint256(1), uint256(48)), value64, bytes1(0x01), FP_MODULUS);
        (bool ok, bytes memory out) = MODEXP.staticcall(input);
        if (!ok || out.length != 48) revert BlsPrecompileFailed();
        return bytes.concat(bytes16(0), out);
    }

    function slice64(bytes memory data, uint256 offset) private pure returns (bytes memory out) {
        out = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            out[i] = data[offset + i];
        }
    }
}
