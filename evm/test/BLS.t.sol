// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {BLS} from "../src/libraries/BLS.sol";

contract BLSTest is Test {
    using stdJson for string;

    string constant DST_SIG = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    string vectors;

    function setUp() public {
        vectors = vm.readFile("../test-vectors/bls-encodings.json");
    }

    function test_hashToG2_matchesVector() public view {
        bytes memory preimage = vectors.readBytes(".settlement.preimage");
        bytes memory expected = vectors.readBytes(".settlement.msgG2.eip2537");
        assertEq(BLS.hashToG2(preimage, bytes(DST_SIG)), expected);
    }

    function test_singleSignatureVerifies() public view {
        bytes memory msgG2 = vectors.readBytes(".settlement.msgG2.eip2537");
        assertTrue(
            BLS.verifySingle(
                vectors.readBytes(".keys.makerBls.pk.eip2537"), msgG2, vectors.readBytes(".settlement.sigMaker.eip2537")
            )
        );
    }

    function test_aggregateVerifies() public view {
        assertTrue(
            BLS.verifyAggregate(
                vectors.readBytes(".keys.makerBls.pk.eip2537"),
                vectors.readBytes(".keys.bridgerBls.pk.eip2537"),
                vectors.readBytes(".settlement.msgG2.eip2537"),
                vectors.readBytes(".settlement.aggSig.eip2537")
            )
        );
    }

    function test_tamperedMessageFails() public view {
        bytes memory preimage = vectors.readBytes(".settlement.preimage");
        preimage[191] ^= 0x01;
        assertFalse(
            BLS.verifyAggregate(
                vectors.readBytes(".keys.makerBls.pk.eip2537"),
                vectors.readBytes(".keys.bridgerBls.pk.eip2537"),
                BLS.hashToG2(preimage, bytes(DST_SIG)),
                vectors.readBytes(".settlement.aggSig.eip2537")
            )
        );
    }

    function test_singleSigIsNotTheAggregate() public view {
        assertFalse(
            BLS.verifyAggregate(
                vectors.readBytes(".keys.makerBls.pk.eip2537"),
                vectors.readBytes(".keys.bridgerBls.pk.eip2537"),
                vectors.readBytes(".settlement.msgG2.eip2537"),
                vectors.readBytes(".settlement.sigMaker.eip2537")
            )
        );
    }
}
