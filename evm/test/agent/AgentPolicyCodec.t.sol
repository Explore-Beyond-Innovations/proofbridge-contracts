// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {AgentPolicyCodec} from "src/agent/AgentPolicyCodec.sol";

/// @dev `parse` reads `bytes calldata`, so the tests go through a real external call.
contract CodecHarness {
    function parse(bytes calldata policy) external pure returns (AgentPolicyCodec.View memory) {
        return AgentPolicyCodec.parse(policy);
    }

    function row(bytes calldata policy, uint256 i) external pure returns (AgentPolicyCodec.TokenRow memory) {
        return AgentPolicyCodec.tokenRowAt(policy, AgentPolicyCodec.parse(policy), i);
    }

    function action(bytes calldata policy, uint256 i) external pure returns (uint8) {
        return AgentPolicyCodec.actionAt(policy, AgentPolicyCodec.parse(policy), i);
    }

    function adHashes(bytes calldata policy) external pure returns (bytes32[] memory) {
        return AgentPolicyCodec.adScopeHashes(policy, AgentPolicyCodec.parse(policy));
    }

    function decode(bytes calldata policy) external pure returns (AgentPolicyCodec.Decoded memory) {
        return AgentPolicyCodec.decode(policy);
    }

    function fingerprint(bytes calldata policy) external pure returns (bytes32) {
        return keccak256(policy);
    }
}

/// The canonical policy encoding, against the vectors the TypeScript encoder produced.
///
/// This is the one artifact three implementations share — the TS encoder, this parser, and
/// Soroban's policy hash — so the vectors are the oracle rather than anything written here.
contract AgentPolicyCodecTest is Test {
    using stdJson for string;

    CodecHarness internal codec;
    string internal vectors;

    function setUp() public {
        codec = new CodecHarness();
        vectors = vm.readFile("../test-vectors/agent-policy.json");
    }

    function _case(string memory name) internal view returns (bytes memory encoded, bytes32 fingerprint) {
        encoded = vectors.readBytes(string.concat(".cases[?(@.name=='", name, "')].encoded"));
        fingerprint = vectors.readBytes32(string.concat(".cases[?(@.name=='", name, "')].fingerprint"));
    }

    function test_domainIsWhatBothChainsHash() public pure {
        assertEq(AgentPolicyCodec.DOMAIN, keccak256("ProofBridge.AgentPolicy.v1"));
    }

    function test_parsesTheTypeScriptEncoding() public view {
        (bytes memory encoded, bytes32 fingerprint) = _case("every-ad");
        AgentPolicyCodec.View memory v = codec.parse(encoded);

        assertEq(v.actionCount, 1, "one action");
        assertEq(codec.action(encoded, 0), AgentPolicyCodec.ACTION_LOCK_FOR_ORDER);
        assertEq(v.tokenCount, 2, "two tokens");
        assertTrue(v.adScopeAll, "no ad scope means every ad this account owns");
        assertEq(v.adScopeCount, 0);
        assertEq(v.validUntil, 1_800_000_000);
        assertEq(v.settlementSigner, bytes32(hex"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"));

        AgentPolicyCodec.TokenRow memory first = codec.row(encoded, 0);
        assertEq(first.token, bytes32(hex"1111111111111111111111111111111111111111111111111111111111111111"));
        assertEq(first.maxPerOrder, 1_000_000);
        assertEq(first.capacity, 5_000_000);
        assertEq(first.refillPerSecond, 10);

        // The fingerprint is `keccak256` of exactly these bytes: the module hashes what it is
        // handed and never re-encodes, so there is no second encoder here to disagree with.
        assertEq(codec.fingerprint(encoded), fingerprint, "Solidity and TypeScript hash the same bytes");
    }

    function test_theEncoderSorts_soRowOrderIsNotPolicy() public view {
        (bytes memory forward, bytes32 fpForward) = _case("every-ad");
        (bytes memory reversed, bytes32 fpReversed) = _case("unsorted-tokens");
        assertEq(keccak256(forward), keccak256(reversed), "the same policy written two ways");
        assertEq(fpForward, fpReversed);
    }

    function test_scopedPolicyCarriesItsAdsInOrder() public view {
        (bytes memory encoded,) = _case("scoped");
        AgentPolicyCodec.View memory v = codec.parse(encoded);
        assertFalse(v.adScopeAll);
        assertEq(v.adScopeCount, 2);
        bytes32[] memory ads = codec.adHashes(encoded);
        assertEq(ads[0], keccak256("ad-alpha"), "sorted by bytes, not by the order the owner typed");
        assertEq(ads[1], keccak256("ad-zulu"));
    }

    /// `decode` is what the module calls; the piecewise readers are what the rest of this file
    /// tests. They have to be the same parser, on every vector.
    function test_decodeAgreesWithThePiecewiseReaders() public view {
        string[4] memory names = ["every-ad", "scoped", "unsorted-tokens", "u128-ceiling"];
        for (uint256 n = 0; n < names.length; ++n) {
            (bytes memory encoded,) = _case(names[n]);
            AgentPolicyCodec.View memory v = codec.parse(encoded);
            AgentPolicyCodec.Decoded memory d = codec.decode(encoded);

            assertEq(d.settlementSigner, v.settlementSigner, names[n]);
            assertEq(d.validUntil, v.validUntil, names[n]);
            assertEq(d.adScopeAll, v.adScopeAll, names[n]);
            assertEq(d.actions.length, v.actionCount, names[n]);
            for (uint256 i = 0; i < d.actions.length; ++i) {
                assertEq(d.actions[i], codec.action(encoded, i), names[n]);
            }
            assertEq(d.tokens.length, v.tokenCount, names[n]);
            for (uint256 i = 0; i < d.tokens.length; ++i) {
                assertEq(keccak256(abi.encode(d.tokens[i])), keccak256(abi.encode(codec.row(encoded, i))), names[n]);
            }
            assertEq(keccak256(abi.encode(d.adScopeHashes)), keccak256(abi.encode(codec.adHashes(encoded))), names[n]);
        }
    }

    function test_decodeRefusesWhatParseRefuses() public {
        (bytes memory encoded,) = _case("every-ad");
        vm.expectRevert();
        codec.decode(bytes.concat(encoded, hex"00"));
    }

    function test_theWidestLimitBothChainsCanHold() public view {
        (bytes memory encoded,) = _case("u128-ceiling");
        AgentPolicyCodec.TokenRow memory row = codec.row(encoded, 0);
        assertEq(row.capacity, type(uint128).max);
        assertEq(codec.parse(encoded).validUntil, type(uint64).max);
    }

    /*//////////////////////////////////////////////////////////////
                              WHAT IS REFUSED
    //////////////////////////////////////////////////////////////*/

    function test_aForeignDomainIsNotAPolicy() public {
        (bytes memory encoded,) = _case("every-ad");
        encoded[0] = bytes1(uint8(encoded[0]) ^ 0xff);
        vm.expectRevert(AgentPolicyCodec.AgentPolicyCodec__BadDomain.selector);
        codec.parse(encoded);
    }

    function test_trailingBytesAreRefused() public {
        (bytes memory encoded,) = _case("every-ad");
        bytes memory padded = bytes.concat(encoded, hex"00");
        vm.expectRevert();
        codec.parse(padded);
        // ...and so is one byte short, so a parse cannot stop early and call two byte strings the
        // same policy.
        bytes memory short = new bytes(encoded.length - 1);
        for (uint256 i = 0; i < short.length; ++i) {
            short[i] = encoded[i];
        }
        vm.expectRevert();
        codec.parse(short);
    }

    function test_repeatedOrUnsortedTokensAreRefused() public {
        // Two rows naming the same token: `setAgentPolicy` would write one row twice and the owner
        // would believe both took effect.
        bytes memory policy = _twoRows(
            hex"1111111111111111111111111111111111111111111111111111111111111111",
            hex"1111111111111111111111111111111111111111111111111111111111111111"
        );
        vm.expectRevert(AgentPolicyCodec.AgentPolicyCodec__NotAscending.selector);
        codec.parse(policy);

        // Descending is the same failure by another name.
        policy = _twoRows(
            hex"2222222222222222222222222222222222222222222222222222222222222222",
            hex"1111111111111111111111111111111111111111111111111111111111111111"
        );
        vm.expectRevert(AgentPolicyCodec.AgentPolicyCodec__NotAscending.selector);
        codec.parse(policy);
    }

    function test_aLimitSorobanCannotHoldIsRefused() public {
        bytes memory policy = _oneRow(
            hex"1111111111111111111111111111111111111111111111111111111111111111", uint256(type(uint128).max) + 1, 1, 1
        );
        vm.expectRevert(AgentPolicyCodec.AgentPolicyCodec__LimitTooWide.selector);
        codec.parse(policy);
    }

    function test_everyAdWithANonZeroCountIsMalformed() public {
        bytes memory policy = bytes.concat(
            AgentPolicyCodec.DOMAIN,
            hex"01",
            hex"01",
            hex"01",
            hex"1111111111111111111111111111111111111111111111111111111111111111",
            bytes32(uint256(1)),
            bytes32(uint256(1)),
            bytes32(uint256(1)),
            hex"0001", // kind 0 ("every ad") with a count of one
            bytes8(uint64(0)),
            bytes32(0)
        );
        vm.expectRevert(AgentPolicyCodec.AgentPolicyCodec__BadAdScope.selector);
        codec.parse(policy);
    }

    function test_zeroActionsOrZeroTokensAreNotAPolicy() public {
        bytes memory noActions = bytes.concat(AgentPolicyCodec.DOMAIN, hex"00");
        vm.expectRevert();
        codec.parse(noActions);

        bytes memory noTokens = bytes.concat(AgentPolicyCodec.DOMAIN, hex"01", hex"01", hex"00");
        vm.expectRevert();
        codec.parse(noTokens);
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _oneRow(bytes32 token, uint256 maxPerOrder, uint256 capacity, uint256 refill)
        internal
        pure
        returns (bytes memory)
    {
        return bytes.concat(
            AgentPolicyCodec.DOMAIN,
            hex"01",
            hex"01",
            hex"01",
            token,
            bytes32(maxPerOrder),
            bytes32(capacity),
            bytes32(refill),
            hex"0000",
            bytes8(uint64(0)),
            bytes32(0)
        );
    }

    function _twoRows(bytes32 a, bytes32 b) internal pure returns (bytes memory) {
        return bytes.concat(
            AgentPolicyCodec.DOMAIN,
            hex"01",
            hex"01",
            hex"02",
            a,
            bytes32(uint256(1)),
            bytes32(uint256(1)),
            bytes32(uint256(1)),
            b,
            bytes32(uint256(1)),
            bytes32(uint256(1)),
            bytes32(uint256(1)),
            hex"0000",
            bytes8(uint64(0)),
            bytes32(0)
        );
    }
}
