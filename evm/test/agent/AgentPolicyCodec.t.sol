// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {AgentPolicyCodec, IAgentPolicyCodecErrors} from "src/agent/AgentPolicyCodec.sol";
import {ProofBridgeAgentPolicy} from "src/agent/ProofBridgeAgentPolicy.sol";

/// @dev `parse` reads `bytes calldata`, so the tests go through a real external call.
contract CodecHarness {
    function parse(bytes calldata policy) external pure returns (AgentPolicyCodec.View memory) {
        return AgentPolicyCodec.parse(policy);
    }

    function row(bytes calldata policy, uint256 i) external pure returns (AgentPolicyCodec.TokenRow memory) {
        return AgentPolicyCodec.tokenRowAt(policy, AgentPolicyCodec.parse(policy), i);
    }

    function orderToken(bytes calldata policy, uint256 i) external pure returns (bytes32) {
        return AgentPolicyCodec.orderTokenAt(policy, AgentPolicyCodec.parse(policy), i);
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
/// The TypeScript encoder and this parser must agree on these bytes (Soroban publishes the fields and
/// the fingerprint is computed off chain), so the vectors are the oracle rather than anything here.
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
        assertEq(AgentPolicyCodec.DOMAIN, keccak256("ProofBridge.AgentPolicy.v3"));
    }

    function test_parsesTheTypeScriptEncoding() public view {
        (bytes memory encoded, bytes32 fingerprint) = _case("every-ad");
        AgentPolicyCodec.View memory v = codec.parse(encoded);

        assertEq(v.actionId, AgentPolicyCodec.ACTION_LOCK_FOR_ORDER, "the one action");
        assertEq(v.tokenCount, 2, "two ad tokens");
        assertEq(v.orderTokenCount, 2, "two order tokens");
        // A token may sit in both lists: 0x11.. is an ad token and an order token.
        assertEq(
            codec.orderToken(encoded, 0), bytes32(hex"1111111111111111111111111111111111111111111111111111111111111111")
        );
        assertEq(
            codec.orderToken(encoded, 1), bytes32(hex"3333333333333333333333333333333333333333333333333333333333333333")
        );
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
            assertEq(d.actionId, v.actionId, names[n]);
            assertEq(d.adTokens.length, v.tokenCount, names[n]);
            for (uint256 i = 0; i < d.adTokens.length; ++i) {
                assertEq(keccak256(abi.encode(d.adTokens[i])), keccak256(abi.encode(codec.row(encoded, i))), names[n]);
            }
            assertEq(d.orderTokens.length, v.orderTokenCount, names[n]);
            for (uint256 i = 0; i < d.orderTokens.length; ++i) {
                assertEq(d.orderTokens[i], codec.orderToken(encoded, i), names[n]);
            }
            assertEq(keccak256(abi.encode(d.adScopeHashes)), keccak256(abi.encode(codec.adHashes(encoded))), names[n]);
        }
    }

    function test_decodeRefusesWhatParseRefuses() public {
        (bytes memory encoded,) = _case("every-ad");

        vm.expectRevert(
            abi.encodeWithSelector(
                IAgentPolicyCodecErrors.AgentPolicyCodec__TrailingBytes.selector, encoded.length + 1, encoded.length
            )
        );
        codec.decode(bytes.concat(encoded, hex"00"));

        bytes memory foreign = bytes.concat(encoded);
        foreign[0] = ~foreign[0];
        vm.expectRevert(IAgentPolicyCodecErrors.AgentPolicyCodec__BadDomain.selector);
        codec.decode(foreign);

        vm.expectRevert(IAgentPolicyCodecErrors.AgentPolicyCodec__NotAscending.selector);
        codec.decode(_twoRows(bytes32(uint256(2)), bytes32(uint256(1))));
    }

    /// The module reaches the parser by DELEGATECALL, so the parser's errors come back out of
    /// `setAgentPolicy` — and a client decodes those with the *module's* ABI. Every error the
    /// library can raise has to be in it; one declared in the library alone would not be.
    function test_theModulesAbiCarriesEveryParserError() public view {
        // Forge is asked where it put the artifacts for the code it just compiled, so a build into
        // another directory fails on the read permission instead of quietly reading a stale `out/`.
        string memory lib = vm.readFile(vm.getArtifactPathByCode(vm.getCode("AgentPolicyCodec.sol:AgentPolicyCodec")));
        string memory mod = vm.readFile(vm.getArtifactPathByCode(type(ProofBridgeAgentPolicy).creationCode));
        string[] memory raised = _errorNames(lib);
        string[] memory known = _errorNames(mod);

        assertGt(raised.length, 0, "the library raises errors; an empty list means the read is wrong");
        for (uint256 i = 0; i < raised.length; ++i) {
            bool found;
            for (uint256 j = 0; j < known.length && !found; ++j) {
                found = keccak256(bytes(known[j])) == keccak256(bytes(raised[i]));
            }
            assertTrue(found, string.concat(raised[i], " is not in the module's ABI"));
        }
    }

    function _errorNames(string memory artifact) internal view returns (string[] memory names) {
        string[] memory all = new string[](256);
        uint256 n;
        for (uint256 i = 0; vm.keyExistsJson(artifact, string.concat(".abi[", vm.toString(i), "]")); ++i) {
            string memory at = string.concat(".abi[", vm.toString(i), "]");
            if (keccak256(bytes(artifact.readString(string.concat(at, ".type")))) != keccak256("error")) continue;
            all[n++] = artifact.readString(string.concat(at, ".name"));
        }
        names = new string[](n);
        for (uint256 i = 0; i < n; ++i) {
            names[i] = all[i];
        }
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
        vm.expectRevert(IAgentPolicyCodecErrors.AgentPolicyCodec__BadDomain.selector);
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
        vm.expectRevert(IAgentPolicyCodecErrors.AgentPolicyCodec__NotAscending.selector);
        codec.parse(policy);

        // Descending is the same failure by another name.
        policy = _twoRows(
            hex"2222222222222222222222222222222222222222222222222222222222222222",
            hex"1111111111111111111111111111111111111111111111111111111111111111"
        );
        vm.expectRevert(IAgentPolicyCodecErrors.AgentPolicyCodec__NotAscending.selector);
        codec.parse(policy);
    }

    function test_aLimitSorobanCannotHoldIsRefused() public {
        bytes memory policy = _oneRow(
            hex"1111111111111111111111111111111111111111111111111111111111111111", uint256(type(uint128).max) + 1, 1, 1
        );
        vm.expectRevert(IAgentPolicyCodecErrors.AgentPolicyCodec__LimitTooWide.selector);
        codec.parse(policy);
    }

    function test_everyAdWithANonZeroCountIsMalformed() public {
        bytes memory policy = bytes.concat(
            _head(_row(T1, 1, 1, 1), 1, bytes.concat(T2), 1),
            hex"0001", // kind 0 ("every ad") with a count of one
            bytes8(uint64(0)),
            bytes32(0)
        );
        vm.expectRevert(IAgentPolicyCodecErrors.AgentPolicyCodec__BadAdScope.selector);
        codec.parse(policy);
    }

    function test_anyActionButLockForOrderIsRefused() public {
        for (uint256 id = 0; id < 256; ++id) {
            if (id == AgentPolicyCodec.ACTION_LOCK_FOR_ORDER) continue;
            bytes memory policy = _policy(_row(T1, 1, 1, 1), 1, bytes.concat(T2), 1);
            policy[32] = bytes1(uint8(id));
            vm.expectRevert(
                abi.encodeWithSelector(IAgentPolicyCodecErrors.AgentPolicyCodec__UnknownAction.selector, id)
            );
            codec.parse(policy);
        }
    }

    function test_zeroAdTokensAreNotAPolicy() public {
        bytes memory noTokens = bytes.concat(AgentPolicyCodec.DOMAIN, hex"01", hex"00");
        vm.expectRevert(abi.encodeWithSelector(IAgentPolicyCodecErrors.AgentPolicyCodec__BadTokenCount.selector, 0));
        codec.parse(noTokens);
    }

    /*//////////////////////////////////////////////////////////////
                            THE ORDER-TOKEN LIST
    //////////////////////////////////////////////////////////////*/

    function test_emptyOrderTokensAreRefused() public {
        bytes memory policy = _policy(_row(T1, 1, 1, 1), 1, "", 0);
        vm.expectRevert(
            abi.encodeWithSelector(IAgentPolicyCodecErrors.AgentPolicyCodec__BadOrderTokenCount.selector, 0)
        );
        codec.parse(policy);
    }

    function test_moreThanSixteenOrderTokensAreRefused() public {
        bytes memory list;
        for (uint256 i = 1; i <= 17; ++i) {
            list = bytes.concat(list, bytes32(i));
        }
        bytes memory policy = _policy(_row(T1, 1, 1, 1), 1, list, 17);
        vm.expectRevert(
            abi.encodeWithSelector(IAgentPolicyCodecErrors.AgentPolicyCodec__BadOrderTokenCount.selector, 17)
        );
        codec.parse(policy);

        // sixteen is the bound, and parses
        list = "";
        for (uint256 i = 1; i <= 16; ++i) {
            list = bytes.concat(list, bytes32(i));
        }
        assertEq(codec.parse(_policy(_row(T1, 1, 1, 1), 1, list, 16)).orderTokenCount, 16);
    }

    function test_unsortedOrRepeatedOrderTokensAreRefused() public {
        vm.expectRevert(IAgentPolicyCodecErrors.AgentPolicyCodec__NotAscending.selector);
        codec.parse(_policy(_row(T1, 1, 1, 1), 1, bytes.concat(T2, T1), 2));

        vm.expectRevert(IAgentPolicyCodecErrors.AgentPolicyCodec__NotAscending.selector);
        codec.parse(_policy(_row(T1, 1, 1, 1), 1, bytes.concat(T2, T2), 2));
    }

    function test_aZeroTokenIsRefusedInEitherList() public {
        vm.expectRevert(IAgentPolicyCodecErrors.AgentPolicyCodec__ZeroToken.selector);
        codec.parse(_policy(_row(T1, 1, 1, 1), 1, bytes.concat(bytes32(0), T2), 2));

        vm.expectRevert(IAgentPolicyCodecErrors.AgentPolicyCodec__ZeroToken.selector);
        codec.parse(_policy(_row(bytes32(0), 1, 1, 1), 1, bytes.concat(T2), 1));
    }

    function test_aTokenMayBeInBothLists() public view {
        AgentPolicyCodec.View memory v = codec.parse(_policy(_row(T1, 1, 1, 1), 1, bytes.concat(T1), 1));
        assertEq(v.tokenCount, 1);
        assertEq(v.orderTokenCount, 1);
    }

    /// A v1 byte string (`01 01 01 …`: one action, id 1, one token row) under its own domain is
    /// not a v3 policy, even though its first bytes after the domain would read as a valid start.
    function test_aV1PolicyIsRefused() public {
        bytes memory v1 = bytes.concat(
            keccak256("ProofBridge.AgentPolicy.v1"),
            hex"01",
            hex"01",
            hex"01",
            _row(T1, 1, 1, 1),
            hex"0000",
            bytes8(uint64(0)),
            bytes32(0)
        );
        vm.expectRevert(IAgentPolicyCodecErrors.AgentPolicyCodec__BadDomain.selector);
        codec.parse(v1);
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    bytes32 internal constant T1 = hex"1111111111111111111111111111111111111111111111111111111111111111";
    bytes32 internal constant T2 = hex"2222222222222222222222222222222222222222222222222222222222222222";

    function _row(bytes32 token, uint256 maxPerOrder, uint256 capacity, uint256 refill)
        internal
        pure
        returns (bytes memory)
    {
        return bytes.concat(token, bytes32(maxPerOrder), bytes32(capacity), bytes32(refill));
    }

    /// Domain, action, the ad-token rows and the order-token list; the caller adds the rest.
    function _head(bytes memory adRows, uint8 adCount, bytes memory orderList, uint8 orderCount)
        internal
        pure
        returns (bytes memory)
    {
        return bytes.concat(
            AgentPolicyCodec.DOMAIN,
            bytes1(AgentPolicyCodec.ACTION_LOCK_FOR_ORDER),
            bytes1(adCount),
            adRows,
            bytes1(orderCount),
            orderList
        );
    }

    /// A whole every-ad policy with no expiry.
    function _policy(bytes memory adRows, uint8 adCount, bytes memory orderList, uint8 orderCount)
        internal
        pure
        returns (bytes memory)
    {
        return bytes.concat(_head(adRows, adCount, orderList, orderCount), hex"0000", bytes8(uint64(0)), bytes32(0));
    }

    function _oneRow(bytes32 token, uint256 maxPerOrder, uint256 capacity, uint256 refill)
        internal
        pure
        returns (bytes memory)
    {
        return _policy(_row(token, maxPerOrder, capacity, refill), 1, bytes.concat(T2), 1);
    }

    function _twoRows(bytes32 a, bytes32 b) internal pure returns (bytes memory) {
        return _policy(bytes.concat(_row(a, 1, 1, 1), _row(b, 1, 1, 1)), 2, bytes.concat(T2), 1);
    }
}
