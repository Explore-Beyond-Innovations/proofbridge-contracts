// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";

import {IAdManager} from "src/interfaces/IAdManager.sol";
import {AgentRateLimit} from "src/agent/AgentRateLimit.sol";
import {DecimalScaling} from "src/libraries/DecimalScaling.sol";
import {PolicyHarness} from "./mocks/PolicyHarness.sol";

/// `AgentRateLimit` is an internal library; this is the external face the vectors are run against.
contract RateLimitHarness {
    function available(AgentRateLimit.Limit memory limit, AgentRateLimit.Bucket memory bucket, uint64 nowTs)
        external
        pure
        returns (uint256)
    {
        return AgentRateLimit.available(limit, bucket, nowTs);
    }

    function trySpend(
        AgentRateLimit.Limit memory limit,
        AgentRateLimit.Bucket memory bucket,
        uint256 spend,
        uint64 nowTs
    ) external pure returns (bool, AgentRateLimit.Bucket memory) {
        return AgentRateLimit.trySpend(limit, bucket, spend, nowTs);
    }
}

/// The escrows' scaling, which reverts with a reason where the module's copy answers no.
contract ScalingHarness {
    function scale(uint256 amount, uint8 fromDec, uint8 toDec) external pure returns (uint256) {
        return DecimalScaling.scale(amount, fromDec, toDec);
    }
}

/// T-60, layer 1: the arithmetic under an agent policy, against the shared vectors.
///
/// The token bucket and decimal scaling are each hand-written more than once — here, in Rust, and
/// (scaling) in TypeScript — and each copy's own tests assert what that copy already believes.
/// `test-vectors/agent-policy-math.json` is computed in unbounded integers by a generator that
/// imports none of them, and every copy reads it.
contract AgentPolicyMathParityTest is Test {
    using stdJson for string;

    RateLimitHarness internal rate;
    PolicyHarness internal policy;
    ScalingHarness internal escrowScaling;
    string internal vectors;

    function setUp() public {
        rate = new RateLimitHarness();
        policy = new PolicyHarness();
        escrowScaling = new ScalingHarness();
        vectors = vm.readFile("../test-vectors/agent-policy-math.json");
    }

    function test_theBucketMatchesTheSharedVectors() public view {
        uint256 ran;
        for (; vm.keyExistsJson(vectors, _at("bucket", ran, "")); ++ran) {
            string memory label = vectors.readString(_at("bucket", ran, ".label"));
            AgentRateLimit.Limit memory limit = AgentRateLimit.Limit({
                capacity: _uint("bucket", ran, ".capacity"), refillPerSecond: _uint("bucket", ran, ".refillPerSecond")
            });
            AgentRateLimit.Bucket memory bucket = AgentRateLimit.Bucket({
                level: _uint("bucket", ran, ".level"), lastTs: uint64(_uint("bucket", ran, ".lastTs"))
            });
            uint64 nowTs = uint64(_uint("bucket", ran, ".now"));

            assertEq(rate.available(limit, bucket, nowTs), _uint("bucket", ran, ".available"), label);

            (bool ok, AgentRateLimit.Bucket memory next) =
                rate.trySpend(limit, bucket, _uint("bucket", ran, ".spend"), nowTs);
            assertEq(ok, vectors.readBool(_at("bucket", ran, ".ok")), label);
            assertEq(next.level, _uint("bucket", ran, ".nextLevel"), label);
            assertEq(next.lastTs, _uint("bucket", ran, ".nextLastTs"), label);
        }
        // Zero rows is a failure, and so is some: a reader that parsed half the file would pass.
        assertGt(ran, 0, "no bucket rows ran");
        assertEq(ran, vectors.readUint(".counts.bucket"), "bucket rows ran");
    }

    /// The module's own scaling, not the escrow's `DecimalScaling.scale`: the module repeats the
    /// arithmetic so it can answer instead of reverting during validation, and
    /// `testFuzz_scalingMatchesTheEscrowsOrRefuses` holds the two together.
    function test_scalingMatchesTheSharedVectors() public view {
        uint256 ran;
        for (; vm.keyExistsJson(vectors, _at("scaling", ran, "")); ++ran) {
            string memory label = vectors.readString(_at("scaling", ran, ".label"));
            IAdManager.OrderParams memory p;
            p.amount = _uint("scaling", ran, ".amount");
            p.orderDecimals = uint8(_uint("scaling", ran, ".fromDecimals"));
            p.adDecimals = uint8(_uint("scaling", ran, ".toDecimals"));
            (bool ok, uint256 value) = policy.adAmount(p);

            // The EVM's word is 256 bits and the module scales in it, so a product past u128 — an
            // overflow to Rust and TypeScript — is a number here. The lock is refused all the same:
            // a per-order cap cannot exceed u128, so an amount that large is over it.
            string memory wide = _at("scaling", ran, ".evmWide");
            if (vm.keyExistsJson(vectors, wide)) {
                assertTrue(ok, label);
                assertEq(value, vectors.readUint(string.concat(wide, ".value")), label);
                assertGt(value, type(uint128).max, "evmWide rows are exactly the ones past u128");
            } else if (vectors.readBool(_at("scaling", ran, ".ok"))) {
                assertTrue(ok, label);
                assertEq(value, _uint("scaling", ran, ".value"), label);
            } else {
                // The module answers yes or no and keeps no reason; the refusal is the parity claim.
                assertFalse(ok, label);
            }
        }
        assertGt(ran, 0, "no scaling rows ran");
        assertEq(ran, vectors.readUint(".counts.scaling"), "scaling rows ran");
    }

    /// The escrows' copy, which is the one that moves money. It keeps its reasons, so here the
    /// shared word for each refusal is held to this implementation's error.
    function test_theEscrowsScalingMatchesTheSharedVectors() public view {
        uint256 ran;
        for (; vm.keyExistsJson(vectors, _at("scaling", ran, "")); ++ran) {
            string memory label = vectors.readString(_at("scaling", ran, ".label"));
            uint256 amount = _uint("scaling", ran, ".amount");
            uint8 from = uint8(_uint("scaling", ran, ".fromDecimals"));
            uint8 to = uint8(_uint("scaling", ran, ".toDecimals"));

            string memory wide = _at("scaling", ran, ".evmWide");
            if (vm.keyExistsJson(vectors, wide)) {
                assertEq(escrowScaling.scale(amount, from, to), vectors.readUint(string.concat(wide, ".value")), label);
            } else if (vectors.readBool(_at("scaling", ran, ".ok"))) {
                assertEq(escrowScaling.scale(amount, from, to), _uint("scaling", ran, ".value"), label);
            } else {
                bytes32 reason = keccak256(bytes(vectors.readString(_at("scaling", ran, ".reason"))));
                bytes4 want;
                if (reason == keccak256("decimals-out-of-range")) {
                    want = DecimalScaling.DecimalScaling__DecimalsOutOfRange.selector;
                } else if (reason == keccak256("non-exact-downscale")) {
                    want = DecimalScaling.DecimalScaling__NonExactDownscale.selector;
                } else {
                    // "overflow" never reaches here: every such row is `evmWide`. Anything else is
                    // a reason this reader does not know, which has to fail rather than match nothing.
                    revert(string.concat(label, ": a reason this reader does not know"));
                }
                try escrowScaling.scale(amount, from, to) returns (uint256) {
                    revert(string.concat(label, ": scaled where the vectors refuse"));
                } catch (bytes memory err) {
                    assertEq(bytes4(err), want, label);
                }
            }
        }
        assertGt(ran, 0, "no scaling rows ran");
        assertEq(ran, vectors.readUint(".counts.scaling"), "scaling rows ran");
    }

    function _at(string memory table, uint256 i, string memory field) internal pure returns (string memory) {
        return string.concat(".", table, "[", vm.toString(i), "]", field);
    }

    function _uint(string memory table, uint256 i, string memory field) internal view returns (uint256) {
        return vectors.readUint(_at(table, i, field));
    }
}
