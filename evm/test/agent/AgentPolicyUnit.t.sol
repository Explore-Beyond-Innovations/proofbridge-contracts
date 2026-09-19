// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";

import {IAdManager} from "src/interfaces/IAdManager.sol";
import {DecimalScaling} from "src/libraries/DecimalScaling.sol";
import {AgentRateLimit} from "src/agent/AgentRateLimit.sol";
import {PolicyHarness} from "./mocks/PolicyHarness.sol";

/// The pieces a UserOp cannot reach directly: the scaling that has to agree with the escrow's, the
/// bucket math that has to agree with Soroban's, and the decoder's refusals.
contract AgentPolicyUnitTest is Test {
    PolicyHarness internal harness;

    function setUp() public {
        harness = new PolicyHarness();
    }

    /*//////////////////////////////////////////////////////////////
                     THE SCALING THE ESCROW WILL USE
    //////////////////////////////////////////////////////////////*/

    /// The module cannot call `DecimalScaling.scale`: it reverts, and a revert during validation is
    /// what gets a module dropped from the mempool, so the arithmetic is repeated as an answer. Two
    /// implementations of the same sum is exactly the shape that drifts, so they are fuzzed against
    /// each other rather than trusted.
    function testFuzz_scalingMatchesTheEscrowsOrRefuses(uint256 amount, uint8 fromDec, uint8 toDec) public {
        fromDec = uint8(bound(fromDec, 0, DecimalScaling.MAX_DECIMALS));
        toDec = uint8(bound(toDec, 0, DecimalScaling.MAX_DECIMALS));
        amount = bound(amount, 0, type(uint128).max);

        IAdManager.OrderParams memory params;
        params.amount = amount;
        params.orderDecimals = fromDec;
        params.adDecimals = toDec;
        (bool ok, uint256 got) = harness.adAmount(params);

        try this.scale(amount, fromDec, toDec) returns (uint256 want) {
            assertTrue(ok, "the escrow would have scaled this; the module must too");
            assertEq(got, want, "and to the same number");
        } catch {
            assertFalse(ok, "the escrow would have reverted; the module must refuse");
        }
    }

    function scale(uint256 amount, uint8 fromDec, uint8 toDec) external pure returns (uint256) {
        return DecimalScaling.scale(amount, fromDec, toDec);
    }

    /*//////////////////////////////////////////////////////////////
                    THE BUCKET SOROBAN ALSO IMPLEMENTS
    //////////////////////////////////////////////////////////////*/

    function test_aFreshBucketIsFullAndSpendsDown() public pure {
        AgentRateLimit.Limit memory limit = AgentRateLimit.Limit({capacity: 1000, refillPerSecond: 10});
        AgentRateLimit.Bucket memory b = AgentRateLimit.full(limit, 100);
        assertEq(AgentRateLimit.available(limit, b, 100), 1000);
        (bool ok, AgentRateLimit.Bucket memory next) = AgentRateLimit.trySpend(limit, b, 400, 100);
        assertTrue(ok);
        assertEq(next.level, 600);
        assertEq(next.lastTs, 100);
    }

    function test_overTheRemainingAllowanceChangesNothing() public pure {
        AgentRateLimit.Limit memory limit = AgentRateLimit.Limit({capacity: 1000, refillPerSecond: 10});
        AgentRateLimit.Bucket memory b = AgentRateLimit.Bucket({level: 100, lastTs: 100});
        (bool ok, AgentRateLimit.Bucket memory next) = AgentRateLimit.trySpend(limit, b, 101, 100);
        assertFalse(ok);
        assertEq(next.level, 100, "a refused spend leaves the bucket alone");
    }

    function test_aClockThatGoesBackwardsIsNotARefund() public pure {
        AgentRateLimit.Limit memory limit = AgentRateLimit.Limit({capacity: 1000, refillPerSecond: 10});
        AgentRateLimit.Bucket memory b = AgentRateLimit.Bucket({level: 100, lastTs: 500});
        assertEq(AgentRateLimit.available(limit, b, 400), 100, "no time passed");

        // ...and the stamp does not move backwards either, or the next call at the true time would
        // refill that interval a second time.
        (bool ok, AgentRateLimit.Bucket memory next) = AgentRateLimit.trySpend(limit, b, 50, 400);
        assertTrue(ok);
        assertEq(next.lastTs, 500);
    }

    /// Rust reads both overflow arms as "more than capacity" and returns it. A mirror that reverted
    /// where the original clamped could not be covered by the fixture that proves the two agree.
    function test_overflowClampsToCapacityRatherThanReverting() public pure {
        AgentRateLimit.Limit memory limit = AgentRateLimit.Limit({capacity: 1000, refillPerSecond: type(uint128).max});
        AgentRateLimit.Bucket memory b = AgentRateLimit.Bucket({level: 1, lastTs: 0});
        assertEq(AgentRateLimit.available(limit, b, type(uint64).max), 1000);

        AgentRateLimit.Limit memory wide = AgentRateLimit.Limit({capacity: type(uint128).max, refillPerSecond: 5});
        AgentRateLimit.Bucket memory nearlyFull = AgentRateLimit.Bucket({level: type(uint128).max - 1, lastTs: 0});
        assertEq(AgentRateLimit.available(wide, nearlyFull, 1), type(uint128).max, "past u128 is past capacity");
    }

    /*//////////////////////////////////////////////////////////////
                              THE DECODER
    //////////////////////////////////////////////////////////////*/

    function test_staticAndDelegateCallTypesAreRefused() public view {
        // A policy reasons about a target and a selector; it says nothing useful about code running
        // in the account's own context.
        for (uint8 callType = 0xfe; callType >= 0xfe; ++callType) {
            bytes memory cd = _execute(callType, abi.encodePacked(address(this), uint256(0), hex"deadbeef"));
            (bool ok,) = harness.decodeCalls(cd);
            assertFalse(ok, "delegate and static executions are not agent business");
            if (callType == 0xff) break;
        }
    }

    function test_anUnknownSelectorIsNotAnExecute() public view {
        (bool ok,) = harness.decodeCalls(abi.encodeWithSelector(bytes4(0x12345678), uint256(1)));
        assertFalse(ok);
    }

    function test_truncatedCalldataIsRefusedRatherThanGuessed() public view {
        (bool ok,) = harness.decodeCalls(hex"e9ae5c53");
        assertFalse(ok);
        (ok,) = harness.decodeCalls(hex"");
        assertFalse(ok);
    }

    function _execute(uint8 callType, bytes memory executionCalldata) internal pure returns (bytes memory) {
        bytes32 mode = bytes32(uint256(callType) << 248);
        return abi.encodeWithSelector(bytes4(0xe9ae5c53), mode, executionCalldata);
    }
}
