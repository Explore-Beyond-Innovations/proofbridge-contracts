// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Vm} from "forge-std/Vm.sol";
import {DisputeTest} from "./Dispute.t.sol";
import {Dispute} from "../src/libraries/Dispute.sol";
import {IEscrow} from "../src/interfaces/IEscrow.sol";
import {IAdManager} from "../src/interfaces/IAdManager.sol";

/// T-24 (2.3j): the EVM half of the differential harness. Interprets the
/// shared scenario fixture — the SAME steps the Soroban driver interprets —
/// and asserts this implementation's normalized terminal record equals the
/// fixture's: terminal status, the appended leaf's domain, and the bond's
/// destination measured in fixture units. Two hand-written fund-moving
/// implementations, one expected record; a divergence fails one suite by
/// name instead of surfacing as a cross-chain incident.
///
/// The driver CONFIGURES the dispute params from the fixture header (13-
/// dispute-integration.md round 3: drivers configure, never inherit), and
/// every amount converts at the boundary: 1 fixture unit = 10^evmScaleExp
/// wei. The fixture's sha256 is pinned below; scripts/repo-checks compares
/// it against the file so neither driver can drift alone.
contract DisputeDifferentialTest is DisputeTest {
    string internal constant FIXTURE_SHA256 = "54fcf9f016c1b1754127950a6773d5526e02815263f70046458cdaae4f7c6792";

    bytes32 private constant LEAF_TOPIC = keccak256("DepositHashAppended(uint256,bytes32,uint256,bytes32)");

    function test_t24_differentialScenarios() public {
        string memory v = vm.readFile("../test-vectors/dispute-scenarios.json");

        uint256 scale = 10 ** vm.parseJsonUint(v, ".header.evmScaleExp");
        uint64 challenge = uint64(vm.parseJsonUint(v, ".header.challengePeriodS"));
        uint128 floorWei = uint128(vm.parseJsonUint(v, ".header.bondFloorUnits") * scale);
        uint16 bps = uint16(vm.parseJsonUint(v, ".header.bondBps"));
        uint256 amountWei = vm.parseJsonUint(v, ".header.orderAmountUnits") * scale;
        uint256 bondWei = vm.parseJsonUint(v, ".header.bondUnits") * scale;
        assertEq(
            Dispute.bondFor(amountWei, Dispute.Params(challenge, floorWei, bps)),
            bondWei,
            "the header's bond must be exact in chain units"
        );

        vm.startPrank(admin);
        dm.setDisputeParams(orderChainId, Dispute.Params(challenge, floorWei, bps));
        // route wiring the base does inside its create test, done once here
        adManager.setPeerEscrow(orderChainId, _b32(orderPortal));
        adManager.setTokenRoute(address(adToken), orderChainId, _b32(orderToken));
        vm.stopPrank();

        uint256 n = vm.parseJsonUint(v, ".counts.scenarios");
        for (uint256 i = 0; i < n; i++) {
            _runScenario(v, i, amountWei, bondWei, scale);
        }
    }

    struct Run {
        string at;
        string name;
        IAdManager.OrderParams p;
        bytes32 h;
        uint256 filerBase;
        uint256 poolBase;
        uint256 scale;
    }

    function _runScenario(string memory v, uint256 i, uint256 amountWei, uint256 bondWei, uint256 scale) internal {
        Run memory r;
        r.at = string.concat(".scenarios[", vm.toString(i), "]");
        r.name = vm.parseJsonString(v, string.concat(r.at, ".name"));
        r.scale = scale;
        // The fixture pins the filer ABSOLUTELY (the two 2.3g harnesses
        // default to different parties — exactly the drift this exists for).
        assertEq(vm.parseJsonString(v, string.concat(r.at, ".filer")), "MAKER", r.name);

        (r.p, r.h) = _openFixtureOrder(1000 + i, amountWei);

        // Baselines AFTER filing: the bond has left the filer, nothing paid.
        vm.deal(maker, bondWei);
        vm.prank(maker);
        adManager.dispute{value: bondWei}(r.p, bytes32("evidence"));
        r.filerBase = _spendable(maker);
        r.poolBase = _spendable(feePool);

        vm.recordLogs();
        _runSteps(v, r);
        _assertRecord(v, r);
    }

    function _runSteps(string memory v, Run memory r) internal {
        uint256 steps = _stepCount(v, r.at);
        for (uint256 s = 1; s < steps; s++) {
            // step 0 is always `file`, executed by the caller for baselines
            _step(v, string.concat(r.at, ".steps[", vm.toString(s), "]"), r);
        }
    }

    function _step(string memory v, string memory sAt, Run memory r) internal {
        string memory action = vm.parseJsonString(v, string.concat(sAt, ".action"));
        if (_eq(action, "rule")) {
            vm.prank(arbiter);
            dm.resolveDispute(r.h, _outcome(vm.parseJsonString(v, string.concat(sAt, ".outcome"))));
        } else if (_eq(action, "warpPastChallenge")) {
            vm.warp(dm.effectiveChallengeDeadline(r.h) + 1);
        } else if (_eq(action, "claimDispute")) {
            dm.claimDispute(r.h);
        } else if (_eq(action, "warpPastWindow")) {
            _warpPastWindow(r.h);
        } else if (_eq(action, "finalize")) {
            adManager.finalizeDispute(r.p);
        } else if (_eq(action, "present")) {
            _presentSettledOn(r.p, r.h);
        } else if (_eq(action, "recordSettled")) {
            adManager.recordSettled(r.p);
        } else {
            revert(string.concat("unknown step: ", action));
        }
    }

    function _assertRecord(string memory v, Run memory r) internal {
        assertEq(
            dm.isDisputed(r.h),
            vm.parseJsonBool(v, string.concat(r.at, ".expect.disputed")),
            string.concat(r.name, ": disputed")
        );
        assertEq(
            uint8(adManager.orders(r.h)),
            _status(vm.parseJsonString(v, string.concat(r.at, ".expect.escrowStatus"))),
            string.concat(r.name, ": escrow status")
        );
        assertEq(
            _lastLeafDomain(r.h),
            vm.parseJsonUint(v, string.concat(r.at, ".expect.primaryLeafDomain")),
            string.concat(r.name, ": leaf domain")
        );
        assertEq(
            (_spendable(maker) - r.filerBase) / r.scale,
            vm.parseJsonUint(v, string.concat(r.at, ".expect.bondToFilerUnits")),
            string.concat(r.name, ": bond to filer (units)")
        );
        assertEq(
            (_spendable(feePool) - r.poolBase) / r.scale,
            vm.parseJsonUint(v, string.concat(r.at, ".expect.bondToPoolUnits")),
            string.concat(r.name, ": bond to pool (units)")
        );
    }

    /// A party's spendable bond-asset total: native + wrapped + the module's
    /// pull-payment credit (T-18: a refusing recipient's payout lands as a
    /// credit — same value, different door).
    function _spendable(address who) internal view returns (uint256) {
        return who.balance + _wNativeToken.balanceOf(who) + dm.claimable(who);
    }

    /// A fresh ad per scenario — six scenarios share one test's state, so
    /// the base's fixed lastAdId path would trip AdManager__UsedAdId.
    function _openFixtureOrder(uint256 salt, uint256 amountWei)
        internal
        returns (IAdManager.OrderParams memory p, bytes32 h)
    {
        string memory adId = string.concat("t24-", vm.toString(salt));
        vm.startPrank(maker);
        adToken.approve(address(adManager), amountWei);
        adManager.createAd(adId, address(adToken), amountWei, orderChainId, _b32(adRecipient), _b32(maker));
        vm.stopPrank();
        (p, h) = _openOrder(adId, address(adToken), amountWei, salt, bridger, recipient);
    }

    function _lastLeafDomain(bytes32 h) internal returns (uint256 domain) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool seen = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length >= 3 && logs[i].topics[0] == LEAF_TOPIC && logs[i].topics[2] == h) {
                (uint256 side,) = abi.decode(logs[i].data, (uint256, bytes32));
                domain = side;
                seen = true; // keep the LAST append for this order
            }
        }
        require(seen, "no leaf appended for the order");
    }

    function _stepCount(string memory v, string memory at) internal view returns (uint256 n) {
        // parseJson on the array returns abi-encoded tuples; counting by
        // probing is simpler and version-stable.
        while (vm.keyExistsJson(v, string.concat(at, ".steps[", vm.toString(n), "].action"))) {
            n++;
        }
    }

    function _outcome(string memory s) internal pure returns (Dispute.Outcome) {
        if (_eq(s, "MutualRefund")) return Dispute.Outcome.MutualRefund;
        if (_eq(s, "BridgerForfeit")) return Dispute.Outcome.BridgerForfeit;
        if (_eq(s, "MakerForfeit")) return Dispute.Outcome.MakerForfeit;
        revert("unknown outcome");
    }

    function _status(string memory s) internal pure returns (uint8) {
        if (_eq(s, "Filled")) return uint8(IEscrow.Status.Filled);
        if (_eq(s, "Cancelled")) return uint8(IEscrow.Status.Cancelled);
        if (_eq(s, "Resolved")) return uint8(IEscrow.Status.Resolved);
        revert("unknown status");
    }

    function _eq(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }
}
