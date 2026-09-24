// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {TestField} from "test/utils/TestField.sol";

import {IEscrow} from "src/interfaces/IEscrow.sol";
import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IRootAnchor} from "src/interfaces/IRootAnchor.sol";
import {Dispute} from "src/libraries/Dispute.sol";
import {MockRootVerifier} from "./mocks/MockRootVerifier.sol";
import {AdManagerCancellationTest} from "./Cancellation.t.sol";
import {DisputeTest} from "./Dispute.t.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {IKeyRegistry} from "src/interfaces/IKeyRegistry.sol";
import {IBLSKeyRegistry} from "src/interfaces/IBLSKeyRegistry.sol";
import {BLSKeyRegistry} from "src/BLSKeyRegistry.sol";
import {RouteTiming} from "src/libraries/RouteTiming.sol";
import {AdManagerTest} from "./Admanager.t.sol";

/*//////////////////////////////////////////////////////////////
          #422 — the maker's settlement halt (F1 residual)
//////////////////////////////////////////////////////////////*/

/// One custody-key transaction stops the co-signed payout of every open order against the maker's
/// ads; evidence still pays; a denied order's cancel waits the evidence grace. The base timing here
/// is buffer 30 min, no anchor wired, so the grace is the buffer alone until a test wires one.
contract SettlementHaltTest is AdManagerCancellationTest {
    bytes32 internal constant ROOT = bytes32(uint256(5));

    function _unlock(IAdManager.OrderParams memory p, string memory nullifier) internal {
        vm.prank(bridger);
        adManager.unlock(p, TestField.fe(nullifier), ROOT, hex"", hex"");
    }

    function _halt() internal {
        vm.prank(maker);
        adManager.haltSettlement();
    }

    function _resume() internal {
        vm.prank(maker);
        adManager.resumeSettlement();
    }

    /*//////////////////////////// the switch ////////////////////////////*/

    function test_halt_refusesTheCoSignedUnlock_resumeAdmitsIt() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lock(1);

        vm.expectEmit(true, true, true, true);
        emit IAdManager.SettlementHalted(maker);
        _halt();
        assertTrue(adManager.halted(maker));

        vm.expectRevert(abi.encodeWithSelector(IAdManager.AdManager__Halted.selector, maker));
        _unlock(p, "N1");
        assertEq(uint256(adManager.orders(h)), uint256(IEscrow.Status.Open), "nothing moved");

        vm.expectEmit(true, true, true, true);
        emit IAdManager.SettlementResumed(maker);
        _resume();
        _unlock(p, "N1");
        assertEq(uint256(adManager.orders(h)), uint256(IEscrow.Status.Filled));
    }

    function test_halt_isKeyedByMaker_someoneElsesHaltChangesNothing() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lock(2);
        vm.prank(bridger);
        adManager.haltSettlement();
        _unlock(p, "N1");
        assertEq(uint256(adManager.orders(h)), uint256(IEscrow.Status.Filled));
    }

    /// A runbook that fires the halt twice is not an error, and the second halt still refuses.
    function test_halt_isIdempotent_secondHaltStillRefuses() public {
        (IAdManager.OrderParams memory p,) = _lock(2);
        _halt();
        vm.warp(block.timestamp + 100);
        _halt();
        vm.expectRevert(abi.encodeWithSelector(IAdManager.AdManager__Halted.selector, maker));
        _unlock(p, "N1");
    }

    /// An incident lever is never pause-gated (the same rule as `setSettlementSigner`).
    function test_halt_andResume_workWhilePaused() public {
        vm.prank(admin);
        adManager.pause();
        _halt();
        _resume();
    }

    /*//////////////////////////// evidence wins ////////////////////////////*/

    /// Rule 2: a halted maker's counterparty is still paid on an anchored SETTLED leaf.
    function test_presentSettled_ignoresTheHalt() public {
        _wireAnchor();
        (IAdManager.OrderParams memory p, bytes32 h) = _lock(3);
        _halt();
        _claim(p);
        bytes32 root = bytes32(uint256(0xf00d));
        _anchorRoot(root);

        vm.warp(p.deadline + 10 minutes);
        adManager.presentSettled(p, root, hex"");
        assertEq(uint256(adManager.orders(h)), uint256(IEscrow.Status.Filled));
        assertEq(adToken.balanceOf(recipient), 60 ether, "the bridger's recipient is paid");
    }

    /*//////////////////////////// the cancel clock ////////////////////////////*/

    /// Halted before the claim: the cancel waits the grace (buffer, with no anchor wired).
    function test_finalizeCancel_haltedSinceBeforeTheClaim_waitsTheGrace() public {
        (IAdManager.OrderParams memory p,) = _lock(4);
        _halt();
        _claim(p);
        vm.warp(p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);
        vm.warp(p.deadline + 60 minutes - 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);
        vm.warp(p.deadline + 60 minutes);
        adManager.finalizeCancel(p);
        assertEq(_locked(), 0, "the lock is released after the grace");
    }

    /// Halted after the deadline and resumed before the window ended: still denied. The resume can
    /// come after the presentation cutoff, when it no longer helps the counterparty.
    function test_finalizeCancel_haltedThenResumedAfterTheDeadline_stillWaits() public {
        (IAdManager.OrderParams memory p,) = _lock(5);
        _claim(p);
        vm.warp(p.deadline + 10 minutes);
        _halt();
        vm.warp(p.deadline + 20 minutes);
        _resume();
        assertFalse(adManager.halted(maker));
        vm.warp(p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);
        vm.warp(p.deadline + 60 minutes);
        adManager.finalizeCancel(p);
    }

    /// Halted from before the deadline and resumed only at the window's last second: the halt
    /// covered the whole window, so the payout was denied and the cancel waits.
    function test_finalizeCancel_haltedThroughTheWindow_resumedAtTheEnd_stillWaits() public {
        (IAdManager.OrderParams memory p,) = _lock(12);
        _halt();
        _claim(p);
        vm.warp(p.deadline + 30 minutes - 1);
        _resume();
        vm.warp(p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);
        vm.warp(p.deadline + 60 minutes);
        adManager.finalizeCancel(p);
    }

    /// A halt lifted before the deadline never denied this window: ordinary timing.
    function test_finalizeCancel_haltLiftedBeforeTheDeadline_ordinaryTiming() public {
        (IAdManager.OrderParams memory p,) = _lock(6);
        _halt();
        vm.warp(p.deadline - 1);
        _resume();
        _claim(p);
        vm.warp(p.deadline + 30 minutes);
        adManager.finalizeCancel(p);
        assertEq(_locked(), 0);
    }

    /// The boundary is the deadline itself: a resume in the deadline's second counts (`>=`).
    function test_finalizeCancel_resumeInTheDeadlinesSecond_counts() public {
        (IAdManager.OrderParams memory p,) = _lock(7);
        _halt();
        vm.warp(p.deadline);
        _resume();
        adManager.claimCancel(p);
        vm.warp(p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);
    }

    /// Review F2: the claim's open time was the maker's to pick. A maker who halts through the
    /// cutoff, resumes, and opens and finalizes the claim in the same block still waits.
    function test_finalizeCancel_lateClaim_cannotSkipTheGrace() public {
        (IAdManager.OrderParams memory p,) = _lock(13);
        _halt();
        vm.warp(p.deadline + 30 minutes);
        _resume();
        vm.warp(p.deadline + 30 minutes + 1);
        adManager.claimCancel(p);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);
        vm.warp(p.deadline + 60 minutes);
        adManager.finalizeCancel(p);
    }

    /// Review F3: a slot of the signer dying since the lock is a denied payout even when a
    /// replacement slot keeps `hasUsableSlot` true.
    function test_finalizeCancel_signerKilledSinceTheLock_waitsTheGrace() public {
        (IAdManager.OrderParams memory p,) = _lock(14);
        vm.warp(block.timestamp + 10);
        keyRegistry.addSlotExpiry(p.adSettlementSigner, uint64(block.timestamp));
        _claim(p);
        vm.warp(p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);
        vm.warp(p.deadline + 60 minutes);
        adManager.finalizeCancel(p);
    }

    /// The boundary is the lock's own second: a slot expiring then counts (`>=`).
    function test_finalizeCancel_signerKilledInTheLocksSecond_counts() public {
        vm.warp(block.timestamp + 10);
        (IAdManager.OrderParams memory p,) = _lock(17);
        keyRegistry.addSlotExpiry(p.adSettlementSigner, uint64(block.timestamp));
        _claim(p);
        vm.warp(p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);
    }

    /// An expiry anywhere inside `[lockedAt, deadline]` is an expiry during the order's life.
    function test_finalizeCancel_expiryInsideTheInterval_waitsTheGrace() public {
        (IAdManager.OrderParams memory p,) = _lock(19);
        keyRegistry.addSlotExpiry(p.adSettlementSigner, uint64(p.deadline - 10 minutes));
        _claim(p);
        vm.warp(p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);
    }

    /// A rotation whose old slot outlives the deadline puts no expiry in the order's life: ordinary.
    function test_finalizeCancel_rotationOutlivingTheCancel_ordinaryTiming() public {
        (IAdManager.OrderParams memory p,) = _lock(20);
        keyRegistry.addSlotExpiry(p.adSettlementSigner, uint64(p.deadline + 2 days));
        _claim(p);
        vm.warp(p.deadline + 30 minutes);
        adManager.finalizeCancel(p);
    }

    /// Review F5: an anchor that cannot answer `anchorDelay` refuses the denied finalize outright —
    /// a long wait, never a shorter one.
    function test_finalizeCancel_unreadableAnchor_refuses() public {
        address noAnchorDelay = address(new MockRootVerifier(true));
        vm.prank(admin);
        adManager.setRootAnchor(IRootAnchor(noAnchorDelay));
        (IAdManager.OrderParams memory p,) = _lock(18);
        _halt();
        _claim(p);
        vm.warp(p.deadline + 2 days);
        vm.expectRevert(bytes(""));
        adManager.finalizeCancel(p);
    }

    /// The view the relayer's janitor asks: 0 before a claim, the window end after, plus the grace
    /// once the payout is denied.
    function test_cancelFinalizesAt_reportsTheGrace() public {
        (IAdManager.OrderParams memory p,) = _lock(16);
        assertEq(adManager.cancelFinalizesAt(p), 0);
        _claim(p);
        assertEq(adManager.cancelFinalizesAt(p), p.deadline + 30 minutes);
        _halt();
        assertEq(adManager.cancelFinalizesAt(p), p.deadline + 60 minutes);
        vm.warp(p.deadline + 60 minutes);
        adManager.finalizeCancel(p);
        assertEq(adManager.cancelFinalizesAt(p), 0, "terminal");
    }

    /// With an anchor wired the grace is its delay for the order chain plus the buffer.
    function test_finalizeCancel_grace_isAnchorDelayPlusBuffer() public {
        _wireAnchor();
        vm.prank(admin);
        anchor.setAnchorDelay(orderChainId, 2 hours);
        (IAdManager.OrderParams memory p,) = _lock(8);
        _halt();
        _claim(p);
        vm.warp(p.deadline + 30 minutes + 2 hours);
        vm.expectRevert(
            abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 30 minutes + 2 hours + 30 minutes)
        );
        adManager.finalizeCancel(p);
        vm.warp(p.deadline + 30 minutes + 2 hours + 30 minutes);
        adManager.finalizeCancel(p);
    }

    /// Lever 2: the signer fully retired in the registry is a denied payout too (the one-sided
    /// retirement race that exists today, closed by the same grace).
    function test_finalizeCancel_signerWithNoUsableSlot_waitsTheGrace() public {
        (IAdManager.OrderParams memory p,) = _lock(9);
        _claim(p);
        keyRegistry.set(p.adSettlementSigner, false);
        vm.warp(p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);
        vm.warp(p.deadline + 60 minutes);
        adManager.finalizeCancel(p);
    }

    /// The grace stacks on a pause the same way the window does: paused seconds extend the end.
    function test_finalizeCancel_grace_stacksOnAPause() public {
        (IAdManager.OrderParams memory p,) = _lock(10);
        _halt();
        _claim(p);
        vm.prank(admin);
        adManager.pause();
        vm.warp(p.deadline + 15 minutes);
        vm.prank(admin);
        adManager.unpause();
        // 15 min paused: window ends at +45, grace ends at +75.
        vm.warp(p.deadline + 75 minutes - 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 75 minutes));
        adManager.finalizeCancel(p);
        vm.warp(p.deadline + 75 minutes);
        adManager.finalizeCancel(p);
    }

    /*//////////////////////////// T-06 ////////////////////////////*/

    /// T-06: a locked, co-signed order stops settling after one custody-key transaction, cannot be
    /// cancelled inside the grace, and reaches `Cancelled` with the CANCEL leaf and the counter
    /// cleared after it. The co-signature is the permissive root verifier here; the shape is the
    /// same with a real aggregate, which the unlock never reaches once halted.
    function test_T06_haltedOrder_stopsSettling_andStillTerminates() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lock(11);
        uint256 leaves = adManager.getMerkleLeafCount();
        uint256 balanceBefore = _balance();

        _halt();
        vm.expectRevert(abi.encodeWithSelector(IAdManager.AdManager__Halted.selector, maker));
        _unlock(p, "N1");

        _claim(p);
        vm.warp(p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);

        // At the window's last second (inclusive) the halt is still what refuses; a second later the
        // cutoff closes the co-signed path on its own.
        vm.expectRevert(abi.encodeWithSelector(IAdManager.AdManager__Halted.selector, maker));
        _unlock(p, "N1");
        vm.warp(p.deadline + 30 minutes + 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderExpired.selector, p.deadline + 30 minutes));
        _unlock(p, "N1");

        vm.warp(p.deadline + 60 minutes);
        adManager.finalizeCancel(p);
        assertEq(uint256(adManager.orders(h)), uint256(IEscrow.Status.Cancelled));
        assertEq(adManager.getMerkleLeafCount(), leaves + 1, "the CANCEL leaf");
        assertEq(_locked(), 0);
        assertEq(_balance(), balanceBefore, "the ad keeps its funds");
        assertEq(adManager.inFlightOf(p.adSettlementSigner), 0);
    }
}

/// Review F1: the dispute fallback is a door too. Every outcome but MakerForfeit hands the lock back
/// to the maker, so a denied payout waits the grace past the challenge deadline.
contract SettlementHaltDisputeTest is DisputeTest {
    function test_finalizeDispute_fallback_waitsTheGrace_whenHalted() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(21);
        vm.prank(maker);
        adManager.haltSettlement();
        _file(p, maker);
        // The module's window, from the fixture's own constants: max(filed + CHALLENGE, deadline + buffer).
        uint256 filed = block.timestamp;
        uint256 until_ = filed + CHALLENGE > p.deadline + 30 minutes ? filed + CHALLENGE : p.deadline + 30 minutes;
        assertEq(dm.effectiveChallengeDeadline(h), until_, "the fixture's arithmetic matches the module's");
        vm.warp(until_ + 1);
        // buffer 30 min, anchor wired with no delay: the grace is the buffer.
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, until_ + 30 minutes));
        adManager.finalizeDispute(p);
        vm.warp(until_ + 30 minutes);
        adManager.finalizeDispute(p);
        assertEq(uint256(adManager.orders(h)), uint256(IEscrow.Status.Resolved));
    }

    /// MakerForfeit pays the counterparty anyway, so it is the one outcome the grace does not gate:
    /// an arbiter's ruling finalizes at the challenge deadline, halted or not.
    function test_finalizeDispute_makerForfeit_ignoresTheGrace() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(23);
        vm.prank(maker);
        adManager.haltSettlement();
        _file(p, maker);
        vm.prank(arbiter);
        dm.resolveDispute(h, Dispute.Outcome.MakerForfeit);
        _warpPastWindow(h);
        uint256 before = adToken.balanceOf(recipient);
        adManager.finalizeDispute(p);
        assertEq(uint256(adManager.orders(h)), uint256(IEscrow.Status.Resolved));
        assertEq(adToken.balanceOf(recipient) - before, 60 ether, "the counterparty is paid");
    }

    /// Not halted: the fallback finalizes at the challenge deadline as before.
    function test_finalizeDispute_fallback_ordinaryTiming_whenNotDenied() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockedOrder(22);
        _file(p, maker);
        _warpPastWindow(h);
        adManager.finalizeDispute(p);
        assertEq(uint256(adManager.orders(h)), uint256(IEscrow.Status.Resolved));
    }
}

/*//////////////////////////////////////////////////////////////
      #422 D14 — the denial read off the REAL registry
//////////////////////////////////////////////////////////////*/

/// The mock above restates the registry's predicate, so it proves wiring and nothing about what the
/// registry stores. The fixture below runs an escrow against `BLSKeyRegistry` itself, with the
/// vector maker's slots, and uses the retirement the protocol actually sends: `setValidUntil(.., 1)`.
abstract contract RealRegistryFixture is AdManagerTest {
    using stdJson for string;

    uint256 constant VECTOR_CHAIN_ID = 11155111;
    address constant REGISTRY = 0x1111111111111111111111111111111111111111;

    string internal v;
    BLSKeyRegistry internal registry;
    bytes32 internal account;

    /// Per test, not in `setUp`: the inherited suites keep running against the mock.
    function _realRegistry() internal {
        // Foundry's clock starts at second 1 — the very date a kill names. Start in 2023 instead.
        vm.warp(1_700_000_000);
        v = vm.readFile("../test-vectors/bls-encodings.json");
        BLSKeyRegistry impl = new BLSKeyRegistry(address(this));
        vm.etch(REGISTRY, address(impl).code);
        vm.store(REGISTRY, bytes32(0), bytes32(uint256(uint160(address(this)))));
        registry = BLSKeyRegistry(REGISTRY);
        account = v.readBytes32(".slots.makerOnSepolia.account");
        // Two slots, so a kill of one leaves `hasUsableSlot` true: the state the attack needs.
        _registerSlot(0);
        _registerSlot(1);
        vm.prank(admin);
        adManager.setKeyRegistry(IKeyRegistry(REGISTRY));
    }

    /*//////////////////////////// vector helpers ////////////////////////////*/

    function _sep53(string memory path) internal view returns (IBLSKeyRegistry.OwnerAuth memory) {
        bytes memory data = abi.encode(
            uint256(v.readBytes32(string.concat(path, ".scl.r"))),
            uint256(v.readBytes32(string.concat(path, ".scl.s"))),
            uint256(v.readBytes32(string.concat(path, ".scl.edX"))),
            uint256(v.readBytes32(string.concat(path, ".scl.edY")))
        );
        return IBLSKeyRegistry.OwnerAuth(IBLSKeyRegistry.Scheme.Sep53, data);
    }

    /// The vector digests bind the Sepolia chain id; the escrow keeps the runtime one.
    modifier onVectorChain() {
        uint256 cid = block.chainid;
        vm.chainId(VECTOR_CHAIN_ID);
        _;
        vm.chainId(cid);
    }

    function _registerSlot(uint256 i) internal onVectorChain {
        string memory path = string.concat(".slots.makerOnSepolia.registrations[", vm.toString(i), "]");
        registry.register(
            account,
            _sep53(string.concat(path, ".ownerSig")),
            v.readBytes(string.concat(path, ".pkNative")),
            v.readBytes(string.concat(path, ".pop")),
            i
        );
    }

    /// `setValidUntil` vectors: index = slotId*2 + (retire ? 0 : 1); a retire names `1`.
    function _setValidUntil(uint32 slotId, bool retire) internal onVectorChain {
        string memory path = string.concat(
            ".slots.makerOnSepolia.setValidUntil[", vm.toString(uint256(slotId) * 2 + (retire ? 0 : 1)), "].ownerSig"
        );
        registry.setValidUntil(account, _sep53(path), slotId, retire ? 1 : _graceTs());
    }

    function _graceTs() internal view returns (uint64) {
        return uint64(vm.parseUint(v.readString(".slots.graceTs")));
    }

    /// An ad whose settlement signer is the vector account, funded, and one lock on it.
    function _lockAs(uint256 salt) internal returns (IAdManager.OrderParams memory p) {
        string memory adId = string.concat("422-real-", vm.toString(salt));
        vm.startPrank(admin);
        adManager.setPeerEscrow(orderChainId, _b32(orderPortal));
        adManager.setTokenRoute(address(adToken), orderChainId, _b32(orderToken));
        vm.stopPrank();
        vm.startPrank(maker);
        adToken.approve(address(adManager), initAmt + fundAmt);
        adManager.createAd(adId, address(adToken), initAmt, orderChainId, _b32(adRecipient), account);
        adManager.fundAd(adId, fundAmt);
        vm.stopPrank();

        p = _defaultParams(adId);
        p.amount = 60 ether;
        p.salt = salt;
        p.adSettlementSigner = account;
        vm.prank(maker);
        adManager.lockForOrder(p);
    }
}

contract SettlementHaltRealRegistryTest is RealRegistryFixture, AdManagerCancellationTest {
    function setUp() public override(AdManagerTest, AdManagerCancellationTest) {
        AdManagerCancellationTest.setUp();
    }

    /// Pass 4 (c41-F3): the standard kill after the lock, a second slot still live. The stored
    /// expiry says 1970; the slot died at the kill, inside the order's life.
    function test_realRegistry_killAfterTheLock_waitsTheGrace() public {
        _realRegistry();
        IAdManager.OrderParams memory p = _lockAs(1);
        vm.warp(block.timestamp + 10);
        _setValidUntil(0, true);
        assertTrue(registry.hasUsableSlot(account), "the second slot keeps the identity usable");
        _claim(p);
        vm.warp(p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);
        vm.warp(p.deadline + 60 minutes);
        adManager.finalizeCancel(p);
    }

    /// A kill before the lock is history: the order was co-signed under the other slot.
    function test_realRegistry_killBeforeTheLock_ordinaryTiming() public {
        _realRegistry();
        vm.warp(block.timestamp + 10);
        _setValidUntil(0, true);
        vm.warp(block.timestamp + 10);
        IAdManager.OrderParams memory p = _lockAs(2);
        _claim(p);
        vm.warp(p.deadline + 30 minutes);
        adManager.finalizeCancel(p);
    }

    /// A shorten made before the lock, naming a date inside the window: the slot dies at the date.
    function test_realRegistry_shortenBeforeTheLockNamingADateInside_waitsTheGrace() public {
        _realRegistry();
        vm.warp(_graceTs() - 12 hours);
        _setValidUntil(0, false);
        vm.warp(block.timestamp + 10);
        IAdManager.OrderParams memory p = _lockAs(3);
        assertTrue(_graceTs() > block.timestamp && _graceTs() < p.deadline, "the date is inside");
        _claim(p);
        vm.warp(p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);
    }

    /// D15 at the boundary: a kill in the deadline's own second counts; one second later it does not.
    function test_realRegistry_killAtTheDeadline_counts() public {
        _realRegistry();
        IAdManager.OrderParams memory p = _lockAs(4);
        vm.warp(p.deadline);
        _setValidUntil(0, true);
        adManager.claimCancel(p);
        vm.warp(p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);
    }

    /// D16: past the presentation cutoff (window end − margin; margin 0 here) the co-signed payout
    /// could not land, so a kill there denies nothing.
    function test_realRegistry_killAfterTheCutoff_ordinaryTiming() public {
        _realRegistry();
        IAdManager.OrderParams memory p = _lockAs(5);
        _claim(p);
        vm.warp(p.deadline + 30 minutes + 1);
        _setValidUntil(0, true);
        adManager.finalizeCancel(p);
    }

    /// Pass 5 (PoC e): the co-signed unlock is accepted until the cutoff, not the deadline. A kill
    /// in the gap blocks the payout, so the cancel waits.
    function test_realRegistry_killBetweenTheDeadlineAndTheCutoff_waitsTheGrace() public {
        _realRegistry();
        IAdManager.OrderParams memory p = _lockAs(6);
        _claim(p);
        vm.warp(p.deadline + 10 minutes);
        _setValidUntil(0, true);
        vm.warp(p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);
        vm.warp(p.deadline + 60 minutes);
        adManager.finalizeCancel(p);
    }

    /// Pass 5 (PoC f): a shorten naming a date in the gap is the same denial by another route.
    function test_realRegistry_shortenNamingADateInTheGap_waitsTheGrace() public {
        _realRegistry();
        vm.warp(_graceTs() - 1 days - 10 minutes);
        IAdManager.OrderParams memory p = _lockAs(7);
        assertTrue(_graceTs() > p.deadline && _graceTs() <= p.deadline + 30 minutes, "the date is in the gap");
        _setValidUntil(0, false);
        _claim(p);
        vm.warp(p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);
    }

    /// Pass 5 (PoC h/h2): a slot that died inside the window, re-killed to `1` after it, still
    /// reads as dying inside it (D14b).
    function test_realRegistry_reKillAfterTheWindow_keepsTheInWindowExpiry() public {
        _realRegistry();
        vm.warp(_graceTs() - 12 hours);
        IAdManager.OrderParams memory p = _lockAs(8);
        _setValidUntil(0, false);
        _claim(p);
        vm.warp(p.deadline + 30 minutes + 1);
        _setValidUntil(0, true);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);
    }

    /// D16 at the boundary, under a margin so the cutoff and the window end differ: a kill in the
    /// cutoff's own second counts, the next second does not.
    function test_realRegistry_killAtTheCutoff_counts() public {
        _realRegistry();
        _setTiming(RouteTiming.Timing(1 hours, 30 minutes, 5 minutes, 1 days, 0));
        IAdManager.OrderParams memory p = _lockAs(9);
        _claim(p);
        vm.warp(p.deadline + 25 minutes);
        _setValidUntil(0, true);
        vm.warp(p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);
    }

    /// D17a: a kill, an at-cap registration and a lock in the same second. The prune must not run
    /// in the expiry's own second, or the lock's-second kill the design counts is forgotten.
    function test_realRegistry_sameSecondKillPruneAndLock_stillWaitsTheGrace() public {
        _realRegistry();
        for (uint256 i = 2; i < 5; i++) {
            _registerSlot(i);
        }
        address[] memory guards = new address[](1);
        guards[0] = address(adManager);
        registry.setPositionGuards(guards);
        _setValidUntil(0, true);
        vm.expectRevert(IBLSKeyRegistry.RegistryFull.selector);
        _registerSlot(5);
        IAdManager.OrderParams memory p = _lockAs(13);
        _claim(p);
        vm.warp(p.deadline + 30 minutes);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, p.deadline + 60 minutes));
        adManager.finalizeCancel(p);
    }

    /// The view the relayer's janitor plans around must carry the same bound as the door.
    function test_realRegistry_cancelFinalizesAt_readsTheGraceForAKillInTheGap() public {
        _realRegistry();
        IAdManager.OrderParams memory p = _lockAs(14);
        _claim(p);
        vm.warp(p.deadline + 10 minutes);
        _setValidUntil(0, true);
        assertEq(adManager.cancelFinalizesAt(p), p.deadline + 60 minutes, "window end + grace");
    }

    function test_realRegistry_killJustPastTheCutoff_ordinaryTiming() public {
        _realRegistry();
        _setTiming(RouteTiming.Timing(1 hours, 30 minutes, 5 minutes, 1 days, 0));
        IAdManager.OrderParams memory p = _lockAs(10);
        _claim(p);
        vm.warp(p.deadline + 25 minutes + 1);
        _setValidUntil(0, true);
        vm.warp(p.deadline + 30 minutes);
        adManager.finalizeCancel(p);
    }
}

/// Pass 5 (PoC g): the dispute door runs to the effective challenge deadline, past the cancel's
/// cutoff. A kill in between blocks the payout the module still accepts, so the fallback waits.
contract SettlementHaltDisputeRealRegistryTest is RealRegistryFixture, DisputeTest {
    function setUp() public override(AdManagerTest, DisputeTest) {
        DisputeTest.setUp();
    }

    function test_realRegistry_killBeforeTheChallengeDeadline_fallbackWaitsTheGrace() public {
        _realRegistry();
        IAdManager.OrderParams memory p = _lockAs(11);
        bytes32 h = adManager.hashOrderPublic(p);
        // Filed late enough that the challenge period outruns the cancel window.
        vm.warp(p.deadline - 1 hours);
        _file(p, maker);
        uint256 until_ = dm.effectiveChallengeDeadline(h);
        assertGt(until_, p.deadline + 30 minutes, "the dispute door outlives the cancel cutoff");
        vm.warp(p.deadline + 45 minutes);
        _setValidUntil(0, true);
        vm.warp(until_ + 1);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__TooEarly.selector, until_ + 30 minutes));
        adManager.finalizeDispute(p);
        vm.warp(until_ + 30 minutes);
        adManager.finalizeDispute(p);
        assertEq(uint256(adManager.orders(h)), uint256(IEscrow.Status.Resolved));
    }

    function test_realRegistry_killAfterTheChallengeDeadline_fallbackOrdinaryTiming() public {
        _realRegistry();
        IAdManager.OrderParams memory p = _lockAs(12);
        bytes32 h = adManager.hashOrderPublic(p);
        vm.warp(p.deadline - 1 hours);
        _file(p, maker);
        uint256 until_ = dm.effectiveChallengeDeadline(h);
        vm.warp(until_ + 1);
        _setValidUntil(0, true);
        adManager.finalizeDispute(p);
        assertEq(uint256(adManager.orders(h)), uint256(IEscrow.Status.Resolved));
    }
}
