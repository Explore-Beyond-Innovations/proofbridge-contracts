// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {IEscrow} from "src/interfaces/IEscrow.sol";
import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IDisputeManager} from "src/interfaces/IDisputeManager.sol";
import {IRootAnchor} from "src/interfaces/IRootAnchor.sol";
import {IVerifier} from "src/interfaces/IVerifier.sol";
import {IMerkleManager} from "src/interfaces/IMerkleManager.sol";
import {IwNativeToken, wNativeToken} from "src/wNativeToken.sol";
import {AdManager} from "src/AdManager.sol";
import {DisputeManager} from "src/DisputeManager.sol";
import {MerkleManager} from "src/MerkleManager.sol";
import {RootAnchor} from "src/RootAnchor.sol";
import {Dispute} from "src/libraries/Dispute.sol";
import {FieldElement} from "src/libraries/FieldElement.sol";
import {RouteTiming} from "src/libraries/RouteTiming.sol";
import {MockVerifier} from "test/mocks/MockVerifier.sol";
import {MockKeyRegistry} from "./mocks/MockKeyRegistry.sol";
import {MockRootVerifier} from "./mocks/MockRootVerifier.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {Poseidon2Yul_BN254 as Poseidon2Yul} from "@poseidon2/src/bn254/yul/Poseidon2Yul.sol";

/*//////////////////////////////////////////////////////////////
       2.3g — the escrow/module correspondence, over sequences
//////////////////////////////////////////////////////////////*/

/// Deliberately standalone rather than extending the AdManager suite.
///
/// In Foundry, inheriting a test contract inherits its *tests*, so a harness built by subclassing
/// re-runs every inherited test under a `setUp` they were not written for — and re-runs the
/// invariants for each subclass too. Both happened here before this file existed: 46 failures and a
/// suite that took minutes. A harness gets its own fixture.
///
/// C-18: the handler used to only file, rule and warp, so no order ever reached a terminal state
/// and `invariant_noTerminalOrderKeepsItsDispute` checked nothing. It now also finalizes, presents
/// evidence, unlocks, cancels, claims, responds and pauses (then unpauses); either party files; and
/// `afterInvariant` fails the run if any terminal state was never reached.
contract DisputeInvariantTest is Test {
    AdManager internal adManager;
    DisputeManager internal dm;
    MerkleManager internal merkleManager;
    wNativeToken internal wNative;
    ERC20Mock internal adToken;
    RootAnchor internal anchor;

    address internal admin = makeAddr("admin");
    address internal maker = makeAddr("maker");
    address internal bridger = makeAddr("bridger");
    address internal recipient = makeAddr("recipient");
    address internal arbiter = makeAddr("arbiter");
    address internal feePool = makeAddr("feePool");
    address internal orderPortal = makeAddr("orderPortal");
    address internal orderToken = makeAddr("orderToken");

    uint256 internal orderChainId = 11155111;
    uint64 internal constant CHALLENGE = 2 hours;
    uint128 internal constant BOND_FLOOR = 1 ether;
    uint16 internal constant BOND_BPS = 100;
    uint256 internal constant LOCK = 1 ether;
    /// Bounded so every invariant's loop stays cheap; a campaign locks well under this many.
    uint256 internal constant MAX_ORDERS = 64;
    /// One notarized root, reused: the mock verifier accepts any event proof against it.
    bytes32 internal constant EVIDENCE_ROOT = bytes32(uint256(0xe71d));

    DisputeHandler internal handler;

    IAdManager.OrderParams[] internal orders;
    bytes32[] internal hashes;
    uint256 internal nonce;

    function setUp() public {
        merkleManager = new MerkleManager(admin, address(new Poseidon2Yul()));
        wNative = new wNativeToken("Wrapped Native Token", "WNATIVE", 18);
        MockKeyRegistry keyRegistry = new MockKeyRegistry();
        keyRegistry.set(bytes32(uint256(uint160(maker))), true);

        adManager = new AdManager(
            admin,
            IVerifier(address(new MockVerifier(true))),
            IMerkleManager(address(merkleManager)),
            IwNativeToken(address(wNative))
        );
        dm = new DisputeManager(admin, IwNativeToken(address(wNative)));
        address[] memory signers = new address[](1);
        signers[0] = address(this);
        anchor = new RootAnchor(admin, signers, 1);
        anchor.anchor(orderChainId, EVIDENCE_ROOT, 1);

        vm.startPrank(admin);
        merkleManager.grantRole(merkleManager.MANAGER_ROLE(), address(adManager));
        adManager.setRootVerifier(orderChainId, address(new MockRootVerifier(true)));
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(0, 30 minutes, 0, 1 days, 0));
        adManager.setKeyRegistry(keyRegistry);
        adManager.setPeerEscrow(orderChainId, bytes32(uint256(uint160(orderPortal))));
        adManager.setDisputeManager(IDisputeManager(address(dm)));
        adManager.setRootAnchor(IRootAnchor(address(anchor)));
        dm.setEscrow(address(adManager), true);
        dm.setArbiter(arbiter);
        dm.setProtocolFeePool(feePool);
        dm.setDisputeParams(orderChainId, Dispute.Params(CHALLENGE, BOND_FLOOR, BOND_BPS));
        vm.stopPrank();

        adToken = new ERC20Mock();
        adToken.mint(maker, 1_000_000 ether);
        vm.startPrank(admin);
        adManager.setTokenRoute(address(adToken), orderChainId, bytes32(uint256(uint160(orderToken))));
        vm.stopPrank();

        vm.startPrank(maker);
        adToken.approve(address(adManager), type(uint256).max);
        adManager.createAd(
            "inv",
            address(adToken),
            500_000 ether,
            orderChainId,
            bytes32(uint256(uint160(recipient))),
            bytes32(uint256(uint160(maker)))
        );
        vm.stopPrank();

        handler = new DisputeHandler(this);
        targetContract(address(handler));
    }

    /*//////////////////// what the handler may do ////////////////////*/

    /// A fresh order. Each gets its own salt and deadline, fixed here, so later actions rebuild the
    /// same hash however far the clock has moved.
    function handlerLock(uint256 seed) public returns (uint256 i) {
        require(orders.length < MAX_ORDERS, "full");
        IAdManager.OrderParams memory p = _params(nonce++, block.timestamp + 1 hours + seed % 6 days);
        // The maker locks its own ad's liquidity; the suite pranks for the same reason.
        vm.prank(maker);
        bytes32 h = adManager.lockForOrder(p);
        orders.push(p);
        hashes.push(h);
        i = orders.length - 1;
    }

    /// Lock and file in one step, by either party (D11: only the order's two parties may file).
    function handlerLockAndFile(uint256 seed, bool byBridger) external returns (bool bridgerFiled) {
        bridgerFiled = _file(handlerLock(seed), byBridger);
    }

    /// File on an order that is already live (Open or Claimed), not only a fresh one.
    function handlerFile(uint256 pick, bool byBridger) external returns (bool bridgerFiled) {
        bridgerFiled = _file(_pick(pick, _mask(IEscrow.Status.Open) | _mask(IEscrow.Status.Claimed)), byBridger);
    }

    function handlerRule(uint256 pick, uint8 outcome) external {
        uint256 i = _pick(pick, _mask(IEscrow.Status.Disputed));
        vm.prank(arbiter);
        dm.resolveDispute(hashes[i], Dispute.Outcome(outcome % 5));
    }

    /// The party that did not file answers.
    function handlerRespond(uint256 pick) external {
        uint256 i = _pick(pick, _mask(IEscrow.Status.Disputed));
        address other = dm.initiatorOf(hashes[i]) == maker ? recipient : maker;
        vm.prank(other);
        adManager.respondToDispute(orders[i], bytes32("answer"));
    }

    /// Nobody ruled: anyone opens the fallback once the window is over.
    function handlerClaim(uint256 pick) external {
        uint256 i = _pick(pick, _mask(IEscrow.Status.Disputed));
        _warpTo(dm.effectiveChallengeDeadline(hashes[i]));
        dm.claimDispute(hashes[i]);
    }

    /// Run the window out and finalize. Returns the outcome applied (no ruling means MutualRefund).
    function handlerFinalize(uint256 pick) external returns (uint8 outcome) {
        uint256 i = _pick(pick, _mask(IEscrow.Status.Disputed));
        _warpTo(dm.effectiveChallengeDeadline(hashes[i]));
        (Dispute.Outcome o,,) = dm.outcomeOf(hashes[i], adManager.pausedSeconds());
        adManager.finalizeDispute(orders[i]);
        outcome = uint8(o == Dispute.Outcome.None ? Dispute.Outcome.MutualRefund : o);
    }

    /// Evidence: the order chain's SETTLED leaf. Beats any dispute, at any time.
    function handlerPresent(uint256 pick) external returns (bool wasDisputed) {
        uint256 i = _pick(pick, _live());
        wasDisputed = adManager.orders(hashes[i]) == IEscrow.Status.Disputed;
        adManager.presentSettled(orders[i], EVIDENCE_ROOT, hex"");
    }

    /// The co-signed unlock, which is evidence too.
    function handlerUnlock(uint256 pick) external returns (bool wasDisputed) {
        uint256 i = _pickInTime(pick);
        if (i == type(uint256).max) i = handlerLock(pick);
        wasDisputed = adManager.orders(hashes[i]) == IEscrow.Status.Disputed;
        vm.prank(bridger);
        adManager.unlock(orders[i], _nullifier(hashes[i]), bytes32(uint256(1)), hex"", hex"");
    }

    /// The clock path: claim at the deadline, finalize once the window is over.
    function handlerCancel(uint256 pick) external {
        // Open orders are what every other action consumes, so lock one when none is left.
        uint256 i = _hasAny(_mask(IEscrow.Status.Open)) ? _pick(pick, _mask(IEscrow.Status.Open)) : handlerLock(pick);
        _warpTo(orders[i].deadline);
        adManager.claimCancel(orders[i]);
        _warpTo(adManager.cancelFinalizesAt(orders[i]));
        adManager.finalizeCancel(orders[i]);
    }

    /// Pause, let time pass, unpause. One step, so a campaign is never left frozen for the rest of
    /// its run, and every window after it has to absorb the paused seconds.
    function handlerPauseFor(uint32 secs) external {
        vm.prank(admin);
        adManager.pause();
        vm.warp(block.timestamp + secs % 1 days);
        vm.prank(admin);
        adManager.unpause();
    }

    function handlerWarp(uint32 by) external {
        vm.warp(block.timestamp + by);
    }

    /// Returns whether the module recorded the bridger-side party as the filer.
    function _file(uint256 i, bool byBridger) internal returns (bool bridgerFiled) {
        uint256 bond = Dispute.bondFor(LOCK, Dispute.Params(CHALLENGE, BOND_FLOOR, BOND_BPS));
        address who = byBridger ? recipient : maker;
        // C-17: the bond is paid exactly; any other value is refused.
        vm.deal(who, bond);
        vm.prank(who);
        adManager.dispute{value: bond}(orders[i], bytes32("e"));
        bridgerFiled = dm.initiatorOf(hashes[i]) == recipient;
    }

    /// The first order at or after `pick` (mod the count) whose status is in `mask`.
    function _pick(uint256 pick, uint256 mask) internal view returns (uint256) {
        uint256 n = orders.length;
        require(n > 0, "none");
        for (uint256 k = 0; k < n; k++) {
            uint256 i = (pick % n + k) % n;
            if (mask & _mask(adManager.orders(hashes[i])) != 0) return i;
        }
        revert("no order in that state");
    }

    /// Like `_pick` over live orders, skipping any whose unlock cutoff has already passed; max if none.
    function _pickInTime(uint256 pick) internal view returns (uint256) {
        uint256 n = orders.length;
        for (uint256 k = 0; k < n; k++) {
            uint256 i = (pick % n + k) % n;
            if (_live() & _mask(adManager.orders(hashes[i])) == 0) continue;
            if (block.timestamp <= orders[i].deadline + 30 minutes) return i;
        }
        return type(uint256).max;
    }

    function _hasAny(uint256 mask) internal view returns (bool) {
        for (uint256 i = 0; i < hashes.length; i++) {
            if (mask & _mask(adManager.orders(hashes[i])) != 0) return true;
        }
        return false;
    }

    function _mask(IEscrow.Status s) internal pure returns (uint256) {
        return uint256(1) << uint8(s);
    }

    function _live() internal pure returns (uint256) {
        return _mask(IEscrow.Status.Open) | _mask(IEscrow.Status.Claimed) | _mask(IEscrow.Status.Disputed);
    }

    function _warpTo(uint256 t) internal {
        if (block.timestamp < t) vm.warp(t);
    }

    function _nullifier(bytes32 h) internal pure returns (bytes32) {
        return bytes32(uint256(keccak256(abi.encode("inv-nullifier", h))) % FieldElement.prime());
    }

    function _params(uint256 salt, uint256 deadline) internal view returns (IAdManager.OrderParams memory p) {
        p.orderChainToken = bytes32(uint256(uint160(orderToken)));
        p.adChainToken = bytes32(uint256(uint160(address(adToken))));
        p.amount = LOCK;
        p.bridger = bytes32(uint256(uint160(bridger)));
        p.orderChainId = orderChainId;
        p.srcOrderPortal = bytes32(uint256(uint160(orderPortal)));
        p.orderRecipient = bytes32(uint256(uint160(recipient)));
        p.adId = "inv";
        p.adCreator = bytes32(uint256(uint160(maker)));
        p.adRecipient = bytes32(uint256(uint160(recipient)));
        p.salt = salt;
        p.orderDecimals = 18;
        p.adDecimals = 18;
        p.deadline = deadline;
        p.adSettlementSigner = bytes32(uint256(uint160(maker)));
    }

    /*//////////////////////// the invariants ////////////////////////*/

    /// An order is `Disputed` on the escrow if and only if the module holds a record for it.
    ///
    /// This is the property the two-contract split created the need for, and it is stronger than a
    /// targeted regression test: that proves one specific mistake is caught, this proves no
    /// reachable sequence breaks the correspondence — including paths nobody thought of.
    function invariant_disputedIffModuleHasARecord() public view {
        for (uint256 i = 0; i < hashes.length; i++) {
            bytes32 h = hashes[i];
            assertEq(adManager.orders(h) == IEscrow.Status.Disputed, dm.isDisputed(h), "escrow and module disagree");
        }
    }

    /// Every bond the module recorded, and every payout it credited, is backed by wrapped native it
    /// holds.
    function invariant_moduleIsSolventForItsBonds() public view {
        uint256 owed = dm.claimable(maker) + dm.claimable(recipient) + dm.claimable(feePool);
        for (uint256 i = 0; i < hashes.length; i++) {
            (, uint128 bond,,,,,,,) = dm.disputes(hashes[i]);
            owed += bond;
        }
        assertGe(wNative.balanceOf(address(dm)), owed, "module cannot cover its bonds");
    }

    /// No order may sit in a terminal state while the module still holds its dispute. This is the
    /// structural version of "every evidence path must close the dispute": a new path that forgets
    /// to strands the bond forever, because once the status leaves `Disputed` nothing can call
    /// `finalizeDispute` again. Stating it as an invariant means the next such path fails here
    /// rather than shipping — which is how the first four escaped review.
    function invariant_noTerminalOrderKeepsItsDispute() public view {
        for (uint256 i = 0; i < hashes.length; i++) {
            bytes32 h = hashes[i];
            IEscrow.Status st = adManager.orders(h);
            bool terminal =
                st == IEscrow.Status.Filled || st == IEscrow.Status.Cancelled || st == IEscrow.Status.Resolved;
            if (terminal) assertFalse(dm.isDisputed(h), "terminal order still holds a dispute");
        }
    }

    /// No dispute may finalize before the order's own deadline plus the route buffer, however short
    /// the challenge period is (T-50). The bug this catches let any third party cancel a week-long
    /// order an hour after filing.
    function invariant_noDisputeFinalizesBeforeTheDeadline() public view {
        for (uint256 i = 0; i < hashes.length; i++) {
            bytes32 h = hashes[i];
            if (!dm.isDisputed(h)) continue;
            (,,,,,,, uint64 orderDeadline, uint64 buffer) = dm.disputes(h);
            assertGe(
                dm.effectiveChallengeDeadline(h),
                uint256(orderDeadline) + buffer,
                "a dispute could finalize before deadline + buffer"
            );
        }
    }

    /// Every live order (Open, Claimed, Disputed) holds its lock and its in-flight count, and no
    /// terminal one does, whichever path ended it.
    function invariant_onlyLiveOrdersHoldTheirLock() public view {
        uint256 live;
        for (uint256 i = 0; i < hashes.length; i++) {
            if (_live() & _mask(adManager.orders(hashes[i])) != 0) live++;
        }
        (,,,,,,,, uint256 locked) = adManager.ads("inv");
        assertEq(locked, live * LOCK, "locked liquidity does not match the live orders");
        assertEq(adManager.inFlightOf(bytes32(uint256(uint160(maker)))), live, "in-flight count drifted");
    }

    /// C-18 vacuity: every run must reach each terminal state, or the invariants above were green
    /// over states they never saw. Forge calls this once at the end of every run.
    function afterInvariant() public view {
        assertGt(handler.filedByMaker(), 0, "the maker never filed");
        assertGt(handler.filedByBridger(), 0, "the bridger never filed");
        assertGt(handler.resolved(), 0, "no dispute was ever finalized (Resolved)");
        assertGt(handler.filledByEvidence(), 0, "presentSettled never filled an order");
        assertGt(handler.filledByUnlock(), 0, "unlock never filled an order");
        assertGt(handler.disputesClosedByEvidence(), 0, "evidence never closed a dispute");
        assertGt(handler.cancelled(), 0, "no order was ever cancelled");
        assertGt(handler.pauses(), 0, "the escrow was never paused");
    }

    /// Proves the harness reaches the state the invariants police. Without this a handler that
    /// reverts on every call yields green invariants that tested nothing — which is exactly what the
    /// first version did, silently, over 128,000 calls.
    function test_handlerFilesDisputesForReal() public {
        handler.file(1, false);
        handler.file(2, true);
        assertEq(handler.filedByMaker(), 1, "the maker's filing did not land");
        assertEq(handler.filedByBridger(), 1, "the bridger's filing did not land");
    }

    /// Each terminal path the campaign relies on, once, in order. A handler step that silently
    /// reverts shows up here as a zero.
    function test_everyTerminalPathIsReachable() public {
        handler.file(1, false); // order 0, disputed by the maker
        handler.file(2, true); // order 1, disputed by the bridger
        handler.lock(3); // order 2, open
        handler.lock(4); // order 3, open
        handler.present(0); // closes order 0's dispute by evidence
        handler.unlock(2); // before any warp, while order 2 is inside its cutoff
        handler.rule(1, uint8(Dispute.Outcome.MakerForfeit));
        handler.finalize(1);
        handler.cancel(3);
        handler.pauseFor(1 hours);
        assertEq(handler.disputesClosedByEvidence(), 1, "evidence closed no dispute");
        assertEq(handler.filledByEvidence(), 1);
        assertEq(handler.resolved(), 1);
        assertEq(handler.resolvedAs(uint8(Dispute.Outcome.MakerForfeit)), 1);
        assertEq(handler.filledByUnlock(), 1);
        assertEq(handler.cancelled(), 1);
        assertEq(handler.pauses(), 1);
    }
}

/// Drives the dispute surface, swallowing reverts so only successful paths shape state. Counts
/// every success so `afterInvariant` can tell a campaign that explored from one that did not.
contract DisputeHandler {
    DisputeInvariantTest internal immutable t;

    uint256 public filedByMaker;
    uint256 public filedByBridger;
    uint256 public resolved;
    mapping(uint8 => uint256) public resolvedAs;
    uint256 public filledByEvidence;
    uint256 public filledByUnlock;
    uint256 public disputesClosedByEvidence;
    uint256 public cancelled;
    uint256 public pauses;

    constructor(DisputeInvariantTest t_) {
        t = t_;
    }

    function lock(uint256 seed) external {
        try t.handlerLock(seed) {} catch {}
    }

    function file(uint256 seed, bool byBridger) external {
        try t.handlerLockAndFile(seed, byBridger) returns (bool bridgerFiled) {
            _countFiling(bridgerFiled);
        } catch {}
    }

    function fileLive(uint256 pick, bool byBridger) external {
        try t.handlerFile(pick, byBridger) returns (bool bridgerFiled) {
            _countFiling(bridgerFiled);
        } catch {}
    }

    function rule(uint256 pick, uint8 outcome) external {
        try t.handlerRule(pick, outcome) {} catch {}
    }

    function respond(uint256 pick) external {
        try t.handlerRespond(pick) {} catch {}
    }

    function claim(uint256 pick) external {
        try t.handlerClaim(pick) {} catch {}
    }

    function finalize(uint256 pick) external {
        try t.handlerFinalize(pick) returns (uint8 outcome) {
            resolved++;
            resolvedAs[outcome]++;
        } catch {}
    }

    function present(uint256 pick) external {
        try t.handlerPresent(pick) returns (bool wasDisputed) {
            filledByEvidence++;
            if (wasDisputed) disputesClosedByEvidence++;
        } catch {}
    }

    function unlock(uint256 pick) external {
        try t.handlerUnlock(pick) returns (bool wasDisputed) {
            filledByUnlock++;
            if (wasDisputed) disputesClosedByEvidence++;
        } catch {}
    }

    function cancel(uint256 pick) external {
        try t.handlerCancel(pick) {
            cancelled++;
        } catch {}
    }

    function pauseFor(uint32 secs) external {
        try t.handlerPauseFor(secs) {
            pauses++;
        } catch {}
    }

    function warp(uint32 by) external {
        try t.handlerWarp(by) {} catch {}
    }

    function _countFiling(bool byBridger) internal {
        if (byBridger) filedByBridger++;
        else filedByMaker++;
    }
}
