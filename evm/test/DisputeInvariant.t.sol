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
///
/// 49E-4: the admin may also swap the dispute module mid-campaign (C-11: an open dispute stays on
/// the module it was filed under), the recipient refuses native so its bond refunds are credited,
/// and it withdraws them with `claimTo` (C-16). `afterInvariant` requires every finalized outcome,
/// a swap with a dispute finalized on an older module, and a `claimTo`.
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
    /// A contract that refuses native, so the module credits its bond refunds (set in setUp).
    address internal recipient;
    /// Where the recipient's credit goes with `claimTo`; only that call ever pays it.
    address internal recipientWallet = makeAddr("recipientWallet");
    address internal arbiter = makeAddr("arbiter");
    address internal feePool = makeAddr("feePool");
    address internal orderPortal = makeAddr("orderPortal");
    address internal orderToken = makeAddr("orderToken");

    uint256 internal orderChainId = 11155111;
    uint64 internal constant CHALLENGE = 2 hours;
    uint128 internal constant BOND_FLOOR = 1 ether;
    uint16 internal constant BOND_BPS = 100;
    uint256 internal constant LOCK = 1 ether;
    /// Bounded so every invariant's loop stays cheap.
    /// The last slots only the steps `afterInvariant` counts on (outcomes, evidence, swap, unlock,
    /// cancel) may use, so the general locks never crowd them out.
    uint256 internal constant MAX_ORDERS = 64;
    uint256 internal constant RESERVED = 16;
    /// One swap is what C-11 needs (a dispute left on the old module); every invariant walks each
    /// module, so more would only slow the campaign.
    uint256 internal constant MAX_MODULES = 2;
    /// One notarized root, reused: the mock verifier accepts any event proof against it.
    bytes32 internal constant EVIDENCE_ROOT = bytes32(uint256(0xe71d));

    DisputeHandler internal handler;

    IAdManager.OrderParams[] internal orders;
    bytes32[] internal hashes;
    uint256 internal nonce;
    /// Every module the escrow was ever wired to, the first included.
    DisputeManager[] internal modules;
    /// Ghost: the total `claimTo` moved to `recipientWallet`.
    uint256 internal claimedTo;

    function setUp() public {
        recipient = address(new NativeRefuser());
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
        modules.push(dm);
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
        require(orders.length < MAX_ORDERS - RESERVED, "full");
        i = _lockOrder(seed);
    }

    function _lockOrder(uint256 seed) internal returns (uint256 i) {
        i = _lockOrderWithin(seed, MAX_ORDERS);
    }

    function _lockOrderWithin(uint256 seed, uint256 cap) internal returns (uint256 i) {
        require(orders.length < cap, "full");
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
        DisputeManager m = _moduleOf(i); // read before the prank, which the next call consumes
        vm.prank(arbiter);
        m.resolveDispute(hashes[i], Dispute.Outcome(outcome % 5));
    }

    /// The party that did not file answers.
    function handlerRespond(uint256 pick) external {
        uint256 i = _pick(pick, _mask(IEscrow.Status.Disputed));
        address other = _moduleOf(i).initiatorOf(hashes[i]) == maker ? recipient : maker;
        vm.prank(other);
        adManager.respondToDispute(orders[i], bytes32("answer"));
    }

    /// Nobody ruled: anyone opens the fallback once the window is over.
    function handlerClaim(uint256 pick) external {
        uint256 i = _pick(pick, _mask(IEscrow.Status.Disputed));
        _warpTo(_moduleOf(i).effectiveChallengeDeadline(hashes[i]));
        _moduleOf(i).claimDispute(hashes[i]);
    }

    /// Run the window out and finalize. Returns the outcome applied (no ruling means MutualRefund),
    /// and whether the dispute was filed under a module the escrow has since swapped out.
    function handlerFinalize(uint256 pick) external returns (uint8 outcome, bool onOldModule) {
        return _finalize(_pick(pick, _mask(IEscrow.Status.Disputed)));
    }

    /// Every finalize outcome in one step (a forfeit each way, and an unruled MutualRefund), so each is
    /// reached in every run: ruling needs an open window, which the warps elsewhere close.
    function handlerEveryOutcome(uint256 seed) external returns (bool onOldModule) {
        bool a;
        bool b;
        bool c;
        (, a) = _fileRuleFinalize(seed, Dispute.Outcome.MakerForfeit);
        (, b) = _fileRuleFinalize(seed + 1, Dispute.Outcome.BridgerForfeit);
        (, c) = _fileRuleFinalize(seed + 2, Dispute.Outcome.None);
        onOldModule = a || b || c;
    }

    /// File, then close the dispute with evidence, in one step: the forfeit and swap steps finalize
    /// disputes too, so evidence closing one has to be reachable in every run on its own.
    function handlerFileAndPresent(uint256 seed, bool byBridger) external {
        uint256 i = _lockOrder(seed);
        _file(i, byBridger);
        adManager.presentSettled(orders[i], EVIDENCE_ROOT, hex"");
    }

    /// The party a ruling vindicates files (the maker for a BridgerForfeit); `None` leaves it unruled.
    function _fileRuleFinalize(uint256 seed, Dispute.Outcome ruling)
        internal
        returns (uint8 outcome, bool onOldModule)
    {
        uint256 i = _lockOrder(seed);
        _file(i, ruling != Dispute.Outcome.BridgerForfeit);
        if (ruling != Dispute.Outcome.None) {
            DisputeManager m = _moduleOf(i); // read before the prank, which the next call consumes
            vm.prank(arbiter);
            m.resolveDispute(hashes[i], ruling);
        }
        (outcome, onOldModule) = _finalize(i);
        Dispute.Outcome want = ruling == Dispute.Outcome.None ? Dispute.Outcome.MutualRefund : ruling;
        require(outcome == uint8(want), "ruling lost");
    }

    function _finalize(uint256 i) internal returns (uint8 outcome, bool onOldModule) {
        DisputeManager m = _moduleOf(i);
        onOldModule = address(m) != address(adManager.disputeManager());
        _warpTo(m.effectiveChallengeDeadline(hashes[i]));
        (Dispute.Outcome o,,) = m.outcomeOf(hashes[i], adManager.pausedSeconds());
        adManager.finalizeDispute(orders[i]);
        outcome = uint8(o == Dispute.Outcome.None ? Dispute.Outcome.MutualRefund : o);
    }

    /// C-11: the admin wires a fresh module. New filings go to it; open disputes stay where they are.
    /// One left-behind dispute is finalized in the same step (so every run reaches that path); any
    /// others stay open on the old module for the rest of the campaign.
    function handlerSwapModule(uint256 pick) external returns (uint8 outcome) {
        require(modules.length < MAX_MODULES, "enough modules");
        // With a dispute open on the old module, filed here if there is none, so one is left behind.
        if (!_hasAny(_mask(IEscrow.Status.Disputed))) {
            // One slot past the cap is the swap's own: it happens once, and must not depend on room.
            _file(_lockOrderWithin(pick, MAX_ORDERS + 1), false);
        }
        DisputeManager next = new DisputeManager(admin, IwNativeToken(address(wNative)));
        vm.startPrank(admin);
        next.setEscrow(address(adManager), true);
        next.setArbiter(arbiter);
        next.setProtocolFeePool(feePool);
        next.setDisputeParams(orderChainId, Dispute.Params(CHALLENGE, BOND_FLOOR, BOND_BPS));
        adManager.setDisputeManager(IDisputeManager(address(next)));
        vm.stopPrank();
        modules.push(next);
        bool onOldModule;
        (outcome, onOldModule) = _finalize(_pick(pick, _mask(IEscrow.Status.Disputed)));
        require(onOldModule, "finalized on the new module");
    }

    /// C-16: the recipient refuses native, so its refunds are credited; it redirects its own credit.
    function handlerClaimTo(uint256 pick) external {
        DisputeManager m = modules[pick % modules.length];
        uint256 amount = m.claimable(recipient);
        vm.prank(recipient);
        m.claimTo(recipientWallet);
        claimedTo += amount;
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
        // The reserve too: with the general slots full, the exit paths must stay reachable.
        if (i == type(uint256).max) i = _lockOrder(pick);
        wasDisputed = adManager.orders(hashes[i]) == IEscrow.Status.Disputed;
        vm.prank(bridger);
        adManager.unlock(orders[i], _nullifier(hashes[i]), bytes32(uint256(1)), hex"", hex"");
    }

    /// The clock path: claim at the deadline, finalize once the window is over.
    function handlerCancel(uint256 pick) external {
        // Open orders are what every other action consumes, so lock one when none is left.
        // The reserve too: with the general slots full, the exit paths must stay reachable.
        uint256 i = _hasAny(_mask(IEscrow.Status.Open)) ? _pick(pick, _mask(IEscrow.Status.Open)) : _lockOrder(pick);
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
        bridgerFiled = _moduleOf(i).initiatorOf(hashes[i]) == recipient;
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

    /// The module the order's dispute was filed under (D5); zero if it never was.
    function _moduleOf(uint256 i) internal view returns (DisputeManager) {
        return DisputeManager(payable(address(adManager.disputeModuleOf(hashes[i]))));
    }

    /// Whether any module the escrow was ever wired to holds a record for `h`.
    function _anyRecord(bytes32 h) internal view returns (bool) {
        for (uint256 k = 0; k < modules.length; k++) {
            if (modules[k].isDisputed(h)) return true;
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
            bool disputed = adManager.orders(h) == IEscrow.Status.Disputed;
            assertEq(disputed, _anyRecord(h), "escrow and modules disagree");
            // C-11: and the record is on the module the order was filed under, whatever is wired now.
            if (disputed) assertTrue(_moduleOf(i).isDisputed(h), "the record is not on the order's own module");
        }
    }

    /// Every bond the module recorded, and every payout it credited, is backed by wrapped native it
    /// holds.
    /// Per module, swapped-out ones included: exactly, since a module takes in nothing but bonds.
    function invariant_moduleIsSolventForItsBonds() public view {
        for (uint256 k = 0; k < modules.length; k++) {
            DisputeManager m = modules[k];
            uint256 owed = m.claimable(maker) + m.claimable(recipient) + m.claimable(feePool);
            for (uint256 i = 0; i < hashes.length; i++) {
                (, uint128 bond,,,,,,,) = m.disputes(hashes[i]);
                owed += bond;
            }
            assertEq(wNative.balanceOf(address(m)), owed, "a module holds other than its bonds and credits");
        }
    }

    /// C-16: `claimTo` moves only the caller's own credit: the wallet holds exactly what it claimed.
    function invariant_claimToPaysOnlyTheCallersCredit() public view {
        assertEq(recipientWallet.balance, claimedTo, "claimTo paid other than the caller's credit");
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
            if (terminal) assertFalse(_anyRecord(h), "terminal order still holds a dispute");
        }
    }

    /// No dispute may finalize before the order's own deadline plus the route buffer, however short
    /// the challenge period is (T-50). The bug this catches let any third party cancel a week-long
    /// order an hour after filing.
    function invariant_noDisputeFinalizesBeforeTheDeadline() public view {
        for (uint256 i = 0; i < hashes.length; i++) {
            bytes32 h = hashes[i];
            if (adManager.orders(h) != IEscrow.Status.Disputed) continue;
            DisputeManager m = _moduleOf(i);
            (,,,,,,, uint64 orderDeadline, uint64 buffer) = m.disputes(h);
            assertGe(
                m.effectiveChallengeDeadline(h),
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
        // 49E-4: every outcome a finalize can apply, not only "something resolved".
        assertGt(handler.resolvedAs(uint8(Dispute.Outcome.MutualRefund)), 0, "no dispute finalized as MutualRefund");
        assertGt(handler.resolvedAs(uint8(Dispute.Outcome.BridgerForfeit)), 0, "no dispute finalized as BridgerForfeit");
        assertGt(handler.resolvedAs(uint8(Dispute.Outcome.MakerForfeit)), 0, "no dispute finalized as MakerForfeit");
        assertGt(handler.swaps(), 0, "the dispute module was never swapped");
        assertGt(handler.finalizedOnOldModule(), 0, "no dispute finalized on a swapped-out module");
        assertGt(handler.claimsTo(), 0, "claimTo never paid");
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

    /// 49E-4: a swap with a dispute open on the old module, both forfeits finalized, and the
    /// recipient's credited refund redirected with `claimTo`.
    function test_swapForfeitsAndClaimToAreReachable() public {
        handler.file(1, true); // order 0, filed by the bridger side on the first module
        handler.file(2, true); // order 1, the same
        handler.rule(0, uint8(Dispute.Outcome.MakerForfeit)); // the bridger side's filing vindicated
        handler.swapModule(0); // finalizes order 0 on the old module; order 1 stays open there
        handler.finalize(1); // and is finalized later, still on the old module
        handler.everyOutcome(3); // orders 2..4 on the new module, one per outcome
        assertEq(handler.swaps(), 1);
        assertEq(handler.finalizedOnOldModule(), 2, "orders 0 and 1 finalized on the swapped-out module");
        assertEq(handler.resolvedAs(uint8(Dispute.Outcome.MakerForfeit)), 2);
        assertEq(handler.resolvedAs(uint8(Dispute.Outcome.BridgerForfeit)), 1);
        assertEq(handler.resolvedAs(uint8(Dispute.Outcome.MutualRefund)), 2);
        assertGt(dm.claimable(recipient), 0, "the refused refund was credited on the first module");
        handler.claimTo(0);
        assertEq(handler.claimsTo(), 1);
        assertEq(dm.claimable(recipient), 0);
        invariant_claimToPaysOnlyTheCallersCredit();
        invariant_moduleIsSolventForItsBonds();
        invariant_disputedIffModuleHasARecord();
    }
}

/// A payout address that refuses native, so its bond refunds become credits on the module.
contract NativeRefuser {
    receive() external payable {
        revert("refusing native");
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
    uint256 public swaps;
    uint256 public finalizedOnOldModule;
    uint256 public claimsTo;

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
        try t.handlerFinalize(pick) returns (uint8 outcome, bool onOldModule) {
            resolved++;
            resolvedAs[outcome]++;
            if (onOldModule) finalizedOnOldModule++;
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

    function fileAndPresent(uint256 seed, bool byBridger) external {
        try t.handlerFileAndPresent(seed, byBridger) {
            _countFiling(byBridger);
            filledByEvidence++;
            disputesClosedByEvidence++;
        } catch {}
    }

    function everyOutcome(uint256 seed) external {
        try t.handlerEveryOutcome(seed) returns (bool onOldModule) {
            // Filed by the bridger side, the maker, the bridger side.
            _countFiling(true);
            _countFiling(false);
            _countFiling(true);
            resolved += 3;
            resolvedAs[uint8(Dispute.Outcome.MakerForfeit)]++;
            resolvedAs[uint8(Dispute.Outcome.BridgerForfeit)]++;
            resolvedAs[uint8(Dispute.Outcome.MutualRefund)]++;
            if (onOldModule) finalizedOnOldModule++;
        } catch {}
    }

    function swapModule(uint256 pick) external {
        try t.handlerSwapModule(pick) returns (uint8 outcome) {
            swaps++;
            resolved++;
            resolvedAs[outcome]++;
            finalizedOnOldModule++;
        } catch {}
    }

    function claimTo(uint256 pick) external {
        try t.handlerClaimTo(pick) {
            claimsTo++;
        } catch {}
    }

    function _countFiling(bool byBridger) internal {
        if (byBridger) filedByBridger++;
        else filedByMaker++;
    }
}
