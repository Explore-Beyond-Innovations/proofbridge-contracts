// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test, Vm} from "forge-std/Test.sol";
import {TestField} from "test/utils/TestField.sol";

import {IEscrow} from "src/interfaces/IEscrow.sol";
import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IOrderPortal} from "src/interfaces/IOrderPortal.sol";
import {IRootAnchor} from "src/interfaces/IRootAnchor.sol";
import {IVerifier} from "src/interfaces/IVerifier.sol";
import {IMerkleManager} from "src/interfaces/IMerkleManager.sol";
import {IDisputeManager} from "src/interfaces/IDisputeManager.sol";
import {IwNativeToken, wNativeToken} from "src/wNativeToken.sol";
import {BaseHonkVerifier, HonkVerifier} from "src/Verifier.sol";
import {RootAnchor} from "src/RootAnchor.sol";
import {MerkleManager} from "src/MerkleManager.sol";
import {DisputeManager} from "src/DisputeManager.sol";
import {Dispute} from "src/libraries/Dispute.sol";
import {RouteTiming} from "src/libraries/RouteTiming.sol";
import {Poseidon2Yul_BN254 as Poseidon2Yul} from "@poseidon2/src/bn254/yul/Poseidon2Yul.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";

import {MockAdManager} from "./Admanager.t.sol";
import {MockOrderPortal} from "./OrderPortal.t.sol";
import {MockVerifier} from "./mocks/MockVerifier.sol";
import {MockRootVerifier} from "./mocks/MockRootVerifier.sol";
import {MockKeyRegistry} from "./mocks/MockKeyRegistry.sol";

/// 2.5c (T-41/T-45a/T-50/T-55/T-56/T-61): the EVM half of the JOINT-outcome
/// sweep. Both legs of one logical trade live in this one world — the
/// AdManager is the primary (the dispute head, the only cancel clock), the
/// OrderPortal the follower (proof-fed, no clock of its own) — and every
/// scenario asserts one normalized joint terminal record from the shared
/// fixture, the same record the Soroban driver asserts. Conservation (T-56's
/// terminal half) rides every scenario as the epilogue.
///
/// ANCHOR DISCIPLINE: the driver anchors ONLY event-claim roots minted for
/// leaves a leg actually appended (read from its MerkleManager's events).
/// That is what renders Tier-0 "unreachability" honestly in a harness whose
/// claim tool can mint any leaf — a maliciously ANCHORED root is residual
/// 13's territory, not this sweep's.
///
/// The follower's verifier is re-etched per scenario: REAL Honk where the
/// scenario's negatives are proof-semantic (wrong domain, foreign order),
/// mock elsewhere (deposit-proof unlocks stay mock territory).
contract JointOutcomesTest is Test {
    string internal constant FIXTURE_SHA256 = "c5409fb9a6647b7c052caa4aad6c33845a67749731ba2a492a8b71a741aab459";

    bytes32 private constant LEAF_TOPIC = keccak256("DepositHashAppended(uint256,bytes32,uint256,bytes32)");

    // ── the world ────────────────────────────────────────────────────────
    address internal admin;
    address internal maker = address(0xA11CE);
    address internal bridger = address(0xB0B);
    address internal orderRecipient = address(0xFEED);
    address internal adRecipient = address(0xCAFE);
    address internal arbiter = address(0xA5B1);
    address internal feePool = address(0xF00157);

    MockVerifier internal verifierP;
    MockVerifier internal verifierF;
    bytes internal mockCode;
    bytes internal realCode;

    MerkleManager internal mmP;
    MerkleManager internal mmF;
    MockAdManager internal adManager;
    MockOrderPortal internal portal;
    wNativeToken internal wnat;
    DisputeManager internal dm;
    RootAnchor internal anchorP; // consumed by the primary (follower's roots land here)
    RootAnchor internal anchorF; // consumed by the follower (primary's roots land here)
    ERC20Mock internal adToken;
    ERC20Mock internal orderToken;

    uint64 internal constant BUFFER = 30 minutes;
    uint64 internal constant LONG_BACKSTOP = 1 days;
    uint64 internal nextSeq = 1;

    // fixture-scaled params
    uint256 internal scale;
    uint64 internal challenge;
    uint256 internal amountWei;
    uint256 internal bondWei;

    function setUp() public {
        admin = makeAddrAndKey_("admin");
        verifierP = new MockVerifier(true);
        verifierF = new MockVerifier(true);
        mockCode = address(verifierF).code;
        realCode = address(new HonkVerifier()).code;

        address poseidon = address(new Poseidon2Yul());
        mmP = new MerkleManager(admin, poseidon);
        mmF = new MerkleManager(admin, poseidon);
        wnat = new wNativeToken("Wrapped Native Token", "WNATIVE", 18);

        adManager = new MockAdManager(
            admin, IVerifier(address(verifierP)), IMerkleManager(address(mmP)), IwNativeToken(address(wnat))
        );
        portal = new MockOrderPortal(
            admin, IVerifier(address(verifierF)), IMerkleManager(address(mmF)), IwNativeToken(address(wnat))
        );
        require(address(adManager) != address(portal), "isolation");

        MockKeyRegistry keyRegistry = new MockKeyRegistry();
        keyRegistry.set(_b32(maker), true);

        string memory v = _fixture();
        scale = 10 ** vm.parseJsonUint(v, ".header.evmScaleExp");
        challenge = uint64(vm.parseJsonUint(v, ".header.challengePeriodS"));
        amountWei = vm.parseJsonUint(v, ".header.orderAmountUnits") * scale;
        bondWei = vm.parseJsonUint(v, ".header.bondUnits") * scale;
        uint128 floorWei = uint128(vm.parseJsonUint(v, ".header.bondFloorUnits") * scale);
        uint16 bps = uint16(vm.parseJsonUint(v, ".header.bondBps"));

        dm = new DisputeManager(admin, IwNativeToken(address(wnat)));
        anchorP = _anchorOf();
        anchorF = _anchorOf();
        adToken = new ERC20Mock();
        orderToken = new ERC20Mock();

        vm.startPrank(admin);
        mmP.grantRole(mmP.MANAGER_ROLE(), address(adManager));
        mmF.grantRole(mmF.MANAGER_ROLE(), address(portal));
        adManager.setRootVerifier(block.chainid, address(new MockRootVerifier(true)));
        portal.setRootVerifier(block.chainid, address(new MockRootVerifier(true)));
        adManager.setRouteTiming(block.chainid, RouteTiming.Timing(0, BUFFER, 0, LONG_BACKSTOP, 0));
        portal.setRouteTiming(block.chainid, RouteTiming.Timing(0, BUFFER, 0, LONG_BACKSTOP, 0));
        adManager.setKeyRegistry(keyRegistry);
        dm.setEscrow(address(adManager), true);
        dm.setArbiter(arbiter);
        dm.setProtocolFeePool(feePool);
        dm.setDisputeParams(block.chainid, Dispute.Params(challenge, floorWei, bps));
        adManager.setDisputeManager(IDisputeManager(address(dm)));
        adManager.setRootAnchor(IRootAnchor(address(anchorP)));
        portal.setRootAnchor(IRootAnchor(address(anchorF)));
        adManager.setPeerEscrow(block.chainid, _b32(address(portal)));
        adManager.setTokenRoute(address(adToken), block.chainid, _b32(address(orderToken)));
        portal.setPeerEscrow(block.chainid, _b32(address(adManager)));
        portal.setTokenRoute(address(orderToken), block.chainid, _b32(address(adToken)));
        vm.stopPrank();

        adToken.mint(maker, 1_000_000 ether);
        orderToken.mint(bridger, 1_000_000 ether);
    }

    function makeAddrAndKey_(string memory name) internal returns (address a) {
        (a,) = makeAddrAndKey(name);
    }

    function _anchorOf() internal returns (RootAnchor) {
        address[] memory s = new address[](1);
        s[0] = address(this);
        return new RootAnchor(address(this), s, 1);
    }

    function _fixture() internal view returns (string memory) {
        return vm.readFile("../test-vectors/joint-outcomes.json");
    }

    // ── the joint trade under test ───────────────────────────────────────
    struct World {
        string at; // json pointer to the scenario
        string name;
        IAdManager.OrderParams pP;
        IOrderPortal.OrderParams pF;
        bytes32 h; // the ONE canonical hash, both legs
        // last minted event-claim per direction (anchored on the consumer side)
        bytes32 rootOnF; // primary's leaf, anchored on the follower's anchor
        bytes proofOnF;
        bytes32 rootOnP;
        bytes proofOnP;
        bytes32 nfP;
        bytes32 nfF;
        uint256 sumBefore;
        uint256 filerBase;
        uint256 bondPaid;
    }

    /// r3 F1: the monorepo's repo-checks gate pins these constants, but it
    /// arrives with a different PR and this one merges first. Until then
    /// nothing in this repo checks them, so the driver hashes what it read.
    function test_fixturePinMatchesTheFileRead() public view {
        assertEq(
            vm.toString(sha256(bytes(_fixture()))),
            string.concat("0x", FIXTURE_SHA256),
            "joint-outcomes.json changed without repinning FIXTURE_SHA256"
        );
    }

    function test_jointOutcomeSweep() public {
        string memory v = _fixture();
        uint256 n = vm.parseJsonUint(v, ".counts.scenarios");
        for (uint256 i = 0; i < n; i++) {
            _runScenario(v, i);
        }
    }

    function _runScenario(string memory v, uint256 i) internal {
        World memory w;
        w.at = string.concat(".scenarios[", vm.toString(i), "]");
        w.name = vm.parseJsonString(v, string.concat(w.at, ".name"));

        delete _buffered;
        _openJointTrade(w, i);

        // The bond's native is dealt BEFORE the snapshot so conservation
        // holds across the scenario (D4).
        if (_scenarioDisputes(v, w.at)) {
            vm.deal(maker, maker.balance + bondWei);
            w.bondPaid = bondWei;
        }
        w.sumBefore = _worldSum();
        w.filerBase = _spendableNative(maker); // the filer is the maker on every row
        _poolBase = _spendableNative(feePool);

        vm.recordLogs();
        uint256 steps = _stepCount(v, w.at);
        for (uint256 s = 0; s < steps; s++) {
            _step(v, string.concat(w.at, ".steps[", vm.toString(s), "]"), w);
        }

        _assertRecord(v, w);
        _epilogue(v, w);
    }

    /// One canonical order, projected into both legs' param structs; the
    /// driver's first assert is the load-bearing one — one hash, two legs.
    function _openJointTrade(World memory w, uint256 i) internal {
        string memory adId = string.concat("joint-", vm.toString(i));
        vm.startPrank(maker);
        adToken.approve(address(adManager), amountWei);
        adManager.createAd(adId, address(adToken), amountWei, block.chainid, _b32(adRecipient), _b32(maker));
        vm.stopPrank();

        uint256 deadline = block.timestamp + 2 days;
        uint256 salt = 0xC0FFEE + i;

        w.pP.orderChainToken = _b32(address(orderToken));
        w.pP.adChainToken = _b32(address(adToken));
        w.pP.amount = amountWei;
        w.pP.bridger = _b32(bridger);
        w.pP.orderChainId = block.chainid;
        w.pP.srcOrderPortal = _b32(address(portal));
        w.pP.orderRecipient = _b32(orderRecipient);
        w.pP.adId = adId;
        w.pP.adCreator = _b32(maker);
        w.pP.adRecipient = _b32(adRecipient);
        w.pP.salt = salt;
        w.pP.orderDecimals = 18;
        w.pP.adDecimals = 18;
        w.pP.deadline = deadline;
        w.pP.adSettlementSigner = _b32(maker);

        w.pF.orderChainToken = _b32(address(orderToken));
        w.pF.adChainToken = _b32(address(adToken));
        w.pF.amount = amountWei;
        w.pF.bridger = _b32(bridger);
        w.pF.orderRecipient = _b32(orderRecipient);
        w.pF.adChainId = block.chainid;
        w.pF.adManager = _b32(address(adManager));
        w.pF.adId = adId;
        w.pF.adCreator = _b32(maker);
        w.pF.adRecipient = _b32(adRecipient);
        w.pF.salt = salt;
        w.pF.orderDecimals = 18;
        w.pF.adDecimals = 18;
        w.pF.deadline = deadline;
        w.pF.adSettlementSigner = _b32(maker);

        bytes32 hP = adManager.hashOrderPublic(w.pP);
        bytes32 hF = portal.hashOrderPublic(w.pF);
        assertEq(hP, hF, string.concat(w.name, ": ONE canonical hash across both legs"));
        w.h = hP;
        w.nfP = TestField.fe(string.concat("nfP-", w.name));
        w.nfF = TestField.fe(string.concat("nfF-", w.name));

        vm.startPrank(bridger);
        orderToken.approve(address(portal), amountWei);
        portal.createOrder(w.pF);
        vm.stopPrank();
        vm.prank(maker);
        adManager.lockForOrder(w.pP);
    }

    // ── the step interpreter ─────────────────────────────────────────────

    function _step(string memory v, string memory sAt, World memory w) internal {
        string memory action = vm.parseJsonString(v, string.concat(sAt, ".action"));
        bool neg = vm.keyExistsJson(v, string.concat(sAt, ".expectRevert"));
        // Armed immediately before each TARGET call, never here: several steps
        // make preparatory external calls (anchoring a freshly minted root)
        // that would consume an expectation armed at the top.
        string memory reason = neg ? vm.parseJsonString(v, string.concat(sAt, ".expectRevert")) : "";

        if (_eq(action, "unlock")) {
            _useMock(_isPrimary(v, sAt));
            _unlock(w, _isPrimary(v, sAt));
        } else if (_eq(action, "unlockNearDeadline")) {
            vm.warp(w.pF.deadline - 60);
            _useMock(_isPrimary(v, sAt));
            _unlock(w, _isPrimary(v, sAt));
        } else if (_eq(action, "recordSettled")) {
            if (_isPrimary(v, sAt)) adManager.recordSettled(w.pP);
            else portal.recordSettled(w.pF);
        } else if (_eq(action, "claimCancel")) {
            if (block.timestamp < w.pP.deadline) vm.warp(w.pP.deadline);
            adManager.claimCancel(w.pP);
        } else if (_eq(action, "finalizeCancel")) {
            if (neg) _expectNamedRevert(reason, w);
            adManager.finalizeCancel(w.pP);
        } else if (_eq(action, "warpPastCancelWindow")) {
            vm.warp(block.timestamp + BUFFER + 1);
        } else if (_eq(action, "warpPastDeadline")) {
            if (block.timestamp <= w.pP.deadline) vm.warp(w.pP.deadline + 1);
        } else if (_eq(action, "dispute")) {
            vm.prank(maker);
            adManager.dispute{value: bondWei}(w.pP, bytes32("evidence"));
        } else if (_eq(action, "rule")) {
            vm.prank(arbiter);
            dm.resolveDispute(w.h, _outcome(vm.parseJsonString(v, string.concat(sAt, ".outcome"))));
        } else if (_eq(action, "warpPastWindow") || _eq(action, "warpPastChallenge")) {
            vm.warp(dm.effectiveChallengeDeadline(w.h) + 1);
        } else if (_eq(action, "claimDispute")) {
            dm.claimDispute(w.h);
        } else if (_eq(action, "finalizeDispute")) {
            if (neg) _expectNamedRevert(reason, w);
            adManager.finalizeDispute(w.pP);
        } else if (_eq(action, "anchorPrimaryLeaf")) {
            (w.rootOnF, w.proofOnF) = _mintAndAnchor(w.h, _lastLeafDomain(w.h, address(mmP)), anchorF);
        } else if (_eq(action, "anchorFollowerLeaf")) {
            (w.rootOnP, w.proofOnP) = _mintAndAnchor(w.h, _lastLeafDomain(w.h, address(mmF)), anchorP);
        } else if (_eq(action, "refundByCancel")) {
            _useReal(false);
            if (neg) _expectNamedRevert(reason, w);
            portal.refundByCancel(w.pF, w.rootOnF, w.proofOnF);
        } else if (_eq(action, "payMakerByForfeit")) {
            _useReal(false);
            if (neg) _expectNamedRevert(reason, w);
            portal.payMakerByForfeit(w.pF, w.rootOnF, w.proofOnF);
        } else if (_eq(action, "refundByCancelUnanchored")) {
            (bytes memory proof, bytes32 root) = _eventProof(2, w.h);
            _useReal(false);
            if (neg) _expectNamedRevert(reason, w);
            portal.refundByCancel(w.pF, root, proof);
        } else if (_eq(action, "refundByCancelForeignOrder")) {
            // a CANCEL claim bound to a DIFFERENT order hash, honestly anchored:
            // the proof's own public input disagrees with this order's hash.
            bytes32 foreign = keccak256(abi.encode(w.h, "foreign"));
            (bytes memory proof, bytes32 root) = _eventProof(2, foreign);
            anchorF.anchor(block.chainid, root, nextSeq++);
            _useReal(false);
            if (neg) _expectNamedRevert(reason, w);
            portal.refundByCancel(w.pF, root, proof);
        } else if (_eq(action, "presentSettled")) {
            bool prim = _isPrimary(v, sAt);
            _useReal(prim);
            if (prim) {
                adManager.presentSettled(w.pP, w.rootOnP, w.proofOnP);
            } else {
                if (neg) _expectNamedRevert(reason, w);
                portal.presentSettled(w.pF, w.rootOnF, w.proofOnF);
            }
        } else if (_eq(action, "warpPastLongBackstop")) {
            if (block.timestamp <= w.pF.deadline + LONG_BACKSTOP) vm.warp(w.pF.deadline + LONG_BACKSTOP + 1);
        } else if (_eq(action, "claimBackstop")) {
            portal.claimBackstop(w.pF);
        } else if (_eq(action, "warpPastBackstopWindow")) {
            vm.warp(block.timestamp + BUFFER + 1);
        } else if (_eq(action, "finalizeBackstop")) {
            if (neg) _expectNamedRevert(reason, w);
            portal.finalizeBackstop(w.pF);
        } else {
            revert(string.concat("unknown step: ", action));
        }
    }

    /// r3 F4: the leaf domain lives ONLY in the verifier's public inputs —
    /// EscrowBase hands `domain` to i_verifier.verify and does nothing else
    /// with it — so every event-claim consumption must run the REAL circuit or
    /// the domain goes unchecked, on BOTH escrows (etching only the follower
    /// graded the same fixture row differently on the two chains). Deposit
    /// proofs carry no domain and keep the permissive mock; one escrow's
    /// verifier serves both paths, so the swap is per STEP.
    function _useReal(bool primary) internal {
        vm.etch(primary ? address(verifierP) : address(verifierF), realCode);
    }

    function _useMock(bool primary) internal {
        vm.etch(primary ? address(verifierP) : address(verifierF), mockCode);
    }

    /// r3 F7: the fixture NAMES the reason; a bare expectRevert lets a row
    /// pass on whichever guard happened to fire first — exactly how
    /// `filled-primary-refund-unreachable` could stop testing the domain
    /// check it exists for.
    function _expectNamedRevert(string memory reason, World memory w) internal {
        if (_eq(reason, "rootNotAnchored")) {
            vm.expectPartialRevert(IEscrow.Escrow__RootNotAnchored.selector);
        } else if (_eq(reason, "wrongLeafDomain") || _eq(reason, "proofBindsOrderHash")) {
            // The leaf domain and the order hash are public inputs of the same
            // event-proof verification, and with the real circuit in place
            // (F4) the rejection happens INSIDE the verifier — it reverts
            // rather than returning false, so `Escrow__InvalidProof` is never
            // reached. Pinning the circuit's own failure is the stronger
            // statement: the proof did not verify, not merely "something
            // reverted".
            vm.expectPartialRevert(BaseHonkVerifier.SumcheckFailed.selector);
        } else if (_eq(reason, "terminalStatus")) {
            vm.expectPartialRevert(IEscrow.Escrow__NotClaimable.selector);
        } else if (_eq(reason, "windowNotOver")) {
            vm.expectPartialRevert(IEscrow.Escrow__TooEarly.selector);
        } else if (_eq(reason, "disputeNotResolved")) {
            vm.expectPartialRevert(IEscrow.Escrow__DisputeNotResolved.selector);
        } else if (_eq(reason, "notClaimed")) {
            vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimed.selector, w.h));
        } else {
            revert(string.concat("unmapped expectRevert reason: ", reason));
        }
    }

    function _unlock(World memory w, bool primary) internal {
        bytes32 nf = primary ? w.nfP : w.nfF;
        if (primary) {
            vm.prank(bridger);
            adManager.unlock(w.pP, nf, bytes32(uint256(5)), hex"", hex"");
        } else {
            vm.prank(maker);
            portal.unlock(w.pF, nf, bytes32(uint256(6)), hex"", hex"");
        }
    }

    /// Mint the event claim for the leaf `subject` ACTUALLY appended (the
    /// anchor discipline) and anchor its root on the consumer's side.
    function _mintAndAnchor(bytes32 subject, uint256 domain, RootAnchor a)
        internal
        returns (bytes32 root, bytes memory proof)
    {
        (proof, root) = _eventProof(domain, subject);
        a.anchor(block.chainid, root, nextSeq++);
    }

    function _eventProof(uint256 domain, bytes32 subject) internal returns (bytes memory proof, bytes32 root) {
        string[] memory a = new string[](5);
        a[0] = "npx";
        a[1] = "tsx";
        a[2] = "js-scripts/deposits/generateEventClaim.ts";
        a[3] = vm.toString(domain);
        a[4] = vm.toString(subject);
        bytes32[] memory pub;
        (proof, pub) = abi.decode(vm.ffi(a), (bytes, bytes32[]));
        root = pub[2];
    }

    // ── the joint record ─────────────────────────────────────────────────

    function _assertRecord(string memory v, World memory w) internal {
        assertEq(
            uint8(adManager.orders(w.h)),
            _status(vm.parseJsonString(v, string.concat(w.at, ".expect.primaryStatus"))),
            string.concat(w.name, ": primary status")
        );
        assertEq(
            uint8(portal.orders(w.h)),
            _status(vm.parseJsonString(v, string.concat(w.at, ".expect.followerStatus"))),
            string.concat(w.name, ": follower status")
        );
        _assertLeaf(v, w, true);
        _assertLeaf(v, w, false);
        assertEq(
            adManager.nullifierUsed(w.nfP),
            vm.parseJsonBool(v, string.concat(w.at, ".expect.primaryUnlockNullifierConsumed")),
            string.concat(w.name, ": primary nullifier")
        );
        assertEq(
            portal.nullifierUsed(w.nfF),
            vm.parseJsonBool(v, string.concat(w.at, ".expect.followerUnlockNullifierConsumed")),
            string.concat(w.name, ": follower nullifier")
        );
    }

    function _assertLeaf(string memory v, World memory w, bool primary) internal {
        string memory want = vm.parseJsonString(
            v, string.concat(w.at, ".expect.", primary ? "primaryLeafDomain" : "followerLeafDomain")
        );
        uint256 got = _lastLeafDomainOr(w.h, primary ? address(mmP) : address(mmF), type(uint256).max);
        if (_eq(want, "none")) {
            assertEq(got, type(uint256).max, string.concat(w.name, ": unexpected leaf (", primary ? "P" : "F", ")"));
        } else {
            assertEq(got, vm.parseUint(want), string.concat(w.name, ": leaf domain (", primary ? "P" : "F", ")"));
        }
    }

    /// D4's epilogue: claim every pull-credit out, then the sum must equal
    /// the pre-scenario sum — token/credit only, and the dm's native/wNative
    /// bond flows are internal to the counted set.
    function _epilogue(string memory v, World memory w) internal {
        // module credits (bond routing's fallback door)
        address[6] memory parties = [maker, bridger, orderRecipient, adRecipient, feePool, arbiter];
        for (uint256 i = 0; i < parties.length; i++) {
            if (dm.claimable(parties[i]) > 0) dm.claim(parties[i]);
        }
        uint256 sumAfter = _worldSum();
        assertEq(sumAfter, w.sumBefore, string.concat(w.name, ": conservation (T-56)"));

        // r3 F2 + F9: assert BOTH destinations, in CHAIN units. Conservation
        // does not imply the filer's share — _worldSum counts the arbiter and
        // all three contracts, so a bond routed to the arbiter or left in the
        // module balances the sum with the pool delta at zero. And dividing by
        // `scale` before comparing would swallow any sub-scale discrepancy.
        uint256 toFiler = vm.parseJsonUint(v, string.concat(w.at, ".expect.bondToFilerUnits")) * scale;
        uint256 toPool = vm.parseJsonUint(v, string.concat(w.at, ".expect.bondToPoolUnits")) * scale;
        assertEq(_spendableNative(feePool) - _poolBase, toPool, string.concat(w.name, ": bond to pool"));
        // The filer POSTS the bond during the steps, so its own outlay is
        // added back before comparing — otherwise a forfeiting row underflows
        // and a returning row reads as zero movement.
        assertEq(_spendableNative(maker) + w.bondPaid - w.filerBase, toFiler, string.concat(w.name, ": bond to filer"));
        _poolBase = _spendableNative(feePool);
    }

    uint256 internal _poolBase;

    /// Everything the scenario can move, all doors: both tokens, wrapped,
    /// native, escrow pull-credits, module credits — over every actor AND
    /// the contracts themselves.
    function _worldSum() internal view returns (uint256 sum) {
        address[9] memory all = [
            maker,
            bridger,
            orderRecipient,
            adRecipient,
            feePool,
            arbiter,
            address(adManager),
            address(portal),
            address(dm)
        ];
        for (uint256 i = 0; i < all.length; i++) {
            sum += adToken.balanceOf(all[i]) + orderToken.balanceOf(all[i]) + wnat.balanceOf(all[i]) + all[i].balance;
            sum += dm.claimable(all[i]);
            sum += adManager.claimable(all[i], address(adToken)) + adManager.claimable(all[i], address(0));
            sum += portal.claimable(all[i], address(orderToken)) + portal.claimable(all[i], address(0));
        }
    }

    function _spendableNative(address who) internal view returns (uint256) {
        return who.balance + wnat.balanceOf(who) + dm.claimable(who);
    }

    // ── small utils ──────────────────────────────────────────────────────

    function _lastLeafDomain(bytes32 h, address mm) internal returns (uint256 d) {
        d = _lastLeafDomainOr(h, mm, type(uint256).max);
        require(d != type(uint256).max, "no leaf appended for the order on this leg");
    }

    /// getRecordedLogs DRAINS — every read appends the drain to a rolling
    /// per-scenario buffer and scans the whole buffer, so later reads still
    /// see earlier appends.
    Vm.Log[] internal _buffered;

    function _lastLeafDomainOr(bytes32 h, address mm, uint256 dflt) internal returns (uint256 domain) {
        domain = dflt;
        Vm.Log[] memory drained = vm.getRecordedLogs();
        for (uint256 i = 0; i < drained.length; i++) {
            _buffered.push(drained[i]);
        }
        for (uint256 i = 0; i < _buffered.length; i++) {
            if (
                _buffered[i].emitter == mm && _buffered[i].topics.length >= 3 && _buffered[i].topics[0] == LEAF_TOPIC
                    && _buffered[i].topics[2] == h
            ) {
                (uint256 side,) = abi.decode(_buffered[i].data, (uint256, bytes32));
                domain = side;
            }
        }
    }

    function _scenarioDisputes(string memory v, string memory at) internal view returns (bool) {
        uint256 n;
        while (vm.keyExistsJson(v, string.concat(at, ".steps[", vm.toString(n), "].action"))) {
            if (_eq(vm.parseJsonString(v, string.concat(at, ".steps[", vm.toString(n), "].action")), "dispute")) {
                return true;
            }
            n++;
        }
        return false;
    }

    function _stepCount(string memory v, string memory at) internal view returns (uint256 n) {
        while (vm.keyExistsJson(v, string.concat(at, ".steps[", vm.toString(n), "].action"))) {
            n++;
        }
    }

    function _isPrimary(string memory v, string memory sAt) internal view returns (bool) {
        return _eq(vm.parseJsonString(v, string.concat(sAt, ".leg")), "primary");
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

    function _b32(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    function _eq(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }
}
