// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {IEscrow} from "src/interfaces/IEscrow.sol";
import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IDisputeManager} from "src/interfaces/IDisputeManager.sol";
import {IVerifier} from "src/interfaces/IVerifier.sol";
import {IMerkleManager} from "src/interfaces/IMerkleManager.sol";
import {IwNativeToken, wNativeToken} from "src/wNativeToken.sol";
import {AdManager} from "src/AdManager.sol";
import {DisputeManager} from "src/DisputeManager.sol";
import {MerkleManager} from "src/MerkleManager.sol";
import {Dispute} from "src/libraries/Dispute.sol";
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
contract DisputeInvariantTest is Test {
    AdManager internal adManager;
    DisputeManager internal dm;
    MerkleManager internal merkleManager;
    wNativeToken internal wNative;
    ERC20Mock internal adToken;

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

    DisputeHandler internal handler;

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

        vm.startPrank(admin);
        merkleManager.grantRole(merkleManager.MANAGER_ROLE(), address(adManager));
        adManager.setRootVerifier(orderChainId, address(new MockRootVerifier(true)));
        adManager.setRouteTiming(orderChainId, RouteTiming.Timing(0, 30 minutes, 0, 1 days, 0));
        adManager.setKeyRegistry(keyRegistry);
        adManager.setPeerEscrow(orderChainId, bytes32(uint256(uint160(orderPortal))));
        adManager.setDisputeManager(IDisputeManager(address(dm)));
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

    function handlerFile(uint256 salt, uint256 value) external returns (bytes32 h) {
        IAdManager.OrderParams memory p = _params(salt);
        // The maker locks its own ad's liquidity; the suite pranks for the same reason.
        vm.prank(maker);
        h = adManager.lockForOrder(p);
        uint256 required = Dispute.bondFor(LOCK, Dispute.Params(CHALLENGE, BOND_FLOOR, BOND_BPS));
        uint256 sent = bound(value, required, required * 2);
        // Only the order's two parties may file (D11). The maker is one of them; a test contract
        // filing as itself is refused, which is how the vacuity guard caught this harness the
        // moment the party check landed.
        vm.deal(maker, sent);
        vm.prank(maker);
        adManager.dispute{value: sent}(p, bytes32("e"));
    }

    function handlerRule(bytes32 h, uint8 outcome) external {
        vm.prank(arbiter);
        dm.resolveDispute(h, Dispute.Outcome(outcome % 5));
    }

    function handlerWarp(uint32 by) external {
        vm.warp(block.timestamp + by);
    }

    function _params(uint256 salt) internal view returns (IAdManager.OrderParams memory p) {
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
        p.deadline = block.timestamp + 7 days;
        p.adSettlementSigner = bytes32(uint256(uint160(maker)));
    }

    /*//////////////////////// the invariants ////////////////////////*/

    /// An order is `Disputed` on the escrow if and only if the module holds a record for it.
    ///
    /// This is the property the two-contract split created the need for, and it is stronger than a
    /// targeted regression test: that proves one specific mistake is caught, this proves no
    /// reachable sequence breaks the correspondence — including paths nobody thought of.
    function invariant_disputedIffModuleHasARecord() public view {
        uint256 n = handler.seenCount();
        for (uint256 i = 0; i < n; i++) {
            bytes32 h = handler.seenAt(i);
            assertEq(adManager.orders(h) == IEscrow.Status.Disputed, dm.isDisputed(h), "escrow and module disagree");
        }
    }

    /// Every bond the module recorded is still backed by wrapped native it holds.
    function invariant_moduleIsSolventForItsBonds() public view {
        uint256 owed;
        uint256 n = handler.seenCount();
        for (uint256 i = 0; i < n; i++) {
            (, uint128 bond,,,,,,,) = dm.disputes(handler.seenAt(i));
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
        uint256 n = handler.seenCount();
        for (uint256 i = 0; i < n; i++) {
            bytes32 h = handler.seenAt(i);
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
        uint256 n = handler.seenCount();
        for (uint256 i = 0; i < n; i++) {
            bytes32 h = handler.seenAt(i);
            if (!dm.isDisputed(h)) continue;
            (,,,,,,, uint64 orderDeadline, uint64 buffer) = dm.disputes(h);
            assertGe(
                dm.effectiveChallengeDeadline(h),
                uint256(orderDeadline) + buffer,
                "a dispute could finalize before deadline + buffer"
            );
        }
    }

    /// Proves the harness reaches the state the invariants police. Without this a handler that
    /// reverts on every call yields green invariants that tested nothing — which is exactly what the
    /// first version did, silently, over 128,000 calls.
    function test_handlerFilesDisputesForReal() public {
        handler.file(1, 1 ether);
        handler.file(2, 2 ether);
        assertGt(handler.seenCount(), 0, "the handler never filed a dispute");
    }
}

/// Drives the dispute surface, swallowing reverts so only successful paths shape state.
contract DisputeHandler {
    DisputeInvariantTest internal immutable t;
    bytes32[] private seen;

    constructor(DisputeInvariantTest t_) {
        t = t_;
    }

    function file(uint256 salt, uint256 value) external {
        try t.handlerFile(salt, value) returns (bytes32 h) {
            seen.push(h);
        } catch {}
    }

    function rule(uint256 idx, uint8 outcome) external {
        if (seen.length == 0) return;
        try t.handlerRule(seen[idx % seen.length], outcome) {} catch {}
    }

    function warp(uint32 by) external {
        try t.handlerWarp(by) {} catch {}
    }

    function seenCount() external view returns (uint256) {
        return seen.length;
    }

    function seenAt(uint256 i) external view returns (bytes32) {
        return seen[i];
    }
}
