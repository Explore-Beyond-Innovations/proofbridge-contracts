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
import {FieldElement} from "src/libraries/FieldElement.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {Poseidon2Yul_BN254 as Poseidon2Yul} from "@poseidon2/src/bn254/yul/Poseidon2Yul.sol";

/*//////////////////////////////////////////////////////////////
   2.3h / T-56 — escrow conservation, over arbitrary sequences
//////////////////////////////////////////////////////////////*/

/// The escrow half of T-56. The module half — `invariant_moduleIsSolventForItsBonds` — shipped with
/// #344, and the two are separate on purpose: bonds live on the module, so a single sum across both
/// contracts is not checkable by either. Splitting it is what the module split bought.
///
/// Standalone rather than subclassing the AdManager suite, for the reason DisputeInvariant records:
/// in Foundry, inheriting a test contract inherits its *tests*.
contract EscrowConservationInvariantTest is Test {
    AdManager internal adManager;
    DisputeManager internal dm;
    MerkleManager internal merkleManager;
    wNativeToken internal wNative;
    RefusableERC20 internal adToken;

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

    EscrowHandler internal handler;
    mapping(uint256 salt => uint256) internal deadlineOf;

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

        adToken = new RefusableERC20();
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

        handler = new EscrowHandler(this);
        targetContract(address(handler));
    }

    /*//////////////////// what the handler may do ////////////////////*/

    /// Open an order against the ad, locking `LOCK` of its liquidity.
    function handlerLock(uint256 salt) external returns (bytes32 h) {
        // Each salt gets its own deadline, fixed the first time it is locked. A single shared
        // deadline froze the campaign: `handlerCancel` warps past it, `vm.warp` is not rolled back
        // when the enclosing call reverts, so the first cancel pinned `block.timestamp` beyond every
        // order's deadline and every later lock and unlock failed its clock gate for the rest of the
        // run. The handler swallows reverts, so 128,000 calls still reported `reverts: 0` while
        // exploring nothing. `test_theCampaignKeepsExploringAfterACancel` is the guard.
        if (deadlineOf[salt] == 0) deadlineOf[salt] = block.timestamp + 7 days;
        IAdManager.OrderParams memory p = _params(salt);
        vm.prank(maker);
        h = adManager.lockForOrder(p);
        if (!everSeen[salt]) {
            everSeen[salt] = true;
            seen.push(salt);
        }
        live[salt] = true;
    }

    /// Settle one: the counterparty's proof arrives and the recipient is paid.
    function handlerUnlock(uint256 salt) external {
        IAdManager.OrderParams memory p = _params(salt);
        vm.prank(bridger);
        adManager.unlock(p, _nullifier(salt), bytes32(uint256(1)), hex"", hex"");
        // only reached when the unlock succeeded
        live[salt] = false;
    }

    /// Or let its clock run out and cancel it back to the pool.
    function handlerCancel(uint256 salt) external {
        IAdManager.OrderParams memory p = _params(salt);
        vm.warp(p.deadline + 31 minutes);
        adManager.claimCancel(p);
        adManager.finalizeCancel(p);
        live[salt] = false;
    }

    function handlerClaim() external {
        adManager.claim(recipient, address(adToken));
    }

    /// Flip the recipient's ability to receive. With it refusing, an unlock credits instead of
    /// paying, which is the branch the solvency invariant exists to police.
    function handlerSetRefusing(bool v) external {
        adToken.setRefusing(v);
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
        // Per salt and fixed at its lock, never `block.timestamp + 7 days` computed here: the
        // handler warps, so a deadline relative to "now" would make `_params(salt)` return different
        // params — and a different order hash — on each call, opening two orders under one salt.
        p.deadline = deadlineOf[salt];
        p.adSettlementSigner = bytes32(uint256(uint160(maker)));
    }

    function _nullifier(uint256 salt) internal pure returns (bytes32) {
        // Canonical, as a real Poseidon2 nullifier is (2.3h T-65).
        return bytes32(uint256(keccak256(abi.encode("inv-nullifier", salt))) % FieldElement.prime());
    }

    /*//////////////////////// the invariants ////////////////////////*/

    /// What the escrow holds always covers what it owes: the ad's own balance plus every credit it
    /// has promised. A push that failed becomes a credit, so the two move together and the total
    /// cannot drift — which is the whole of "no state holds funds with no exit" on the money side.
    function invariant_escrowHoldsWhatItOwes() public view {
        (,,,,,,, uint256 adBalance,) = adManager.ads("inv");
        uint256 owed = adManager.claimable(recipient, address(adToken));
        assertGe(adToken.balanceOf(address(adManager)), adBalance + owed, "escrow insolvent");
    }

    /// Locked liquidity equals the orders actually live. An order that terminates without releasing
    /// its lock strands that liquidity forever: the maker cannot withdraw it and no call releases
    /// it. This is the accounting form of the same rule.
    function invariant_lockedMatchesLiveOrders() public view {
        (,,,,,,,, uint256 locked) = adManager.ads("inv");
        uint256 expected;
        for (uint256 i = 0; i < seen.length; i++) {
            if (live[seen[i]]) expected += LOCK;
        }
        assertEq(locked, expected, "locked liquidity does not match the live orders");
    }

    /// Proves the handler reaches the states the invariants police. Without this a handler that
    /// reverts on every call yields green invariants that tested nothing — which is exactly what
    /// the 2.3g harness did, silently, over 128,000 calls.
    function test_handlerOpensAndClosesOrdersForReal() public {
        this.handlerLock(1);
        (,,,,,,,, uint256 lockedAfterOpen) = adManager.ads("inv");
        assertEq(lockedAfterOpen, LOCK, "the handler never opened an order");
        this.handlerCancel(1);
        (,,,,,,,, uint256 lockedAfterClose) = adManager.ads("inv");
        assertEq(lockedAfterClose, 0, "the handler never closed one");
    }

    /// The credit branch must actually be reachable, or `invariant_escrowHoldsWhatItOwes` reduces to
    /// `balance >= adBalance` and never tests what it claims to.
    function test_theCreditBranchIsReachable() public {
        this.handlerLock(7);
        this.handlerSetRefusing(true);
        this.handlerUnlock(7);
        assertGt(
            adManager.claimable(recipient, address(adToken)),
            0,
            "a refused push must leave a credit, or the solvency invariant is vacuous"
        );
    }

    /// The campaign must keep exploring after a cancel. It did not: one shared deadline plus a warp
    /// that survives a revert froze every clock-gated path, and nothing failed — the handler
    /// swallows reverts, so the run still reported 128,000 calls. `test_handlerOpensAndClosesOrders`
    /// cannot see this because it starts from a fresh `setUp`; only a sequence can.
    function test_theCampaignKeepsExploringAfterACancel() public {
        this.handlerLock(1);
        this.handlerCancel(1);

        this.handlerLock(2);
        (,,,,,,,, uint256 locked) = adManager.ads("inv");
        assertEq(locked, LOCK, "a new order must still be openable after a cancel");

        this.handlerUnlock(2);
        (,,,,,,,, uint256 lockedAfter) = adManager.ads("inv");
        assertEq(lockedAfter, 0, "and still settleable");
    }

    mapping(uint256 salt => bool) internal live;
    mapping(uint256 salt => bool) internal everSeen;
    uint256[] internal seen;
}

/// An ERC20 that can be told to refuse transfers, so the escrow's credit path is actually reached.
///
/// Without this the solvency invariant was a triviality: `ERC20Mock.transfer` never fails and the
/// recipient is an EOA, so `_payOrCredit` never took its catch branch, `claimable` was always zero,
/// and the assertion reduced to `balance >= adBalance`. The property its name promises — that a
/// failed push becomes a credit and the two move together — went unexercised.
contract RefusableERC20 is ERC20Mock {
    bool public refusing;

    function setRefusing(bool v) external {
        refusing = v;
    }

    function transfer(address to, uint256 amount) public override returns (bool) {
        require(!refusing, "refusing");
        return super.transfer(to, amount);
    }
}

/// Drives the escrow surface, swallowing reverts so only successful paths shape state.
contract EscrowHandler {
    EscrowConservationInvariantTest internal immutable t;

    constructor(EscrowConservationInvariantTest t_) {
        t = t_;
    }

    function lock(uint256 salt) external {
        try t.handlerLock(salt % 32) {} catch {}
    }

    function unlock(uint256 salt) external {
        try t.handlerUnlock(salt % 32) {} catch {}
    }

    function cancel(uint256 salt) external {
        try t.handlerCancel(salt % 32) {} catch {}
    }

    function claim() external {
        try t.handlerClaim() {} catch {}
    }

    function setRefusing(bool v) external {
        try t.handlerSetRefusing(v) {} catch {}
    }
}
