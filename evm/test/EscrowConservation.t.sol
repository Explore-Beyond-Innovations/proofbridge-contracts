// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {IEscrow} from "src/interfaces/IEscrow.sol";
import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IOrderPortal} from "src/interfaces/IOrderPortal.sol";
import {IDisputeManager} from "src/interfaces/IDisputeManager.sol";
import {IRootAnchor} from "src/interfaces/IRootAnchor.sol";
import {IVerifier} from "src/interfaces/IVerifier.sol";
import {IMerkleManager} from "src/interfaces/IMerkleManager.sol";
import {IwNativeToken, wNativeToken} from "src/wNativeToken.sol";
import {AdManager} from "src/AdManager.sol";
import {OrderPortal} from "src/OrderPortal.sol";
import {DisputeManager} from "src/DisputeManager.sol";
import {MerkleManager} from "src/MerkleManager.sol";
import {RootAnchor} from "src/RootAnchor.sol";
import {Dispute} from "src/libraries/Dispute.sol";
import {RouteTiming} from "src/libraries/RouteTiming.sol";
import {OrderHash} from "src/libraries/OrderHash.sol";
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
///
/// C-18: the campaign now also reaches MakerForfeit (the one outcome that pays out of the ad),
/// `presentSettled`, every other dispute outcome, and a native-token ad beside the ERC20 one.
///
/// 49E-4: the solvency check is an equality (a stranded surplus fails it as surely as a shortfall),
/// the credited recipients redirect their credit with `claimTo` (C-16), and `afterInvariant`
/// requires BridgerForfeit as well as the other outcomes.
contract EscrowConservationInvariantTest is Test {
    AdManager internal adManager;
    DisputeManager internal dm;
    MerkleManager internal merkleManager;
    wNativeToken internal wNative;
    RefusableERC20 internal adToken;
    RootAnchor internal anchor;
    /// The native orders' recipient: a contract, so a refused native push is reachable too.
    ToggleNativeRecipient internal nativeRecipient;

    address internal admin = makeAddr("admin");
    address internal maker = makeAddr("maker");
    address internal bridger = makeAddr("bridger");
    address internal recipient = makeAddr("recipient");
    address internal arbiter = makeAddr("arbiter");
    address internal feePool = makeAddr("feePool");
    address internal orderPortal = makeAddr("orderPortal");
    address internal orderToken = makeAddr("orderToken");
    /// Where `claimTo` sends the recipients' credit; nothing else pays these two.
    address internal claimWallet = makeAddr("claimWallet");
    address internal nativeClaimWallet = makeAddr("nativeClaimWallet");
    /// Ghosts: what `claimTo` moved, per token.
    uint256 internal claimedToErc20;
    uint256 internal claimedToNative;

    address internal constant NATIVE = address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);
    string internal constant ERC20_AD = "inv";
    string internal constant NATIVE_AD = "inv-native";
    /// Salts at or above this are orders on the native ad.
    uint256 internal constant NATIVE_FROM = 16;
    bytes32 internal constant EVIDENCE_ROOT = bytes32(uint256(0xe71d));

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
        address[] memory signers = new address[](1);
        signers[0] = address(this);
        anchor = new RootAnchor(admin, signers, 1);
        anchor.anchor(orderChainId, EVIDENCE_ROOT, 1);
        nativeRecipient = new ToggleNativeRecipient();

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

        adToken = new RefusableERC20();
        adToken.mint(maker, 1_000_000 ether);
        vm.startPrank(admin);
        adManager.setTokenRoute(address(adToken), orderChainId, bytes32(uint256(uint160(orderToken))));
        adManager.setTokenRoute(NATIVE, orderChainId, bytes32(uint256(uint160(orderToken))));
        vm.stopPrank();

        vm.deal(maker, 1_000 ether);
        vm.startPrank(maker);
        adToken.approve(address(adManager), type(uint256).max);
        adManager.createAd(
            ERC20_AD,
            address(adToken),
            500_000 ether,
            orderChainId,
            bytes32(uint256(uint160(recipient))),
            bytes32(uint256(uint160(maker)))
        );
        adManager.createAd{value: 500 ether}(
            NATIVE_AD,
            NATIVE,
            500 ether,
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
        // A salt whose last order ended starts a new one: a new generation, so a new hash.
        if (!live[salt]) {
            if (deadlineOf[salt] != 0) generation[salt]++;
            deadlineOf[salt] = block.timestamp + 7 days;
        }
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

    /// Evidence: the order chain's SETTLED leaf pays the recipient, as an unlock would.
    function handlerPresent(uint256 salt) external {
        adManager.presentSettled(_params(salt), EVIDENCE_ROOT, hex"");
        live[salt] = false;
    }

    /// A dispute run to its end: filed by either party, ruled `outcome` (or left unruled), then
    /// finalized. MakerForfeit is the one that pays out of the ad.
    function handlerDispute(uint256 salt, bool byBridger, uint8 outcome) external returns (uint8 applied) {
        IAdManager.OrderParams memory p = _params(salt);
        bytes32 h = _hash(p);
        address who = byBridger ? _recipientOf(salt) : maker;
        uint256 bond = Dispute.bondFor(LOCK, Dispute.Params(CHALLENGE, BOND_FLOOR, BOND_BPS));
        vm.deal(who, bond);
        vm.prank(who);
        adManager.dispute{value: bond}(p, bytes32("e"));
        // 0 leaves it unruled (the fallback); 1, 3, 4 are what the arbiter may rule.
        Dispute.Outcome o = Dispute.Outcome([uint8(0), 1, 3, 4][outcome % 4]);
        if (o != Dispute.Outcome.None) {
            vm.prank(arbiter);
            dm.resolveDispute(h, o);
        }
        uint256 until = dm.effectiveChallengeDeadline(h);
        if (block.timestamp < until) vm.warp(until);
        adManager.finalizeDispute(p);
        live[salt] = false;
        applied = uint8(o == Dispute.Outcome.None ? Dispute.Outcome.MutualRefund : o);
    }

    function handlerClaim() external {
        adManager.claim(recipient, address(adToken));
    }

    function handlerClaimNative() external {
        adManager.claim(address(nativeRecipient), NATIVE);
    }

    /// C-16: the credited account redirects its own credit, e.g. while it still refuses payment.
    function handlerClaimTo(bool native) external {
        if (native) {
            uint256 amount = adManager.claimable(address(nativeRecipient), NATIVE);
            vm.prank(address(nativeRecipient));
            adManager.claimTo(NATIVE, nativeClaimWallet);
            claimedToNative += amount;
        } else {
            uint256 amount = adManager.claimable(recipient, address(adToken));
            vm.prank(recipient);
            adManager.claimTo(address(adToken), claimWallet);
            claimedToErc20 += amount;
        }
    }

    /// Flip the recipients' ability to receive. With them refusing, a payout credits instead of
    /// paying, which is the branch the solvency invariant exists to police.
    function handlerSetRefusing(bool v) external {
        adToken.setRefusing(v);
        nativeRecipient.setRefusing(v);
    }

    /// Pause, let time pass, unpause: every window must absorb the paused seconds.
    function handlerPauseFor(uint32 secs) external {
        vm.prank(admin);
        adManager.pause();
        vm.warp(block.timestamp + secs % 1 days);
        vm.prank(admin);
        adManager.unpause();
    }

    function _isNative(uint256 salt) internal pure returns (bool) {
        return salt >= NATIVE_FROM;
    }

    function _recipientOf(uint256 salt) internal view returns (address) {
        return _isNative(salt) ? address(nativeRecipient) : recipient;
    }

    function _params(uint256 salt) internal view returns (IAdManager.OrderParams memory p) {
        bool native = _isNative(salt);
        p.orderChainToken = bytes32(uint256(uint160(orderToken)));
        p.adChainToken = bytes32(uint256(uint160(native ? NATIVE : address(adToken))));
        p.amount = LOCK;
        p.bridger = bytes32(uint256(uint160(bridger)));
        p.orderChainId = orderChainId;
        p.srcOrderPortal = bytes32(uint256(uint160(orderPortal)));
        p.orderRecipient = bytes32(uint256(uint160(_recipientOf(salt))));
        p.adId = native ? NATIVE_AD : ERC20_AD;
        p.adCreator = bytes32(uint256(uint160(maker)));
        p.adRecipient = bytes32(uint256(uint160(recipient)));
        p.salt = salt | (generation[salt] << 128);
        p.orderDecimals = 18;
        p.adDecimals = 18;
        // Per salt and fixed at its lock, never `block.timestamp + 7 days` computed here: the
        // handler warps, so a deadline relative to "now" would make `_params(salt)` return different
        // params — and a different order hash — on each call, opening two orders under one salt.
        p.deadline = deadlineOf[salt];
        p.adSettlementSigner = bytes32(uint256(uint160(maker)));
    }

    /// The hash the escrow keys the order by.
    function _hash(IAdManager.OrderParams memory p) internal view returns (bytes32) {
        return OrderHashReader.hash(p, address(adManager));
    }

    function _nullifier(uint256 salt) internal view returns (bytes32) {
        // Canonical, as a real Poseidon2 nullifier is (2.3h T-65).
        return bytes32(uint256(keccak256(abi.encode("inv-nullifier", salt, generation[salt]))) % FieldElement.prime());
    }

    /// Like `liveFrom`, but only an order still inside its unlock cutoff (and filing window).
    function liveInTimeFrom(uint256 pick) external view returns (uint256) {
        for (uint256 k = 0; k < 32; k++) {
            uint256 salt = (pick % 32 + k) % 32;
            if (live[salt] && block.timestamp <= deadlineOf[salt] + 30 minutes) return salt;
        }
        return pick % 32;
    }

    function isLive(uint256 salt) external view returns (bool) {
        return live[salt];
    }

    /// The first live salt at or after `pick` (mod 32), or `pick` itself when none is live.
    function liveFrom(uint256 pick) external view returns (uint256) {
        for (uint256 k = 0; k < 32; k++) {
            uint256 salt = (pick % 32 + k) % 32;
            if (live[salt]) return salt;
        }
        return pick % 32;
    }

    /*//////////////////////// the invariants ////////////////////////*/

    /// What the escrow holds always covers what it owes: each ad's own balance plus every credit it
    /// has promised in that ad's token. A push that failed becomes a credit, so the two move
    /// together and the total cannot drift — which is the whole of "no state holds funds with no
    /// exit" on the money side. Native is held wrapped.
    ///
    /// 49E-4: exactly, not at least. Nothing else ever pays the escrow, so a surplus is funds with
    /// no exit, stranded as surely as a shortfall is a promise it cannot keep.
    function invariant_escrowHoldsWhatItOwes() public view {
        (,,,,,,, uint256 adBalance,) = adManager.ads(ERC20_AD);
        uint256 owed = adManager.claimable(recipient, address(adToken));
        assertEq(adToken.balanceOf(address(adManager)), adBalance + owed, "escrow holds other than it owes (ERC20)");

        (,,,,,,, uint256 nativeBalance,) = adManager.ads(NATIVE_AD);
        uint256 nativeOwed = adManager.claimable(address(nativeRecipient), NATIVE);
        assertEq(
            wNative.balanceOf(address(adManager)),
            nativeBalance + nativeOwed,
            "escrow holds other than it owes (native)"
        );
    }

    /// C-16: `claimTo` moves only the caller's own credit: each wallet holds exactly what was claimed to it.
    function invariant_claimToPaysOnlyTheCallersCredit() public view {
        assertEq(adToken.balanceOf(claimWallet), claimedToErc20, "claimTo paid other than the credit (ERC20)");
        assertEq(nativeClaimWallet.balance, claimedToNative, "claimTo paid other than the credit (native)");
    }

    /// Locked liquidity equals the orders actually live, per ad. An order that terminates without
    /// releasing its lock strands that liquidity forever: the maker cannot withdraw it and no call
    /// releases it. This is the accounting form of the same rule.
    function invariant_lockedMatchesLiveOrders() public view {
        uint256 erc20Live;
        uint256 nativeLive;
        for (uint256 i = 0; i < seen.length; i++) {
            if (!live[seen[i]]) continue;
            if (_isNative(seen[i])) nativeLive += LOCK;
            else erc20Live += LOCK;
        }
        (,,,,,,,, uint256 locked) = adManager.ads(ERC20_AD);
        assertEq(locked, erc20Live, "locked liquidity does not match the live orders (ERC20)");
        (,,,,,,,, uint256 nativeLocked) = adManager.ads(NATIVE_AD);
        assertEq(nativeLocked, nativeLive, "locked liquidity does not match the live orders (native)");
    }

    /// C-18 vacuity: every run reaches each way out, on both tokens, and the credit branch.
    function afterInvariant() public view {
        assertGt(handler.unlocks(), 0, "no unlock landed");
        assertGt(handler.cancels(), 0, "no cancel landed");
        assertGt(handler.presents(), 0, "presentSettled never landed");
        assertGt(handler.outcomes(uint8(Dispute.Outcome.MakerForfeit)), 0, "MakerForfeit never paid out");
        assertGt(handler.outcomes(uint8(Dispute.Outcome.MutualRefund)), 0, "no dispute refunded");
        assertGt(handler.outcomes(uint8(Dispute.Outcome.BridgerForfeit)), 0, "no dispute finalized as BridgerForfeit");
        assertGt(handler.nativeLocks(), 0, "the native ad never locked");
        assertGt(handler.credits(), 0, "no payout was ever credited");
        assertGt(handler.claimsTo(), 0, "claimTo never paid");
    }

    /// Proves the handler reaches the states the invariants police. Without this a handler that
    /// reverts on every call yields green invariants that tested nothing — which is exactly what
    /// the 2.3g harness did, silently, over 128,000 calls.
    function test_handlerOpensAndClosesOrdersForReal() public {
        this.handlerLock(1);
        (,,,,,,,, uint256 lockedAfterOpen) = adManager.ads(ERC20_AD);
        assertEq(lockedAfterOpen, LOCK, "the handler never opened an order");
        this.handlerCancel(1);
        (,,,,,,,, uint256 lockedAfterClose) = adManager.ads(ERC20_AD);
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
        (,,,,,,,, uint256 locked) = adManager.ads(ERC20_AD);
        assertEq(locked, LOCK, "a new order must still be openable after a cancel");

        this.handlerUnlock(2);
        (,,,,,,,, uint256 lockedAfter) = adManager.ads(ERC20_AD);
        assertEq(lockedAfter, 0, "and still settleable");
    }

    /// MakerForfeit takes the lock out of the native ad and pays the (refusing) recipient's credit.
    function test_c18_makerForfeitOnTheNativeAdIsReachable() public {
        this.handlerLock(20);
        this.handlerSetRefusing(true);
        uint8 applied = this.handlerDispute(20, true, 3); // index 3 = MakerForfeit
        assertEq(applied, uint8(Dispute.Outcome.MakerForfeit));
        (,,,,,,, uint256 nativeBalance, uint256 nativeLocked) = adManager.ads(NATIVE_AD);
        assertEq(nativeBalance, 500 ether - LOCK, "the forfeit left the ad");
        assertEq(nativeLocked, 0);
        assertEq(adManager.claimable(address(nativeRecipient), NATIVE), LOCK, "credited to the recipient");
        // C-16: still refusing, the recipient redirects its own credit.
        handler.claimTo(true);
        assertEq(handler.claimsTo(), 1);
        assertEq(nativeClaimWallet.balance, LOCK);
        invariant_claimToPaysOnlyTheCallersCredit();
        invariant_escrowHoldsWhatItOwes();
    }

    /// 49E-4: BridgerForfeit is reachable through the handler (index 2 of its outcome table).
    function test_bridgerForfeitIsReachable() public {
        handler.dispute(3, false, 2);
        assertEq(handler.outcomes(uint8(Dispute.Outcome.BridgerForfeit)), 1);
        invariant_escrowHoldsWhatItOwes();
    }

    /// Every credit the escrow holds, both tokens: a rise means a refused payout was credited.
    function creditOutstanding() external view returns (uint256) {
        return adManager.claimable(recipient, address(adToken)) + adManager.claimable(address(nativeRecipient), NATIVE);
    }

    mapping(uint256 salt => bool) internal live;
    mapping(uint256 salt => bool) internal everSeen;
    mapping(uint256 salt => uint256) internal generation;
    uint256[] internal seen;
}

/// The order hash as `AdManager` computes it, for the handler's dispute calls.
library OrderHashReader {
    function hash(IAdManager.OrderParams memory p, address adManager) internal view returns (bytes32) {
        return OrderHash.digest(
            OrderHash.Order({
                orderChainToken: p.orderChainToken,
                adChainToken: p.adChainToken,
                amount: p.amount,
                bridger: p.bridger,
                orderChainId: p.orderChainId,
                orderPortal: p.srcOrderPortal,
                orderRecipient: p.orderRecipient,
                adChainId: block.chainid,
                adManager: bytes32(uint256(uint160(adManager))),
                adId: p.adId,
                adCreator: p.adCreator,
                adRecipient: p.adRecipient,
                salt: p.salt,
                orderDecimals: p.orderDecimals,
                adDecimals: p.adDecimals,
                deadline: p.deadline,
                adSettlementSigner: p.adSettlementSigner
            })
        );
    }
}

/*//////////////////////////////////////////////////////////////
          C-18 — the follower (OrderPortal) conserves too
//////////////////////////////////////////////////////////////*/

/// The order chain's escrow over arbitrary sequences: create (ERC20 and native), the maker's unlock,
/// the three evidence doors (cancel refund, forfeit payout, settled payout), the backstop, claims,
/// refusing recipients and pauses. What it holds must equal what it owes, exactly: the live orders'
/// deposits plus every credit. Nothing else ever pays it.
contract OrderPortalConservationInvariantTest is Test {
    OrderPortal internal portal;
    MerkleManager internal merkleManager;
    wNativeToken internal wNative;
    RefusableERC20 internal orderToken;
    RootAnchor internal anchor;
    /// The maker's payout address: a contract, so a refused native payout is reachable too.
    ToggleNativeRecipient internal adRecipient;

    address internal admin = makeAddr("admin");
    address internal bridger = makeAddr("bridger");
    address internal adManager = makeAddr("adManager");
    bytes32 internal adToken = bytes32(uint256(uint160(makeAddr("adToken"))));

    address internal constant NATIVE = address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);
    uint256 internal constant NATIVE_FROM = 16;
    uint256 internal constant SALTS = 32;
    uint256 internal constant AMOUNT = 1 ether;
    bytes32 internal constant EVIDENCE_ROOT = bytes32(uint256(0xe71d));
    uint256 internal adChainId = 11155111;

    PortalHandler internal handler;
    mapping(uint256 salt => uint256) internal deadlineOf;
    mapping(uint256 salt => bool) public live;
    mapping(uint256 salt => uint256) internal generation;

    function setUp() public {
        merkleManager = new MerkleManager(admin, address(new Poseidon2Yul()));
        wNative = new wNativeToken("Wrapped Native Token", "WNATIVE", 18);
        portal = new OrderPortal(
            admin,
            IVerifier(address(new MockVerifier(true))),
            IMerkleManager(address(merkleManager)),
            IwNativeToken(address(wNative))
        );
        address[] memory signers = new address[](1);
        signers[0] = address(this);
        anchor = new RootAnchor(admin, signers, 1);
        anchor.anchor(adChainId, EVIDENCE_ROOT, 1);
        orderToken = new RefusableERC20();
        adRecipient = new ToggleNativeRecipient();

        vm.startPrank(admin);
        merkleManager.grantRole(merkleManager.MANAGER_ROLE(), address(portal));
        portal.setRootVerifier(adChainId, address(new MockRootVerifier(true)));
        portal.setRouteTiming(adChainId, RouteTiming.Timing(0, 30 minutes, 0, 1 days, 0));
        portal.setPeerEscrow(adChainId, bytes32(uint256(uint160(adManager))));
        portal.setTokenRoute(address(orderToken), adChainId, adToken);
        portal.setTokenRoute(NATIVE, adChainId, adToken);
        portal.setRootAnchor(IRootAnchor(address(anchor)));
        vm.stopPrank();

        orderToken.mint(bridger, 1_000_000 ether);
        vm.prank(bridger);
        orderToken.approve(address(portal), type(uint256).max);

        handler = new PortalHandler(this);
        targetContract(address(handler));
    }

    /*//////////////////// what the handler may do ////////////////////*/

    /// The bridger deposits. One order per salt, its deadline fixed at creation.
    function handlerCreate(uint256 salt) external returns (bool native) {
        salt %= SALTS;
        // A salt whose last order ended starts a new one: a new generation, so a new hash.
        if (!live[salt]) {
            if (deadlineOf[salt] != 0) generation[salt]++;
            deadlineOf[salt] = block.timestamp + 7 days;
        }
        IOrderPortal.OrderParams memory p = _params(salt);
        native = _isNative(salt);
        vm.deal(bridger, AMOUNT);
        vm.prank(bridger);
        portal.createOrder{value: native ? AMOUNT : 0}(p);
        live[salt] = true;
    }

    /// The maker's co-signed unlock pays the maker.
    function handlerUnlock(uint256 pick) external {
        uint256 salt = _pickLive(pick, true);
        portal.unlock(_params(salt), _nullifier(salt), bytes32(uint256(1)), hex"", hex"");
        live[salt] = false;
    }

    /// The primary's CANCEL leaf refunds the bridger.
    function handlerRefundByCancel(uint256 pick) external {
        uint256 salt = _pickLive(pick, false);
        portal.refundByCancel(_params(salt), EVIDENCE_ROOT, hex"");
        live[salt] = false;
    }

    /// The primary's FORFEIT leaf pays the maker.
    function handlerForfeit(uint256 pick) external {
        uint256 salt = _pickLive(pick, false);
        portal.payMakerByForfeit(_params(salt), EVIDENCE_ROOT, hex"");
        live[salt] = false;
    }

    /// The primary's SETTLED leaf pays the maker.
    function handlerPresent(uint256 pick) external {
        uint256 salt = _pickLive(pick, false);
        portal.presentSettled(_params(salt), EVIDENCE_ROOT, hex"");
        live[salt] = false;
    }

    /// Nothing arrived: the long backstop refunds the bridger.
    function handlerBackstop(uint256 pick) external {
        uint256 salt = _pickLive(pick, false);
        IOrderPortal.OrderParams memory p = _params(salt);
        if (block.timestamp < p.deadline + 1 days) vm.warp(p.deadline + 1 days);
        portal.claimBackstop(p);
        vm.warp(block.timestamp + 30 minutes);
        portal.finalizeBackstop(p);
        live[salt] = false;
    }

    function handlerClaim(bool native, bool toMaker) external {
        address who = toMaker ? address(adRecipient) : bridger;
        portal.claim(who, native ? NATIVE : address(orderToken));
    }

    function handlerSetRefusing(bool v) external {
        orderToken.setRefusing(v);
        adRecipient.setRefusing(v);
    }

    function handlerPauseFor(uint32 secs) external {
        vm.prank(admin);
        portal.pause();
        vm.warp(block.timestamp + secs % 1 days);
        vm.prank(admin);
        portal.unpause();
    }

    /// The first live salt at or after `pick`; `inTime` also skips any past its unlock cutoff.
    function _pickLive(uint256 pick, bool inTime) internal view returns (uint256) {
        for (uint256 k = 0; k < SALTS; k++) {
            uint256 salt = (pick % SALTS + k) % SALTS;
            if (live[salt] && (!inTime || block.timestamp <= deadlineOf[salt])) return salt;
        }
        revert("nothing live");
    }

    function _isNative(uint256 salt) internal pure returns (bool) {
        return salt >= NATIVE_FROM;
    }

    function _params(uint256 salt) internal view returns (IOrderPortal.OrderParams memory p) {
        p.orderChainToken = bytes32(uint256(uint160(_isNative(salt) ? NATIVE : address(orderToken))));
        p.adChainToken = adToken;
        p.amount = AMOUNT;
        p.bridger = bytes32(uint256(uint160(bridger)));
        p.orderRecipient = bytes32(uint256(uint160(makeAddrPure("order-recipient"))));
        p.adChainId = adChainId;
        p.adManager = bytes32(uint256(uint160(adManager)));
        p.adId = "ad";
        p.adCreator = bytes32(uint256(0xACAC));
        p.adRecipient = bytes32(uint256(uint160(address(adRecipient))));
        p.salt = salt | (generation[salt] << 128);
        p.orderDecimals = 18;
        p.adDecimals = 18;
        p.deadline = deadlineOf[salt];
        p.adSettlementSigner = p.adCreator;
    }

    function makeAddrPure(string memory name) internal pure returns (address) {
        return address(uint160(uint256(keccak256(bytes(name)))));
    }

    function _nullifier(uint256 salt) internal view returns (bytes32) {
        return
            bytes32(uint256(keccak256(abi.encode("portal-nullifier", salt, generation[salt]))) % FieldElement.prime());
    }

    /*//////////////////////// the invariants ////////////////////////*/

    /// The portal holds exactly the live deposits plus every credit, per token. More would be funds
    /// with no exit; less would be a promise it cannot keep.
    function invariant_portalHoldsExactlyWhatItOwes() public view {
        uint256 erc20Live;
        uint256 nativeLive;
        for (uint256 salt = 0; salt < SALTS; salt++) {
            if (!live[salt]) continue;
            if (_isNative(salt)) nativeLive += AMOUNT;
            else erc20Live += AMOUNT;
        }
        assertEq(
            orderToken.balanceOf(address(portal)),
            erc20Live + portal.claimable(address(adRecipient), address(orderToken))
                + portal.claimable(bridger, address(orderToken)),
            "portal holds other than it owes (ERC20)"
        );
        assertEq(
            wNative.balanceOf(address(portal)),
            nativeLive + portal.claimable(address(adRecipient), NATIVE) + portal.claimable(bridger, NATIVE),
            "portal holds other than it owes (native)"
        );
    }

    /// The bridger's in-flight count is its live orders: every exit counts out exactly once.
    function invariant_inFlightMatchesLiveOrders() public view {
        uint256 n;
        for (uint256 salt = 0; salt < SALTS; salt++) {
            if (live[salt]) n++;
        }
        assertEq(portal.inFlightOf(bytes32(uint256(uint160(bridger)))), n, "in-flight count drifted");
    }

    /// C-18 vacuity: every run reaches each way out, on both tokens, and the credit branch.
    function afterInvariant() public view {
        assertGt(handler.unlocks(), 0, "no unlock landed");
        assertGt(handler.refunds(), 0, "no cancel refund landed");
        assertGt(handler.forfeits(), 0, "no forfeit payout landed");
        assertGt(handler.presents(), 0, "presentSettled never landed");
        assertGt(handler.backstops(), 0, "the backstop never refunded");
        assertGt(handler.nativeCreates(), 0, "no native order was created");
        assertGt(handler.credits(), 0, "no payout was ever credited");
    }

    /// Each door once, including a refused payout that becomes a credit and is then claimed.
    function test_c18_everyDoorIsReachable() public {
        handler.create(0);
        handler.create(1);
        handler.create(2);
        handler.create(NATIVE_FROM);
        handler.create(NATIVE_FROM + 1);
        handler.setRefusing(true);
        handler.unlock(0);
        handler.forfeit(NATIVE_FROM);
        handler.setRefusing(false);
        handler.refundByCancel(1);
        handler.present(2);
        handler.backstop(NATIVE_FROM + 1);
        assertEq(handler.unlocks(), 1);
        assertEq(handler.forfeits(), 1);
        assertEq(handler.refunds(), 1);
        assertEq(handler.presents(), 1);
        assertEq(handler.backstops(), 1);
        assertEq(handler.nativeCreates(), 2);
        assertEq(handler.credits(), 2, "both refused payouts were credited");
        handler.claim(false, true);
        handler.claim(true, true);
        assertEq(portal.claimable(address(adRecipient), address(orderToken)), 0, "the ERC20 credit was claimed");
        assertEq(portal.claimable(address(adRecipient), NATIVE), 0, "the native credit was claimed");
        invariant_portalHoldsExactlyWhatItOwes();
        invariant_inFlightMatchesLiveOrders();
    }

    function creditOutstanding() external view returns (uint256) {
        return
            portal.claimable(address(adRecipient), address(orderToken)) + portal.claimable(address(adRecipient), NATIVE);
    }
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

/// A payout address that can be told to refuse native value.
contract ToggleNativeRecipient {
    bool public refusing;

    function setRefusing(bool v) external {
        refusing = v;
    }

    receive() external payable {
        require(!refusing, "refusing");
    }
}

/// Drives the escrow surface, swallowing reverts so only successful paths shape state. Counts each
/// way out that landed, for `afterInvariant`.
contract EscrowHandler {
    EscrowConservationInvariantTest internal immutable t;

    uint256 public unlocks;
    uint256 public cancels;
    uint256 public presents;
    uint256 public nativeLocks;
    uint256 public credits;
    uint256 public claimsTo;
    mapping(uint8 => uint256) public outcomes;

    constructor(EscrowConservationInvariantTest t_) {
        t = t_;
    }

    function lock(uint256 salt) external {
        _lock(salt % 32);
    }

    function unlock(uint256 salt) external {
        uint256 before = t.creditOutstanding();
        try t.handlerUnlock(_liveInTime(salt)) {
            unlocks++;
            _countCredit(before);
        } catch {}
    }

    function cancel(uint256 salt) external {
        try t.handlerCancel(t.liveFrom(salt)) {
            cancels++;
        } catch {}
    }

    function present(uint256 salt) external {
        uint256 before = t.creditOutstanding();
        try t.handlerPresent(t.liveFrom(salt)) {
            presents++;
            _countCredit(before);
        } catch {}
    }

    function dispute(uint256 salt, bool byBridger, uint8 outcome) external {
        uint256 before = t.creditOutstanding();
        try t.handlerDispute(_liveInTime(salt), byBridger, outcome) returns (uint8 applied) {
            outcomes[applied]++;
            _countCredit(before);
        } catch {}
    }

    function claim() external {
        try t.handlerClaim() {} catch {}
    }

    function claimNative() external {
        try t.handlerClaimNative() {} catch {}
    }

    function claimTo(bool native) external {
        try t.handlerClaimTo(native) {
            claimsTo++;
        } catch {}
    }

    function setRefusing(bool v) external {
        try t.handlerSetRefusing(v) {} catch {}
    }

    function pauseFor(uint32 secs) external {
        try t.handlerPauseFor(secs) {} catch {}
    }

    function _lock(uint256 salt) internal {
        try t.handlerLock(salt) {
            if (salt >= 16) nativeLocks++;
        } catch {}
    }

    /// A live order inside its window; locks a fresh one when there is none, since every other
    /// action consumes them.
    function _liveInTime(uint256 pick) internal returns (uint256 salt) {
        salt = t.liveInTimeFrom(pick);
        if (!t.isLive(salt)) _lock(salt);
    }

    function _countCredit(uint256 before) internal {
        if (t.creditOutstanding() > before) credits++;
    }
}

/// Drives the follower, swallowing reverts; counts each door that landed.
contract PortalHandler {
    OrderPortalConservationInvariantTest internal immutable t;

    uint256 public unlocks;
    uint256 public refunds;
    uint256 public forfeits;
    uint256 public presents;
    uint256 public backstops;
    uint256 public nativeCreates;
    uint256 public credits;

    constructor(OrderPortalConservationInvariantTest t_) {
        t = t_;
    }

    function create(uint256 salt) external {
        try t.handlerCreate(salt) returns (bool native) {
            if (native) nativeCreates++;
        } catch {}
    }

    function unlock(uint256 pick) external {
        uint256 before = t.creditOutstanding();
        try t.handlerUnlock(pick) {
            unlocks++;
            if (t.creditOutstanding() > before) credits++;
        } catch {}
    }

    function refundByCancel(uint256 pick) external {
        try t.handlerRefundByCancel(pick) {
            refunds++;
        } catch {}
    }

    function forfeit(uint256 pick) external {
        uint256 before = t.creditOutstanding();
        try t.handlerForfeit(pick) {
            forfeits++;
            if (t.creditOutstanding() > before) credits++;
        } catch {}
    }

    function present(uint256 pick) external {
        uint256 before = t.creditOutstanding();
        try t.handlerPresent(pick) {
            presents++;
            if (t.creditOutstanding() > before) credits++;
        } catch {}
    }

    function backstop(uint256 pick) external {
        try t.handlerBackstop(pick) {
            backstops++;
        } catch {}
    }

    function claim(bool native, bool toMaker) external {
        try t.handlerClaim(native, toMaker) {} catch {}
    }

    function setRefusing(bool v) external {
        try t.handlerSetRefusing(v) {} catch {}
    }

    function pauseFor(uint32 secs) external {
        try t.handlerPauseFor(secs) {} catch {}
    }
}
