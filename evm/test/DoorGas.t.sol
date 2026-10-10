// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test, console2} from "forge-std/Test.sol";
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
import {HonkVerifier} from "src/Verifier.sol";
import {Dispute} from "src/libraries/Dispute.sol";
import {LeafDomain} from "src/libraries/LeafDomain.sol";
import {OrderHash} from "src/libraries/OrderHash.sol";
import {RouteTiming} from "src/libraries/RouteTiming.sol";
import {MockKeyRegistry} from "./mocks/MockKeyRegistry.sol";
import {MockRootVerifier} from "./mocks/MockRootVerifier.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {Poseidon2Yul_BN254 as Poseidon2Yul} from "@poseidon2/src/bn254/yul/Poseidon2Yul.sol";

/*//////////////////////////////////////////////////////////////
   C-7 (#358) — every escrow door, real proofs, a realistic MMR
//////////////////////////////////////////////////////////////*/

/// Gas ceilings for each door #358 names, so a regression fails the build. The co-signed unlocks
/// (real BLS + real UltraHonk) live in `UnlockGas.t.sol` beside the 1.6c baselines.
///
/// How each number is taken:
/// - Real `HonkVerifier` and real event proofs (the events circuit, via the ffi generator).
/// - The chain's MMR is seeded to 2^16 − 1 leaves first, so a door that appends pays the worst
///   append at that width (16 merges + the peak bag). A fresh tree would understate it.
/// - Every contract is cooled before the call, so storage reads are cold as in a fresh transaction.
/// - Execution gas only (`gasleft` delta around the call): no 21k intrinsic, no calldata. A proof's
///   calldata alone adds ~14.6 KB, roughly 150–230k gas at 4/16 per byte.
/// - Measured on forge 1.7.1 (the CI pin). Ceiling = measured + ~10%, rounded up.
///
/// | door (at MMR width 2^16 - 1, cold)        |  measured |   ceiling |
/// | ----------------------------------------- | --------- | --------- |
/// | AdManager.lockForOrder                    | 1,201,540 | 1,322,000 |
/// | OrderPortal.createOrder                   | 1,185,878 | 1,305,000 |
/// | AdManager.finalizeCancel                  | 1,131,511 | 1,245,000 |
/// | AdManager.dispute                         |   245,221 |   270,000 |
/// | AdManager.finalizeDispute (MakerForfeit)  | 1,240,336 | 1,365,000 |
/// | AdManager.presentSettled (disputed)       | 2,017,565 | 2,220,000 |
/// | OrderPortal.refundByCancel                | 1,892,278 | 2,082,000 |
/// | OrderPortal.payMakerByForfeit             | 1,908,505 | 2,100,000 |
/// | OrderPortal.presentSettled                | 1,907,379 | 2,099,000 |
/// | AdManager.recordSettled                   | 1,108,622 | 1,220,000 |
/// | MerkleManager.appendOrderHash             | 1,077,954 | 1,186,000 |
///
/// Reading it: the worst-case append is ~1.08M of every door that appends (lock, create, cancel,
/// finalizeDispute, recordSettled), and the UltraHonk verify is ~1.83M of every evidence door.
contract EscrowDoorGas is Test {
    AdManager internal adManager;
    OrderPortal internal portal;
    DisputeManager internal dm;
    MerkleManager internal adMmr;
    MerkleManager internal orderMmr;
    HonkVerifier internal honk;
    RootAnchor internal anchor;
    MockKeyRegistry internal keyRegistry;
    ERC20Mock internal adToken;
    ERC20Mock internal orderToken;
    wNativeToken internal wNative;
    address internal hasher;

    address internal admin = makeAddr("admin");
    address internal maker = makeAddr("maker");
    address internal bridger = makeAddr("bridger");
    address internal recipient = makeAddr("recipient");
    address internal adRecipient = makeAddr("adRecipient");
    address internal arbiter = makeAddr("arbiter");
    address internal feePool = makeAddr("feePool");

    // The two legs share one EVM here; the peer chain ids only have to differ.
    uint256 internal constant ORDER_CHAIN = 111;
    uint256 internal constant AD_CHAIN = 222;
    string internal constant AD_ID = "gas-ad";
    uint256 internal constant AMOUNT = 60 ether;
    uint64 internal constant CHALLENGE = 2 hours;
    uint64 internal nextSeq = 1;

    /// The worst width to append at below 2^16: all 16 peaks merge on the next leaf.
    uint256 internal constant SEED_WIDTH = (1 << 16) - 1;

    // Ceilings, measured + ~10%. See the table above.
    uint256 internal constant LOCK_FOR_ORDER_CEILING = 1_322_000;
    uint256 internal constant CREATE_ORDER_CEILING = 1_305_000;
    uint256 internal constant FINALIZE_CANCEL_CEILING = 1_245_000;
    uint256 internal constant DISPUTE_CEILING = 270_000;
    uint256 internal constant FINALIZE_DISPUTE_CEILING = 1_365_000;
    uint256 internal constant AD_PRESENT_SETTLED_CEILING = 2_220_000;
    uint256 internal constant REFUND_BY_CANCEL_CEILING = 2_082_000;
    uint256 internal constant PAY_MAKER_BY_FORFEIT_CEILING = 2_100_000;
    uint256 internal constant PORTAL_PRESENT_SETTLED_CEILING = 2_099_000;
    uint256 internal constant RECORD_SETTLED_CEILING = 1_220_000;
    uint256 internal constant MMR_APPEND_CEILING = 1_186_000;

    function setUp() public {
        hasher = address(new Poseidon2Yul());
        adMmr = new MerkleManager(admin, hasher);
        orderMmr = new MerkleManager(admin, hasher);
        honk = new HonkVerifier();
        wNative = new wNativeToken("Wrapped Native Token", "WNATIVE", 18);
        keyRegistry = new MockKeyRegistry();
        keyRegistry.set(_b32(maker), true);
        address[] memory signers = new address[](1);
        signers[0] = address(this);
        anchor = new RootAnchor(admin, signers, 1);
        adToken = new ERC20Mock();
        orderToken = new ERC20Mock();

        adManager = new AdManager(
            admin, IVerifier(address(honk)), IMerkleManager(address(adMmr)), IwNativeToken(address(wNative))
        );
        portal = new OrderPortal(
            admin, IVerifier(address(honk)), IMerkleManager(address(orderMmr)), IwNativeToken(address(wNative))
        );
        dm = new DisputeManager(admin, IwNativeToken(address(wNative)));

        vm.startPrank(admin);
        adMmr.setManager(address(adManager), true);
        adMmr.setManager(admin, true);
        orderMmr.setManager(address(portal), true);

        adManager.setKeyRegistry(keyRegistry);
        adManager.setPeerEscrow(ORDER_CHAIN, _b32(address(portal)));
        adManager.setTokenRoute(address(adToken), ORDER_CHAIN, _b32(address(orderToken)));
        adManager.setRootVerifier(ORDER_CHAIN, address(new MockRootVerifier(true)));
        adManager.setRouteTiming(ORDER_CHAIN, RouteTiming.Timing(0, 30 minutes, 0, 1 days, 0));
        adManager.setRootAnchor(IRootAnchor(address(anchor)));
        adManager.setDisputeManager(IDisputeManager(address(dm)));
        dm.setEscrow(address(adManager), true);
        dm.setArbiter(arbiter);
        dm.setProtocolFeePool(feePool);
        dm.setDisputeParams(ORDER_CHAIN, Dispute.Params(CHALLENGE, 1 ether, 100));

        portal.setPeerEscrow(AD_CHAIN, _b32(address(adManager)));
        portal.setTokenRoute(address(orderToken), AD_CHAIN, _b32(address(adToken)));
        portal.setRootVerifier(AD_CHAIN, address(new MockRootVerifier(true)));
        portal.setRouteTiming(AD_CHAIN, RouteTiming.Timing(0, 30 minutes, 0, 1 days, 0));
        portal.setRootAnchor(IRootAnchor(address(anchor)));
        vm.stopPrank();

        adToken.mint(maker, 1_000 ether);
        vm.startPrank(maker);
        adToken.approve(address(adManager), type(uint256).max);
        adManager.createAd(AD_ID, address(adToken), 1_000 ether, ORDER_CHAIN, _b32(adRecipient), _b32(maker));
        vm.stopPrank();

        orderToken.mint(bridger, 1_000 ether);
        vm.prank(bridger);
        orderToken.approve(address(portal), type(uint256).max);
    }

    /*//////////////////////////////////////////////////////////////
                            THE AD CHAIN
    //////////////////////////////////////////////////////////////*/

    function test_gas_lockForOrder() public {
        IAdManager.OrderParams memory p = _adParams(1);
        _prepare(adMmr);
        vm.prank(maker);
        uint256 g0 = gasleft();
        adManager.lockForOrder(p);
        _check("AdManager.lockForOrder", g0 - gasleft(), LOCK_FOR_ORDER_CEILING);
    }

    function test_gas_finalizeCancel() public {
        IAdManager.OrderParams memory p = _lock(2);
        vm.warp(p.deadline);
        adManager.claimCancel(p);
        vm.warp(p.deadline + 30 minutes);
        _prepare(adMmr);
        uint256 g0 = gasleft();
        adManager.finalizeCancel(p);
        _check("AdManager.finalizeCancel", g0 - gasleft(), FINALIZE_CANCEL_CEILING);
    }

    function test_gas_dispute() public {
        IAdManager.OrderParams memory p = _lock(3);
        uint256 bond = Dispute.bondFor(AMOUNT, Dispute.Params(CHALLENGE, 1 ether, 100));
        vm.deal(recipient, bond);
        _prepare(adMmr);
        vm.prank(recipient);
        uint256 g0 = gasleft();
        adManager.dispute{value: bond}(p, bytes32("evidence"));
        _check("AdManager.dispute", g0 - gasleft(), DISPUTE_CEILING);
    }

    /// The dearest outcome: MakerForfeit pays the lock out of the ad, returns the bond, appends.
    function test_gas_finalizeDispute() public {
        IAdManager.OrderParams memory p = _lock(4);
        bytes32 h = _adHash(p);
        _fileAs(p, recipient);
        vm.prank(arbiter);
        dm.resolveDispute(h, Dispute.Outcome.MakerForfeit);
        vm.warp(dm.effectiveChallengeDeadline(h));
        _prepare(adMmr);
        uint256 g0 = gasleft();
        adManager.finalizeDispute(p);
        _check("AdManager.finalizeDispute (MakerForfeit)", g0 - gasleft(), FINALIZE_DISPUTE_CEILING);
    }

    /// Evidence on a disputed order: the proof, the payout, and the dispute closed with its bond.
    function test_gas_adPresentSettled() public {
        IAdManager.OrderParams memory p = _lock(5);
        bytes32 h = _adHash(p);
        _fileAs(p, maker);
        (bytes memory proof, bytes32 root) = _eventProof(LeafDomain.SETTLED, h);
        anchor.anchor(ORDER_CHAIN, root, nextSeq++);
        _prepare(adMmr);
        uint256 g0 = gasleft();
        adManager.presentSettled(p, root, proof);
        _check("AdManager.presentSettled (real proof, closes a dispute)", g0 - gasleft(), AD_PRESENT_SETTLED_CEILING);
    }

    /// The SETTLED leaf's own transaction, at the seeded width (1.6c measured it at width 1 → 2).
    function test_gas_recordSettled() public {
        IAdManager.OrderParams memory p = _lock(6);
        (bytes memory proof, bytes32 root) = _eventProof(LeafDomain.SETTLED, _adHash(p));
        anchor.anchor(ORDER_CHAIN, root, nextSeq++);
        adManager.presentSettled(p, root, proof);
        _prepare(adMmr);
        uint256 g0 = gasleft();
        adManager.recordSettled(p);
        _check("AdManager.recordSettled (seeded MMR)", g0 - gasleft(), RECORD_SETTLED_CEILING);
    }

    /// One append straight into the MerkleManager at 2^16 − 1 → 2^16, the worst case below 2^17.
    function test_gas_mmrAppendAtWidth2e16() public {
        _prepare(adMmr);
        vm.prank(admin);
        uint256 g0 = gasleft();
        adMmr.appendOrderHash(keccak256("leaf"), LeafDomain.ORDER);
        _check("MerkleManager.appendOrderHash (2^16 - 1 -> 2^16)", g0 - gasleft(), MMR_APPEND_CEILING);
        assertEq(adMmr.getWidth(), 1 << 16);
    }

    /*//////////////////////////////////////////////////////////////
                           THE ORDER CHAIN
    //////////////////////////////////////////////////////////////*/

    function test_gas_createOrder() public {
        IOrderPortal.OrderParams memory p = _orderParams(11);
        _prepare(orderMmr);
        vm.prank(bridger);
        uint256 g0 = gasleft();
        portal.createOrder(p);
        _check("OrderPortal.createOrder", g0 - gasleft(), CREATE_ORDER_CEILING);
    }

    function test_gas_refundByCancel() public {
        IOrderPortal.OrderParams memory p = _create(12);
        (bytes memory proof, bytes32 root) = _eventProof(LeafDomain.CANCEL, _orderHash(p));
        anchor.anchor(AD_CHAIN, root, nextSeq++);
        _prepare(orderMmr);
        uint256 g0 = gasleft();
        portal.refundByCancel(p, root, proof);
        _check("OrderPortal.refundByCancel (real proof)", g0 - gasleft(), REFUND_BY_CANCEL_CEILING);
    }

    function test_gas_payMakerByForfeit() public {
        IOrderPortal.OrderParams memory p = _create(13);
        (bytes memory proof, bytes32 root) = _eventProof(LeafDomain.FORFEIT, _orderHash(p));
        anchor.anchor(AD_CHAIN, root, nextSeq++);
        _prepare(orderMmr);
        uint256 g0 = gasleft();
        portal.payMakerByForfeit(p, root, proof);
        _check("OrderPortal.payMakerByForfeit (real proof)", g0 - gasleft(), PAY_MAKER_BY_FORFEIT_CEILING);
    }

    function test_gas_portalPresentSettled() public {
        IOrderPortal.OrderParams memory p = _create(14);
        (bytes memory proof, bytes32 root) = _eventProof(LeafDomain.SETTLED, _orderHash(p));
        anchor.anchor(AD_CHAIN, root, nextSeq++);
        _prepare(orderMmr);
        uint256 g0 = gasleft();
        portal.presentSettled(p, root, proof);
        _check("OrderPortal.presentSettled (real proof)", g0 - gasleft(), PORTAL_PRESENT_SETTLED_CEILING);
    }

    /*//////////////////////////////////////////////////////////////
                  THE SEEDING, AND PROOF THAT IT HOLDS
    //////////////////////////////////////////////////////////////*/

    /// The seeding writes a tree's state directly, so it must be a tree the library would have built:
    /// a real 7-leaf tree and a seeded copy of it take the same next leaf to the same root.
    function test_seedingMatchesARealTree() public {
        MerkleManager real = new MerkleManager(address(this), hasher);
        MerkleManager seeded = new MerkleManager(address(this), hasher);
        real.setManager(address(this), true);
        seeded.setManager(address(this), true);
        for (uint256 i = 0; i < 7; i++) {
            real.appendOrderHash(keccak256(abi.encode(i)), i % 2);
        }
        uint256[] memory peaks = _peakIndexes(7);
        bytes32[] memory values = new bytes32[](peaks.length);
        for (uint256 i = 0; i < peaks.length; i++) {
            values[i] = real.getNode(peaks[i]);
        }
        _seed(seeded, 7, peaks, values, real.getRoot());
        assertEq(seeded.getSize(), real.getSize(), "size");
        assertEq(seeded.getRoot(), real.getRoot(), "root");

        real.appendOrderHash(keccak256("next"), 1);
        seeded.appendOrderHash(keccak256("next"), 1);
        assertEq(seeded.getRoot(), real.getRoot(), "a seeded tree appends exactly as a real one");
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// Seed `mmr` to `SEED_WIDTH` leaves and cool every contract a door touches.
    function _prepare(MerkleManager mmr) internal {
        uint256[] memory peaks = _peakIndexes(SEED_WIDTH);
        bytes32[] memory values = new bytes32[](peaks.length);
        for (uint256 i = 0; i < peaks.length; i++) {
            // Any field element: Poseidon2 costs the same whatever it hashes.
            values[i] = bytes32(uint256(keccak256(abi.encode("peak", i))) >> 4);
        }
        _seed(mmr, SEED_WIDTH, peaks, values, bytes32(uint256(1)));

        address[13] memory touched = [
            address(adManager),
            address(portal),
            address(dm),
            address(adMmr),
            address(orderMmr),
            address(honk),
            address(anchor),
            address(keyRegistry),
            address(adToken),
            address(orderToken),
            address(wNative),
            hasher,
            address(adManager.rootVerifier(ORDER_CHAIN))
        ];
        for (uint256 i = 0; i < touched.length; i++) {
            vm.cool(touched[i]);
        }
    }

    // MerkleManager storage: `_tree` at slot 2 (after `admin`, `pendingAdmin`) = {root, size, width, hasher, hashes}.
    uint256 internal constant TREE_SLOT = 2;

    function _seed(MerkleManager mmr, uint256 width, uint256[] memory peaks, bytes32[] memory values, bytes32 root)
        internal
    {
        vm.store(address(mmr), bytes32(TREE_SLOT), root);
        vm.store(address(mmr), bytes32(TREE_SLOT + 1), bytes32((width << 1) - peaks.length));
        vm.store(address(mmr), bytes32(TREE_SLOT + 2), bytes32(width));
        for (uint256 i = 0; i < peaks.length; i++) {
            vm.store(address(mmr), keccak256(abi.encode(peaks[i], TREE_SLOT + 4)), values[i]);
        }
    }

    /// The library's own peak walk (`MMRPoseidon2._getPeakIndexes`), 1-based node indexes.
    function _peakIndexes(uint256 width) internal pure returns (uint256[] memory out) {
        uint256 n;
        for (uint256 b = width; b > 0; b &= b - 1) {
            n++;
        }
        out = new uint256[](n);
        uint8 maxHeight = 1;
        while ((1 << maxHeight) <= width) maxHeight++;
        uint256 count;
        uint256 running;
        for (uint256 i = maxHeight; i > 0; i--) {
            if (width & (1 << (i - 1)) != 0) {
                running += (1 << i) - 1;
                out[count++] = running;
            }
        }
    }

    function _check(string memory door, uint256 used, uint256 ceiling) internal pure {
        console2.log(door, used);
        assertLe(used, ceiling, door);
    }

    function _adParams(uint256 salt) internal view returns (IAdManager.OrderParams memory p) {
        p.orderChainToken = _b32(address(orderToken));
        p.adChainToken = _b32(address(adToken));
        p.amount = AMOUNT;
        p.bridger = _b32(bridger);
        p.orderChainId = ORDER_CHAIN;
        p.srcOrderPortal = _b32(address(portal));
        p.orderRecipient = _b32(recipient);
        p.adId = AD_ID;
        p.adCreator = _b32(maker);
        p.adRecipient = _b32(adRecipient);
        p.salt = salt;
        p.orderDecimals = 18;
        p.adDecimals = 18;
        p.deadline = block.timestamp + 1 days;
        p.adSettlementSigner = _b32(maker);
    }

    function _orderParams(uint256 salt) internal view returns (IOrderPortal.OrderParams memory p) {
        p.orderChainToken = _b32(address(orderToken));
        p.adChainToken = _b32(address(adToken));
        p.amount = AMOUNT;
        p.bridger = _b32(bridger);
        p.orderRecipient = _b32(recipient);
        p.adChainId = AD_CHAIN;
        p.adManager = _b32(address(adManager));
        p.adId = AD_ID;
        p.adCreator = _b32(maker);
        p.adRecipient = _b32(adRecipient);
        p.salt = salt;
        p.orderDecimals = 18;
        p.adDecimals = 18;
        p.deadline = block.timestamp + 1 days;
        p.adSettlementSigner = _b32(maker);
    }

    function _lock(uint256 salt) internal returns (IAdManager.OrderParams memory p) {
        p = _adParams(salt);
        vm.prank(maker);
        adManager.lockForOrder(p);
    }

    function _create(uint256 salt) internal returns (IOrderPortal.OrderParams memory p) {
        p = _orderParams(salt);
        vm.prank(bridger);
        portal.createOrder(p);
    }

    function _fileAs(IAdManager.OrderParams memory p, address who) internal {
        uint256 bond = Dispute.bondFor(AMOUNT, Dispute.Params(CHALLENGE, 1 ether, 100));
        vm.deal(who, bond);
        vm.prank(who);
        adManager.dispute{value: bond}(p, bytes32("evidence"));
    }

    function _adHash(IAdManager.OrderParams memory p) internal view returns (bytes32) {
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
                adManager: _b32(address(adManager)),
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

    function _orderHash(IOrderPortal.OrderParams memory p) internal view returns (bytes32) {
        return OrderHash.digest(
            OrderHash.Order({
                orderChainToken: p.orderChainToken,
                adChainToken: p.adChainToken,
                amount: p.amount,
                bridger: p.bridger,
                orderChainId: block.chainid,
                orderPortal: _b32(address(portal)),
                orderRecipient: p.orderRecipient,
                adChainId: p.adChainId,
                adManager: p.adManager,
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

    function _b32(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }
}
