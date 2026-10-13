// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IEscrow} from "src/interfaces/IEscrow.sol";
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
import {RouteTiming} from "src/libraries/RouteTiming.sol";
import {OrderHash} from "src/libraries/OrderHash.sol";
import {ProofBridgeUtils} from "src/libraries/ProofBridgeUtils.sol";
import {FieldElement} from "src/libraries/FieldElement.sol";
import {MockVerifier} from "test/mocks/MockVerifier.sol";
import {MockKeyRegistry} from "../mocks/MockKeyRegistry.sol";
import {MockRootVerifier} from "../mocks/MockRootVerifier.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {Poseidon2Yul_BN254 as Poseidon2Yul} from "@poseidon2/src/bn254/yul/Poseidon2Yul.sol";

/// A wired ad chain with an ERC20 ad and a native ad, for the fee and the bond suites.
abstract contract Phase3Base is Test {
    AdManager internal adManager;
    DisputeManager internal dm;
    MerkleManager internal mmr;
    wNativeToken internal wNative;
    ERC20Mock internal adToken;
    RootAnchor internal anchor;

    address internal admin = makeAddr("admin");
    address internal maker = makeAddr("maker");
    address internal bridger = makeAddr("bridger");
    address internal recipient = makeAddr("recipient");
    address internal arbiter = makeAddr("arbiter");
    address internal bondPool = makeAddr("bondPool");
    address internal pool = makeAddr("protocolPool");
    address internal orderPortal = makeAddr("orderPortal");
    address internal orderToken = makeAddr("orderToken");

    address internal constant NATIVE = address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);
    string internal constant AD = "fees";
    string internal constant NATIVE_AD = "fees-native";
    bytes32 internal constant EVIDENCE_ROOT = bytes32(uint256(0xe71d));
    uint256 internal constant ORDER_CHAIN = 11155111;
    uint128 internal constant BOND_FLOOR = 1 ether;
    uint256 internal constant AD_START = 1e30;

    function setUp() public virtual {
        mmr = new MerkleManager(admin, address(new Poseidon2Yul()));
        wNative = new wNativeToken("Wrapped Native Token", "WNATIVE", 18);
        MockKeyRegistry keyRegistry = new MockKeyRegistry();
        keyRegistry.set(bytes32(uint256(uint160(maker))), true);
        adManager = new AdManager(
            admin,
            IVerifier(address(new MockVerifier(true))),
            IMerkleManager(address(mmr)),
            IwNativeToken(address(wNative))
        );
        dm = new DisputeManager(admin, IwNativeToken(address(wNative)));
        address[] memory signers = new address[](1);
        signers[0] = address(this);
        anchor = new RootAnchor(admin, signers, 1);
        anchor.anchor(ORDER_CHAIN, EVIDENCE_ROOT, 1);
        adToken = new ERC20Mock();

        vm.startPrank(admin);
        mmr.setManager(address(adManager), true);
        adManager.setRootVerifier(ORDER_CHAIN, address(new MockRootVerifier(true)));
        adManager.setRouteTiming(ORDER_CHAIN, RouteTiming.Timing(0, 30 minutes, 0, 0));
        adManager.setKeyRegistry(keyRegistry);
        adManager.setPeerEscrow(ORDER_CHAIN, bytes32(uint256(uint160(orderPortal))));
        adManager.setDisputeManager(IDisputeManager(address(dm)));
        adManager.setRootAnchor(IRootAnchor(address(anchor)));
        adManager.setTokenRoute(address(adToken), ORDER_CHAIN, bytes32(uint256(uint160(orderToken))));
        adManager.setTokenRoute(NATIVE, ORDER_CHAIN, bytes32(uint256(uint160(orderToken))));
        dm.setEscrow(address(adManager), true);
        dm.setArbiter(arbiter);
        dm.setProtocolFeePool(bondPool);
        dm.setDisputeParams(ORDER_CHAIN, Dispute.Params(2 hours, BOND_FLOOR));
        vm.stopPrank();

        adToken.mint(maker, AD_START);
        vm.deal(maker, 1_000 ether);
        vm.startPrank(maker);
        adToken.approve(address(adManager), type(uint256).max);
        adManager.createAd(AD, address(adToken), AD_START, ORDER_CHAIN, _b(recipient), _b(maker));
        adManager.createAd{value: 500 ether}(NATIVE_AD, NATIVE, 500 ether, ORDER_CHAIN, _b(recipient), _b(maker));
        vm.stopPrank();
    }

    function _b(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    function _fees(uint16 lp, uint16 protocol) internal {
        vm.startPrank(admin);
        adManager.setProtocolFeePool(pool);
        adManager.setFeeBps(lp, protocol);
        vm.stopPrank();
    }

    function _params(bool native, uint256 amount, uint256 salt)
        internal
        view
        returns (IAdManager.OrderParams memory p)
    {
        p.orderChainToken = _b(orderToken);
        p.adChainToken = _b(native ? NATIVE : address(adToken));
        p.amount = amount;
        p.bridger = _b(bridger);
        p.orderChainId = ORDER_CHAIN;
        p.srcOrderPortal = _b(orderPortal);
        p.orderRecipient = _b(recipient);
        p.adId = native ? NATIVE_AD : AD;
        p.adCreator = _b(maker);
        p.adRecipient = _b(recipient);
        p.salt = salt;
        p.orderDecimals = 18;
        p.adDecimals = 18;
        p.deadline = 1 days + 7 days; // fixed, so the hash does not move with a warp
        p.adSettlementSigner = _b(maker);
    }

    function _lock(IAdManager.OrderParams memory p) internal returns (bytes32 h) {
        vm.prank(maker);
        h = adManager.lockForOrder(p, 0);
    }

    function _unlock(IAdManager.OrderParams memory p, uint256 salt) internal {
        bytes32 nullifier = bytes32(uint256(keccak256(abi.encode("fee-nullifier", salt))) % FieldElement.prime());
        vm.prank(bridger);
        adManager.unlock(p, nullifier, bytes32(uint256(1)), hex"", hex"");
    }

    function _hash(IAdManager.OrderParams memory p) internal view returns (bytes32) {
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
                adManager: _b(address(adManager)),
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

    function _adBalance(string memory id) internal view returns (uint256 balance, uint256 locked) {
        (,,,,,,, balance, locked) = adManager.ads(id);
    }

    /// File as `who`, have the arbiter rule `o` (None = leave it unruled), and finalize.
    function _disputeTo(IAdManager.OrderParams memory p, address who, Dispute.Outcome o) internal {
        bytes32 h = _hash(p);
        vm.deal(who, BOND_FLOOR);
        vm.prank(who);
        adManager.dispute{value: BOND_FLOOR}(p, bytes32("e"));
        if (o != Dispute.Outcome.None) {
            vm.prank(arbiter);
            dm.resolveDispute(h, o);
        }
        vm.warp(dm.effectiveChallengeDeadline(h));
        adManager.finalizeDispute(p);
    }
}

