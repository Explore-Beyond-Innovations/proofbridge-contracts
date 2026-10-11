// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IEscrow} from "src/interfaces/IEscrow.sol";
import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IDisputeManager} from "src/interfaces/IDisputeManager.sol";
import {IwNativeToken} from "src/wNativeToken.sol";
import {DisputeManager} from "src/DisputeManager.sol";
import {Dispute} from "src/libraries/Dispute.sol";
import {TestField} from "test/utils/TestField.sol";
import {AdManagerTest} from "./Admanager.t.sol";
import {Test} from "forge-std/Test.sol";
import {AdManager} from "src/AdManager.sol";
import {MerkleManager} from "src/MerkleManager.sol";
import {IVerifier} from "src/Verifier.sol";
import {IMerkleManager} from "src/MerkleManager.sol";
import {wNativeToken} from "src/wNativeToken.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {MockVerifier} from "test/mocks/MockVerifier.sol";
import {MockRootVerifier} from "test/mocks/MockRootVerifier.sol";
import {RouteTiming} from "src/libraries/RouteTiming.sol";
import {Poseidon2Yul_BN254 as Poseidon2Yul} from "@poseidon2/src/bn254/yul/Poseidon2Yul.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {BLSKeyRegistry} from "src/BLSKeyRegistry.sol";
import {IBLSKeyRegistry} from "src/interfaces/IBLSKeyRegistry.sol";
import {IKeyRegistry} from "src/interfaces/IKeyRegistry.sol";
import {OwnerAuthVectors} from "test/utils/OwnerAuthVectors.sol";

/// A settlement signer other than the maker must have approved the maker in the key registry:
/// checked at `createAd`, `setSettlementSigner` and every lock. Naming yourself needs no approval.
contract SignerConsentTest is AdManagerTest {
    bytes32 internal constant SIGNER = bytes32(uint256(0x5161e7));
    address internal arbiter = makeAddr("arbiter");

    function setUp() public virtual override {
        super.setUp();
        keyRegistry.set(SIGNER, true);
    }

    function _route() internal {
        vm.startPrank(admin);
        adManager.setPeerEscrow(orderChainId, _b32(orderPortal));
        adManager.setTokenRoute(address(adToken), orderChainId, _b32(orderToken));
        vm.stopPrank();
    }

    function _create(address who, string memory adId, bytes32 signer) internal {
        adToken.mint(who, initAmt);
        vm.prank(who);
        adToken.approve(address(adManager), initAmt);
        vm.prank(who);
        adManager.createAd(adId, address(adToken), initAmt, orderChainId, _b32(adRecipient), signer);
    }

    function _notApproved(bytes32 signer, address who) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IAdManager.AdManager__SignerNotApproved.selector, signer, _b32(who));
    }

    /// The fixture ad, re-pointed at SIGNER after SIGNER approved the maker, with one lock on it.
    function _lockOnApprovedSigner(uint256 salt) internal returns (IAdManager.OrderParams memory p, bytes32 h) {
        test_fundAd_makerOnly();
        keyRegistry.approve(SIGNER, _b32(maker), true);
        vm.prank(maker);
        adManager.setSettlementSigner(lastAdId, SIGNER);
        p = _defaultParams(lastAdId);
        p.amount = 60 ether;
        p.salt = salt;
        p.adSettlementSigner = SIGNER;
        vm.prank(maker);
        h = adManager.lockForOrder(p);
        assertEq(adManager.inFlightOf(SIGNER), 1, "the signer is counted");
    }

    function test_selfSigner_needsNoApproval() public {
        // createAd names the maker itself (the fixture), then the lever and a lock do too.
        test_fundAd_makerOnly();
        assertFalse(keyRegistry.isApprovedMaker(_b32(maker), _b32(maker)), "no approval on file");
        vm.prank(maker);
        adManager.setSettlementSigner(lastAdId, _b32(maker));
        _openOrder(lastAdId, address(adToken), 60 ether, 1, bridger, recipient);
        assertEq(adManager.inFlightOf(_b32(maker)), 1);
    }

    function test_createAd_unapprovedSigner_reverts_thenPassesWithApproval() public {
        _route();
        adToken.mint(maker, initAmt);
        vm.prank(maker);
        adToken.approve(address(adManager), initAmt);
        vm.prank(maker);
        vm.expectRevert(_notApproved(SIGNER, maker));
        adManager.createAd("c1", address(adToken), initAmt, orderChainId, _b32(adRecipient), SIGNER);

        keyRegistry.approve(SIGNER, _b32(maker), true);
        _create(maker, "c1", SIGNER);
        (,,,,,, bytes32 s,,) = adManager.ads("c1");
        assertEq(s, SIGNER);
    }

    function test_setSettlementSigner_unapprovedSigner_reverts_thenPassesWithApproval() public {
        test_fundAd_makerOnly();
        vm.prank(maker);
        vm.expectRevert(_notApproved(SIGNER, maker));
        adManager.setSettlementSigner(lastAdId, SIGNER);

        keyRegistry.approve(SIGNER, _b32(maker), true);
        vm.prank(maker);
        adManager.setSettlementSigner(lastAdId, SIGNER);
    }

    function test_lock_afterWithdrawal_reverts() public {
        (IAdManager.OrderParams memory p,) = _lockOnApprovedSigner(2);

        keyRegistry.approve(SIGNER, _b32(maker), false);
        p.salt = 3;
        vm.prank(maker);
        vm.expectRevert(_notApproved(SIGNER, maker));
        adManager.lockForOrder(p);
    }

    function test_withdrawal_lockedOrderStillSettles() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockOnApprovedSigner(4);
        keyRegistry.approve(SIGNER, _b32(maker), false);

        vm.prank(bridger);
        adManager.unlock(p, TestField.fe("SC4"), bytes32(uint256(3)), hex"", hex"");
        assertEq(uint8(adManager.orders(h)), uint8(IEscrow.Status.Filled));
        assertEq(adManager.inFlightOf(SIGNER), 0);
    }

    function test_withdrawal_lockedOrderStillCancels() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockOnApprovedSigner(5);
        keyRegistry.approve(SIGNER, _b32(maker), false);

        vm.warp(p.deadline);
        adManager.claimCancel(p);
        vm.warp(p.deadline + 30 minutes);
        adManager.finalizeCancel(p);
        assertEq(uint8(adManager.orders(h)), uint8(IEscrow.Status.Cancelled));
        assertEq(adManager.inFlightOf(SIGNER), 0);
    }

    function test_withdrawal_lockedOrderDisputeStillCloses() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _lockOnApprovedSigner(6);
        keyRegistry.approve(SIGNER, _b32(maker), false);

        DisputeManager dm = new DisputeManager(admin, IwNativeToken(address(_wNativeToken)));
        Dispute.Params memory params = Dispute.Params(2 hours, 1 ether);
        vm.startPrank(admin);
        dm.setEscrow(address(adManager), true);
        dm.setArbiter(arbiter);
        dm.setProtocolFeePool(makeAddr("feePool"));
        dm.setDisputeParams(orderChainId, params);
        adManager.setDisputeManager(IDisputeManager(address(dm)));
        vm.stopPrank();

        uint256 bond = params.bondFloor;
        vm.deal(recipient, bond);
        vm.prank(recipient);
        adManager.dispute{value: bond}(p, bytes32("evidence"));
        vm.prank(arbiter);
        dm.resolveDispute(h, Dispute.Outcome.MutualRefund);
        vm.warp(dm.effectiveChallengeDeadline(h) + 1);
        adManager.finalizeDispute(p);
        assertEq(uint8(adManager.orders(h)), uint8(IEscrow.Status.Resolved));
        assertEq(adManager.inFlightOf(SIGNER), 0);
    }

    function test_approvalForOneMaker_doesNotLetAnotherMakerName() public {
        _route();
        keyRegistry.approve(SIGNER, _b32(maker), true);
        _create(maker, "m1", SIGNER);

        adToken.mint(nonMaker, initAmt);
        vm.prank(nonMaker);
        adToken.approve(address(adManager), initAmt);
        vm.prank(nonMaker);
        vm.expectRevert(_notApproved(SIGNER, nonMaker));
        adManager.createAd("n1", address(adToken), initAmt, orderChainId, _b32(adRecipient), SIGNER);
    }

    /// The agent shape: a smart account holds the funds and is the maker; its key account signs.
    /// One approval by the key account is all the account needs.
    function test_agentShape_smartAccountMaker_keyAccountSigner_oneApproval() public {
        address account = makeAddr("smartAccount");
        vm.etch(account, hex"00");
        _route();
        keyRegistry.approve(SIGNER, _b32(account), true);
        _create(account, "agent", SIGNER);

        IAdManager.OrderParams memory p = _defaultParams("agent");
        p.adCreator = _b32(account);
        p.adSettlementSigner = SIGNER;
        p.amount = 60 ether;
        vm.prank(account);
        adManager.lockForOrder(p);
        assertEq(adManager.inFlightOf(SIGNER), 1);
    }
}

/// The same gate against the real key registry, with the vector account as the would-be signer and
/// forge's `makeAddr("maker")` as the maker the vector approvals name.
contract SignerConsentRealRegistryTest is Test {
    using stdJson for string;

    uint256 constant VECTOR_CHAIN_ID = 11155111;
    uint256 constant ORDER_CHAIN_ID = 1000002;
    address constant REGISTRY = 0x1111111111111111111111111111111111111111;

    string vjson;
    BLSKeyRegistry reg;
    AdManager adManager;
    ERC20Mock adToken;
    bytes32 signer;
    address admin = makeAddr("admin");
    address maker = makeAddr("maker");

    function _b32(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    function setUp() public {
        vm.chainId(VECTOR_CHAIN_ID);
        vjson = vm.readFile("../test-vectors/bls-encodings.json");
        vm.warp(vm.parseUint(vjson.readString(".ownerAuth._meta.deadline.registerChainTime")));

        MerkleManager mm = new MerkleManager(admin, address(new Poseidon2Yul()));
        adManager = new AdManager(
            admin,
            IVerifier(address(new MockVerifier(true))),
            IMerkleManager(address(mm)),
            IwNativeToken(address(new wNativeToken("Wrapped Native Token", "WNATIVE", 18)))
        );
        adToken = new ERC20Mock();
        adToken.mint(maker, 1_000 ether);

        BLSKeyRegistry impl = new BLSKeyRegistry(address(this), "testnet");
        vm.etch(REGISTRY, address(impl).code);
        vm.store(REGISTRY, bytes32(0), bytes32(uint256(uint160(address(this))))); // admin
        reg = BLSKeyRegistry(REGISTRY);
        address[] memory guards = new address[](1);
        guards[0] = address(adManager);
        reg.setPositionGuards(guards);

        signer = vjson.readBytes32(".registration.makerOnSepolia.account");
        reg.register(
            signer,
            OwnerAuthVectors.auth(vjson, ".ownerAuth.maker.register[0]"),
            vjson.readBytes(".registration.makerOnSepolia.pkNative"),
            vjson.readBytes(".registration.makerOnSepolia.pop"),
            0,
            OwnerAuthVectors.deadline(vjson, ".ownerAuth.maker.register[0]")
        );
        vm.startPrank(admin);
        mm.setManager(address(adManager), true);
        adManager.setRootVerifier(ORDER_CHAIN_ID, address(new MockRootVerifier(true)));
        adManager.setRouteTiming(ORDER_CHAIN_ID, RouteTiming.Timing(0, 30 minutes, 0, 1 days, 0));
        adManager.setKeyRegistry(IKeyRegistry(REGISTRY));
        adManager.setPeerEscrow(ORDER_CHAIN_ID, _b32(makeAddr("orderPortal")));
        adManager.setTokenRoute(address(adToken), ORDER_CHAIN_ID, _b32(makeAddr("orderToken")));
        vm.stopPrank();

        assertEq(_b32(maker), vjson.readBytes32(".ownerAuth._meta.makers.approved"), "vectors name this maker");
    }

    function _file(string memory entry) internal {
        string memory path = string.concat(".ownerAuth.maker.", entry);
        reg.approveMaker(
            signer,
            _b32(maker),
            vjson.readBool(string.concat(path, ".approved")),
            OwnerAuthVectors.auth(vjson, path),
            OwnerAuthVectors.legs(vjson, path)[0].nonce,
            OwnerAuthVectors.deadline(vjson, path)
        );
    }

    function _createNamingSigner(string memory adId) internal {
        vm.prank(maker);
        adToken.approve(address(adManager), 100 ether);
        _createOnly(adId);
    }

    function _createOnly(string memory adId) internal {
        vm.prank(maker);
        adManager.createAd(adId, address(adToken), 100 ether, ORDER_CHAIN_ID, _b32(makeAddr("adRecipient")), signer);
    }

    function _params(string memory adId) internal returns (IAdManager.OrderParams memory p) {
        p.orderChainToken = _b32(makeAddr("orderToken"));
        p.adChainToken = _b32(address(adToken));
        p.amount = 40 ether;
        p.bridger = _b32(makeAddr("bridger"));
        p.orderChainId = ORDER_CHAIN_ID;
        p.srcOrderPortal = _b32(makeAddr("orderPortal"));
        p.orderRecipient = _b32(makeAddr("recipient"));
        p.adId = adId;
        p.adCreator = _b32(maker);
        p.adRecipient = _b32(makeAddr("adRecipient"));
        p.salt = 1;
        p.orderDecimals = 18;
        p.adDecimals = 18;
        p.deadline = block.timestamp + 1 days;
        p.adSettlementSigner = signer;
    }

    /// The lockout cannot set up: a maker naming a stranger is refused, so the stranger can leave.
    function test_strangerCannotBeNamed_andCanStillRevoke() public {
        vm.prank(maker);
        adToken.approve(address(adManager), 100 ether);
        vm.expectRevert(abi.encodeWithSelector(IAdManager.AdManager__SignerNotApproved.selector, signer, _b32(maker)));
        _createOnly("x");

        reg.revoke(signer, OwnerAuthVectors.auth(vjson, ".ownerAuth.maker.revoke[1]"), 1);
        assertFalse(reg.hasUsableSlot(signer));
    }

    /// With the signer's approval the maker locks, and the open lock then guards the signer, as
    /// intended; withdrawing refuses the next lock while the open one stays.
    function test_approvedSigner_locks_thenWithdrawalRefusesTheNextLock() public {
        _file("approveMaker[0]");
        _createNamingSigner("y");
        IAdManager.OrderParams memory p = _params("y");
        vm.prank(maker);
        adManager.lockForOrder(p);

        IBLSKeyRegistry.OwnerAuth memory anyAuth;
        vm.expectRevert(IBLSKeyRegistry.AccountInFlight.selector);
        reg.revoke(signer, anyAuth, 1);

        _file("approveMaker[1]");
        p.salt = 77;
        vm.prank(maker);
        vm.expectRevert(abi.encodeWithSelector(IAdManager.AdManager__SignerNotApproved.selector, signer, _b32(maker)));
        adManager.lockForOrder(p);
        assertEq(adManager.inFlightOf(signer), 1, "the open lock is untouched");
    }
}
