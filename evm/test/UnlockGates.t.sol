// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {TestField} from "test/utils/TestField.sol";

import {stdJson} from "forge-std/StdJson.sol";
import {IBLSKeyRegistry} from "src/interfaces/IBLSKeyRegistry.sol";
import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IOrderPortal} from "src/interfaces/IOrderPortal.sol";
import {AdManagerTest} from "./Admanager.t.sol";
import {OrderPortalTest} from "./OrderPortal.t.sol";
import {AdManager} from "src/AdManager.sol";
import {OrderPortal} from "src/OrderPortal.sol";
import {BLSKeyRegistry} from "src/BLSKeyRegistry.sol";
import {CounterpartyVerifier} from "src/CounterpartyVerifier.sol";
import {RootVerifierRegistry} from "src/libraries/RootVerifierRegistry.sol";
import {MockRootVerifier} from "./mocks/MockRootVerifier.sol";
import {CoSign} from "test/utils/CoSign.sol";

abstract contract GateVectors {
    uint256 constant VECTOR_CHAIN_ID = 11155111;
    address constant REGISTRY = 0x1111111111111111111111111111111111111111;
}

contract AdManagerGateTest is AdManagerTest, GateVectors {
    using stdJson for string;

    string vjson;
    CounterpartyVerifier cVerifier;
    bytes32 vOrderRoot;

    function setUp() public override {
        vm.chainId(VECTOR_CHAIN_ID);
        super.setUp();

        vjson = vm.readFile("../test-vectors/bls-encodings.json");
        vOrderRoot = vjson.readBytes32(".settlement.auth.orderChainRoot");

        BLSKeyRegistry impl = new BLSKeyRegistry(address(this));
        vm.etch(REGISTRY, address(impl).code);
        _registerVectorParties(vjson);
        cVerifier = new CounterpartyVerifier(REGISTRY);
    }

    function _cosigData() internal view returns (bytes memory) {
        return _vectorCosig(vjson);
    }

    IAdManager.OrderParams gp;

    /// Configures the module and locks an order via the standard helpers.
    function _prepareUnlock(address module, bytes32 targetRoot) internal {
        test_fundAd_makerOnly();
        (IAdManager.OrderParams memory p, bytes32 orderHash) =
            _openOrder(lastAdId, address(adToken), 60 ether, 999, bridger, recipient);
        gp = p;
        // Wired after the lock: the real verifier reads REGISTRY, the escrow the mock, and #464
        // refuses a lock on that split. These tests are about the unlock's gates, which it never reads.
        vm.prank(admin);
        adManager.setRootVerifier(orderChainId, module);
    }

    function _unlockVia(address module, bytes32 targetRoot, bytes memory cosig) internal {
        _prepareUnlock(module, targetRoot);
        adManager.unlock(gp, TestField.fe("NG"), targetRoot, hex"", cosig);
    }

    function test_gate2_mockTrue_unlocks() public {
        _unlockVia(address(new MockRootVerifier(true)), bytes32(uint256(5)), hex"");
    }

    function test_gate2_mockFalse_reverts() public {
        _prepareUnlock(address(new MockRootVerifier(false)), bytes32(uint256(5)));
        vm.expectRevert(
            abi.encodeWithSelector(RootVerifierRegistry.RootNotValid.selector, orderChainId, bytes32(uint256(5)))
        );
        adManager.unlock(gp, TestField.fe("NG"), bytes32(uint256(5)), hex"", hex"");
    }

    function test_gate2_rootNotInSignedAuth_reverts() public {
        bytes32 junkRoot = bytes32(uint256(0xbad));
        _prepareUnlock(address(cVerifier), junkRoot);
        vm.expectRevert(abi.encodeWithSelector(RootVerifierRegistry.RootNotValid.selector, orderChainId, junkRoot));
        adManager.unlock(gp, TestField.fe("NG"), junkRoot, hex"", _cosigData());
    }

    function test_gate2_partiesNotTheSigners_reverts() public {
        // right root, real aggregate - but the order's parties are local test
        // addresses, not the registered vector signers
        _prepareUnlock(address(cVerifier), vOrderRoot);
        vm.expectRevert(abi.encodeWithSelector(RootVerifierRegistry.RootNotValid.selector, orderChainId, vOrderRoot));
        adManager.unlock(gp, TestField.fe("NG"), vOrderRoot, hex"", _cosigData());
    }

    function test_gate2_garbageCosig_reverts() public {
        _prepareUnlock(address(cVerifier), vOrderRoot);
        vm.expectRevert();
        adManager.unlock(gp, TestField.fe("NG"), vOrderRoot, hex"", hex"deadbeef");
    }

    function test_gate2_noModuleConfigured_reverts() public {
        vm.prank(admin);
        adManager.setRootVerifier(orderChainId, address(0));

        test_fundAd_makerOnly();
        (IAdManager.OrderParams memory p,) = _openOrder(lastAdId, address(adToken), 60 ether, 998, bridger, recipient);
        bytes32 targetRoot = bytes32(uint256(7));
        vm.prank(bridger);
        vm.expectRevert(abi.encodeWithSelector(RootVerifierRegistry.NoRootVerifier.selector, orderChainId));
        adManager.unlock(p, TestField.fe("NS"), targetRoot, hex"", hex"");
    }

    /// C0: in the split case the guard counts the settlement signer the unlock verifies, so the
    /// owner of that key cannot revoke it out from under an open lock — even though custody (the
    /// maker's address) is a different account and is not counted at all.
    function test_inFlight_splitCase_guardsTheSettlementSigner() public {
        BLSKeyRegistry reg = BLSKeyRegistry(REGISTRY);
        vm.store(REGISTRY, bytes32(0), bytes32(uint256(uint160(address(this)))));
        address[] memory guards = new address[](1);
        guards[0] = address(adManager);
        reg.setPositionGuards(guards);
        address module = address(new MockRootVerifier(true));
        vm.prank(admin);
        adManager.setRootVerifier(orderChainId, module);

        // The vector maker's registered key becomes the ad's settlement signer; custody stays `maker`.
        bytes32 signer = vjson.readBytes32(".registration.makerOnSepolia.account");
        test_fundAd_makerOnly();
        keyRegistry.set(signer, true);
        vm.prank(maker);
        adManager.setSettlementSigner(lastAdId, signer);
        IAdManager.OrderParams memory p = _defaultParams(lastAdId);
        p.salt = 4244;
        p.adSettlementSigner = signer;
        vm.prank(maker);
        adManager.lockForOrder(p);

        assertTrue(adManager.hasOpenPositions(signer));
        assertFalse(adManager.hasOpenPositions(_b32(maker)), "custody is not counted");

        // The guard runs before the owner check, so the auth payload is irrelevant here.
        IBLSKeyRegistry.OwnerAuth memory anyAuth = IBLSKeyRegistry.OwnerAuth(IBLSKeyRegistry.Scheme.Eip712, hex"");
        vm.expectRevert(IBLSKeyRegistry.AccountInFlight.selector);
        reg.revoke(signer, anyAuth, 1);

        adManager.unlock(p, TestField.fe("NR2"), bytes32(uint256(3)), hex"", hex"");
        assertFalse(adManager.hasOpenPositions(signer));
    }

    /// Two locks on one ad whose settlement signer and bridger are the registered vector parties.
    function _lockTwoVectorOrders()
        internal
        returns (IAdManager.OrderParams memory x, IAdManager.OrderParams memory y)
    {
        bytes32 signer = vjson.readBytes32(".registration.makerOnSepolia.account");
        test_fundAd_makerOnly();
        keyRegistry.set(signer, true);
        vm.prank(maker);
        adManager.setSettlementSigner(lastAdId, signer);
        x = _defaultParams(lastAdId);
        x.amount = 60 ether;
        x.salt = 5001;
        x.adSettlementSigner = signer;
        x.bridger = vjson.readBytes32(".registration.bridgerOnSepolia.account");
        y = _defaultParams(lastAdId);
        y.amount = 60 ether;
        y.salt = 5002;
        y.adSettlementSigner = signer;
        y.bridger = x.bridger;
        vm.startPrank(maker);
        adManager.lockForOrder(x);
        adManager.lockForOrder(y);
        vm.stopPrank();
        // After the locks, as in `_prepareUnlock` (#464).
        vm.prank(admin);
        adManager.setRootVerifier(orderChainId, address(cVerifier));
    }

    /// #433: two orders between the same parties under the same signed roots. A co-signature over
    /// X is not consent to Y: `unlock(Y)` is refused, `unlock(X)` settles.
    function test_433_cosigOverAnotherOrder_isRefused() public {
        (IAdManager.OrderParams memory x, IAdManager.OrderParams memory y) = _lockTwoVectorOrders();
        bytes memory cosigX = CoSign.moduleDataFor(vjson, adManager.hashOrderPublic(x));
        vm.expectRevert(abi.encodeWithSelector(RootVerifierRegistry.RootNotValid.selector, orderChainId, vOrderRoot));
        adManager.unlock(y, TestField.fe("NY"), vOrderRoot, hex"", cosigX);
        adManager.unlock(x, TestField.fe("NX"), vOrderRoot, hex"", cosigX);
    }

    function test_inFlight_tracksLockAndUnlock() public {
        test_fundAd_makerOnly();
        (IAdManager.OrderParams memory p, bytes32 orderHash) =
            _openOrder(lastAdId, address(adToken), 60 ether, 997, bridger, recipient);

        assertTrue(adManager.hasOpenPositions(p.adCreator));
        // 2.3c D1: the AdManager counts only the maker it authenticated. The bridger is counted by
        // the OrderPortal that authenticated them (see the portal case below).
        assertFalse(adManager.hasOpenPositions(p.bridger));

        bytes32 targetRoot = bytes32(uint256(3));
        vm.prank(bridger);
        adManager.unlock(p, TestField.fe("NI"), targetRoot, hex"", hex"");

        assertFalse(adManager.hasOpenPositions(p.adCreator));
        assertFalse(adManager.hasOpenPositions(p.bridger));
    }
}

contract OrderPortalGateTest is OrderPortalTest, GateVectors {
    using stdJson for string;

    string vjson;
    CounterpartyVerifier cVerifier;
    bytes32 vOrderRoot;
    bytes32 makerAcct;
    bytes32 bridgerAcct;
    address vBridger;

    function setUp() public override {
        vm.chainId(VECTOR_CHAIN_ID);
        super.setUp();

        vjson = vm.readFile("../test-vectors/bls-encodings.json");
        vOrderRoot = vjson.readBytes32(".settlement.auth.orderChainRoot");
        makerAcct = vjson.readBytes32(".registration.makerOnSepolia.account");
        bridgerAcct = vjson.readBytes32(".registration.bridgerOnSepolia.account");
        vBridger = address(uint160(uint256(bridgerAcct)));

        BLSKeyRegistry impl = new BLSKeyRegistry(address(this));
        vm.etch(REGISTRY, address(impl).code);
        _registerVectorParties(vjson);
        cVerifier = new CounterpartyVerifier(REGISTRY);
    }

    function _cosigData() internal view returns (bytes memory) {
        return _vectorCosig(vjson);
    }

    IOrderPortal.OrderParams gp;

    /// Configures the module and creates an order whose parties are the
    /// vector signers (the bridger must be the sender).
    function _prepareUnlock(address module, bytes32 targetRoot) internal {
        vm.prank(admin);
        portal.setRootVerifier(adChainId, module);
        test_setTokenRoute_setsAndEmits_whenSupported();

        IOrderPortal.OrderParams memory p = _defaultParams();
        p.salt = 4242;
        p.bridger = bridgerAcct;
        p.adCreator = makerAcct;
        p.adSettlementSigner = makerAcct;

        orderToken.mint(vBridger, p.amount);
        bytes32 orderHash = portal.hashOrderPublic(p);
        vm.startPrank(vBridger);
        orderToken.approve(address(portal), p.amount);
        portal.createOrder(p);
        vm.stopPrank();

        gp = p;
    }

    function _unlockAsVectorParties(address module, bytes32 targetRoot, bytes memory cosig) internal {
        _prepareUnlock(module, targetRoot);
        portal.unlock(gp, TestField.fe("NG"), targetRoot, hex"", cosig);
    }

    /// Both vector parties' co-signature over `p` itself (#433: the auth must name this order).
    function _cosigFor(IOrderPortal.OrderParams memory p) internal view returns (bytes memory) {
        return CoSign.moduleDataFor(vjson, portal.hashOrderPublic(p));
    }

    function test_gate2_realModule_fullCosig_unlocks() public {
        _prepareUnlock(address(cVerifier), vOrderRoot);
        portal.unlock(gp, TestField.fe("NG"), vOrderRoot, hex"", _cosigFor(gp));
    }

    /// #433: two orders between the same parties under the same signed roots. A co-signature over
    /// X is not consent to Y: `unlock(Y)` is refused, `unlock(X)` settles.
    function test_433_cosigOverAnotherOrder_isRefused() public {
        _prepareUnlock(address(cVerifier), vOrderRoot);
        IOrderPortal.OrderParams memory x = gp;
        IOrderPortal.OrderParams memory y = gp; // a second copy, not an alias of x
        y.salt = x.salt + 1;
        orderToken.mint(vBridger, y.amount);
        vm.startPrank(vBridger);
        orderToken.approve(address(portal), y.amount);
        portal.createOrder(y);
        vm.stopPrank();

        bytes memory cosigX = _cosigFor(x);
        vm.expectRevert(abi.encodeWithSelector(RootVerifierRegistry.RootNotValid.selector, adChainId, vOrderRoot));
        portal.unlock(y, TestField.fe("NY"), vOrderRoot, hex"", cosigX);
        portal.unlock(x, TestField.fe("NX"), vOrderRoot, hex"", cosigX);
    }

    function test_gate2_mockFalse_reverts() public {
        _prepareUnlock(address(new MockRootVerifier(false)), vOrderRoot);
        vm.expectRevert(abi.encodeWithSelector(RootVerifierRegistry.RootNotValid.selector, adChainId, vOrderRoot));
        portal.unlock(gp, TestField.fe("NG"), vOrderRoot, hex"", hex"");
    }

    function test_gate2_rootNotInSignedAuth_reverts() public {
        bytes32 junkRoot = bytes32(uint256(0xbad));
        _prepareUnlock(address(cVerifier), junkRoot);
        vm.expectRevert(abi.encodeWithSelector(RootVerifierRegistry.RootNotValid.selector, adChainId, junkRoot));
        portal.unlock(gp, TestField.fe("NG"), junkRoot, hex"", _cosigData());
    }

    function test_gate2_singleSigNotAggregate_reverts() public {
        CounterpartyVerifier.SettlementAuth memory auth = CounterpartyVerifier.SettlementAuth({
            orderChainId: VECTOR_CHAIN_ID,
            adChainId: 1_000_002,
            orderHash: vjson.readBytes32(".settlement.auth.orderHash"),
            orderChainRoot: vOrderRoot,
            adChainRoot: vjson.readBytes32(".settlement.auth.adChainRoot")
        });
        bytes memory cosig = abi.encode(
            uint8(2),
            auth,
            uint32(0),
            uint32(0),
            vjson.readBytes(".keys.makerBls.pk.eip2537"),
            vjson.readBytes(".keys.bridgerBls.pk.eip2537"),
            vjson.readBytes(".settlement.sigMaker.eip2537")
        );
        _prepareUnlock(address(cVerifier), vOrderRoot);
        vm.expectRevert(abi.encodeWithSelector(RootVerifierRegistry.RootNotValid.selector, adChainId, vOrderRoot));
        portal.unlock(gp, TestField.fe("NG"), vOrderRoot, hex"", cosig);
    }

    function test_gate2_garbageCosig_reverts() public {
        _prepareUnlock(address(cVerifier), vOrderRoot);
        vm.expectRevert();
        portal.unlock(gp, TestField.fe("NG"), vOrderRoot, hex"", hex"beef");
    }

    function test_inFlight_blocksRevokeUntilUnlock() public {
        BLSKeyRegistry reg = BLSKeyRegistry(REGISTRY);
        vm.store(REGISTRY, bytes32(0), bytes32(uint256(uint160(address(this)))));
        address[] memory guards = new address[](1);
        guards[0] = address(portal);
        reg.setPositionGuards(guards);

        address mockModule = address(new MockRootVerifier(true));
        vm.prank(admin);
        portal.setRootVerifier(adChainId, mockModule);
        test_setTokenRoute_setsAndEmits_whenSupported();

        IOrderPortal.OrderParams memory p = _defaultParams();
        p.salt = 4243;
        p.bridger = bridgerAcct;
        orderToken.mint(vBridger, p.amount);
        bytes32 orderHash = portal.hashOrderPublic(p);
        vm.startPrank(vBridger);
        orderToken.approve(address(portal), p.amount);
        portal.createOrder(p);
        vm.stopPrank();

        assertTrue(portal.hasOpenPositions(bridgerAcct));
        IBLSKeyRegistry.OwnerAuth memory revokeAuth = IBLSKeyRegistry.OwnerAuth(
            IBLSKeyRegistry.Scheme.Eip712,
            abi.encodePacked(
                vjson.readBytes32(".registration.bridgerOnSepolia.revokeAtNonce1.ownerSig.sig.r"),
                vjson.readBytes32(".registration.bridgerOnSepolia.revokeAtNonce1.ownerSig.sig.s"),
                uint8(vjson.readUint(".registration.bridgerOnSepolia.revokeAtNonce1.ownerSig.sig.v"))
            )
        );
        vm.expectRevert(IBLSKeyRegistry.AccountInFlight.selector);
        reg.revoke(bridgerAcct, revokeAuth, 1);

        bytes32 targetRoot = bytes32(uint256(3));
        portal.unlock(p, TestField.fe("NR"), targetRoot, hex"", hex"");

        assertFalse(portal.hasOpenPositions(bridgerAcct));
        reg.revoke(bridgerAcct, revokeAuth, 1);
    }
}

function _registerVectorParties(string memory vjson) {
    _registerOne(vjson, "makerOnSepolia", true);
    _registerOne(vjson, "bridgerOnSepolia", false);
}

function _registerOne(string memory vjson, string memory who, bool sep53) {
    string memory base = string.concat(".registration.", who);
    IBLSKeyRegistry.OwnerAuth memory auth;
    if (sep53) {
        auth = IBLSKeyRegistry.OwnerAuth(
            IBLSKeyRegistry.Scheme.Sep53,
            abi.encode(
                uint256(stdJson.readBytes32(vjson, string.concat(base, ".ownerSig.scl.r"))),
                uint256(stdJson.readBytes32(vjson, string.concat(base, ".ownerSig.scl.s"))),
                uint256(stdJson.readBytes32(vjson, string.concat(base, ".ownerSig.scl.edX"))),
                uint256(stdJson.readBytes32(vjson, string.concat(base, ".ownerSig.scl.edY")))
            )
        );
    } else {
        auth = IBLSKeyRegistry.OwnerAuth(
            IBLSKeyRegistry.Scheme.Eip712,
            abi.encodePacked(
                stdJson.readBytes32(vjson, string.concat(base, ".ownerSig.sig.r")),
                stdJson.readBytes32(vjson, string.concat(base, ".ownerSig.sig.s")),
                uint8(stdJson.readUint(vjson, string.concat(base, ".ownerSig.sig.v")))
            )
        );
    }
    BLSKeyRegistry(0x1111111111111111111111111111111111111111)
        .register(
            stdJson.readBytes32(vjson, string.concat(base, ".account")),
            auth,
            stdJson.readBytes(vjson, string.concat(base, ".pkNative")),
            stdJson.readBytes(vjson, string.concat(base, ".pop")),
            0
        );
}

function _vectorCosig(string memory vjson) view returns (bytes memory) {
    CounterpartyVerifier.SettlementAuth memory auth = CounterpartyVerifier.SettlementAuth({
        orderChainId: 11155111,
        adChainId: 1_000_002,
        orderHash: stdJson.readBytes32(vjson, ".settlement.auth.orderHash"),
        orderChainRoot: stdJson.readBytes32(vjson, ".settlement.auth.orderChainRoot"),
        adChainRoot: stdJson.readBytes32(vjson, ".settlement.auth.adChainRoot")
    });
    // metadata v2: both settlement keys sit in slot 0 of the registry
    return abi.encode(
        uint8(2),
        auth,
        uint32(0),
        uint32(0),
        stdJson.readBytes(vjson, ".keys.makerBls.pk.eip2537"),
        stdJson.readBytes(vjson, ".keys.bridgerBls.pk.eip2537"),
        stdJson.readBytes(vjson, ".settlement.aggSig.eip2537")
    );
}
