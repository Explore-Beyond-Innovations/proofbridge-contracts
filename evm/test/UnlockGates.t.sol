// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {stdJson} from "forge-std/StdJson.sol";
import {AdManagerTest} from "./Admanager.t.sol";
import {OrderPortalTest} from "./OrderPortal.t.sol";
import {AdManager} from "src/AdManager.sol";
import {OrderPortal} from "src/OrderPortal.sol";
import {BLSKeyRegistry} from "src/BLSKeyRegistry.sol";
import {CounterpartyVerifier} from "src/CounterpartyVerifier.sol";
import {IRootVerifier} from "src/interfaces/IRootVerifier.sol";
import {RootVerifierRegistry} from "src/libraries/RootVerifierRegistry.sol";

contract MockRootVerifier is IRootVerifier {
    bool public ok;

    constructor(bool ok_) {
        ok = ok_;
    }

    function isRootValid(uint256, bytes32, bytes calldata) external view returns (bool) {
        return ok;
    }
}

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

    AdManager.OrderParams gp;

    /// Configures the module and locks an order via the standard helpers.
    function _prepareUnlock(address module, bytes32 targetRoot) internal {
        vm.prank(admin);
        adManager.setRootVerifier(orderChainId, module);

        test_fundAd_makerOnly();
        (AdManager.OrderParams memory p, bytes32 orderHash) =
            _openOrder(lastAdId, address(adToken), 60 ether, 999, bridger, recipient);
        gp = p;
        (authToken, timeToLive, signature) = generateUnlockOrderRequestHash(lastAdId, orderHash, targetRoot);
    }

    function _unlockVia(address module, bytes32 targetRoot, bytes memory cosig) internal {
        _prepareUnlock(module, targetRoot);
        adManager.unlock(signature, authToken, timeToLive, gp, bytes32("NG"), targetRoot, hex"", cosig);
    }

    function test_gate2_mockTrue_unlocks() public {
        _unlockVia(address(new MockRootVerifier(true)), bytes32(uint256(5)), hex"");
    }

    function test_gate2_mockFalse_reverts() public {
        _prepareUnlock(address(new MockRootVerifier(false)), bytes32(uint256(5)));
        vm.expectRevert(
            abi.encodeWithSelector(RootVerifierRegistry.RootNotValid.selector, orderChainId, bytes32(uint256(5)))
        );
        adManager.unlock(signature, authToken, timeToLive, gp, bytes32("NG"), bytes32(uint256(5)), hex"", hex"");
    }

    function test_gate2_rootNotInSignedAuth_reverts() public {
        bytes32 junkRoot = bytes32(uint256(0xbad));
        _prepareUnlock(address(cVerifier), junkRoot);
        vm.expectRevert(abi.encodeWithSelector(RootVerifierRegistry.RootNotValid.selector, orderChainId, junkRoot));
        adManager.unlock(signature, authToken, timeToLive, gp, bytes32("NG"), junkRoot, hex"", _cosigData());
    }

    function test_gate2_partiesNotTheSigners_reverts() public {
        // right root, real aggregate - but the order's parties are local test
        // addresses, not the registered vector signers
        _prepareUnlock(address(cVerifier), vOrderRoot);
        vm.expectRevert(abi.encodeWithSelector(RootVerifierRegistry.RootNotValid.selector, orderChainId, vOrderRoot));
        adManager.unlock(signature, authToken, timeToLive, gp, bytes32("NG"), vOrderRoot, hex"", _cosigData());
    }

    function test_gate2_garbageCosig_reverts() public {
        _prepareUnlock(address(cVerifier), vOrderRoot);
        vm.expectRevert();
        adManager.unlock(signature, authToken, timeToLive, gp, bytes32("NG"), vOrderRoot, hex"", hex"deadbeef");
    }

    function test_gate2_noModuleConfigured_skipsGate() public {
        test_fundAd_makerOnly();
        (AdManager.OrderParams memory p, bytes32 orderHash) =
            _openOrder(lastAdId, address(adToken), 60 ether, 998, bridger, recipient);
        bytes32 targetRoot = bytes32(uint256(7));
        (authToken, timeToLive, signature) = generateUnlockOrderRequestHash(lastAdId, orderHash, targetRoot);
        vm.prank(bridger);
        adManager.unlock(signature, authToken, timeToLive, p, bytes32("NS"), targetRoot, hex"", hex"");
    }

    function test_inFlight_tracksLockAndUnlock() public {
        test_fundAd_makerOnly();
        (AdManager.OrderParams memory p, bytes32 orderHash) =
            _openOrder(lastAdId, address(adToken), 60 ether, 997, bridger, recipient);

        assertTrue(adManager.hasOpenPositions(p.adCreator));
        assertTrue(adManager.hasOpenPositions(p.bridger));

        bytes32 targetRoot = bytes32(uint256(3));
        (authToken, timeToLive, signature) = generateUnlockOrderRequestHash(lastAdId, orderHash, targetRoot);
        vm.prank(bridger);
        adManager.unlock(signature, authToken, timeToLive, p, bytes32("NI"), targetRoot, hex"", hex"");

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

    OrderPortal.OrderParams gp;

    /// Configures the module and creates an order whose parties are the
    /// vector signers (the bridger must be the sender).
    function _prepareUnlock(address module, bytes32 targetRoot) internal {
        vm.prank(admin);
        portal.setRootVerifier(adChainId, module);
        test_setTokenRoute_setsAndEmits_whenSupported();

        OrderPortal.OrderParams memory p = _defaultParams();
        p.salt = 4242;
        p.bridger = bridgerAcct;
        p.adCreator = makerAcct;

        orderToken.mint(vBridger, p.amount);
        bytes32 orderHash = portal.hashOrderPublic(p);
        (authToken, timeToLive, signature) = generateCreateOrderRequestParams(p.adId, orderHash);
        vm.startPrank(vBridger);
        orderToken.approve(address(portal), p.amount);
        portal.createOrder(signature, authToken, timeToLive, p);
        vm.stopPrank();

        gp = p;
        (authToken, timeToLive, signature) = generateUnlockOrderRequestHash(p.adId, orderHash, targetRoot);
    }

    function _unlockAsVectorParties(address module, bytes32 targetRoot, bytes memory cosig) internal {
        _prepareUnlock(module, targetRoot);
        portal.unlock(signature, authToken, timeToLive, gp, bytes32("NG"), targetRoot, hex"", cosig);
    }

    function test_gate2_realModule_fullCosig_unlocks() public {
        _unlockAsVectorParties(address(cVerifier), vOrderRoot, _cosigData());
    }

    function test_gate2_mockFalse_reverts() public {
        _prepareUnlock(address(new MockRootVerifier(false)), vOrderRoot);
        vm.expectRevert(abi.encodeWithSelector(RootVerifierRegistry.RootNotValid.selector, adChainId, vOrderRoot));
        portal.unlock(signature, authToken, timeToLive, gp, bytes32("NG"), vOrderRoot, hex"", hex"");
    }

    function test_gate2_rootNotInSignedAuth_reverts() public {
        bytes32 junkRoot = bytes32(uint256(0xbad));
        _prepareUnlock(address(cVerifier), junkRoot);
        vm.expectRevert(abi.encodeWithSelector(RootVerifierRegistry.RootNotValid.selector, adChainId, junkRoot));
        portal.unlock(signature, authToken, timeToLive, gp, bytes32("NG"), junkRoot, hex"", _cosigData());
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
            uint8(1),
            auth,
            vjson.readBytes(".keys.makerBls.pk.eip2537"),
            vjson.readBytes(".keys.bridgerBls.pk.eip2537"),
            vjson.readBytes(".settlement.sigMaker.eip2537")
        );
        _prepareUnlock(address(cVerifier), vOrderRoot);
        vm.expectRevert(abi.encodeWithSelector(RootVerifierRegistry.RootNotValid.selector, adChainId, vOrderRoot));
        portal.unlock(signature, authToken, timeToLive, gp, bytes32("NG"), vOrderRoot, hex"", cosig);
    }

    function test_gate2_garbageCosig_reverts() public {
        _prepareUnlock(address(cVerifier), vOrderRoot);
        vm.expectRevert();
        portal.unlock(signature, authToken, timeToLive, gp, bytes32("NG"), vOrderRoot, hex"", hex"beef");
    }

    function test_inFlight_blocksRevokeUntilUnlock() public {
        BLSKeyRegistry reg = BLSKeyRegistry(REGISTRY);
        vm.store(REGISTRY, bytes32(0), bytes32(uint256(uint160(address(this)))));
        reg.setPositionGuard(address(portal));

        address mockModule = address(new MockRootVerifier(true));
        vm.prank(admin);
        portal.setRootVerifier(adChainId, mockModule);
        test_setTokenRoute_setsAndEmits_whenSupported();

        OrderPortal.OrderParams memory p = _defaultParams();
        p.salt = 4243;
        p.bridger = bridgerAcct;
        orderToken.mint(vBridger, p.amount);
        bytes32 orderHash = portal.hashOrderPublic(p);
        (authToken, timeToLive, signature) = generateCreateOrderRequestParams(p.adId, orderHash);
        vm.startPrank(vBridger);
        orderToken.approve(address(portal), p.amount);
        portal.createOrder(signature, authToken, timeToLive, p);
        vm.stopPrank();

        assertTrue(portal.hasOpenPositions(bridgerAcct));
        BLSKeyRegistry.OwnerAuth memory revokeAuth = BLSKeyRegistry.OwnerAuth(
            BLSKeyRegistry.Scheme.Eip712,
            abi.encodePacked(
                vjson.readBytes32(".registration.bridgerOnSepolia.revokeAtNonce1.ownerSig.sig.r"),
                vjson.readBytes32(".registration.bridgerOnSepolia.revokeAtNonce1.ownerSig.sig.s"),
                uint8(vjson.readUint(".registration.bridgerOnSepolia.revokeAtNonce1.ownerSig.sig.v"))
            )
        );
        vm.expectRevert(BLSKeyRegistry.AccountInFlight.selector);
        reg.revoke(bridgerAcct, revokeAuth, 1);

        bytes32 targetRoot = bytes32(uint256(3));
        (authToken, timeToLive, signature) = generateUnlockOrderRequestHash(p.adId, orderHash, targetRoot);
        portal.unlock(signature, authToken, timeToLive, p, bytes32("NR"), targetRoot, hex"", hex"");

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
    BLSKeyRegistry.OwnerAuth memory auth;
    if (sep53) {
        auth = BLSKeyRegistry.OwnerAuth(
            BLSKeyRegistry.Scheme.Sep53,
            abi.encode(
                uint256(stdJson.readBytes32(vjson, string.concat(base, ".ownerSig.scl.r"))),
                uint256(stdJson.readBytes32(vjson, string.concat(base, ".ownerSig.scl.s"))),
                uint256(stdJson.readBytes32(vjson, string.concat(base, ".ownerSig.scl.edX"))),
                uint256(stdJson.readBytes32(vjson, string.concat(base, ".ownerSig.scl.edY")))
            )
        );
    } else {
        auth = BLSKeyRegistry.OwnerAuth(
            BLSKeyRegistry.Scheme.Eip712,
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
    return abi.encode(
        uint8(1),
        auth,
        stdJson.readBytes(vjson, ".keys.makerBls.pk.eip2537"),
        stdJson.readBytes(vjson, ".keys.bridgerBls.pk.eip2537"),
        stdJson.readBytes(vjson, ".settlement.aggSig.eip2537")
    );
}
