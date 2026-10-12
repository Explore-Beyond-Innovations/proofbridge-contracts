// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {stdJson} from "forge-std/StdJson.sol";
import {TestField} from "test/utils/TestField.sol";
import {CoSign} from "test/utils/CoSign.sol";
import {statusOf} from "test/utils/OrderStatus.sol";
import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IEscrow} from "src/interfaces/IEscrow.sol";
import {BLSKeyRegistry} from "src/BLSKeyRegistry.sol";
import {CounterpartyVerifier} from "src/CounterpartyVerifier.sol";
import {Dispute} from "src/libraries/Dispute.sol";
import {RootVerifierRegistry} from "src/libraries/RootVerifierRegistry.sol";
import {DisputeTest} from "./Dispute.t.sol";
import {_registerVectorParties} from "./UnlockGates.t.sol";

/// The co-signed nullifier against a ruling: a party holding the co-signature cannot settle the
/// other side's leg with a secret of its own choosing to turn a forfeit ruling into a plain trade.
/// The real CounterpartyVerifier and the vector parties' keys; the ZK verifier is the permissive
/// mock, so a proof for the invented nullifier is taken as valid.
contract CoSignedNullifierRulingTest is DisputeTest {
    using stdJson for string;

    address constant REGISTRY = 0x1111111111111111111111111111111111111111;

    string vjson;
    CounterpartyVerifier cVerifier;
    bytes32 vOrderRoot;

    function setUp() public override {
        vm.chainId(11155111);
        super.setUp();
        vjson = vm.readFile("../test-vectors/bls-encodings.json");
        vOrderRoot = vjson.readBytes32(".settlement.auth.orderChainRoot");
        BLSKeyRegistry impl = new BLSKeyRegistry(address(this), "testnet");
        vm.etch(REGISTRY, address(impl).code);
        _registerVectorParties(vjson);
        cVerifier = new CounterpartyVerifier(REGISTRY);
    }

    /// One lock whose settlement signer and bridger are the registered vector parties.
    function _vectorOrder() internal returns (IAdManager.OrderParams memory p, bytes32 h) {
        bytes32 signer = vjson.readBytes32(".registration.makerOnSepolia.account");
        test_fundAd_makerOnly();
        keyRegistry.set(signer, true);
        keyRegistry.approve(signer, _b32(maker), true);
        vm.prank(maker);
        adManager.setSettlementSigner(lastAdId, signer);
        p = _defaultParams(lastAdId);
        p.amount = 60 ether;
        p.salt = 6001;
        p.adSettlementSigner = signer;
        p.bridger = vjson.readBytes32(".registration.bridgerOnSepolia.account");
        vm.prank(maker);
        h = adManager.lockForOrder(p, 0);
    }

    /// A dispute ruled for the maker's forfeit, then an ad-leg unlock under the parties' real
    /// co-signature but an invented nullifier: refused at the root check, the dispute stays open,
    /// and the ruling is what finalizes the order.
    function test_forfeitRuling_inventedNullifierUnlock_isRefused_theRulingApplies() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _vectorOrder();
        _file(p, filer);
        vm.prank(arbiter);
        dm.resolveDispute(h, Dispute.Outcome.MakerForfeit);
        // Wired after the lock, as the gate tests do: the real module reads REGISTRY (#464).
        vm.prank(admin);
        adManager.setRootVerifier(orderChainId, address(cVerifier));

        bytes memory cosig = CoSign.moduleDataFor(vjson, h, TestField.fe("real ad leg"), TestField.fe("real order leg"));
        bytes32 invented = TestField.fe("invented");
        vm.expectRevert(abi.encodeWithSelector(RootVerifierRegistry.RootNotValid.selector, orderChainId, vOrderRoot));
        adManager.unlock(p, invented, vOrderRoot, hex"", cosig);
        assertTrue(dm.isDisputed(h), "the dispute is still open");
        assertEq(uint256(statusOf(address(adManager), h)), uint256(IEscrow.Status.Disputed));
        assertFalse(adManager.nullifierUsed(invented));

        _warpPastWindow(h);
        adManager.finalizeDispute(p);
        assertFalse(dm.isDisputed(h), "closed by the ruling");
        assertTrue(uint256(statusOf(address(adManager), h)) != uint256(IEscrow.Status.Filled), "not a plain trade");
    }
}
