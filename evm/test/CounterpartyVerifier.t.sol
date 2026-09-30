// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {IBLSKeyRegistry} from "src/interfaces/IBLSKeyRegistry.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {BLSKeyRegistry} from "../src/BLSKeyRegistry.sol";
import {CounterpartyVerifier} from "../src/CounterpartyVerifier.sol";
import {CoSign} from "test/utils/CoSign.sol";
import {OwnerAuthVectors} from "test/utils/OwnerAuthVectors.sol";

/// Vector-driven tests; the Soroban verifier suite consumes the same JSON.
contract CounterpartyVerifierTest is Test {
    using stdJson for string;

    uint256 constant CHAIN_ID = 11155111;
    address constant REGISTRY = 0x1111111111111111111111111111111111111111;
    uint64 constant T0 = 1_700_000_000;

    string v;
    BLSKeyRegistry registry;
    CounterpartyVerifier verifier;

    uint256 orderChainId;
    uint256 adChainId;
    bytes32 orderChainRoot;
    bytes32 adChainRoot;
    bytes32 maker;
    bytes32 bridger;

    function setUp() public {
        v = vm.readFile("../test-vectors/bls-encodings.json");
        vm.chainId(CHAIN_ID);
        vm.warp(T0);

        BLSKeyRegistry impl = new BLSKeyRegistry(address(this), "testnet");
        vm.etch(REGISTRY, address(impl).code);
        registry = BLSKeyRegistry(REGISTRY);
        verifier = new CounterpartyVerifier(REGISTRY);

        orderChainId = vm.parseUint(v.readString(".settlement.auth.orderChainId"));
        adChainId = vm.parseUint(v.readString(".settlement.auth.adChainId"));
        orderChainRoot = v.readBytes32(".settlement.auth.orderChainRoot");
        adChainRoot = v.readBytes32(".settlement.auth.adChainRoot");
        maker = v.readBytes32(".registration.makerOnSepolia.account");
        bridger = v.readBytes32(".registration.bridgerOnSepolia.account");

        registerBoth();
    }

    function registerBoth() internal {
        registry.register(
            maker,
            OwnerAuthVectors.auth(v, ".ownerAuth.maker.register[0]"),
            v.readBytes(".registration.makerOnSepolia.pkNative"),
            v.readBytes(".registration.makerOnSepolia.pop"),
            0,
            OwnerAuthVectors.deadline(v, ".ownerAuth.maker.register[0]")
        );
        registry.register(
            bridger,
            OwnerAuthVectors.auth(v, ".ownerAuth.bridger.register[0]"),
            v.readBytes(".registration.bridgerOnSepolia.pkNative"),
            v.readBytes(".registration.bridgerOnSepolia.pop"),
            0,
            OwnerAuthVectors.deadline(v, ".ownerAuth.bridger.register[0]")
        );
    }

    /// The order the vector auth was signed over; the envelope carries it as the escrow would (#433).
    function signedOrderHash() internal view returns (bytes32) {
        return v.readBytes32(".settlement.auth.orderHash");
    }

    function metadata() internal view returns (bytes memory) {
        return metadataWith(v.readBytes(".keys.makerBls.pk.eip2537"), v.readBytes(".settlement.aggSig.eip2537"));
    }

    function metadataWith(bytes memory pkMaker, bytes memory aggSig) internal view returns (bytes memory) {
        return metadataSlots(0, 0, pkMaker, aggSig);
    }

    /// Both parties' settlement keys sit in slot 0; the slot hints are calldata, not hash-bound.
    function metadataSlots(uint32 makerSlot, uint32 bridgerSlot, bytes memory pkMaker, bytes memory aggSig)
        internal
        view
        returns (bytes memory)
    {
        CounterpartyVerifier.SettlementAuth memory auth = CounterpartyVerifier.SettlementAuth({
            orderChainId: orderChainId,
            adChainId: adChainId,
            orderHash: v.readBytes32(".settlement.auth.orderHash"),
            orderChainRoot: orderChainRoot,
            adChainRoot: adChainRoot,
            makerKeyCommitment: v.readBytes32(".settlement.auth.makerKeyCommitment")
        });
        bytes memory moduleData = abi.encode(
            uint8(3), auth, makerSlot, bridgerSlot, pkMaker, v.readBytes(".keys.bridgerBls.pk.eip2537"), aggSig
        );
        return abi.encode(maker, bridger, signedOrderHash(), moduleData);
    }

    // ---- maker slot helpers (slots.makerOnSepolia: sep53 owner, registrations[i] at nonce i) ----

    function makerSlotPath(uint256 i) internal pure returns (string memory) {
        return string.concat(".slots.makerOnSepolia.registrations[", vm.toString(i), "]");
    }

    function registerMakerSlot(uint256 i) internal returns (uint32) {
        string memory path = OwnerAuthVectors.registerPath(v, "maker", i);
        return registry.register(
            maker,
            OwnerAuthVectors.auth(v, path),
            v.readBytes(string.concat(makerSlotPath(i), ".pkNative")),
            v.readBytes(string.concat(makerSlotPath(i), ".pop")),
            i,
            OwnerAuthVectors.deadline(v, path)
        );
    }

    /// ownerAuth.maker.retire[key*2 + (retire ? 0 : 1)] -> value 1 or graceTs, naming key i.
    function setMakerValidUntil(uint32 key, bool retire) internal {
        string memory path =
            string.concat(".ownerAuth.maker.retire[", vm.toString(uint256(key) * 2 + (retire ? 0 : 1)), "]");
        registry.setValidUntil(
            maker, OwnerAuthVectors.auth(v, path), OwnerAuthVectors.key(v, path), retire ? 1 : graceTs()
        );
    }

    function graceTs() internal view returns (uint64) {
        return uint64(vm.parseUint(v.readString(".slots.graceTs")));
    }

    // =========================================================================

    function test_orderChainRootIsValid() public view {
        assertTrue(verifier.isRootValid(orderChainId, orderChainRoot, metadata()));
    }

    function test_adChainRootIsValid() public view {
        assertTrue(verifier.isRootValid(adChainId, adChainRoot, metadata()));
    }

    function test_rootNotMatchingAuthFails() public view {
        assertFalse(verifier.isRootValid(orderChainId, adChainRoot, metadata()));
    }

    function test_unknownSourceChainFails() public view {
        assertFalse(verifier.isRootValid(424242, orderChainRoot, metadata()));
    }

    function test_wrongVersionFails() public view {
        CounterpartyVerifier.SettlementAuth memory auth = CounterpartyVerifier.SettlementAuth({
            orderChainId: orderChainId,
            adChainId: adChainId,
            orderHash: v.readBytes32(".settlement.auth.orderHash"),
            orderChainRoot: orderChainRoot,
            adChainRoot: adChainRoot,
            makerKeyCommitment: v.readBytes32(".settlement.auth.makerKeyCommitment")
        });
        bytes memory moduleData = abi.encode(
            uint8(1),
            auth,
            uint32(0),
            uint32(0),
            v.readBytes(".keys.makerBls.pk.eip2537"),
            v.readBytes(".keys.bridgerBls.pk.eip2537"),
            v.readBytes(".settlement.aggSig.eip2537")
        );
        assertFalse(
            verifier.isRootValid(
                orderChainId, orderChainRoot, abi.encode(maker, bridger, signedOrderHash(), moduleData)
            )
        );
    }

    /// A v1-layout blob (no slot ids) must return false, not revert with empty data.
    function test_v1LayoutBlobFails() public view {
        CounterpartyVerifier.SettlementAuth memory auth = CounterpartyVerifier.SettlementAuth({
            orderChainId: orderChainId,
            adChainId: adChainId,
            orderHash: v.readBytes32(".settlement.auth.orderHash"),
            orderChainRoot: orderChainRoot,
            adChainRoot: adChainRoot,
            makerKeyCommitment: v.readBytes32(".settlement.auth.makerKeyCommitment")
        });
        bytes memory v1 = abi.encode(
            uint8(1),
            auth,
            v.readBytes(".keys.makerBls.pk.eip2537"),
            v.readBytes(".keys.bridgerBls.pk.eip2537"),
            v.readBytes(".settlement.aggSig.eip2537")
        );
        assertFalse(
            verifier.isRootValid(orderChainId, orderChainRoot, abi.encode(maker, bridger, signedOrderHash(), v1))
        );
        assertFalse(
            verifier.isRootValid(orderChainId, orderChainRoot, abi.encode(maker, bridger, signedOrderHash(), hex""))
        );
    }

    // =========================================================================
    // T-02: slot hints + use-time validity
    // =========================================================================

    /// Rotation: the old slot keeps verifying through its grace window, then stops.
    function test_T02_oldSlotInGraceSettlesThenExpires() public {
        registerMakerSlot(1); // new key in slot 1
        setMakerValidUntil(0, false); // old slot valid until graceTs

        assertTrue(verifier.isRootValid(orderChainId, orderChainRoot, metadata()));
        vm.warp(graceTs() - 1);
        assertTrue(verifier.isRootValid(orderChainId, orderChainRoot, metadata()));
        vm.warp(graceTs());
        assertFalse(verifier.isRootValid(orderChainId, orderChainRoot, metadata()));
    }

    /// Citing the wrong slot for a key fails on commitment mismatch.
    function test_T02_wrongSlotHintFails() public {
        registerMakerSlot(1);
        bytes memory pkMaker = v.readBytes(".keys.makerBls.pk.eip2537");
        bytes memory aggSig = v.readBytes(".settlement.aggSig.eip2537");
        assertFalse(verifier.isRootValid(orderChainId, orderChainRoot, metadataSlots(1, 0, pkMaker, aggSig)));
        assertFalse(verifier.isRootValid(orderChainId, orderChainRoot, metadataSlots(0, 1, pkMaker, aggSig)));
        assertFalse(verifier.isRootValid(orderChainId, orderChainRoot, metadataSlots(9, 0, pkMaker, aggSig)));
    }

    /// A retired slot fails immediately; a pruned slot fails as missing, with no state change.
    function test_T02_retiredThenPrunedSlotFails() public {
        setMakerValidUntil(0, true);
        assertFalse(verifier.isRootValid(orderChainId, orderChainRoot, metadata()));

        for (uint256 i = 1; i < 5; i++) {
            registerMakerSlot(i);
        }
        // #422 D14: the kill expired the slot at the kill, not in 1970; it is prunable 30 days later.
        vm.warp(graceTs()); // well past the grace; the late register entries are signed for it (D2)
        registerMakerSlot(5); // at cap: prunes slot 0
        vm.expectRevert(IBLSKeyRegistry.NoSuchSlot.selector);
        registry.lookup(maker, 0);
        assertFalse(verifier.isRootValid(orderChainId, orderChainRoot, metadata()));
        assertEq(registry.liveSlots(maker).length, 5);
    }

    function test_pkNotMatchingCommitmentFails() public view {
        bytes memory pk = v.readBytes(".keys.bridgerBls.pk.eip2537"); // bridger's key as maker's
        assertFalse(
            verifier.isRootValid(
                orderChainId, orderChainRoot, metadataWith(pk, v.readBytes(".settlement.aggSig.eip2537"))
            )
        );
    }

    function test_unregisteredAccountFails() public {
        registry.revoke(maker, OwnerAuthVectors.auth(v, ".ownerAuth.maker.revoke[1]"), 1);
        assertFalse(verifier.isRootValid(orderChainId, orderChainRoot, metadata()));
    }

    function test_singleSignatureIsNotTheAggregate() public view {
        assertFalse(
            verifier.isRootValid(
                orderChainId,
                orderChainRoot,
                metadataWith(v.readBytes(".keys.makerBls.pk.eip2537"), v.readBytes(".settlement.sigMaker.eip2537"))
            )
        );
    }

    function test_tamperedRootInAuthFails() public view {
        // aggSig was made over the real roots; a substituted root must fail the
        // pairing even though root == auth root.
        CounterpartyVerifier.SettlementAuth memory auth = CounterpartyVerifier.SettlementAuth({
            orderChainId: orderChainId,
            adChainId: adChainId,
            orderHash: v.readBytes32(".settlement.auth.orderHash"),
            orderChainRoot: bytes32(uint256(orderChainRoot) ^ 1),
            adChainRoot: adChainRoot,
            makerKeyCommitment: v.readBytes32(".settlement.auth.makerKeyCommitment")
        });
        bytes memory moduleData = abi.encode(
            uint8(3),
            auth,
            uint32(0),
            uint32(0),
            v.readBytes(".keys.makerBls.pk.eip2537"),
            v.readBytes(".keys.bridgerBls.pk.eip2537"),
            v.readBytes(".settlement.aggSig.eip2537")
        );
        assertFalse(
            verifier.isRootValid(
                orderChainId,
                bytes32(uint256(orderChainRoot) ^ 1),
                abi.encode(maker, bridger, signedOrderHash(), moduleData)
            )
        );
    }

    // ---- #469: the co-signed message names the maker's key ----

    /// A v2-layout blob (no makerKeyCommitment in the auth) must return false by its version.
    function test_v2LayoutBlobFails() public view {
        // The five-word auth of v2 abi-encodes as five inline words; version 2 in front.
        bytes memory v2 = abi.encode(
            uint8(2),
            orderChainId,
            adChainId,
            signedOrderHash(),
            orderChainRoot,
            adChainRoot,
            uint32(0),
            uint32(0),
            v.readBytes(".keys.makerBls.pk.eip2537"),
            v.readBytes(".keys.bridgerBls.pk.eip2537"),
            v.readBytes(".settlement.aggSig.eip2537")
        );
        assertFalse(
            verifier.isRootValid(orderChainId, orderChainRoot, abi.encode(maker, bridger, signedOrderHash(), v2))
        );
    }

    /// The bridger's half aggregated with another live maker key: the pairing holds, the slot is
    /// live and its commitment matches the key used, the roots and order are right — and it must
    /// still fail, because the signed auth names a different maker key. The control shows the
    /// golden pair keeps verifying in the same registry state.
    function test_rePairedUnderAnotherMakerKeyFails() public {
        uint32 altSlot = registerMakerSlot(1);
        bytes memory rePaired = metadataSlots(
            altSlot,
            0,
            v.readBytes(".settlement.rePaired.pkAlt.eip2537"),
            v.readBytes(".settlement.rePaired.aggSig.eip2537")
        );
        assertFalse(verifier.isRootValid(orderChainId, orderChainRoot, rePaired));
        assertTrue(verifier.isRootValid(orderChainId, orderChainRoot, metadata()));
    }

    // ---- #433: the co-signature binds the order ----

    /// The helper the unlock fixtures use must be the real signing, not a lookalike: signed over the
    /// vector's own auth it reproduces the vector's aggregate byte for byte.
    function test_coSignHelperReproducesTheVectorAggregate() public view {
        bytes memory agg = CoSign.aggregate(v, CoSign.authFor(v, signedOrderHash()));
        assertEq(agg, v.readBytes(".settlement.aggSig.eip2537"));
    }

    /// A valid co-signature over one order is not consent to another: the envelope names the order
    /// the escrow is unlocking, and the auth must name the same one.
    function test_envelopeOrderHashDiffersFromTheAuth_fails() public view {
        bytes memory moduleData = abi.encode(
            uint8(3),
            CoSign.authFor(v, signedOrderHash()),
            uint32(0),
            uint32(0),
            v.readBytes(".keys.makerBls.pk.eip2537"),
            v.readBytes(".keys.bridgerBls.pk.eip2537"),
            v.readBytes(".settlement.aggSig.eip2537")
        );
        bytes32 other = keccak256("another order");
        assertTrue(
            verifier.isRootValid(
                orderChainId, orderChainRoot, abi.encode(maker, bridger, signedOrderHash(), moduleData)
            )
        );
        assertFalse(verifier.isRootValid(orderChainId, orderChainRoot, abi.encode(maker, bridger, other, moduleData)));
    }
}
