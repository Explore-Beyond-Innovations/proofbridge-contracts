// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {BLSKeyRegistry} from "../src/BLSKeyRegistry.sol";
import {CounterpartyVerifier} from "../src/CounterpartyVerifier.sol";

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

        BLSKeyRegistry impl = new BLSKeyRegistry(address(this));
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
        bytes memory sep53Data = abi.encode(
            uint256(v.readBytes32(".registration.makerOnSepolia.ownerSig.scl.r")),
            uint256(v.readBytes32(".registration.makerOnSepolia.ownerSig.scl.s")),
            uint256(v.readBytes32(".registration.makerOnSepolia.ownerSig.scl.edX")),
            uint256(v.readBytes32(".registration.makerOnSepolia.ownerSig.scl.edY"))
        );
        registry.register(
            maker,
            BLSKeyRegistry.OwnerAuth(BLSKeyRegistry.Scheme.Sep53, sep53Data),
            v.readBytes(".registration.makerOnSepolia.pkNative"),
            v.readBytes(".registration.makerOnSepolia.pop"),
            0
        );

        bytes memory eip712 = abi.encodePacked(
            v.readBytes32(".registration.bridgerOnSepolia.ownerSig.sig.r"),
            v.readBytes32(".registration.bridgerOnSepolia.ownerSig.sig.s"),
            uint8(v.readUint(".registration.bridgerOnSepolia.ownerSig.sig.v"))
        );
        registry.register(
            bridger,
            BLSKeyRegistry.OwnerAuth(BLSKeyRegistry.Scheme.Eip712, eip712),
            v.readBytes(".registration.bridgerOnSepolia.pkNative"),
            v.readBytes(".registration.bridgerOnSepolia.pop"),
            0
        );
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
            adChainRoot: adChainRoot
        });
        bytes memory moduleData = abi.encode(
            uint8(2), auth, makerSlot, bridgerSlot, pkMaker, v.readBytes(".keys.bridgerBls.pk.eip2537"), aggSig
        );
        return abi.encode(maker, bridger, moduleData);
    }

    // ---- maker slot helpers (slots.makerOnSepolia: sep53 owner, registrations[i] at nonce i) ----

    function makerSlotPath(uint256 i) internal pure returns (string memory) {
        return string.concat(".slots.makerOnSepolia.registrations[", vm.toString(i), "]");
    }

    function sep53(string memory path) internal view returns (BLSKeyRegistry.OwnerAuth memory) {
        return BLSKeyRegistry.OwnerAuth(
            BLSKeyRegistry.Scheme.Sep53,
            abi.encode(
                uint256(v.readBytes32(string.concat(path, ".scl.r"))),
                uint256(v.readBytes32(string.concat(path, ".scl.s"))),
                uint256(v.readBytes32(string.concat(path, ".scl.edX"))),
                uint256(v.readBytes32(string.concat(path, ".scl.edY")))
            )
        );
    }

    function registerMakerSlot(uint256 i) internal returns (uint32) {
        return registry.register(
            maker,
            sep53(string.concat(makerSlotPath(i), ".ownerSig")),
            v.readBytes(string.concat(makerSlotPath(i), ".pkNative")),
            v.readBytes(string.concat(makerSlotPath(i), ".pop")),
            i
        );
    }

    /// setValidUntil[slotId*2 + (retire ? 0 : 1)] -> value 1 or graceTs.
    function setMakerValidUntil(uint32 slotId, bool retire) internal {
        string memory path = string.concat(
            ".slots.makerOnSepolia.setValidUntil[", vm.toString(uint256(slotId) * 2 + (retire ? 0 : 1)), "].ownerSig"
        );
        registry.setValidUntil(maker, sep53(path), slotId, retire ? 1 : graceTs());
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
            adChainRoot: adChainRoot
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
        assertFalse(verifier.isRootValid(orderChainId, orderChainRoot, abi.encode(maker, bridger, moduleData)));
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
        registerMakerSlot(5); // at cap: prunes slot 0 (validUntil 1 + 30 days < now)
        vm.expectRevert(BLSKeyRegistry.NoSuchSlot.selector);
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
        registry.revoke(
            maker,
            BLSKeyRegistry.OwnerAuth(
                BLSKeyRegistry.Scheme.Sep53,
                abi.encode(
                    uint256(v.readBytes32(".registration.makerOnSepolia.revokeAtNonce1.ownerSig.scl.r")),
                    uint256(v.readBytes32(".registration.makerOnSepolia.revokeAtNonce1.ownerSig.scl.s")),
                    uint256(v.readBytes32(".registration.makerOnSepolia.revokeAtNonce1.ownerSig.scl.edX")),
                    uint256(v.readBytes32(".registration.makerOnSepolia.revokeAtNonce1.ownerSig.scl.edY"))
                )
            ),
            1
        );
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
            adChainRoot: adChainRoot
        });
        bytes memory moduleData = abi.encode(
            uint8(2),
            auth,
            uint32(0),
            uint32(0),
            v.readBytes(".keys.makerBls.pk.eip2537"),
            v.readBytes(".keys.bridgerBls.pk.eip2537"),
            v.readBytes(".settlement.aggSig.eip2537")
        );
        assertFalse(
            verifier.isRootValid(
                orderChainId, bytes32(uint256(orderChainRoot) ^ 1), abi.encode(maker, bridger, moduleData)
            )
        );
    }
}
