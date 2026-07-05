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
        bytes memory sep53 = abi.encode(
            uint256(v.readBytes32(".registration.makerOnSepolia.ownerSig.scl.r")),
            uint256(v.readBytes32(".registration.makerOnSepolia.ownerSig.scl.s")),
            uint256(v.readBytes32(".registration.makerOnSepolia.ownerSig.scl.edX")),
            uint256(v.readBytes32(".registration.makerOnSepolia.ownerSig.scl.edY"))
        );
        registry.register(
            maker,
            BLSKeyRegistry.OwnerAuth(BLSKeyRegistry.Scheme.Sep53, sep53),
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
        CounterpartyVerifier.SettlementAuth memory auth = CounterpartyVerifier.SettlementAuth({
            orderChainId: orderChainId,
            adChainId: adChainId,
            orderHash: v.readBytes32(".settlement.auth.orderHash"),
            orderChainRoot: orderChainRoot,
            adChainRoot: adChainRoot
        });
        return abi.encode(uint8(1), auth, maker, bridger, pkMaker, v.readBytes(".keys.bridgerBls.pk.eip2537"), aggSig);
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
        bytes memory m = metadata();
        m[31] = 0x02; // version word
        assertFalse(verifier.isRootValid(orderChainId, orderChainRoot, m));
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
        bytes memory m = abi.encode(
            uint8(1),
            auth,
            maker,
            bridger,
            v.readBytes(".keys.makerBls.pk.eip2537"),
            v.readBytes(".keys.bridgerBls.pk.eip2537"),
            v.readBytes(".settlement.aggSig.eip2537")
        );
        assertFalse(verifier.isRootValid(orderChainId, bytes32(uint256(orderChainRoot) ^ 1), m));
    }
}
