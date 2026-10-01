// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {TestField} from "test/utils/TestField.sol";

import {OrderPortalGateTest, AdManagerGateTest} from "./UnlockGates.t.sol";
import {MockRootVerifier} from "./mocks/MockRootVerifier.sol";
import {console2} from "forge-std/console2.sol";
import {Vm} from "forge-std/Vm.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {HonkVerifier} from "src/Verifier.sol";
import {CounterpartyVerifier} from "src/CounterpartyVerifier.sol";
import {IAdManager} from "src/interfaces/IAdManager.sol";
import {CoSign} from "test/utils/CoSign.sol";

// 1.6c cost-measurement gate: gas for a single unlock external call, asserted
// against an in-source ceiling so a regression fails the build. Ceilings are the
// measured baseline plus ~10% headroom; keep headroom generous across toolchain bumps.
//
// Scope caveat: `g0 - gasleft()` meters EXECUTION gas only. It excludes the 21k
// intrinsic cost and per-byte calldata gas of a real transaction, so these numbers
// are regression tripwires, NOT transaction-cost estimates — do not size a fee or
// gas-limit budget from them (add intrinsic + calldata for a submit estimate).
//
// 2.3e (D8): the SETTLED leaf is NOT in the unlock — `recordSettled` appends it in its
// own transaction (one Poseidon2 MMR append, metered below), so the unlock ceilings
// stay at their 1.6c baselines.

/// C-7 (#358): what a real unlock carries — a real UltraHonk deposit proof over a root, and both
/// parties' BLS co-signature over that same root. Shared by the two escrows' gas tests below.
library RealUnlock {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    /// (makerNullifier, bridgerNullifier, secret) for `orderHash`, from the deposit script.
    function nullifiers(bytes32 orderHash) internal returns (bytes32, bytes32, bytes32) {
        string[] memory a = new string[](4);
        a[0] = "npx";
        a[1] = "tsx";
        a[2] = "js-scripts/deposits/getNullifierHash.ts";
        a[3] = vm.toString(orderHash);
        return abi.decode(vm.ffi(a), (bytes32, bytes32, bytes32));
    }

    /// A deposit proof for `orderHash` in a one-leaf tree; `adSide` picks the circuit's side flag.
    function depositProof(bytes32 orderHash, bytes32 nullifier, bytes32 secret, bool adSide)
        internal
        returns (bytes memory proof, bytes32 root)
    {
        string[] memory a = new string[](8);
        a[0] = "npx";
        a[1] = "tsx";
        a[2] = "js-scripts/deposits/generateProof.ts";
        a[3] = vm.toString(nullifier);
        a[4] = vm.toString(orderHash);
        a[5] = vm.toString(adSide);
        a[6] = vm.toString(secret);
        a[7] = vm.toString(
            bytes32(uint256(orderHash) % 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001)
        );
        bytes32[] memory pub;
        (proof, pub) = abi.decode(vm.ffi(a), (bytes, bytes32[]));
        root = pub[2];
    }

    /// Module data v3: the vector parties co-sign `orderHash` with `root` on both legs.
    function cosigOverRoot(string memory vjson, bytes32 orderHash, bytes32 root) internal view returns (bytes memory) {
        CounterpartyVerifier.SettlementAuth memory auth = CoSign.authFor(vjson, orderHash);
        auth.orderChainRoot = root;
        auth.adChainRoot = root;
        return abi.encode(
            uint8(3),
            auth,
            uint32(0),
            uint32(0),
            stdJson.readBytes(vjson, ".keys.makerBls.pk.eip2537"),
            stdJson.readBytes(vjson, ".keys.bridgerBls.pk.eip2537"),
            CoSign.aggregate(vjson, auth)
        );
    }

    /// Calldata gas of a byte string at EIP-2028 prices, for the table's context column.
    function calldataGas(bytes memory data) internal pure returns (uint256 gas) {
        for (uint256 i = 0; i < data.length; i++) {
            gas += data[i] == 0 ? 4 : 16;
        }
    }
}

contract OrderPortalUnlockGas is OrderPortalGateTest {
    uint256 constant ORDER_PORTAL_UNLOCK_GAS_CEILING = 400_000;

    // Full unlock through the real CounterpartyVerifier: includes the ~285k BLS
    // aggregate-verify (EIP-2537 pairing) that dominates the cosig path. This is the
    // canonical baseline for the shared verify cost on both escrows.
    function test_orderPortalUnlockGas() public {
        _prepareUnlock(address(cVerifier), vOrderRoot);
        bytes memory cosig = _cosigFor(gp);

        uint256 g0 = gasleft();
        portal.unlock(gp, TestField.fe("NG"), vOrderRoot, hex"", cosig);
        uint256 used = g0 - gasleft();

        console2.log("OrderPortal.unlock gas (full, real BLS verify):", used);
        assertLe(used, ORDER_PORTAL_UNLOCK_GAS_CEILING);
    }

    /// C-7 (#358): the unlock a maker actually sends — real BLS co-signature and a real UltraHonk
    /// deposit proof over the root it signs. Cold storage, execution gas only.
    ///
    /// | measured (forge 1.7.1)                      |       gas |
    /// | ------------------------------------------- | --------- |
    /// | UltraHonk verify alone                      | 1,832,656 |
    /// | OrderPortal.unlock (BLS + UltraHonk)        | 2,218,754 |
    /// | proof + cosig calldata (EIP-2028, not in it)|   155,792 |
    /// | ceiling (+10%)                              | 2,441,000 |
    uint256 constant ORDER_PORTAL_UNLOCK_REAL_PROOF_GAS_CEILING = 2_441_000;

    function test_orderPortalUnlockGas_realProof() public {
        _prepareUnlock(address(cVerifier), bytes32(0));
        bytes32 orderHash = portal.hashOrderPublic(gp);
        (bytes32 nullifier,, bytes32 secret) = RealUnlock.nullifiers(orderHash);
        (bytes memory proof, bytes32 root) = RealUnlock.depositProof(orderHash, nullifier, secret, false);
        bytes memory cosig = RealUnlock.cosigOverRoot(vjson, orderHash, root);
        vm.etch(address(verifier), address(new HonkVerifier()).code);

        // The verify alone, for the table.
        bytes32[] memory pub = new bytes32[](4);
        pub[0] = nullifier;
        pub[1] = bytes32(uint256(orderHash) % 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
        pub[2] = root;
        pub[3] = bytes32(0);
        vm.cool(address(verifier));
        uint256 v0 = gasleft();
        assertTrue(verifier.verify(proof, pub));
        console2.log("UltraHonk verify alone:", v0 - gasleft());

        address[6] memory cold = [
            address(portal),
            address(verifier),
            address(cVerifier),
            REGISTRY,
            address(orderToken),
            address(merkleManager)
        ];
        for (uint256 i = 0; i < cold.length; i++) {
            vm.cool(cold[i]);
        }
        uint256 g0 = gasleft();
        portal.unlock(gp, nullifier, root, proof, cosig);
        uint256 used = g0 - gasleft();

        console2.log("OrderPortal.unlock gas (real BLS + real UltraHonk):", used);
        console2.log("  proof + cosig calldata gas (EIP-2028):", RealUnlock.calldataGas(bytes.concat(proof, cosig)));
        assertLe(used, ORDER_PORTAL_UNLOCK_REAL_PROOF_GAS_CEILING);
    }
}

contract AdManagerUnlockGas is AdManagerGateTest {
    // Re-baselined for #422: the maker's halt flag is one cold SLOAD on this path (80,649 → 83,442
    // measured), and the previous ceiling had only ~1.7% left over the drifted baseline.
    uint256 constant AD_MANAGER_UNLOCK_ESCROW_GAS_CEILING = 91_000;

    // Escrow-settlement path ONLY: metered through MockRootVerifier(true) with an
    // empty cosig, so it excludes the BLS aggregate-verify. A real AdManager unlock
    // adds the same ~285k verify cost already baselined by OrderPortal above
    // (identical CounterpartyVerifier module) — union coverage, not double-counted.
    // This number is the escrow/settlement overhead in isolation, NOT the full
    // AdManager.unlock cost.
    function test_adManagerUnlockEscrowGas() public {
        _prepareUnlock(address(new MockRootVerifier(true)), bytes32(uint256(5)));

        uint256 g0 = gasleft();
        adManager.unlock(gp, TestField.fe("NG"), bytes32(uint256(5)), hex"", hex"");
        uint256 used = g0 - gasleft();

        console2.log("AdManager.unlock gas (escrow-only, mock verifier, excl. BLS verify):", used);
        assertLe(used, AD_MANAGER_UNLOCK_ESCROW_GAS_CEILING);
    }

    uint256 constant RECORD_SETTLED_GAS_CEILING = 245_000;

    // The SETTLED leaf's own transaction (2.3e D8): one Poseidon2 MMR append at width 1 → 2.
    // Later appends merge more peaks (one hash each), so this is the floor, not the cost.
    function test_recordSettledGas() public {
        _prepareUnlock(address(new MockRootVerifier(true)), bytes32(uint256(5)));
        adManager.unlock(gp, TestField.fe("NG"), bytes32(uint256(5)), hex"", hex"");

        uint256 g0 = gasleft();
        adManager.recordSettled(gp);
        uint256 used = g0 - gasleft();

        console2.log("AdManager.recordSettled gas (one MMR append):", used);
        assertLe(used, RECORD_SETTLED_GAS_CEILING);
    }

    /// C-7 (#358): the bridger's unlock with a real UltraHonk proof and the real BLS co-signature,
    /// on an order whose parties are the vector's registered signers. Cold, execution gas only.
    ///
    /// | measured (forge 1.7.1)                      |       gas |
    /// | ------------------------------------------- | --------- |
    /// | AdManager.unlock (BLS + UltraHonk)          | 2,237,725 |
    /// | proof + cosig calldata (EIP-2028, not in it)|   155,600 |
    /// | ceiling (+10%)                              | 2,462,000 |
    uint256 constant AD_MANAGER_UNLOCK_REAL_PROOF_GAS_CEILING = 2_462_000;

    function test_adManagerUnlockGas_realProof() public {
        bytes32 makerAcct = stdJson.readBytes32(vjson, ".registration.makerOnSepolia.account");
        bytes32 bridgerAcct = stdJson.readBytes32(vjson, ".registration.bridgerOnSepolia.account");
        test_createAd_succeedsWhenRouteExists_emitsAndStores();
        keyRegistry.set(makerAcct, true);
        vm.prank(maker);
        adManager.setSettlementSigner(lastAdId, makerAcct);

        IAdManager.OrderParams memory p = _defaultParams(lastAdId);
        p.amount = 60 ether;
        p.salt = 4243;
        p.bridger = bridgerAcct;
        p.adSettlementSigner = makerAcct;
        vm.prank(maker);
        bytes32 orderHash = adManager.lockForOrder(p);
        // Wired after the lock, as `_prepareUnlock` does: the real module reads REGISTRY (#464).
        vm.prank(admin);
        adManager.setRootVerifier(orderChainId, address(cVerifier));

        (, bytes32 nullifier, bytes32 secret) = RealUnlock.nullifiers(orderHash);
        (bytes memory proof, bytes32 root) = RealUnlock.depositProof(orderHash, nullifier, secret, true);
        bytes memory cosig = RealUnlock.cosigOverRoot(vjson, orderHash, root);
        vm.etch(address(verifier), address(new HonkVerifier()).code);

        address[7] memory cold = [
            address(adManager),
            address(verifier),
            address(cVerifier),
            REGISTRY,
            address(adToken),
            address(merkleManager),
            address(keyRegistry)
        ];
        for (uint256 i = 0; i < cold.length; i++) {
            vm.cool(cold[i]);
        }
        uint256 g0 = gasleft();
        adManager.unlock(p, nullifier, root, proof, cosig);
        uint256 used = g0 - gasleft();

        console2.log("AdManager.unlock gas (real BLS + real UltraHonk):", used);
        console2.log("  proof + cosig calldata gas (EIP-2028):", RealUnlock.calldataGas(bytes.concat(proof, cosig)));
        assertEq(adToken.balanceOf(recipient), 60 ether, "the recipient was paid");
        assertLe(used, AD_MANAGER_UNLOCK_REAL_PROOF_GAS_CEILING);
    }
}
