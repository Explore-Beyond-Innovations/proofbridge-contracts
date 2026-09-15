// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {OrderPortalGateTest, AdManagerGateTest} from "./UnlockGates.t.sol";
import {MockRootVerifier} from "./mocks/MockRootVerifier.sol";
import {console2} from "forge-std/console2.sol";

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

contract OrderPortalUnlockGas is OrderPortalGateTest {
    uint256 constant ORDER_PORTAL_UNLOCK_GAS_CEILING = 400_000;

    // Full unlock through the real CounterpartyVerifier: includes the ~285k BLS
    // aggregate-verify (EIP-2537 pairing) that dominates the cosig path. This is the
    // canonical baseline for the shared verify cost on both escrows.
    function test_orderPortalUnlockGas() public {
        _prepareUnlock(address(cVerifier), vOrderRoot);
        bytes memory cosig = _cosigData();

        uint256 g0 = gasleft();
        portal.unlock(gp, bytes32("NG"), vOrderRoot, hex"", cosig);
        uint256 used = g0 - gasleft();

        console2.log("OrderPortal.unlock gas (full, real BLS verify):", used);
        assertLe(used, ORDER_PORTAL_UNLOCK_GAS_CEILING);
    }
}

contract AdManagerUnlockGas is AdManagerGateTest {
    uint256 constant AD_MANAGER_UNLOCK_ESCROW_GAS_CEILING = 82_000;

    // Escrow-settlement path ONLY: metered through MockRootVerifier(true) with an
    // empty cosig, so it excludes the BLS aggregate-verify. A real AdManager unlock
    // adds the same ~285k verify cost already baselined by OrderPortal above
    // (identical CounterpartyVerifier module) — union coverage, not double-counted.
    // This number is the escrow/settlement overhead in isolation, NOT the full
    // AdManager.unlock cost.
    function test_adManagerUnlockEscrowGas() public {
        _prepareUnlock(address(new MockRootVerifier(true)), bytes32(uint256(5)));

        uint256 g0 = gasleft();
        adManager.unlock(gp, bytes32("NG"), bytes32(uint256(5)), hex"", hex"");
        uint256 used = g0 - gasleft();

        console2.log("AdManager.unlock gas (escrow-only, mock verifier, excl. BLS verify):", used);
        assertLe(used, AD_MANAGER_UNLOCK_ESCROW_GAS_CEILING);
    }

    uint256 constant RECORD_SETTLED_GAS_CEILING = 245_000;

    // The SETTLED leaf's own transaction (2.3e D8): one Poseidon2 MMR append at width 1 → 2.
    // Later appends merge more peaks (one hash each), so this is the floor, not the cost.
    function test_recordSettledGas() public {
        _prepareUnlock(address(new MockRootVerifier(true)), bytes32(uint256(5)));
        adManager.unlock(gp, bytes32("NG"), bytes32(uint256(5)), hex"", hex"");

        uint256 g0 = gasleft();
        adManager.recordSettled(gp);
        uint256 used = g0 - gasleft();

        console2.log("AdManager.recordSettled gas (one MMR append):", used);
        assertLe(used, RECORD_SETTLED_GAS_CEILING);
    }
}
