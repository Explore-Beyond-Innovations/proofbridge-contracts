// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {TestField} from "test/utils/TestField.sol";

import {AdManagerTest} from "./Admanager.t.sol";
import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IEscrow} from "src/interfaces/IEscrow.sol";
import {AdManager} from "src/AdManager.sol";

/// A recipient that can refuse native payouts, then relent — models a
/// blocklisted/broken address that later recovers.
contract ToggleReceiver {
    bool public accepting;

    function setAccepting(bool ok) external {
        accepting = ok;
    }

    receive() external payable {
        require(accepting, "not accepting");
    }
}

/// Payout liveness + solvency: a failing recipient can never block unlock;
/// the failed payout becomes claimable and pays exactly once on recovery.
contract PayoutFallbackTest is AdManagerTest {
    ToggleReceiver receiver;

    function setUp() public override {
        super.setUp();
        receiver = new ToggleReceiver();
    }

    function _unlockNativeTo(address recipient, bytes32 nullifier) internal returns (IAdManager.OrderParams memory p) {
        test_createAd_with_native_token_success();
        bytes32 orderHash;
        (p, orderHash) = _openOrder("nativeAd", NATIVE_TOKEN_ADDRESS, 50 ether, 777, bridger, recipient);

        bytes32 targetRoot = bytes32(uint256(7));
        vm.prank(bridger);
        adManager.unlock(p, nullifier, targetRoot, hex"", hex"");
    }

    function test_happyPath_paysDirectly_nothingClaimable() public {
        receiver.setAccepting(true);
        IAdManager.OrderParams memory p = _unlockNativeTo(address(receiver), TestField.fe("HP"));

        assertEq(address(receiver).balance, p.amount, "not paid directly");
        assertEq(adManager.claimable(address(receiver), NATIVE_TOKEN_ADDRESS), 0);
    }

    function test_failingRecipient_neverBlocksUnlock_creditsInstead() public {
        // receiver rejects payouts: unlock must still settle
        IAdManager.OrderParams memory p = _unlockNativeTo(address(receiver), TestField.fe("FB"));

        assertEq(address(receiver).balance, 0, "push should have failed");
        assertEq(adManager.claimable(address(receiver), NATIVE_TOKEN_ADDRESS), p.amount, "not credited");

        // still broken: claim fails, credit stays parked
        vm.expectRevert();
        adManager.claim(address(receiver), NATIVE_TOKEN_ADDRESS);

        // recipient recovers: claim pays exactly once
        receiver.setAccepting(true);
        adManager.claim(address(receiver), NATIVE_TOKEN_ADDRESS);
        assertEq(address(receiver).balance, p.amount);
        assertEq(adManager.claimable(address(receiver), NATIVE_TOKEN_ADDRESS), 0);

        vm.expectRevert(IEscrow.Escrow__NothingToClaim.selector);
        adManager.claim(address(receiver), NATIVE_TOKEN_ADDRESS);
    }

    /// T-58 (2.3h): `claim` is the one entry point a pause must not freeze. It moves no order state
    /// and creates no credit — it hands an already-credited balance to the account that already owns
    /// it, so freezing it does not contain an incident, it only holds honest users' money while one
    /// is investigated. Asserted as an explicit success so the exception is pinned, not implied.
    function test_2_3h_claimSucceedsWhilePaused() public {
        IAdManager.OrderParams memory p = _unlockNativeTo(address(receiver), TestField.fe("PZ"));
        assertEq(adManager.claimable(address(receiver), NATIVE_TOKEN_ADDRESS), p.amount, "credited");

        vm.prank(admin);
        adManager.pause();

        receiver.setAccepting(true);
        adManager.claim(address(receiver), NATIVE_TOKEN_ADDRESS);
        assertEq(address(receiver).balance, p.amount, "a credit stays reachable while paused");
    }

    /// ...and the pause still holds for everything else, so the exception is exactly one call wide.
    function test_2_3h_thePauseStillHoldsForEverythingElse() public {
        // Params need only be well-formed: the pause gate fires before any of them is read.
        IAdManager.OrderParams memory p;
        vm.prank(admin);
        adManager.pause();

        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        adManager.lockForOrder(p);
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        adManager.claimCancel(p);
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        adManager.finalizeCancel(p);
    }

    /// Escrow solvency across both payout paths: wrapped-native holdings always
    /// cover the ad pool plus every outstanding credit.
    function testFuzz_solvency_acrossPushAndFallback(uint256 seed) public {
        test_createAd_with_native_token_success();
        string memory adId = "nativeAd";

        for (uint256 i = 0; i < 4; i++) {
            uint256 available = adManager.availableLiquidity(adId);
            if (available < 2) break;
            uint256 amount = bound(uint256(keccak256(abi.encode(seed, i))), 1, available / 2);
            receiver.setAccepting(i % 2 == 0);

            (IAdManager.OrderParams memory p, bytes32 orderHash) =
                _openOrder(adId, NATIVE_TOKEN_ADDRESS, amount, 9000 + i, bridger, address(receiver));

            bytes32 targetRoot = bytes32(uint256(100 + i));
            vm.prank(bridger);
            adManager.unlock(p, bytes32(uint256(9000 + i)), targetRoot, hex"", hex"");

            (,,,,,,, uint256 adBalance,) = adManager.ads(adId);
            uint256 owed = adManager.claimable(address(receiver), NATIVE_TOKEN_ADDRESS);
            assertEq(_wNativeToken.balanceOf(address(adManager)), adBalance + owed, "escrow insolvent");
        }

        receiver.setAccepting(true);
        uint256 owedFinal = adManager.claimable(address(receiver), NATIVE_TOKEN_ADDRESS);
        if (owedFinal > 0) {
            uint256 before = address(receiver).balance;
            adManager.claim(address(receiver), NATIVE_TOKEN_ADDRESS);
            assertEq(address(receiver).balance - before, owedFinal, "claim paid wrong amount");
        }
        (,,,,,,, uint256 adBalanceEnd,) = adManager.ads(adId);
        assertEq(_wNativeToken.balanceOf(address(adManager)), adBalanceEnd, "credits not settled");
    }

    function test_claim_withNoCredit_reverts() public {
        vm.expectRevert(IEscrow.Escrow__NothingToClaim.selector);
        adManager.claim(makeAddr("nobody"), address(adToken));
    }

    function test_directPayout_selfCallOnly() public {
        vm.expectRevert(IEscrow.Escrow__SelfCallOnly.selector);
        adManager.directPayout(makeAddr("x"), address(adToken), 1);
    }
}
