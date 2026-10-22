// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Poseidon2Yul_BN254 as Poseidon2Yul} from "@poseidon2/src/bn254/yul/Poseidon2Yul.sol";

import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IVerifier} from "src/interfaces/IVerifier.sol";
import {IMerkleManager} from "src/interfaces/IMerkleManager.sol";
import {IwNativeToken, wNativeToken} from "src/wNativeToken.sol";
import {AdManager} from "src/AdManager.sol";
import {MerkleManager} from "src/MerkleManager.sol";
import {RouteTiming} from "src/libraries/RouteTiming.sol";
import {AddressCast} from "src/libraries/AddressCast.sol";
import {AgentPolicyCodec, IAgentPolicyCodecErrors} from "src/agent/AgentPolicyCodec.sol";
import {AgentRateLimit} from "src/agent/AgentRateLimit.sol";
import {ProofBridgeAgentPolicy} from "src/agent/ProofBridgeAgentPolicy.sol";
import {IAgentPolicyDirect, ProofBridgeCustodyAccount} from "src/agent/ProofBridgeCustodyAccount.sol";
import {CustodyGuardRail} from "src/agent/CustodyGuardRail.sol";
import {CustodyAccountFactory} from "src/agent/CustodyAccountFactory.sol";
import {MockVerifier} from "../mocks/MockVerifier.sol";
import {MockKeyRegistry} from "../mocks/MockKeyRegistry.sol";
import {MockRootVerifier} from "../mocks/MockRootVerifier.sol";

/// An escrow that doesn't take what it is paid, and a dispute module that takes a bond from the filer: the two
/// cases the real `AdManager` can't produce for the pass-through's own checks.
contract SkimEscrow {
    address public disputeManager;

    constructor(address dm) {
        disputeManager = dm;
    }

    function fundAd(string calldata, uint256) external payable {}

    function dispute(IAdManager.OrderParams calldata, bytes32) external payable {
        BondTaker(disputeManager).take(msg.sender);
    }
}

contract BondTaker {
    IERC20 public token;
    uint256 public bond;

    constructor(IERC20 t, uint256 b) {
        token = t;
        bond = b;
    }

    function take(address filer) external {
        token.transferFrom(filer, address(this), bond);
    }
}

/// Plan 46 on the EVM custody account: funds pass from the owner's wallet to the escrow in one call and never
/// stay; the owner's guard rail (A5); the parity fixes (A6). Real `AdManager` throughout, except the stubs above.
/// A contract that takes any call and any value: where a drain would land.
contract Sink {
    fallback() external payable {}
}

contract CustodyGuardRailTest is Test {
    using AddressCast for address;

    uint256 internal constant ORDER_CHAIN_ID = 11155111;
    string internal constant AD = "gr-ad";
    uint256 internal constant AD_FUNDS = 10_000_000;
    uint64 internal constant DELAY = 1 hours;
    uint64 internal constant WINDOW = 1 days;
    bytes32 internal constant ACCOUNT = bytes32(0);

    ProofBridgeAgentPolicy internal module;
    CustodyAccountFactory internal factory;
    ProofBridgeCustodyAccount internal account;
    AdManager internal adManager;
    MockKeyRegistry internal keys;
    ERC20Mock internal adToken;

    address internal admin = makeAddr("escrow-admin");
    address internal orderPortal = makeAddr("order-portal");
    address internal orderToken = makeAddr("order-token");
    address internal adRecipient = makeAddr("ad-recipient");
    address internal owner = makeAddr("maker-wallet");
    address internal thief = makeAddr("thief");
    bytes32 internal signer;

    function setUp() public {
        module = new ProofBridgeAgentPolicy();
        factory = new CustodyAccountFactory(IAgentPolicyDirect(address(module)));
        MerkleManager merkleManager = new MerkleManager(admin, address(new Poseidon2Yul()));
        adManager = new AdManager(
            admin,
            IVerifier(address(new MockVerifier(true))),
            IMerkleManager(address(merkleManager)),
            IwNativeToken(address(new wNativeToken("Wrapped Native Token", "WNATIVE", 18)))
        );
        keys = new MockKeyRegistry();
        vm.startPrank(admin);
        merkleManager.setManager(address(adManager), true);
        adManager.setKeyRegistry(keys);
        adManager.setRootVerifier(ORDER_CHAIN_ID, address(new MockRootVerifier(true)));
        adManager.setRouteTiming(ORDER_CHAIN_ID, RouteTiming.Timing(0, 30 minutes, 0, 0));
        adManager.setPeerEscrow(ORDER_CHAIN_ID, _b32(orderPortal));
        adToken = new ERC20Mock();
        adManager.setTokenRoute(address(adToken), ORDER_CHAIN_ID, _b32(orderToken));
        adManager.setTokenRoute(AddressCast.NATIVE_TOKEN_ADDRESS, ORDER_CHAIN_ID, _b32(orderToken));
        vm.stopPrank();

        signer = _b32(owner);
        keys.set(signer, true);
        address[] memory targets = new address[](1);
        targets[0] = address(adManager);
        vm.prank(owner);
        account = ProofBridgeCustodyAccount(payable(factory.deploy(0, targets)));
        keys.approve(signer, _b32(address(account)), true);

        adToken.mint(owner, 2 * AD_FUNDS);
        vm.prank(owner);
        adToken.approve(address(account), type(uint256).max);
        vm.deal(owner, 100 ether);
        _createAd(AD, AD_FUNDS);
    }

    /*//////////////////////////////////////////////////////////////
                    A4: FUNDS PASS THROUGH, NEVER STAY
    //////////////////////////////////////////////////////////////*/

    function test_a4_createAdFundedTakesTheDepositFromTheWalletStraightToTheEscrow() public {
        assertEq(adManager.availableLiquidity(AD), AD_FUNDS);
        assertEq(adToken.balanceOf(owner), AD_FUNDS, "the deposit came from the wallet");
        assertEq(adToken.balanceOf(address(account)), 0, "and never stayed in the account");
        assertEq(adToken.allowance(address(account), address(adManager)), 0, "no allowance outlives the call");
    }

    function test_a4_fundAdFundedTopsUpTheSameWay() public {
        vm.prank(owner);
        account.fundAdFunded(adManager, AD, address(adToken), 1_000);
        assertEq(adManager.availableLiquidity(AD), AD_FUNDS + 1_000);
        assertEq(adToken.balanceOf(address(account)), 0);
        assertEq(adToken.allowance(address(account), address(adManager)), 0);
    }

    function test_a4_aNativeAdRidesOnTheCall() public {
        vm.prank(owner);
        account.createAdFunded{value: 1 ether}(
            adManager, "native-ad", AddressCast.NATIVE_TOKEN_ADDRESS, 1 ether, ORDER_CHAIN_ID, _b32(adRecipient), signer
        );
        assertEq(adManager.availableLiquidity("native-ad"), 1 ether);
        assertEq(address(account).balance, 0);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ProofBridgeCustodyAccount.CustodyAccount__ValueMismatch.selector, 1, 2));
        account.createAdFunded{value: 1}(
            adManager, "native-ad-2", AddressCast.NATIVE_TOKEN_ADDRESS, 2, ORDER_CHAIN_ID, _b32(adRecipient), signer
        );
    }

    function test_a4_onlyTheOwnerFundsAndOnlyAPinnedEscrow() public {
        vm.prank(thief);
        vm.expectRevert(ProofBridgeCustodyAccount.CustodyAccount__NotOwner.selector);
        account.fundAdFunded(adManager, AD, address(adToken), 1);

        address other = makeAddr("not-pinned");
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ProofBridgeCustodyAccount.CustodyAccount__NotPinned.selector, other));
        account.fundAdFunded(IAdManager(other), AD, address(adToken), 1);
    }

    /// The pass-through's own check: an escrow that doesn't take what was paid in leaves funds in the account,
    /// so the call is refused and the payment reverts with it.
    function test_a4_fundsTheEscrowDoesNotTakeNeverStayInTheAccount() public {
        (ProofBridgeCustodyAccount acct, SkimEscrow skim,) = _accountWithSkimEscrow();
        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(ProofBridgeCustodyAccount.CustodyAccount__FundsLeft.selector, address(adToken))
        );
        acct.fundAdFunded(IAdManager(address(skim)), AD, address(adToken), 500);
        assertEq(adToken.balanceOf(address(acct)), 0);
    }

    /// The dispute bond the same way: from the wallet to the dispute module, approved for exactly the bond.
    function test_a4_disputeFundedPaysTheBondFromTheWallet() public {
        (ProofBridgeCustodyAccount acct, SkimEscrow skim, BondTaker dm) = _accountWithSkimEscrow();
        uint256 walletBefore = adToken.balanceOf(owner);
        vm.prank(owner);
        acct.disputeFunded(IAdManager(address(skim)), _order(AD, 1, 1), bytes32("evidence"), address(adToken), 777);
        assertEq(adToken.balanceOf(address(dm)), 777);
        assertEq(adToken.balanceOf(owner), walletBefore - 777);
        assertEq(adToken.balanceOf(address(acct)), 0);
        assertEq(adToken.allowance(address(acct), address(dm)), 0);
    }

    function test_a4_sweepIsInstantOnAnUnguardedAccount() public {
        adToken.mint(address(account), 50);
        vm.deal(address(account), 3);
        vm.startPrank(owner);
        account.sweep(address(adToken), owner, 50);
        account.sweep(AddressCast.NATIVE_TOKEN_ADDRESS, owner, 3);
        vm.stopPrank();
        assertEq(adToken.balanceOf(address(account)), 0);
        assertEq(address(account).balance, 0);
    }

    /*//////////////////////////////////////////////////////////////
                         A5: THE PER-AD GUARD RAIL
    //////////////////////////////////////////////////////////////*/

    function test_a5_anOverThresholdWithdrawalMustBeAnnouncedAndWaitedOut() public {
        _guard(AD, 100);
        bytes memory w101 = abi.encodeCall(IAdManager.withdrawFromAd, (AD, 101, owner));

        _exec(abi.encodeCall(IAdManager.withdrawFromAd, (AD, 100, owner))); // at the threshold: instant
        _expectNotScheduled(w101);

        vm.prank(owner);
        account.schedule(_adKey(AD), address(adManager), 0, w101);
        _expectNotScheduled(w101); // not matured

        vm.warp(block.timestamp + DELAY);
        _exec(w101);
        _expectNotScheduled(w101); // single use
        assertEq(adManager.availableLiquidity(AD), AD_FUNDS - 201);
    }

    function test_a5_aScheduleAuthorizesExactlyWhatItNamed() public {
        _guard(AD, 0);
        vm.prank(owner);
        account.schedule(_adKey(AD), address(adManager), 0, abi.encodeCall(IAdManager.withdrawFromAd, (AD, 100, owner)));
        vm.warp(block.timestamp + DELAY);
        _expectNotScheduled(abi.encodeCall(IAdManager.withdrawFromAd, (AD, 101, owner)));
        _expectNotScheduled(abi.encodeCall(IAdManager.withdrawFromAd, (AD, 100, thief)));
        _exec(abi.encodeCall(IAdManager.withdrawFromAd, (AD, 100, owner)));
    }

    function test_a5_aScheduleExpiresAndCanBeCancelled() public {
        _guard(AD, 0);
        bytes memory w = abi.encodeCall(IAdManager.withdrawFromAd, (AD, 5, owner));
        vm.prank(owner);
        account.schedule(_adKey(AD), address(adManager), 0, w);
        vm.warp(block.timestamp + DELAY + WINDOW);
        _expectNotScheduled(w);

        vm.startPrank(owner);
        account.schedule(_adKey(AD), address(adManager), 0, w);
        account.cancel(_adKey(AD), IAdManager.withdrawFromAd.selector);
        vm.expectRevert(CustodyGuardRail.GuardRail__NotScheduled.selector);
        account.cancel(_adKey(AD), IAdManager.withdrawFromAd.selector);
        vm.stopPrank();
        vm.warp(block.timestamp + DELAY);
        _expectNotScheduled(w);
    }

    function test_a5_subThresholdWithdrawalsAreBoundedByAFlowRate() public {
        _guardWithRate(AD, 100, 150, 1);
        _exec(abi.encodeCall(IAdManager.withdrawFromAd, (AD, 100, owner)));
        vm.prank(owner);
        vm.expectRevert(CustodyGuardRail.GuardRail__VolumeExceeded.selector);
        account.execute(address(adManager), 0, abi.encodeCall(IAdManager.withdrawFromAd, (AD, 100, owner)));
        vm.warp(block.timestamp + 50);
        _exec(abi.encodeCall(IAdManager.withdrawFromAd, (AD, 100, owner))); // refilled
    }

    function test_a5_closeIsAlwaysAnnouncedOnAGuardedAd() public {
        _guard(AD, type(uint256).max);
        _expectNotScheduled(abi.encodeCall(IAdManager.closeAd, (AD, owner)));
        _createAd("other-ad", 10); // an unguarded ad closes at once
        _exec(abi.encodeCall(IAdManager.closeAd, ("other-ad", owner)));
    }

    function test_a5_aManualLockAboveTheThresholdIsAnnounced() public {
        _guard(AD, 10);
        _expectNotScheduled(abi.encodeCall(IAdManager.lockForOrder, (_order(AD, 11, 1), uint32(0))));
    }

    function test_a5_aScheduleMustNameItsAdAndAGuardedOne() public {
        _guard(AD, 0);
        vm.startPrank(owner);
        vm.expectRevert(CustodyGuardRail.GuardRail__ScopeMismatch.selector);
        account.schedule(
            _adKey("other-ad"), address(adManager), 0, abi.encodeCall(IAdManager.withdrawFromAd, (AD, 1, owner))
        );
        vm.expectRevert(CustodyGuardRail.GuardRail__NoGuardRail.selector);
        account.schedule(
            _adKey("other-ad"), address(adManager), 0, abi.encodeCall(IAdManager.withdrawFromAd, ("other-ad", 1, owner))
        );
        vm.expectRevert(CustodyGuardRail.GuardRail__ScopeMismatch.selector);
        account.schedule(ACCOUNT, address(adManager), 0, abi.encodeCall(IAdManager.withdrawFromAd, (AD, 1, owner)));
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                     A5: ARMING, LOOSENING, DISARMING
    //////////////////////////////////////////////////////////////*/

    function test_a5_armingAndTighteningAreInstantLooseningAndDisarmingWait() public {
        _guard(AD, 100);
        _setRail(AD, _rail(50, DELAY * 2)); // tighter: instant

        CustodyGuardRail.GuardRail memory looser = _rail(1_000, DELAY * 2);
        vm.prank(owner);
        vm.expectRevert(CustodyGuardRail.GuardRail__NotScheduled.selector);
        account.setGuardRail(AD, looser);

        bytes memory call_ = abi.encodeCall(CustodyGuardRail.setGuardRail, (AD, looser));
        vm.prank(owner);
        account.schedule(_adKey(AD), address(account), 0, call_);
        vm.warp(block.timestamp + DELAY * 2);
        _setRail(AD, looser);
        assertEq(account.guardRail(AD).rail.threshold, 1_000);

        bytes memory disarm = abi.encodeCall(CustodyGuardRail.disarmGuardRail, (AD));
        vm.prank(owner);
        vm.expectRevert(CustodyGuardRail.GuardRail__NotScheduled.selector);
        account.disarmGuardRail(AD);
        vm.prank(owner);
        account.schedule(_adKey(AD), address(account), 0, disarm);
        vm.warp(block.timestamp + DELAY * 2);
        vm.prank(owner);
        account.disarmGuardRail(AD);
        assertFalse(account.guardRail(AD).armed);
        assertEq(account.guardedAds().length, 0);
    }

    function test_a5_aLooseningClearsPendingSchedules() public {
        _guard(AD, 0);
        bytes memory w = abi.encodeCall(IAdManager.withdrawFromAd, (AD, 5, owner));
        vm.startPrank(owner);
        account.schedule(_adKey(AD), address(adManager), 0, w);
        CustodyGuardRail.GuardRail memory looser = _rail(10, DELAY);
        account.schedule(_adKey(AD), address(account), 0, abi.encodeCall(CustodyGuardRail.setGuardRail, (AD, looser)));
        vm.stopPrank();
        vm.warp(block.timestamp + DELAY);
        _setRail(AD, looser);
        assertEq(account.scheduled(_adKey(AD), IAdManager.withdrawFromAd.selector).readyAt, 0, "cleared");
    }

    /// A pending change waits the new, longer delay once the owner raises it (Soroban 49S-1).
    function test_a5_raisingTheDelayRestampsWhatIsPending() public {
        _guard(AD, 0);
        bytes memory w = abi.encodeCall(IAdManager.withdrawFromAd, (AD, 5, owner));
        vm.prank(owner);
        account.schedule(_adKey(AD), address(adManager), 0, w);
        _setRail(AD, _rail(0, DELAY * 3));
        vm.warp(block.timestamp + DELAY);
        _expectNotScheduled(w);
        vm.warp(block.timestamp + DELAY * 2);
        _exec(w);
    }

    /// 81-4 (R1): a guard rail is bounded, so neither a stolen key nor a slip can freeze an ad: a delay of at most
    /// 30 days and a window of at least an hour. Inside the bounds, arming and tightening stay instant.
    function test_r81_4_aGuardRailIsBoundedSoItCannotFreezeTheAd() public {
        uint64 maxDelay = account.MAX_GUARD_DELAY();
        uint64 minWindow = account.MIN_GUARD_WINDOW();
        assertEq(maxDelay, 30 days);
        assertEq(minWindow, 1 hours);
        CustodyGuardRail.GuardRail memory r = _rail(0, maxDelay + 1);
        vm.startPrank(owner);
        vm.expectRevert(CustodyGuardRail.GuardRail__DelayTooLong.selector);
        account.setGuardRail(AD, r);
        r = _rail(0, DELAY);
        r.window = minWindow - 1;
        vm.expectRevert(CustodyGuardRail.GuardRail__WindowTooShort.selector);
        account.setGuardRail(AD, r);

        // At the bounds: armed, then tightened to them at once.
        account.setGuardRail(AD, _rail(0, DELAY));
        r = _rail(0, maxDelay);
        r.window = minWindow;
        account.setGuardRail(AD, r);
        assertEq(account.guardRail(AD).rail.delay, maxDelay);
        // One second past them is refused even as a "tightening".
        r.delay = maxDelay + 1;
        vm.expectRevert(CustodyGuardRail.GuardRail__DelayTooLong.selector);
        account.setGuardRail(AD, r);
        r.delay = maxDelay;
        r.window = minWindow - 1;
        vm.expectRevert(CustodyGuardRail.GuardRail__WindowTooShort.selector);
        account.setGuardRail(AD, r);
        vm.stopPrank();
    }

    function test_a5_badSettingsAndTooManyGuardedAdsAreRefused() public {
        vm.startPrank(owner);
        vm.expectRevert(CustodyGuardRail.GuardRail__BadGuardRail.selector);
        account.setGuardRail(AD, _rail(0, 0));
        for (uint256 i = 0; i < account.MAX_GUARDED_ADS(); ++i) {
            account.setGuardRail(vm.toString(i), _rail(0, DELAY));
        }
        vm.expectRevert(CustodyGuardRail.GuardRail__BadGuardRail.selector);
        account.setGuardRail("one-too-many", _rail(0, DELAY));
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    A5: ACCOUNT-WIDE, WHILE ANY AD IS GUARDED
    //////////////////////////////////////////////////////////////*/

    function test_a5_movingFundsOutOfTheAccountWaits() public {
        _guard(AD, 0);
        adToken.mint(address(account), 10);
        vm.deal(address(account), 10);
        vm.startPrank(owner);
        // R3: a token is no target the account knows, so the call is refused outright; `sweep` is the way out.
        vm.expectRevert(CustodyGuardRail.GuardRail__NotAllowed.selector);
        account.execute(address(adToken), 0, abi.encodeCall(IERC20.transfer, (thief, 10)));
        vm.expectRevert(CustodyGuardRail.GuardRail__NotAllowed.selector);
        account.execute(address(adToken), 0, abi.encodeCall(IERC20.approve, (thief, 10)));
        vm.expectRevert(CustodyGuardRail.GuardRail__NotScheduled.selector);
        account.execute(thief, 10, "");
        vm.expectRevert(CustodyGuardRail.GuardRail__NotScheduled.selector);
        account.execute(
            address(adManager), 0, abi.encodeWithSignature("claimTo(address,address)", address(adToken), thief)
        );
        vm.expectRevert(CustodyGuardRail.GuardRail__NotScheduled.selector);
        account.sweep(address(adToken), thief, 10);

        bytes memory sweepCall = abi.encodeCall(ProofBridgeCustodyAccount.sweep, (address(adToken), owner, 10));
        account.schedule(ACCOUNT, address(account), 0, sweepCall);
        vm.warp(block.timestamp + DELAY);
        account.sweep(address(adToken), owner, 10);
        vm.stopPrank();
        assertEq(adToken.balanceOf(address(account)), 0);
    }

    /// 81-1: native value leaving a guarded account always needs its own schedule, whatever selector it rides on,
    /// on an armed ad and on an unarmed one alike.
    function test_r81_1_nativeValueOnAnEscrowShapedCallStillWaits() public {
        _guard(AD, 100);
        _createAd("unarmed", 10);
        vm.deal(address(account), 5 ether);
        Sink sink = new Sink();
        bytes memory withdrawShaped = abi.encodeCall(IAdManager.withdrawFromAd, (AD, 0, owner));
        bytes memory lockShaped = abi.encodeCall(IAdManager.lockForOrder, (_order(AD, 1, 99), uint32(0)));
        bytes memory unarmedShaped = abi.encodeCall(IAdManager.withdrawFromAd, ("unarmed", 0, owner));
        vm.startPrank(owner);
        vm.expectRevert(CustodyGuardRail.GuardRail__NotScheduled.selector);
        account.execute(address(sink), 5 ether, withdrawShaped);
        vm.expectRevert(CustodyGuardRail.GuardRail__NotScheduled.selector);
        account.execute(address(sink), 1 ether, lockShaped);
        vm.expectRevert(CustodyGuardRail.GuardRail__NotScheduled.selector);
        account.execute(address(sink), 1 ether, unarmedShaped);

        // Announced as native value leaving the account (the account scope), it runs once, after the delay.
        account.schedule(ACCOUNT, address(sink), 5 ether, withdrawShaped);
        vm.warp(block.timestamp + DELAY);
        account.execute(address(sink), 5 ether, withdrawShaped);
        vm.stopPrank();
        assertEq(address(sink).balance, 5 ether);
    }

    /// R3: while any ad is guarded, an owner call is an allowlist. A target the account doesn't know, or a function
    /// it doesn't list, is refused; this is what closes the token calls a blocklist misses (81-b2).
    function test_r3_whileGuardedAnUnlistedCallIsRefused() public {
        Sink sink = new Sink();
        // Unguarded: the account is a plain account, as before.
        _exec2(address(sink), abi.encodeWithSignature("transferAndCall(address,uint256,bytes)", thief, 1, ""));
        _guard(AD, 0);
        vm.startPrank(owner);
        vm.expectRevert(CustodyGuardRail.GuardRail__NotAllowed.selector);
        account.execute(
            address(sink), 0, abi.encodeWithSignature("transferAndCall(address,uint256,bytes)", thief, 1, "")
        );
        vm.expectRevert(CustodyGuardRail.GuardRail__NotAllowed.selector);
        account.execute(address(sink), 0, abi.encodeWithSignature("send(address,uint256,bytes)", thief, 1, ""));
        // An escrow function the list doesn't name (the wrappers fund ads, not execute).
        vm.expectRevert(CustodyGuardRail.GuardRail__NotAllowed.selector);
        account.execute(address(adManager), 0, abi.encodeCall(IAdManager.fundAd, (AD, 1)));
        // A per-ad selector on a target that isn't a pinned escrow.
        vm.expectRevert(CustodyGuardRail.GuardRail__NotAllowed.selector);
        account.execute(address(sink), 0, abi.encodeCall(IAdManager.withdrawFromAd, (AD, 1, thief)));
        // A module function the list doesn't name.
        vm.expectRevert(CustodyGuardRail.GuardRail__NotAllowed.selector);
        account.execute(address(module), 0, abi.encodeWithSignature("someNewSetter(uint256)", 1));
        // And it can't be announced either: a schedule that could never be spent would only mislead a watcher.
        vm.expectRevert(CustodyGuardRail.GuardRail__NotAllowed.selector);
        account.schedule(ACCOUNT, address(adToken), 0, abi.encodeCall(IERC20.transfer, (thief, 10)));
        vm.expectRevert(CustodyGuardRail.GuardRail__NotAllowed.selector);
        account.schedule(_adKey(AD), address(sink), 0, abi.encodeCall(IAdManager.withdrawFromAd, (AD, 1, thief)));
        vm.stopPrank();
    }

    /// R3: the protective calls stay instant while guarded.
    function test_r3_protectiveCallsStayInstantWhileGuarded() public {
        bytes32 agentId = _b32(makeAddr("pod"));
        _exec2(address(module), abi.encodeCall(module.setAccountLimit, (_b32(address(adToken)), 5_000, 10)));
        _exec2(address(module), abi.encodeCall(module.setAgentPolicy, (agentId, _policy())));
        _guard(AD, 0);
        _exec(abi.encodeCall(IAdManager.haltSettlement, ()));
        assertTrue(adManager.halted(address(account)));
        _exec2(address(module), abi.encodeCall(module.revokeAgent, (agentId)));
        assertTrue(module.isRevoked(address(account), agentId));
    }

    /// 81-2: the dispute module's own credit claims are announced and waited out, like the escrow's `claimTo`.
    function test_r81_2_theDisputeModulesClaimsWait() public {
        _guard(AD, 0);
        Sink dm = new Sink();
        bytes memory claim = abi.encodeWithSignature("claimTo(address)", owner);
        bytes memory claimToken = abi.encodeWithSignature("claimTokenTo(address,address)", address(adToken), owner);
        _expectNotScheduled2(address(dm), claim);
        _expectNotScheduled2(address(dm), claimToken);
        vm.startPrank(owner);
        account.schedule(ACCOUNT, address(dm), 0, claim);
        account.schedule(ACCOUNT, address(dm), 0, claimToken);
        vm.warp(block.timestamp + DELAY);
        account.execute(address(dm), 0, claim);
        account.execute(address(dm), 0, claimToken);
        vm.stopPrank();
    }

    /// R2 (81-b1): while guarded, undoing a halt waits, and so does re-pointing a guarded ad's settlement signer:
    /// either lets a thief settle trades the owner stopped, or settle them under a key the thief holds. Halting
    /// stays instant; an unguarded ad's signer moves at once.
    function test_r2_resumeAndAGuardedAdsSignerWait() public {
        bytes32 next = bytes32(uint256(0xbeef));
        keys.set(next, true);
        keys.approve(next, _b32(address(account)), true);
        _createAd("unarmed", 10);
        _guard(AD, 0);

        _exec(abi.encodeCall(IAdManager.haltSettlement, ()));
        bytes memory resume = abi.encodeCall(IAdManager.resumeSettlement, ());
        _expectNotScheduled(resume);
        bytes memory repoint = abi.encodeCall(IAdManager.setSettlementSigner, (AD, next));
        _expectNotScheduled(repoint);
        _exec(abi.encodeCall(IAdManager.setSettlementSigner, ("unarmed", next)));

        vm.startPrank(owner);
        account.schedule(ACCOUNT, address(adManager), 0, resume);
        account.schedule(_adKey(AD), address(adManager), 0, repoint);
        vm.warp(block.timestamp + DELAY);
        account.execute(address(adManager), 0, resume);
        account.execute(address(adManager), 0, repoint);
        vm.stopPrank();
        assertFalse(adManager.halted(address(account)));
    }

    function test_a5_ownershipWaitsWhileGuarded() public {
        _guard(AD, 0);
        vm.prank(owner);
        vm.expectRevert(CustodyGuardRail.GuardRail__NotScheduled.selector);
        account.transferOwnership(thief);
    }

    function test_a5_policyWritesWaitProtectiveOnesDoNot() public {
        bytes32 agentId = _b32(makeAddr("pod"));
        _exec2(address(module), abi.encodeCall(module.setAccountLimit, (_b32(address(adToken)), 5_000, 10)));
        _exec2(address(module), abi.encodeCall(module.setAgentPolicy, (agentId, _policy())));
        _guard(AD, 0);

        _expectNotScheduled2(address(module), abi.encodeCall(module.setAgentPolicy, (agentId, _policy())));
        _expectNotScheduled2(
            address(module), abi.encodeCall(module.setAccountLimit, (_b32(address(adToken)), 6_000, 10))
        );
        address[] memory more = new address[](1);
        more[0] = makeAddr("another-escrow");
        _expectNotScheduled2(address(module), abi.encodeCall(module.setTargets, (more, true)));
        _expectNotScheduled2(address(module), abi.encodeCall(module.onUninstall, (abi.encode(uint256(4)))));

        // Protective: instant.
        _exec2(address(module), abi.encodeCall(module.setAccountLimit, (_b32(address(adToken)), 4_000, 10)));
        _exec2(address(module), abi.encodeCall(module.setTargets, (more, false)));
        _exec2(address(module), abi.encodeCall(module.revokeAgent, (agentId)));
        assertTrue(module.isRevoked(address(account), agentId));
    }

    function test_a5_theAccountCannotCallItselfThroughExecute() public {
        vm.prank(owner);
        vm.expectRevert(CustodyGuardRail.GuardRail__SelfCall.selector);
        account.execute(address(account), 0, abi.encodeCall(ProofBridgeCustodyAccount.transferOwnership, (thief)));
    }

    function test_a5_aBatchPassesEveryCallThroughTheGuardRail() public {
        _guard(AD, 0);
        ProofBridgeCustodyAccount.Call[] memory calls = new ProofBridgeCustodyAccount.Call[](1);
        calls[0] = ProofBridgeCustodyAccount.Call(
            address(adManager), 0, abi.encodeCall(IAdManager.withdrawFromAd, (AD, 1, owner))
        );
        vm.prank(owner);
        vm.expectRevert(CustodyGuardRail.GuardRail__NotScheduled.selector);
        account.executeBatch(calls);
    }

    function test_a5_schedulingNeedsAGuardedAccountAndEmits() public {
        vm.prank(owner);
        vm.expectRevert(CustodyGuardRail.GuardRail__NoGuardRail.selector);
        account.schedule(
            ACCOUNT, address(account), 0, abi.encodeCall(ProofBridgeCustodyAccount.sweep, (address(adToken), owner, 1))
        );
        _guard(AD, 0);
        bytes memory w = abi.encodeCall(IAdManager.withdrawFromAd, (AD, 1, owner));
        vm.expectEmit(address(account));
        emit CustodyGuardRail.Scheduled(
            _adKey(AD),
            IAdManager.withdrawFromAd.selector,
            address(adManager),
            0,
            w,
            uint64(block.timestamp + DELAY),
            uint64(block.timestamp + DELAY + WINDOW)
        );
        vm.prank(owner);
        account.schedule(_adKey(AD), address(adManager), 0, w);
    }

    /*//////////////////////////////////////////////////////////////
                              A6: PARITY FIXES
    //////////////////////////////////////////////////////////////*/

    function test_a6_aZeroSettlementSignerIsRefused() public {
        _exec2(address(module), abi.encodeCall(module.setAccountLimit, (_b32(address(adToken)), 5_000, 10)));
        bytes memory p = _policyWithSigner(bytes32(0));
        vm.prank(owner);
        vm.expectRevert(IAgentPolicyCodecErrors.AgentPolicyCodec__ZeroSettlementSigner.selector);
        account.execute(address(module), 0, abi.encodeCall(module.setAgentPolicy, (_b32(makeAddr("pod")), p)));
    }

    function test_a6_pinningZeroTheAccountOrTheModuleIsRefused() public {
        address[3] memory bad = [address(0), address(account), address(module)];
        for (uint256 i = 0; i < bad.length; ++i) {
            address[] memory t = new address[](1);
            t[0] = bad[i];
            vm.prank(owner);
            vm.expectRevert(abi.encodeWithSelector(ProofBridgeAgentPolicy.AgentPolicy__BadTarget.selector, bad[i]));
            account.execute(address(module), 0, abi.encodeCall(module.setTargets, (t, true)));
        }
        // And at install, through the factory.
        address[] memory selfish = new address[](1);
        selfish[0] = address(0);
        vm.prank(thief);
        vm.expectRevert(abi.encodeWithSelector(ProofBridgeAgentPolicy.AgentPolicy__BadTarget.selector, address(0)));
        factory.deploy(1, selfish);
    }

    function test_a6_theAccountLimitIsReadable() public {
        _exec2(address(module), abi.encodeCall(module.setAccountLimit, (_b32(address(adToken)), 5_000, 10)));
        AgentRateLimit.Limit memory l = module.accountLimit(address(account), _b32(address(adToken)));
        assertEq(l.capacity, 5_000);
        assertEq(l.refillPerSecond, 10);
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _accountWithSkimEscrow() internal returns (ProofBridgeCustodyAccount acct, SkimEscrow skim, BondTaker dm) {
        dm = new BondTaker(IERC20(address(adToken)), 777);
        skim = new SkimEscrow(address(dm));
        address[] memory targets = new address[](1);
        targets[0] = address(skim);
        vm.prank(owner);
        acct = ProofBridgeCustodyAccount(payable(factory.deploy(7, targets)));
        vm.prank(owner);
        adToken.approve(address(acct), type(uint256).max);
    }

    function _createAd(string memory adId, uint256 amount) internal {
        vm.prank(owner);
        account.createAdFunded(adManager, adId, address(adToken), amount, ORDER_CHAIN_ID, _b32(adRecipient), signer);
    }

    function _rail(uint256 threshold, uint64 delay) internal pure returns (CustodyGuardRail.GuardRail memory) {
        return CustodyGuardRail.GuardRail({
            threshold: threshold, delay: delay, window: WINDOW, capacity: type(uint128).max, refillPerSecond: 1
        });
    }

    function _guard(string memory adId, uint256 threshold) internal {
        _setRail(adId, _rail(threshold, DELAY));
    }

    function _guardWithRate(string memory adId, uint256 threshold, uint256 capacity, uint256 refill) internal {
        _setRail(
            adId,
            CustodyGuardRail.GuardRail({
                threshold: threshold, delay: DELAY, window: WINDOW, capacity: capacity, refillPerSecond: refill
            })
        );
    }

    function _setRail(string memory adId, CustodyGuardRail.GuardRail memory rail) internal {
        vm.prank(owner);
        account.setGuardRail(adId, rail);
    }

    function _exec(bytes memory data) internal {
        _exec2(address(adManager), data);
    }

    function _exec2(address target, bytes memory data) internal {
        vm.prank(owner);
        account.execute(target, 0, data);
    }

    function _expectNotScheduled(bytes memory data) internal {
        _expectNotScheduled2(address(adManager), data);
    }

    function _expectNotScheduled2(address target, bytes memory data) internal {
        vm.prank(owner);
        vm.expectRevert(CustodyGuardRail.GuardRail__NotScheduled.selector);
        account.execute(target, 0, data);
    }

    function _adKey(string memory adId) internal pure returns (bytes32) {
        return keccak256(bytes(adId));
    }

    function _order(string memory adId, uint256 amount, uint256 salt)
        internal
        view
        returns (IAdManager.OrderParams memory)
    {
        return IAdManager.OrderParams({
            orderChainToken: _b32(orderToken),
            adChainToken: _b32(address(adToken)),
            amount: amount,
            bridger: bytes32(uint256(0xb1)),
            orderChainId: ORDER_CHAIN_ID,
            srcOrderPortal: _b32(orderPortal),
            orderRecipient: bytes32(uint256(0xb2)),
            adId: adId,
            adCreator: _b32(address(account)),
            adRecipient: _b32(adRecipient),
            salt: salt,
            orderDecimals: 18,
            adDecimals: 18,
            deadline: block.timestamp + 1 days,
            adSettlementSigner: signer,
            lpFeeBps: 0,
            protocolFeeBps: 0
        });
    }

    function _policy() internal view returns (bytes memory) {
        return _policyWithSigner(signer);
    }

    function _policyWithSigner(bytes32 s) internal view returns (bytes memory) {
        bytes memory tokens = bytes.concat(
            AgentPolicyCodec.DOMAIN,
            bytes1(AgentPolicyCodec.ACTION_LOCK_FOR_ORDER),
            bytes1(uint8(1)),
            _b32(address(adToken)),
            bytes32(uint256(100)),
            bytes32(uint256(1_000)),
            bytes32(uint256(1)),
            bytes1(uint8(1)),
            _b32(orderToken)
        );
        return bytes.concat(tokens, bytes1(uint8(0)), bytes1(uint8(0)), bytes8(uint64(0)), s);
    }

    function _b32(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }
}
