// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IEscrow} from "src/interfaces/IEscrow.sol";
import {IDisputeManager} from "src/interfaces/IDisputeManager.sol";
import {DisputeManager} from "src/DisputeManager.sol";
import {Dispute} from "src/libraries/Dispute.sol";
import {RootVerifierRegistry} from "src/libraries/RootVerifierRegistry.sol";
import {CustodyGuardRail} from "src/agent/CustodyGuardRail.sol";
import {ProofBridgeAgentPolicy} from "src/agent/ProofBridgeAgentPolicy.sol";
import {ProofBridgeCustodyAccount} from "src/agent/ProofBridgeCustodyAccount.sol";
import {PinRootVerifier} from "../mocks/PinRootVerifier.sol";
import {TestField} from "test/utils/TestField.sol";
import {statusOf} from "test/utils/OrderStatus.sol";
import {OrderHash} from "src/libraries/OrderHash.sol";
import {CustodyAccountTest} from "../agent/CustodyAccount.t.sol";

/// Chaos pack (CHAOS.md), EVM: an agent's key misbehaves, or is lost, around a trade it locked. Built on
/// `CustodyAccountTest`'s real AdManager + custody account + policy module; disputes use the real DisputeManager.
contract ChaosAgentTest is CustodyAccountTest {
    uint256 internal constant NO_CALL = type(uint256).max;
    uint256 internal constant AMOUNT = 100_000;
    uint128 internal constant BOND = 0.01 ether;
    /// The bridger's payout address on this chain: the order's `orderRecipient`.
    address internal constant BRIDGER = address(uint160(0xb2));

    DisputeManager internal dm;
    address internal arbiter = makeAddr("arbiter");
    address internal feePool = makeAddr("fee-pool");

    /*//////////////////////////////////////////////////////////////
                  C1: THE AGENT'S KEY IS STOLEN MID-TRADE
    //////////////////////////////////////////////////////////////*/

    /// The thief holds the agent key while its lock is open: nothing outside "lock within the policy" gets through.
    function test_chaos_c1_stolenKeyCannotDefundTheAdOrTouchThePolicy() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _agentLock(AMOUNT, 1);
        bytes32 fingerprint = module.fingerprintOf(address(account), agentId);

        // Through the account, as the agent: no withdraw, close, signer swap, token move or policy write.
        _thiefRefused(
            address(adManager),
            abi.encodeCall(IAdManager.withdrawFromAd, (AD, AD_FUNDS - AMOUNT, agent)),
            0,
            ProofBridgeAgentPolicy.Refusal.ActionNotAllowed
        );
        _thiefRefused(
            address(adManager),
            abi.encodeCall(IAdManager.closeAd, (OTHER_AD, agent)),
            0,
            ProofBridgeAgentPolicy.Refusal.ActionNotAllowed
        );
        _thiefRefused(
            address(adManager),
            abi.encodeCall(IAdManager.setSettlementSigner, (AD, _b32(agent))),
            0,
            ProofBridgeAgentPolicy.Refusal.ActionNotAllowed
        );
        _thiefRefused(
            address(adToken),
            abi.encodeCall(adToken.transfer, (agent, 1)),
            0,
            ProofBridgeAgentPolicy.Refusal.TargetNotPinned
        );
        _thiefRefused(
            address(module),
            abi.encodeCall(module.setAgentPolicy, (agentId, _policy(OTHER_AD))),
            0,
            ProofBridgeAgentPolicy.Refusal.TargetNotPinned
        );
        _thiefRefused(
            address(module),
            abi.encodeCall(module.setAccountLimit, (_b32(address(adToken)), type(uint128).max, 1)),
            0,
            ProofBridgeAgentPolicy.Refusal.TargetNotPinned
        );

        // Straight at the account: every owner door is shut to the agent key.
        vm.startPrank(agent);
        vm.expectRevert(ProofBridgeCustodyAccount.CustodyAccount__NotOwner.selector);
        account.execute(address(adManager), 0, abi.encodeCall(IAdManager.withdrawFromAd, (AD, 1, agent)));
        ProofBridgeCustodyAccount.Call[] memory calls = new ProofBridgeCustodyAccount.Call[](1);
        calls[0] = ProofBridgeCustodyAccount.Call(
            address(module), 0, abi.encodeCall(module.setAgentPolicy, (agentId, _policy(OTHER_AD)))
        );
        vm.expectRevert(ProofBridgeCustodyAccount.CustodyAccount__NotOwner.selector);
        account.executeBatch(calls);
        vm.expectRevert(ProofBridgeCustodyAccount.CustodyAccount__NotOwner.selector);
        account.sweep(address(adToken), agent, 1);
        vm.expectRevert(ProofBridgeCustodyAccount.CustodyAccount__NotOwner.selector);
        account.transferOwnership(agent);
        vm.expectRevert(ProofBridgeCustodyAccount.CustodyAccount__NotOwner.selector);
        account.setGuardRail(AD, CustodyGuardRail.GuardRail(0, 1 hours, 1 days, type(uint128).max, 1));
        // Straight at the module: its setters key on the caller, and the agent key has no account there.
        vm.expectRevert(ProofBridgeAgentPolicy.AgentPolicy__NotInstalled.selector);
        module.setAgentPolicy(agentId, _policy(OTHER_AD));
        vm.expectRevert(ProofBridgeAgentPolicy.AgentPolicy__NotInstalled.selector);
        module.setAccountLimit(_b32(address(adToken)), type(uint128).max, 1);
        module.onUninstall(abi.encode(uint256(4))); // a no-op for an address with nothing installed
        vm.stopPrank();

        assertEq(module.fingerprintOf(address(account), agentId), fingerprint, "the policy is the owner's");
        assertTrue(account.isModuleInstalled(4, address(module), ""), "the hook is still mounted");
        assertEq(account.owner(), owner);
        assertEq(account.pendingOwner(), address(0));
        assertEq(uint8(statusOf(address(adManager), h)), uint8(IEscrow.Status.Open), "the open trade is untouched");
        assertEq(_adBalance(AD), AD_FUNDS, "nothing left the ad");
        assertEq(adManager.availableLiquidity(AD), AD_FUNDS - AMOUNT, "and only the trade's amount is locked");
        assertEq(adToken.balanceOf(agent), 0);

        // The order's payout is frozen in its hash: a re-pointed recipient is a different, unlocked order.
        IAdManager.OrderParams memory redirected = p;
        redirected.orderRecipient = _b32(agent);
        bytes32 hr = _hash(redirected);
        vm.prank(agent);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderNotOpen.selector, hr));
        adManager.unlock(redirected, TestField.fe("c1-redirect"), bytes32(uint256(1)), hex"", hex"");
    }

    /// The thief can lock, but only inside the caps, the ad scope and the settlement signer the owner set.
    function test_chaos_c1_stolenKeyStaysInsideTheCaps() public {
        _agentLock(AMOUNT, 1);
        _thiefRefused(
            address(adManager),
            _lock(_order(AD, MAX_PER_ORDER + 1, 2)),
            0,
            ProofBridgeAgentPolicy.Refusal.OverPerOrderCap
        );
        _thiefRefused(
            address(adManager), _lock(_order(OTHER_AD, 100, 3)), 0, ProofBridgeAgentPolicy.Refusal.AdNotInScope
        );
        IAdManager.OrderParams memory ownSigner = _order(AD, 100, 4);
        ownSigner.adSettlementSigner = _b32(agent);
        _thiefRefused(address(adManager), _lock(ownSigner), 0, ProofBridgeAgentPolicy.Refusal.SettlementSignerMismatch);

        // Drain at the per-order cap: the bucket runs dry and the next lock is refused before the escrow.
        uint256 landed;
        while (module.agentBucket(address(account), agentId, _b32(address(adToken))).level >= MAX_PER_ORDER) {
            _agentLock(MAX_PER_ORDER, 10 + landed);
            ++landed;
        }
        assertEq(landed, (CAPACITY - AMOUNT) / MAX_PER_ORDER, "exactly the capacity landed");
        _thiefRefused(
            address(adManager),
            _lock(_order(AD, MAX_PER_ORDER, 99)),
            0,
            ProofBridgeAgentPolicy.Refusal.AgentAllowanceExceeded
        );
        assertEq(adManager.availableLiquidity(AD), AD_FUNDS - AMOUNT - landed * MAX_PER_ORDER);
    }

    /// The owner revokes the stolen key: its next lock is refused and the open trade still settles to its parties.
    function test_chaos_c1_afterTheRevokeTheOpenTradeStillSettlesToItsParties() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _agentLock(AMOUNT, 1);
        _asOwner(address(module), abi.encodeCall(module.revokeAgent, (agentId)));

        _thiefRefused(address(adManager), _lock(_order(AD, 100, 2)), NO_CALL, ProofBridgeAgentPolicy.Refusal.NoPolicy);
        _settles(p, h, "c1");
        assertEq(adToken.balanceOf(agent), 0, "the thief got nothing");
    }

    /*//////////////////////////////////////////////////////////////
                C3: THE AGENT IS REVOKED WHILE ITS TRADE IS OPEN
    //////////////////////////////////////////////////////////////*/

    function test_chaos_c3_revokedMidTrade_theOpenOrderSettles() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _agentLock(AMOUNT, 1);
        _asOwner(address(module), abi.encodeCall(module.revokeAgent, (agentId)));
        assertTrue(module.isRevoked(address(account), agentId));
        assertEq(uint8(statusOf(address(adManager), h)), uint8(IEscrow.Status.Open), "the revoke left it open");
        assertEq(adManager.availableLiquidity(AD), AD_FUNDS - AMOUNT, "and still locked");

        _settles(p, h, "c3");
        _thiefRefused(address(adManager), _lock(_order(AD, 100, 2)), NO_CALL, ProofBridgeAgentPolicy.Refusal.NoPolicy);
    }

    /// No co-signed unlock comes: past the deadline the lock goes back to the ad and the CANCEL leaf
    /// (the bridger's refund on the order chain) is appended once.
    function test_chaos_c3_revokedMidTrade_theBridgerIsRefundedAfterTheDeadline() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _agentLock(AMOUNT, 1);
        _asOwner(address(module), abi.encodeCall(module.revokeAgent, (agentId)));

        vm.warp(p.deadline);
        adManager.claimCancel(p);
        vm.warp(adManager.cancelFinalizesAt(p));
        uint256 leaves = adManager.getMerkleLeafCount();
        adManager.finalizeCancel(p);

        assertEq(uint8(statusOf(address(adManager), h)), uint8(IEscrow.Status.Cancelled));
        assertEq(adManager.getMerkleLeafCount(), leaves + 1, "the CANCEL leaf");
        assertEq(adManager.availableLiquidity(AD), AD_FUNDS, "the lock is back in the ad");
        assertEq(adToken.balanceOf(BRIDGER), 0, "the ad paid nobody");
        vm.warp(p.deadline); // back inside the unlock window, so the status is what refuses
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__OrderNotOpen.selector, h));
        adManager.unlock(p, TestField.fe("c3-late"), bytes32(uint256(1)), hex"", hex"");
        _thiefRefused(address(adManager), _lock(_order(AD, 100, 2)), NO_CALL, ProofBridgeAgentPolicy.Refusal.NoPolicy);
    }

    /// The tombstone is permanent: the owner cannot reinstall the revoked id, so a stolen key stays dead.
    function test_chaos_c3_theRevokeIsPermanent() public {
        _agentLock(AMOUNT, 1);
        _asOwner(address(module), abi.encodeCall(module.revokeAgent, (agentId)));
        vm.prank(owner);
        vm.expectRevert(ProofBridgeAgentPolicy.AgentPolicy__AgentRevoked.selector);
        account.execute(address(module), 0, abi.encodeCall(module.setAgentPolicy, (agentId, _policy(AD))));
        _thiefRefused(address(adManager), _lock(_order(AD, 100, 2)), NO_CALL, ProofBridgeAgentPolicy.Refusal.NoPolicy);
    }

    /*//////////////////////////////////////////////////////////////
          C4: A SETTLEMENT KEY IS ADDED WHILE THE AGENT'S ORDER IS OPEN
    //////////////////////////////////////////////////////////////*/

    /// A new co-signing slot mid-trade: the order stays pinned to the slot it locked with and settles on it;
    /// the new slot cannot vouch for it; the ad stays open.
    function test_chaos_c4_aKeyAddedMidTradeLeavesTheOrderOnItsPin() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _agentLock(AMOUNT, 1);
        keys.setSlotExpiry(signer, 1, 0);

        (,,, uint32 slot) = adManager.orders(h);
        assertEq(slot, 0, "still pinned to the lock's slot");
        (, bool open,,,,,,,) = adManager.ads(AD);
        assertTrue(open, "no ad is closed");
        assertEq(uint8(statusOf(address(adManager), h)), uint8(IEscrow.Status.Open));

        _setRootVerifier(address(new PinRootVerifier(1)));
        vm.expectRevert(
            abi.encodeWithSelector(RootVerifierRegistry.RootNotValid.selector, ORDER_CHAIN_ID, bytes32(uint256(1)))
        );
        adManager.unlock(p, TestField.fe("c4"), bytes32(uint256(1)), hex"", hex"");
        _setRootVerifier(address(new PinRootVerifier(0)));
        _settles(p, h, "c4");
    }

    /*//////////////////////////////////////////////////////////////
              C5: A DISPUTE AGAINST A LOCK THE AGENT MADE
    //////////////////////////////////////////////////////////////*/

    function test_chaos_c5_mutualRefund_lockBackToTheAd_bondBackToTheFiler() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _disputedAgentLock(1);
        _ruleAndFinalize(p, h, Dispute.Outcome.MutualRefund);
        assertEq(adManager.availableLiquidity(AD), AD_FUNDS, "the lock is back in the ad");
        assertEq(_adBalance(AD), AD_FUNDS);
        assertEq(adToken.balanceOf(BRIDGER), 0);
        assertEq(BRIDGER.balance, BOND, "the bond came back");
        _assertBondGone();
    }

    function test_chaos_c5_bridgerForfeit_lockBackToTheAd_bondToTheFeePool() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _disputedAgentLock(2);
        _ruleAndFinalize(p, h, Dispute.Outcome.BridgerForfeit);
        assertEq(adManager.availableLiquidity(AD), AD_FUNDS, "the lock is back in the ad");
        assertEq(adToken.balanceOf(BRIDGER), 0);
        assertEq(BRIDGER.balance, 0, "the losing filer's bond is kept");
        assertEq(feePool.balance, BOND, "by the fee pool");
        _assertBondGone();
    }

    function test_chaos_c5_makerForfeit_theRecipientIsPaidFromTheAd_bondBackToTheFiler() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _disputedAgentLock(3);
        _ruleAndFinalize(p, h, Dispute.Outcome.MakerForfeit);
        assertEq(adToken.balanceOf(BRIDGER), AMOUNT, "the bridger's recipient is paid the lock");
        assertEq(_adBalance(AD), AD_FUNDS - AMOUNT, "out of the account's ad");
        assertEq(adManager.availableLiquidity(AD), AD_FUNDS - AMOUNT);
        assertEq(BRIDGER.balance, BOND, "the vindicated filer's bond came back");
        _assertBondGone();
    }

    /// TradeProceeds comes only from evidence: the co-signed unlock settles the disputed order and the bond
    /// of a filer who disputed a settleable trade goes to the fee pool.
    function test_chaos_c5_tradeProceedsByEvidence_settles_bondToTheFeePool() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _disputedAgentLock(4);
        vm.prank(arbiter);
        vm.expectRevert(DisputeManager.DisputeManager__ArbiterCannotSettle.selector);
        dm.resolveDispute(h, Dispute.Outcome.TradeProceeds);

        adManager.unlock(p, TestField.fe("c5-evidence"), bytes32(uint256(1)), hex"", hex"");
        assertEq(uint8(statusOf(address(adManager), h)), uint8(IEscrow.Status.Filled));
        assertEq(adToken.balanceOf(BRIDGER), AMOUNT);
        assertEq(feePool.balance, BOND, "the bond went to the fee pool");
        assertEq(BRIDGER.balance, 0);
        assertFalse(dm.isDisputed(h), "the evidence closed the dispute");
        _assertBondGone();
    }

    /// The agent key has no hand in the dispute: it cannot file, answer or rule, and a finalize it sends
    /// pays by the ruling, never to itself. The account (the maker) still answers through its owner.
    function test_chaos_c5_theAgentCannotAnswerRuleOrProfitFromTheDispute() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _disputedAgentLock(5);

        // Through the account: the policy allows a lock and nothing else.
        _thiefRefused(
            address(adManager),
            abi.encodeCall(IAdManager.respondToDispute, (p, bytes32("agent"))),
            0,
            ProofBridgeAgentPolicy.Refusal.ActionNotAllowed
        );
        _thiefRefused(
            address(adManager),
            abi.encodeCall(IAdManager.dispute, (p, bytes32("agent"))),
            0,
            ProofBridgeAgentPolicy.Refusal.ActionNotAllowed
        );
        _thiefRefused(
            address(adManager),
            abi.encodeCall(IAdManager.finalizeDispute, (p)),
            0,
            ProofBridgeAgentPolicy.Refusal.ActionNotAllowed
        );
        // Directly: the agent key is neither party nor arbiter, and has no credit to claim.
        vm.startPrank(agent);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotAParty.selector, agent));
        adManager.respondToDispute(p, bytes32("agent"));
        vm.expectRevert(DisputeManager.DisputeManager__NotArbiter.selector);
        dm.resolveDispute(h, Dispute.Outcome.MutualRefund);
        vm.expectRevert(DisputeManager.DisputeManager__NothingToClaim.selector);
        dm.claim(agent);
        vm.stopPrank();

        _asOwner(address(adManager), abi.encodeCall(IAdManager.respondToDispute, (p, bytes32("maker"))));
        (,,,, bytes32 answer,,,,) = dm.disputes(h);
        assertEq(answer, bytes32("maker"), "the maker's answer, from the owner");

        vm.prank(arbiter);
        dm.resolveDispute(h, Dispute.Outcome.MakerForfeit);
        vm.warp(adManager.disputeFinalizesAt(p));
        vm.prank(agent);
        adManager.finalizeDispute(p);
        assertEq(adToken.balanceOf(BRIDGER), AMOUNT, "paid by the ruling");
        assertEq(adToken.balanceOf(agent), 0, "not to the key that sent it");
        assertEq(agent.balance, 0);
        _assertBondGone();
    }

    /*//////////////////////////////////////////////////////////////
                    C6 / C8: ONE DISPUTE, AND NONE ONCE SETTLED
    //////////////////////////////////////////////////////////////*/

    /// The other party's second filing is refused, as is a repeat: one bond is held, and paid out once.
    function test_chaos_c6_aSecondFilingIsRefused_oneBondHeldOnce() public {
        (IAdManager.OrderParams memory p, bytes32 h) = _disputedAgentLock(6);
        vm.deal(owner, BOND);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotDisputable.selector, h, IEscrow.Status.Disputed));
        account.execute{value: BOND}(
            address(adManager), BOND, abi.encodeCall(IAdManager.dispute, (p, bytes32("maker")))
        );
        vm.deal(BRIDGER, BOND);
        vm.prank(BRIDGER);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotDisputable.selector, h, IEscrow.Status.Disputed));
        adManager.dispute{value: BOND}(p, bytes32("again"));
        assertEq(_heldBond(), BOND, "one bond held");

        _ruleAndFinalize(p, h, Dispute.Outcome.MutualRefund);
        assertEq(BRIDGER.balance, 2 * BOND, "the held bond back once, the refused one never taken");
        assertEq(owner.balance, BOND, "the maker's refused filing took nothing");
        _assertBondGone();
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimable.selector, h, IEscrow.Status.Resolved));
        adManager.finalizeDispute(p);
    }

    /// A leg that already settled cannot be disputed, and no ruling exists to undo it.
    function test_chaos_c8_aSettledTradeCannotBeDisputedOrRuled() public {
        _wireDisputes();
        (IAdManager.OrderParams memory p, bytes32 h) = _agentLock(AMOUNT, 8);
        _settles(p, h, "c8");

        vm.deal(BRIDGER, BOND);
        vm.prank(BRIDGER);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotDisputable.selector, h, IEscrow.Status.Filled));
        adManager.dispute{value: BOND}(p, bytes32("too late"));
        vm.prank(arbiter);
        vm.expectRevert(abi.encodeWithSelector(DisputeManager.DisputeManager__NotDisputed.selector, h));
        dm.resolveDispute(h, Dispute.Outcome.MakerForfeit);
        vm.expectRevert(abi.encodeWithSelector(IEscrow.Escrow__NotClaimable.selector, h, IEscrow.Status.Filled));
        adManager.finalizeDispute(p);

        assertEq(adToken.balanceOf(BRIDGER), AMOUNT, "paid once");
        assertEq(BRIDGER.balance, BOND, "no bond taken");
        assertEq(uint8(statusOf(address(adManager), h)), uint8(IEscrow.Status.Filled));
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _agentLock(uint256 amount, uint256 salt) internal returns (IAdManager.OrderParams memory p, bytes32 h) {
        p = _order(AD, amount, salt);
        vm.prank(agent);
        h = abi.decode(account.executeAsAgent(address(adManager), _lock(p)), (bytes32));
        assertEq(h, _hash(p));
    }

    /// The agent key's call refused by the module with `reason`; the ad, its locks and the agent's bucket unmoved.
    function _thiefRefused(address target, bytes memory data, uint256 callIndex, ProofBridgeAgentPolicy.Refusal reason)
        internal
    {
        uint256 balance = _adBalance(AD);
        uint256 liquidity = adManager.availableLiquidity(AD);
        uint256 level = module.agentBucket(address(account), agentId, _b32(address(adToken))).level;
        vm.prank(agent);
        vm.expectRevert(
            abi.encodeWithSelector(ProofBridgeAgentPolicy.AgentPolicy__RefusedAtExecution.selector, callIndex, reason)
        );
        account.executeAsAgent(target, data);
        assertEq(_adBalance(AD), balance, "the ad's funds didn't move");
        assertEq(adManager.availableLiquidity(AD), liquidity, "the escrow never saw it");
        assertEq(module.agentBucket(address(account), agentId, _b32(address(adToken))).level, level, "not debited");
    }

    /// The co-signed unlock (root and proof mocked) pays the order's recipient exactly the lock, from the ad.
    function _settles(IAdManager.OrderParams memory p, bytes32 h, string memory label) internal {
        uint256 before = adToken.balanceOf(BRIDGER);
        uint256 balance = _adBalance(AD);
        adManager.unlock(p, TestField.fe(label), bytes32(uint256(1)), hex"", hex"");
        assertEq(uint8(statusOf(address(adManager), h)), uint8(IEscrow.Status.Filled), "settled");
        assertEq(adToken.balanceOf(BRIDGER), before + p.amount, "the order's recipient is paid");
        assertEq(_adBalance(AD), balance - p.amount, "out of the ad");
        assertEq(adToken.balanceOf(address(account)), 0, "nothing rests in the account");
    }

    function _wireDisputes() internal {
        dm = new DisputeManager(admin, adManager.i_wNativeToken());
        vm.startPrank(admin);
        dm.setEscrow(address(adManager), true);
        dm.setArbiter(arbiter);
        dm.setProtocolFeePool(feePool);
        dm.setDisputeParams(ORDER_CHAIN_ID, Dispute.Params(1 hours, BOND));
        adManager.setDisputeManager(IDisputeManager(address(dm)));
        vm.stopPrank();
    }

    /// The agent locks, then the bridger files against that lock.
    function _disputedAgentLock(uint256 salt) internal returns (IAdManager.OrderParams memory p, bytes32 h) {
        _wireDisputes();
        (p, h) = _agentLock(AMOUNT, salt);
        vm.deal(BRIDGER, BOND);
        vm.prank(BRIDGER);
        adManager.dispute{value: BOND}(p, bytes32("evidence"));
        assertEq(dm.initiatorOf(h), BRIDGER);
        assertEq(uint8(statusOf(address(adManager), h)), uint8(IEscrow.Status.Disputed));
    }

    function _ruleAndFinalize(IAdManager.OrderParams memory p, bytes32 h, Dispute.Outcome outcome) internal {
        vm.prank(arbiter);
        dm.resolveDispute(h, outcome);
        vm.warp(adManager.disputeFinalizesAt(p));
        adManager.finalizeDispute(p);
        assertEq(uint8(statusOf(address(adManager), h)), uint8(IEscrow.Status.Resolved));
    }

    function _assertBondGone() internal view {
        assertEq(_heldBond(), 0, "no bond left in the module");
        assertEq(address(dm).balance, 0);
        assertEq(adToken.balanceOf(address(account)), 0, "nothing rests in the account");
    }

    function _heldBond() internal view returns (uint256) {
        return IERC20(address(adManager.i_wNativeToken())).balanceOf(address(dm));
    }

    function _setRootVerifier(address v) internal {
        vm.prank(admin);
        adManager.setRootVerifier(ORDER_CHAIN_ID, v);
    }

    function _adBalance(string memory adId) internal view returns (uint256 balance) {
        (,,,,,,, balance,) = adManager.ads(adId);
    }

    /// The order hash this AdManager computes.
    function _hash(IAdManager.OrderParams memory p) internal view returns (bytes32) {
        return OrderHash.digest(
            OrderHash.Order({
                orderChainToken: p.orderChainToken,
                adChainToken: p.adChainToken,
                amount: p.amount,
                bridger: p.bridger,
                orderChainId: p.orderChainId,
                orderPortal: p.srcOrderPortal,
                orderRecipient: p.orderRecipient,
                adChainId: block.chainid,
                adManager: _b32(address(adManager)),
                adId: p.adId,
                adCreator: p.adCreator,
                adRecipient: p.adRecipient,
                salt: p.salt,
                orderDecimals: p.orderDecimals,
                adDecimals: p.adDecimals,
                deadline: p.deadline,
                adSettlementSigner: p.adSettlementSigner,
                lpFeeBps: p.lpFeeBps,
                protocolFeeBps: p.protocolFeeBps
            })
        );
    }
}
