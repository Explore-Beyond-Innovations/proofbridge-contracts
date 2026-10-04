// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IwNativeToken, SafeNativeToken} from "./wNativeToken.sol";
import {IDisputeManager, IEscrowPause} from "./interfaces/IDisputeManager.sol";
import {Dispute} from "./libraries/Dispute.sol";
import {TwoStepAdmin} from "./libraries/TwoStepAdmin.sol";

/**
 * @title DisputeManager (Proofbridge)
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice The dispute lifecycle for both escrows on a chain: the filing, the bond, the arbiter's
 *         ruling, the clock, and the fallback when nobody rules (2.3g).
 * @dev A module contract, the same shape as `RootAnchor`: the escrows *read* it and apply their own
 *      half of the outcome. It never moves their funds and never writes their state at all — the
 *      trust edge runs one way and carries no callback. An earlier draft gave it a permissioned
 *      `setDisputeOpen` write; it turned out not to need one, because filing has to start at the
 *      escrow anyway (only the escrow can hash an order and vouch for its amount), so the escrow
 *      sets its own status on the way through.
 *
 *      Three rules carry the design, and each is enforced somewhere below:
 *
 *      1. **Evidence beats arbitration.** A proof that the trade settled terminates a dispute
 *         immediately. The escrow's evidence paths accept `Disputed` and clear the record; nothing
 *         here can stop them, and no ruling survives one.
 *      2. **The arbiter rules only the vacuum.** {resolveDispute} refuses `TradeProceeds` under any
 *         input — that outcome is reachable by evidence alone.
 *      3. **A ruling opens a window; it does not pay.** Evidence inside that window overrides it.
 *
 *      Why one module for both escrows: the inline draft duplicated all five entry points across
 *      AdManager and OrderPortal, on both chains. One implementation means one outcome table to
 *      audit, one arbiter key, and one bond pot — and it is what returned AdManager's size margin.
 */
contract DisputeManager is IDisputeManager, TwoStepAdmin {
    using SafeNativeToken for IwNativeToken;
    using Dispute for mapping(uint256 => Dispute.Params);

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Bonds are wrapped native, held here and never co-mingled with an escrow's order funds.
    IwNativeToken public immutable i_wNativeToken;

    /// @notice The escrows allowed to open disputes and settle bonds. Set once per escrow by the admin.
    mapping(address escrow => bool) public isEscrow;

    /// @notice Per-peer-chain parameters (2.3g D1), validated at the write, fail-closed when unset.
    mapping(uint256 chainId => Dispute.Params) public disputeParams;

    /// @notice The open dispute per order.
    mapping(bytes32 orderHash => Dispute.Record) public disputes;

    /// @notice The escrow that opened each dispute — the only one allowed to finalize it.
    mapping(bytes32 orderHash => address) public disputeEscrow;

    /// @notice Where forfeited bonds are credited.
    address public protocolFeePool;

    /// @notice The only account that may rule. Never an agent key, and never the admin: an arbiter
    ///         must not be able to pause an escrow, re-route tokens or re-point the anchor, and
    ///         keeping it on this contract is what bounds its blast radius.
    address public arbiter;

    /// @notice Payouts that could not be pushed, claimable later. Mirrors the escrows' ledger so a
    ///         reverting recipient can never brick a resolution (D8).
    mapping(address recipient => uint256) public claimable;

    /*//////////////////////////////////////////////////////////////
                             EVENTS / ERRORS
    //////////////////////////////////////////////////////////////*/

    event EscrowSet(address indexed escrow, bool allowed);
    event DisputeParamsSet(uint256 indexed chainId, Dispute.Params params);
    event ArbiterSet(address indexed arbiter);
    event ProtocolFeePoolSet(address indexed pool);
    event DisputeFiled(
        bytes32 indexed orderHash, address indexed initiator, uint128 bond, uint64 challengeDeadline, bytes32 evidence
    );
    event DisputeResponded(bytes32 indexed orderHash, address indexed responder, bytes32 evidence);
    event DisputeRuled(bytes32 indexed orderHash, Dispute.Outcome outcome, uint64 finalizeAt);
    event DisputeClaimed(bytes32 indexed orderHash, uint64 finalizeAt);
    event BondRouted(bytes32 indexed orderHash, address indexed to, uint128 amount, bool returnedToFiler);
    event PayoutCredited(address indexed recipient, uint256 amount);
    /// @notice A credited bond payout left for `to` (`to == recipient` for `claim`). Named apart from
    ///         the escrows' `PayoutClaimed` so the two can never share a topic0 (49E-1).
    event BondClaimed(address indexed recipient, address indexed to, uint256 amount);

    error DisputeManager__NotEscrow();
    error DisputeManager__NotArbiter();
    error DisputeManager__ZeroAddress();
    error DisputeManager__DisputeExists(bytes32 orderHash);
    error DisputeManager__NotDisputed(bytes32 orderHash);
    error DisputeManager__ArbiterCannotSettle();
    /// @notice The bond must be paid exactly (C-17): a surplus is refused, not refunded.
    error DisputeManager__NativeAmountMismatch(uint256 sent, uint256 expected);
    /// @notice Plain native sends are refused; only the wrapped-native contract's unwraps land.
    error DisputeManager__NativeNotAccepted(address sender);
    error DisputeManager__ChallengeOpen(uint256 until);
    error DisputeManager__ChallengeClosed(uint256 since);
    error DisputeManager__AlreadyRuled(bytes32 orderHash);
    error DisputeManager__NotResponder();
    /// @notice D5: answers close with the challenge window, the instant the arbiter's ruling does.
    error DisputeManager__ResponseWindowClosed(uint256 since);
    /// @notice D5: the responder slot takes one answer; the first one stands.
    error DisputeManager__AlreadyResponded(bytes32 orderHash);
    /// @notice D5: an empty answer is refused, so "answered" is exactly "the slot is non-zero".
    error DisputeManager__ZeroResponse();
    error DisputeManager__NothingToClaim();

    modifier onlyEscrow() {
        if (!isEscrow[msg.sender]) revert DisputeManager__NotEscrow();
        _;
    }

    constructor(address admin, IwNativeToken wNativeToken_) {
        if (admin == address(0) || address(wNativeToken_) == address(0)) {
            revert DisputeManager__ZeroAddress();
        }
        _initAdmin(admin);
        i_wNativeToken = wNativeToken_;
    }

    /*//////////////////////////////////////////////////////////////
                                 ADMIN
    //////////////////////////////////////////////////////////////*/

    function setEscrow(address escrow, bool allowed) external onlyAdmin {
        if (escrow == address(0)) revert DisputeManager__ZeroAddress();
        isEscrow[escrow] = allowed;
        emit EscrowSet(escrow, allowed);
    }

    function setDisputeParams(uint256 chainId, Dispute.Params calldata params) external onlyAdmin {
        Dispute.validate(params);
        disputeParams[chainId] = params;
        emit DisputeParamsSet(chainId, params);
    }

    function setArbiter(address arbiter_) external onlyAdmin {
        if (arbiter_ == address(0)) revert DisputeManager__ZeroAddress();
        arbiter = arbiter_;
        emit ArbiterSet(arbiter_);
    }

    function setProtocolFeePool(address pool) external onlyAdmin {
        if (pool == address(0)) revert DisputeManager__ZeroAddress();
        protocolFeePool = pool;
        emit ProtocolFeePoolSet(pool);
    }

    /*//////////////////////////////////////////////////////////////
                           THE ESCROW-FACING EDGE
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IDisputeManager
    function openDispute(
        bytes32 orderHash,
        uint256 amount,
        uint256 peerChainId,
        address filer,
        bytes32 evidence,
        uint64 deadline,
        uint64 buffer,
        uint64 escrowPausedSeconds
    ) external payable onlyEscrow returns (uint128 bond) {
        if (disputes[orderHash].initiator != address(0)) {
            revert DisputeManager__DisputeExists(orderHash);
        }

        Dispute.Params storage p = disputeParams.load(peerChainId);
        uint256 required = Dispute.bondFor(amount, p);
        // Exact (C-17): an over- or under-paid bond is refused, so nothing is left to refund.
        if (msg.value != required) revert DisputeManager__NativeAmountMismatch(msg.value, required);
        bond = uint128(required);
        i_wNativeToken.safeDeposit(required);

        // The challenge period can be shorter than the order has left to run, so it is a floor on
        // how long the arbiter has, never a licence to finish early: no dispute path may complete
        // before the order's own `deadline + buffer` (D3, T-50). Without this a 1-hour challenge
        // period would let a dispute cancel an order with a week still on its clock.
        uint64 challengeDeadline = uint64(block.timestamp) + p.challengePeriod;
        uint64 floor_ = deadline + buffer;
        if (floor_ > challengeDeadline) challengeDeadline = floor_;

        disputes[orderHash] = Dispute.Record({
            initiator: filer,
            bond: bond,
            challengeDeadline: challengeDeadline,
            pausedAtOpen: escrowPausedSeconds,
            initiatorEvidence: evidence,
            responderEvidence: bytes32(0),
            ruling: Dispute.Outcome.None,
            orderDeadline: deadline,
            buffer: buffer
        });
        disputeEscrow[orderHash] = msg.sender;
        emit DisputeFiled(orderHash, filer, bond, challengeDeadline, evidence);
    }

    /// @inheritdoc IDisputeManager
    /// @dev Keyed on `disputeEscrow[orderHash]` rather than `isEscrow`, deliberately: an escrow
    ///      de-authorised during a rotation or an incident must still be able to close the disputes
    ///      it opened, or their bonds have no exit and no admin override to give them one.
    function settleBond(bytes32 orderHash, Dispute.Outcome outcome, bool filerIsBridger) external {
        if (disputeEscrow[orderHash] != msg.sender) revert DisputeManager__NotEscrow();
        Dispute.Record storage d = disputes[orderHash];
        if (d.initiator == address(0)) revert DisputeManager__NotDisputed(orderHash);

        uint128 bond = d.bond;
        address filer = d.initiator;
        delete disputes[orderHash];
        delete disputeEscrow[orderHash];

        if (bond != 0) {
            bool toFiler = Dispute.bondReturnsToFiler(outcome, filerIsBridger);
            address to = toFiler ? filer : protocolFeePool;
            // An unset fee pool must not strand the bond; the filer keeps it rather than this
            // contract holding it forever.
            if (to == address(0)) to = filer;
            _payOrCredit(to, bond);
            emit BondRouted(orderHash, to, bond, toFiler);
        }
    }

    /*//////////////////////////////////////////////////////////////
                             THE DISPUTE ITSELF
    //////////////////////////////////////////////////////////////*/

    /// @notice Record the counterparty's evidence hash. Moves no funds, posts no bond (D11). One
    ///         non-zero answer, before the effective challenge deadline (D5).
    /// @dev Escrow-only. Authenticating "an address that is not the filer" here would let any
    ///      passer-by overwrite the genuine counterparty's hash — the slot is single, not an append
    ///      — so the responder's identity has to come from the side that knows the order's parties,
    ///      the same way the amount does.
    function recordResponse(bytes32 orderHash, address responder, bytes32 evidence) external {
        if (disputeEscrow[orderHash] != msg.sender) revert DisputeManager__NotEscrow();
        Dispute.Record storage d = disputes[orderHash];
        if (d.initiator == address(0)) revert DisputeManager__NotDisputed(orderHash);
        if (responder == d.initiator) revert DisputeManager__NotResponder();
        if (evidence == bytes32(0)) revert DisputeManager__ZeroResponse();
        if (d.responderEvidence != bytes32(0)) revert DisputeManager__AlreadyResponded(orderHash);
        uint256 until_ = effectiveChallengeDeadline(orderHash);
        if (block.timestamp >= until_) revert DisputeManager__ResponseWindowClosed(until_);
        d.responderEvidence = evidence;
        emit DisputeResponded(orderHash, responder, evidence);
    }

    /**
     * @notice Rule the vacuum. Opens a presentation window; it does not pay (D3).
     * @dev `TradeProceeds` is refused under any input: that outcome is what evidence produces, and
     *      an arbiter reaching it would be arbitration overruling proof (D6).
     */
    function resolveDispute(bytes32 orderHash, Dispute.Outcome outcome) external {
        if (msg.sender != arbiter) revert DisputeManager__NotArbiter();
        if (outcome == Dispute.Outcome.TradeProceeds || outcome == Dispute.Outcome.None) {
            revert DisputeManager__ArbiterCannotSettle();
        }
        Dispute.Record storage d = _unwindowed(orderHash);
        uint256 until_ = effectiveChallengeDeadline(orderHash);
        if (block.timestamp >= until_) revert DisputeManager__ChallengeClosed(until_);

        // D3: a ruling opens a window, it does not pay. `max(now, deadline) + buffer` is what gives
        // the forfeited party room to present a settled-leaf proof and override it — a ruling issued
        // a second before the deadline must not become payable a second after it.
        //
        // Stored unadjusted: `effectiveChallengeDeadline` applies the escrow's paused seconds on
        // read, so writing an adjusted value back here would count the same pause twice.
        d.ruling = outcome;
        uint64 base = uint64(block.timestamp) > d.orderDeadline ? uint64(block.timestamp) : d.orderDeadline;
        uint64 finalizeAt = base + d.buffer;
        d.challengeDeadline = finalizeAt;
        emit DisputeRuled(orderHash, outcome, finalizeAt);
    }

    /// @notice Open the fallback window once the challenge period expired with no ruling (D4).
    /// @dev Permissionless: an unresolved dispute must not depend on the arbiter ever showing up.
    function claimDispute(bytes32 orderHash) external {
        Dispute.Record storage d = _unwindowed(orderHash);
        if (d.ruling != Dispute.Outcome.None) revert DisputeManager__AlreadyRuled(orderHash);
        uint256 until_ = effectiveChallengeDeadline(orderHash);
        if (block.timestamp < until_) revert DisputeManager__ChallengeOpen(until_);
        emit DisputeClaimed(orderHash, uint64(until_));
    }

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IDisputeManager
    function outcomeOf(bytes32 orderHash, uint64 escrowPausedSeconds)
        external
        view
        returns (Dispute.Outcome outcome, bool windowOver, address initiator)
    {
        Dispute.Record storage d = disputes[orderHash];
        initiator = d.initiator;
        outcome = d.ruling;
        uint256 until_ = uint256(d.challengeDeadline) + (escrowPausedSeconds - d.pausedAtOpen);
        windowOver = initiator != address(0) && block.timestamp >= until_;
    }

    /// @notice The exact bond a filing on `peerChainId`'s route must carry for `amount` (49E-2): the
    ///         bond is exact (C-17), so clients quote it here instead of re-deriving the formula.
    ///         Reverts as the filing would when the route has no params.
    function bondFor(uint256 amount, uint256 peerChainId) external view returns (uint256) {
        return Dispute.bondFor(amount, disputeParams.load(peerChainId));
    }

    /// @inheritdoc IDisputeManager
    function initiatorOf(bytes32 orderHash) external view returns (address) {
        return disputes[orderHash].initiator;
    }

    /// @inheritdoc IDisputeManager
    function isDisputed(bytes32 orderHash) external view returns (bool) {
        return disputes[orderHash].initiator != address(0);
    }

    /**
     * @notice The challenge deadline in real time: the recorded one plus every second the *escrow*
     *         has been paused past the snapshot the filing carried — the order's own, from its
     *         lock, so the floor is the escrow's window end to the second (D10, c41-J).
     * @dev The escrow's counter, not one of this contract's own. A pause matters here for exactly
     *      one reason — it stops the parties presenting evidence — and presentation is gated by the
     *      escrow. A pause clock on this module would be a second, unrelated number that happened
     *      to be called the same thing, and would leave the real failure D10 describes unfixed: the
     *      escrow paused, nobody able to present, the challenge period running out regardless.
     */
    function effectiveChallengeDeadline(bytes32 orderHash) public view returns (uint256) {
        Dispute.Record storage d = disputes[orderHash];
        address escrow = disputeEscrow[orderHash];
        if (escrow == address(0)) return d.challengeDeadline;
        return uint256(d.challengeDeadline) + (IEscrowPause(escrow).pausedSeconds() - d.pausedAtOpen);
    }

    /// @notice Withdraw a credited bond payout to its recipient. Permissionless.
    function claim(address recipient) external {
        _payCredit(recipient, recipient);
    }

    /// @notice Withdraw the caller's own credit to `to` (C-16): for a recipient that refuses native.
    function claimTo(address to) external {
        if (to == address(0)) revert DisputeManager__ZeroAddress();
        _payCredit(msg.sender, to);
    }

    /*//////////////////////////////////////////////////////////////
                                INTERNAL
    //////////////////////////////////////////////////////////////*/

    function _payCredit(address recipient, address to) private {
        uint256 amount = claimable[recipient];
        if (amount == 0) revert DisputeManager__NothingToClaim();
        claimable[recipient] = 0;
        i_wNativeToken.safeWithdrawTo(amount, to);
        emit BondClaimed(recipient, to, amount);
    }

    function _unwindowed(bytes32 orderHash) private view returns (Dispute.Record storage d) {
        d = disputes[orderHash];
        if (d.initiator == address(0)) revert DisputeManager__NotDisputed(orderHash);
    }

    /// @notice The payout transfer, self-callable only so {_payOrCredit} can catch it.
    /// @dev Same shape as the escrows' `directPayout`: a `try` needs an external call to catch.
    function directPayout(address to, uint256 amount) external {
        if (msg.sender != address(this)) revert DisputeManager__NotEscrow();
        i_wNativeToken.safeWithdrawTo(amount, to);
    }

    /// @dev Best effort, then credit — a recipient that reverts cannot brick a resolution (D8).
    function _payOrCredit(address to, uint128 amount) private {
        try this.directPayout{gas: 150_000}(to, amount) {}
        catch {
            claimable[to] += amount;
            emit PayoutCredited(to, amount);
        }
    }

    /// @dev Only the wrapper's unwraps land here; a stray send would be stranded (C-17).
    receive() external payable {
        if (msg.sender != address(i_wNativeToken)) revert DisputeManager__NativeNotAccepted(msg.sender);
    }
}
