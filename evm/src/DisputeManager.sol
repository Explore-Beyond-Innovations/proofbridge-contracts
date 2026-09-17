// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IwNativeToken, SafeNativeToken} from "./wNativeToken.sol";
import {IDisputeManager} from "./interfaces/IDisputeManager.sol";
import {Dispute} from "./libraries/Dispute.sol";
import {TwoStepAdmin} from "./libraries/TwoStepAdmin.sol";

/**
 * @title DisputeManager (Proofbridge)
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice The dispute lifecycle for both escrows on a chain: the filing, the bond, the arbiter's
 *         ruling, the clock, and the fallback when nobody rules (2.3g).
 * @dev A module contract, the same shape as `RootAnchor`: the escrows *read* it and apply their own
 *      half of the outcome; it never moves their funds and never writes their state, except one
 *      narrow call — `setDisputeOpen` — because an order's status is read on the evidence hot path
 *      and so cannot become a cross-contract read.
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

    /// @notice The pause clock, so a challenge period does not expire while nobody can present.
    uint64 public pausedSeconds;

    /*//////////////////////////////////////////////////////////////
                             EVENTS / ERRORS
    //////////////////////////////////////////////////////////////*/

    event EscrowSet(address indexed escrow, bool allowed);
    event DisputeParamsSet(uint256 indexed chainId, Dispute.Params params);
    event ArbiterSet(address indexed arbiter);
    event ProtocolFeePoolSet(address indexed pool);
    event DisputeFiled(bytes32 indexed orderHash, address indexed initiator, uint128 bond, uint64 challengeDeadline);
    event DisputeResponded(bytes32 indexed orderHash, address indexed responder, bytes32 evidence);
    event DisputeRuled(bytes32 indexed orderHash, Dispute.Outcome outcome, uint64 finalizeAt);
    event DisputeClaimed(bytes32 indexed orderHash, uint64 finalizeAt);
    event BondRouted(bytes32 indexed orderHash, address indexed to, uint128 amount, bool returnedToFiler);
    event PayoutCredited(address indexed recipient, uint256 amount);

    error DisputeManager__NotEscrow();
    error DisputeManager__NotArbiter();
    error DisputeManager__ZeroAddress();
    error DisputeManager__DisputeExists(bytes32 orderHash);
    error DisputeManager__NotDisputed(bytes32 orderHash);
    error DisputeManager__ArbiterCannotSettle();
    error DisputeManager__BondTooSmall(uint256 required, uint256 provided);
    error DisputeManager__ChallengeOpen(uint256 until);
    error DisputeManager__ChallengeClosed(uint256 since);
    error DisputeManager__WindowOpen(bytes32 orderHash);
    error DisputeManager__NotResponder();
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
    function openDispute(bytes32 orderHash, uint256 amount, uint256 peerChainId, address filer, bytes32 evidence)
        external
        payable
        onlyEscrow
        returns (uint128 bond)
    {
        if (disputes[orderHash].initiator != address(0)) revert DisputeManager__DisputeExists(orderHash);

        Dispute.Params storage p = disputeParams.load(peerChainId);
        uint256 required = Dispute.bondFor(amount, p);
        if (msg.value < required) revert DisputeManager__BondTooSmall(required, msg.value);
        bond = uint128(required);
        i_wNativeToken.safeDeposit(required);

        uint64 challengeDeadline = uint64(block.timestamp) + p.challengePeriod;
        disputes[orderHash] = Dispute.Record({
            initiator: filer,
            bond: bond,
            challengeDeadline: challengeDeadline,
            pausedAtOpen: pausedSeconds,
            initiatorEvidence: evidence,
            responderEvidence: bytes32(0),
            ruling: Dispute.Outcome.None
        });
        disputeEscrow[orderHash] = msg.sender;
        emit DisputeFiled(orderHash, filer, bond, challengeDeadline);
    }

    /// @inheritdoc IDisputeManager
    function settleBond(bytes32 orderHash, bool filerWasCounterparty) external onlyEscrow {
        if (disputeEscrow[orderHash] != msg.sender) revert DisputeManager__NotEscrow();
        Dispute.Record storage d = disputes[orderHash];
        if (d.initiator == address(0)) revert DisputeManager__NotDisputed(orderHash);

        Dispute.Outcome outcome = d.ruling == Dispute.Outcome.None ? Dispute.Outcome.MutualRefund : d.ruling;
        uint128 bond = d.bond;
        address filer = d.initiator;
        delete disputes[orderHash];
        delete disputeEscrow[orderHash];

        if (bond != 0) {
            bool toFiler = Dispute.bondReturnsToFiler(outcome, filerWasCounterparty);
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

    /// @notice Record the counterparty's evidence hash. Moves no funds, posts no bond (D11).
    function respondToDispute(bytes32 orderHash, bytes32 evidence) external {
        Dispute.Record storage d = disputes[orderHash];
        if (d.initiator == address(0)) revert DisputeManager__NotDisputed(orderHash);
        if (msg.sender == d.initiator) revert DisputeManager__NotResponder();
        d.responderEvidence = evidence;
        emit DisputeResponded(orderHash, msg.sender, evidence);
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

        d.ruling = outcome;
        uint64 finalizeAt = uint64(until_);
        d.challengeDeadline = finalizeAt;
        emit DisputeRuled(orderHash, outcome, finalizeAt);
    }

    /// @notice Open the fallback window once the challenge period expired with no ruling (D4).
    /// @dev Permissionless: an unresolved dispute must not depend on the arbiter ever showing up.
    function claimDispute(bytes32 orderHash) external {
        Dispute.Record storage d = _unwindowed(orderHash);
        if (d.ruling != Dispute.Outcome.None) revert DisputeManager__WindowOpen(orderHash);
        uint256 until_ = effectiveChallengeDeadline(orderHash);
        if (block.timestamp < until_) revert DisputeManager__ChallengeOpen(until_);
        emit DisputeClaimed(orderHash, uint64(until_));
    }

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IDisputeManager
    function outcomeOf(bytes32 orderHash)
        external
        view
        returns (Dispute.Outcome outcome, bool windowOver, address initiator)
    {
        Dispute.Record storage d = disputes[orderHash];
        initiator = d.initiator;
        outcome = d.ruling;
        windowOver = initiator != address(0) && block.timestamp >= effectiveChallengeDeadline(orderHash);
    }

    /// @inheritdoc IDisputeManager
    function isDisputed(bytes32 orderHash) external view returns (bool) {
        return disputes[orderHash].initiator != address(0);
    }

    /// @notice The challenge deadline in real time: the recorded one plus every second this contract
    ///         has been paused since the dispute opened (D10).
    function effectiveChallengeDeadline(bytes32 orderHash) public view returns (uint256) {
        Dispute.Record storage d = disputes[orderHash];
        return uint256(d.challengeDeadline) + (pausedSeconds - d.pausedAtOpen);
    }

    /// @notice Withdraw a credited bond payout.
    function claim(address recipient) external {
        uint256 amount = claimable[recipient];
        if (amount == 0) revert DisputeManager__NothingToClaim();
        claimable[recipient] = 0;
        i_wNativeToken.safeWithdrawTo(amount, recipient);
    }

    /*//////////////////////////////////////////////////////////////
                                INTERNAL
    //////////////////////////////////////////////////////////////*/

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

    receive() external payable {}
}
