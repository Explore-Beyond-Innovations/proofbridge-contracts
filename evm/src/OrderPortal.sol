// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {EscrowBase} from "./escrow/EscrowBase.sol";
import {IOrderPortal} from "./interfaces/IOrderPortal.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";
import {IMerkleManager} from "./interfaces/IMerkleManager.sol";
import {IwNativeToken} from "./wNativeToken.sol";
import {AddressCast} from "./libraries/AddressCast.sol";
import {DecimalScaling} from "./libraries/DecimalScaling.sol";
import {LeafDomain} from "./libraries/LeafDomain.sol";
import {OrderHash} from "./libraries/OrderHash.sol";
import {RequestAuth} from "./libraries/RequestAuth.sol";
import {RouteTiming} from "./libraries/RouteTiming.sol";
import {Dispute} from "./libraries/Dispute.sol";
import {Termination} from "./libraries/Termination.sol";

/**
 * @title OrderPortal (Proofbridge)
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice The bridger's leg. Bridgers deposit `orderChainToken` against a maker's ad; the maker
 *         unlocks the deposit on this chain with a proof of their lock on the ad chain. This leg is
 *         the termination follower (2.3e): it refunds only against a proof of the ad leg's CANCEL
 *         leaf under an anchored root, never on a clock; the maker's co-signed `unlock` stops
 *         `claimStagger` before the deadline, in every state, so a cancel claim always leaves time
 *         to land it — the package proves the lock, not the outcome; and a far backstop
 *         (`deadline + longBackstop`) opens a window in which only outcome evidence counts (a
 *         settled-leaf proof pays the maker, a cancel-leaf proof refunds the bridger, silence
 *         refunds the bridger), never a bare refund;
 *         `recordSettled` appends the SETTLED leaf after a fill. Everything not specific to
 *         deposits lives in {EscrowBase}.
 */
contract OrderPortal is EscrowBase, IOrderPortal {
    using AddressCast for address;
    using AddressCast for bytes32;

    /// @notice The deposit proof's chain flag on the order chain (not a leaf domain).
    uint256 private constant _PUBLIC_INPUT_SIDE_ORDER = 0;

    constructor(address admin, IVerifier verifier_, IMerkleManager merkleManager_, IwNativeToken wNativeToken_)
        EscrowBase(admin, verifier_, merkleManager_, wNativeToken_)
    {}

    /*//////////////////////////////////////////////////////////////
                       BRIDGER ACTION — CREATE ORDER
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IOrderPortal
    function createOrder(OrderParams calldata params)
        external
        payable
        nonReentrant
        whenNotPaused
        returns (bytes32 orderHash)
    {
        orderHash = _validateOrder(params);
        _requireMinWindow(params.adChainId, params.deadline);
        _openOrder(orderHash);
        _pullFunds(params.orderChainToken.toAddressChecked(), params.amount);
        // The deposit is consumed on the ad side: its leaf carries the AD domain.
        _appendLeaf(orderHash, LeafDomain.AD);
        // 2.3c D1: count the party this escrow authenticated (the bridger, `msg.sender`); the maker
        // is counted by the AdManager that authenticated them.
        _countIn(params.bridger);

        emit OrderCreated(
            orderHash,
            msg.sender.toBytes32(),
            params.orderChainToken,
            params.amount,
            params.adChainId,
            params.adChainToken,
            params.adManager,
            params.adId,
            params.adCreator,
            params.adRecipient
        );
    }

    /*//////////////////////////////////////////////////////////////
                     MAKER ACTION — UNLOCK WITH PROOF
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IOrderPortal
    function unlock(
        OrderParams calldata params,
        bytes32 nullifierHash,
        bytes32 targetRoot,
        bytes calldata proof,
        bytes calldata cosigData
    ) external nonReentrant whenNotPaused {
        bytes32 orderHash = _hashOrder(params, block.chainid, address(this));
        // `Open` only: after the deadline the co-signed package says nothing about the ad leg's
        // outcome, so a backstop window (`Claimed`) never reopens it.
        if (nullifierUsed[nullifierHash]) revert Escrow__NullifierUsed(nullifierHash);
        if (_orders[orderHash].status != Status.Open) revert Escrow__OrderNotOpen(orderHash);
        // D2: stop `claimStagger` before the deadline so the maker's cancel claim on the ad chain
        // always leaves the watchtower time to land this leg.
        _requireNotPast(params.deadline - _timing(params.adChainId).claimStagger);
        // Gate 2 — root authenticity (the co-signed root); mandatory, reverts NoRootVerifier when unwired.
        _requireRootValid(
            params.adChainId, targetRoot, RequestAuth.rootEnvelope(params.adSettlementSigner, params.bridger, cosigData)
        );
        _requireDepositProof(orderHash, nullifierHash, targetRoot, proof, _PUBLIC_INPUT_SIDE_ORDER);

        _settle(orderHash, nullifierHash, params.bridger);
        _payMaker(params);

        emit OrderUnlocked(orderHash, params.adRecipient, nullifierHash);
    }

    /*//////////////////////////////////////////////////////////////
                        TERMINATION — THE FOLLOWER (2.3e)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IOrderPortal
    function refundByCancel(OrderParams calldata params, bytes32 targetRoot, bytes calldata proof)
        external
        nonReentrant
        whenNotPaused
    {
        bytes32 orderHash = _hashOrder(params, block.chainid, address(this));
        _requirePresentable(orderHash);
        _requireAnchored(params.adChainId, targetRoot);
        _requireEventProof(targetRoot, orderHash, proof, LeafDomain.CANCEL);
        // D4: no deadline read anywhere on this path.
        _cancel(orderHash, params.bridger, true);
        _refundBridger(orderHash, params);
    }

    /*//////////////////////////////////////////////////////////////
                              DISPUTES (2.3g)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IOrderPortal
    function dispute(OrderParams calldata params, bytes32 evidence) external payable nonReentrant whenNotPaused {
        bytes32 orderHash = _hashOrder(params, block.chainid, address(this));
        // The amount is vouched for by the hash the caller had to reproduce; the module cannot do
        // that itself, which is why filing starts here.
        _openDispute(orderHash, params.amount, params.adChainId, evidence);
    }

    /// @inheritdoc IOrderPortal
    function finalizeDispute(OrderParams calldata params) external nonReentrant whenNotPaused {
        bytes32 orderHash = _hashOrder(params, block.chainid, address(this));
        _requireStatus(orderHash, Status.Disputed);

        (Dispute.Outcome outcome, bool windowOver, address initiator) = _disputeManager().outcomeOf(orderHash);
        if (!windowOver) revert Escrow__DisputeNotResolved(orderHash);
        // No ruling means the fallback: a mutual refund (D4).
        if (outcome == Dispute.Outcome.None) outcome = Dispute.Outcome.MutualRefund;

        _orders[orderHash].status = Status.Resolved;
        _countOut(params.bridger);
        if (outcome == Dispute.Outcome.BridgerForfeit) {
            // The bridger forfeits its deposit: it goes to the maker's recipient on this chain.
            _payMaker(params);
        } else {
            // Mutual refund, or a ruling against the maker — either way the deposit goes home.
            _refundBridger(orderHash, params);
        }

        // The flag is absolute: was this filed by the bridger? This leg authenticates the bridger,
        // so that is an equality here and an inequality on the ad leg. Phrasing it relative to the
        // calling escrow inverted the routing on exactly one of the two.
        _disputeManager().settleBond(orderHash, initiator == params.bridger.toAddressChecked());
        emit OrderCancelled(orderHash, false);
    }

    /// @inheritdoc IOrderPortal
    function recordSettled(OrderParams calldata params) external nonReentrant whenNotPaused {
        _recordSettled(_hashOrder(params, block.chainid, address(this)));
    }

    /// @inheritdoc IOrderPortal
    function presentSettled(OrderParams calldata params, bytes32 targetRoot, bytes calldata proof)
        external
        nonReentrant
        whenNotPaused
    {
        bytes32 orderHash = _hashOrder(params, block.chainid, address(this));
        _requirePresentable(orderHash);
        _requireAnchored(params.adChainId, targetRoot);
        _requireEventProof(targetRoot, orderHash, proof, LeafDomain.SETTLED);

        _fill(orderHash, params.bridger, true);
        _payMaker(params);
    }

    /// @inheritdoc IOrderPortal
    function claimBackstop(OrderParams calldata params) external nonReentrant whenNotPaused {
        bytes32 orderHash = _hashOrder(params, block.chainid, address(this));
        _requireStatus(orderHash, Status.Open);
        RouteTiming.Timing storage t = _timing(params.adChainId);
        _requireReached(params.deadline + t.longBackstop);
        // Claim-anchored (D1): this clock starts days late; no evidence race straddles it.
        _openClaim(orderHash, Termination.ClaimEntry.Backstop, block.timestamp + t.buffer);
    }

    /// @inheritdoc IOrderPortal
    function finalizeBackstop(OrderParams calldata params) external nonReentrant whenNotPaused {
        bytes32 orderHash = _hashOrder(params, block.chainid, address(this));
        _requireFinalizable(orderHash);
        _cancel(orderHash, params.bridger, false);
        _refundBridger(orderHash, params);
    }

    /*//////////////////////////////////////////////////////////////
                              INTERNAL LOGIC
    //////////////////////////////////////////////////////////////*/

    /// @dev The canonical 17-field order from this leg's params plus the order-chain context.
    function _hashOrder(OrderParams calldata p, uint256 orderChainId, address orderPortal)
        internal
        pure
        returns (bytes32)
    {
        OrderHash.Order memory o = OrderHash.Order({
            orderChainToken: p.orderChainToken,
            adChainToken: p.adChainToken,
            amount: p.amount,
            bridger: p.bridger,
            orderChainId: orderChainId,
            orderPortal: orderPortal.toBytes32(),
            orderRecipient: p.orderRecipient,
            adChainId: p.adChainId,
            adManager: p.adManager,
            adId: p.adId,
            adCreator: p.adCreator,
            adRecipient: p.adRecipient,
            salt: p.salt,
            orderDecimals: p.orderDecimals,
            adDecimals: p.adDecimals,
            deadline: p.deadline,
            adSettlementSigner: p.adSettlementSigner
        });
        return OrderHash.digest(o);
    }

    /// @dev The maker's payout: the deposit, to the ad's recipient.
    function _payMaker(OrderParams calldata p) private {
        _payOrCredit(p.adRecipient.toAddressChecked(), p.orderChainToken.toAddressChecked(), p.amount);
    }

    /// @dev The bridger's refund: the deposit, back to them.
    function _refundBridger(bytes32 orderHash, OrderParams calldata p) private {
        _payOrCredit(p.bridger.toAddressChecked(), p.orderChainToken.toAddressChecked(), p.amount);
        emit OrderRefunded(orderHash, p.bridger, p.amount);
    }

    /// @dev Every create-time rule, cheapest first.
    function _validateOrder(OrderParams calldata params) private view returns (bytes32 orderHash) {
        if (params.amount == 0) revert Escrow__ZeroAmount();
        if (params.bridger != msg.sender.toBytes32()) revert OrderPortal__BridgerMustBeSender();
        if (params.adRecipient == bytes32(0)) revert Escrow__ZeroAddress();
        params.adRecipient.assertEvmAddress();
        OrderHash.checkWidths(params.amount, block.chainid, params.adChainId, params.deadline);
        // Both signed decimals are checked here so a bad route fails at create time, not at unlock.
        DecimalScaling.assertInRange(params.orderDecimals);
        DecimalScaling.assertInRange(params.adDecimals);

        // The peer AdManager named in the order must be the one wired for that chain.
        bytes32 peer = peerEscrow[params.adChainId];
        if (peer == bytes32(0)) revert Escrow__ChainNotSupported(params.adChainId);
        if (peer != params.adManager) revert OrderPortal__AdManagerMismatch(peer);

        // Routes key on the local ERC20 address; the order carries its 32-byte form.
        address orderTokenAddr = params.orderChainToken.toAddressChecked();
        bytes32 route = tokenRoute[orderTokenAddr][params.adChainId];
        if (route == bytes32(0)) revert Escrow__MissingRoute(params.adChainToken, params.adChainId);
        if (route != params.adChainToken) revert Escrow__PeerTokenMismatch(route, params.adChainToken);
        DecimalScaling.assertMatchesOnChain(orderTokenAddr, params.orderDecimals);

        orderHash = _hashOrder(params, block.chainid, address(this));
    }
}
