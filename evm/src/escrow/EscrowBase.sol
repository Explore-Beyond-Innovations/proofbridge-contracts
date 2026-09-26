// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {IEscrow} from "../interfaces/IEscrow.sol";
import {IVerifier} from "../interfaces/IVerifier.sol";
import {IMerkleManager} from "../interfaces/IMerkleManager.sol";
import {IRootAnchor} from "../interfaces/IRootAnchor.sol";
import {IDisputeManager} from "../interfaces/IDisputeManager.sol";
import {Dispute} from "../libraries/Dispute.sol";
import {IwNativeToken, SafeNativeToken} from "../wNativeToken.sol";
import {AddressCast} from "../libraries/AddressCast.sol";
import {LeafDomain} from "../libraries/LeafDomain.sol";
import {RequestAuth} from "../libraries/RequestAuth.sol";
import {RootVerifierRegistry} from "../libraries/RootVerifierRegistry.sol";
import {RouteTiming} from "../libraries/RouteTiming.sol";
import {Termination} from "../libraries/Termination.sol";
import {TwoStepAdmin} from "../libraries/TwoStepAdmin.sol";

/**
 * @title EscrowBase (Proofbridge)
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice Everything the two escrows share: the admin surface (pause, peers, routes, root
 *         verifiers), the order ledger (`orders`, `nullifierUsed`, `inFlightOf`), the pull-payment
 *         escrow (`claimable`), funds in/out for ERC20 and the native sentinel, the proof core an
 *         unlock runs, the termination primitive's shared half (route timing, the claim record, the
 *         anchored event proof, the terminal transitions), and the MMR seam. `AdManager` and
 *         `OrderPortal` add their own leg on top.
 * @dev Storage is laid out here first; the inheritors append. Immutables never touch storage.
 *
 *      Order state machine (2.3e), the same on both legs:
 *
 *        None ──lock/create──▶ Open ──claim*──▶ Claimed ──finalize*──▶ Cancelled
 *          │                    │                  │
 *          │                    └──unlock / presentSettled──┘──▶ Filled ──recordSettled──▶ (+ SETTLED leaf)
 *          └──cancelNeverLocked (primary only)──▶ Cancelled (+ CANCEL leaf)
 *
 *      `Filled` and `Cancelled` are terminal. Nothing terminal happens on a clock alone: a clock only
 *      opens a window, and evidence inside the window always wins over the refund after it — a pause
 *      included: a pause stops the clocks (`pausedSeconds`, measured from the leg's lock/create or
 *      from a backstop claim), so a window ends later by exactly the pause, and a window that had
 *      already closed stays closed. The
 *      SETTLED leaf is its own transaction on both chains so the relayer batches one shape,
 *      permissionless and single-shot. (Historically this said Soroban's per-tx budget forced it
 *      there; that was measured against the SDK harness default of 100M, not the network's 400M.
 *      The split stands on the shape argument, not the CPU one.)
 */
abstract contract EscrowBase is IEscrow, TwoStepAdmin, Pausable, ReentrancyGuardTransient, RootVerifierRegistry {
    using SafeERC20 for IERC20;
    using SafeNativeToken for IwNativeToken;
    using AddressCast for address;
    using AddressCast for bytes32;
    using RouteTiming for mapping(uint256 => RouteTiming.Timing);

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Gas forwarded to the best-effort payout attempt; a failure credits `claimable`.
    uint256 private constant _PAYOUT_GAS_LIMIT = 150_000;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IEscrow
    IVerifier public immutable i_verifier;
    /// @inheritdoc IEscrow
    IMerkleManager public immutable i_merkleManager;
    /// @inheritdoc IEscrow
    IwNativeToken public immutable i_wNativeToken;

    /// @notice Peer escrow per chain id (32-byte cross-chain id). Zero = chain not supported.
    mapping(uint256 chainId => bytes32 peer) public peerEscrow;

    /// @notice Token routes: local token → peer chain id → the peer chain's token id.
    mapping(address localToken => mapping(uint256 peerChainId => bytes32 peerToken)) public tokenRoute;

    /// @notice The order's leg by EIP-712 hash: status + the pause counter when it opened.
    mapping(bytes32 orderHash => Order) internal _orders;

    /// @notice Consumed nullifiers; one settlement proof per nullifier, protocol-wide.
    mapping(bytes32 nullifierHash => bool) public nullifierUsed;

    /// @notice Open legs per universal account id — the BLSKeyRegistry revoke guard's source.
    mapping(bytes32 account => uint256) public inFlightOf;

    /// @notice Payouts awaiting `claim`: recipient → token → amount.
    mapping(address recipient => mapping(address token => uint256)) public claimable;

    /// @notice Termination clocks per peer chain (2.3e D6). Unset (`buffer == 0`) fails closed.
    mapping(uint256 chainId => RouteTiming.Timing) public routeTiming;

    /// @notice The notary the evidence paths read (2.3e D7). Unset fails closed; settlement never reads it.
    IRootAnchor public rootAnchor;

    /// @notice The open presentation window per order, if any (`Claimed` ⇔ a record exists).
    mapping(bytes32 orderHash => Termination.Claim) public claims;

    /// @notice Whether the order's SETTLED leaf is in the MMR (`recordSettled`, once per fill).
    mapping(bytes32 orderHash => bool) public settledRecorded;

    /// @notice The pause clock: a pause freezes evidence, so it must not run the windows. Every
    ///         presentation window is measured in unpaused seconds — `pausedSeconds` accumulates at
    ///         each unpause, each leg snapshots it when it opens, and a window's real end moves by
    ///         exactly the pause time since that snapshot.
    uint64 public pausedSeconds;
    uint64 private _pausedAt;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address admin, IVerifier verifier_, IMerkleManager merkleManager_, IwNativeToken wNativeToken_) {
        if (
            admin == address(0) || address(verifier_) == address(0) || address(merkleManager_) == address(0)
                || address(wNativeToken_) == address(0)
        ) revert Escrow__ZeroAddress();
        _initAdmin(admin);
        i_verifier = verifier_;
        i_merkleManager = merkleManager_;
        i_wNativeToken = wNativeToken_;
    }

    /*//////////////////////////////////////////////////////////////
                                 ADMIN
    //////////////////////////////////////////////////////////////*/

    function pause() external onlyAdmin {
        _pause();
        _pausedAt = uint64(block.timestamp);
    }

    function unpause() external onlyAdmin {
        _unpause();
        pausedSeconds += uint64(block.timestamp) - _pausedAt;
    }

    /// @inheritdoc IEscrow
    function setPeerEscrow(uint256 chainId, bytes32 peer) external onlyAdmin {
        peerEscrow[chainId] = peer;
        emit PeerEscrowSet(chainId, peer);
    }

    /// @inheritdoc IEscrow
    function setRootVerifier(uint256 chainId, address verifier) external onlyAdmin {
        _setRootVerifier(chainId, verifier);
    }

    /// @inheritdoc IEscrow
    function setTokenRoute(address localToken, uint256 peerChainId, bytes32 peerToken) external onlyAdmin {
        if (localToken == address(0) || peerToken == bytes32(0)) revert Escrow__RouteZeroAddress();
        if (peerEscrow[peerChainId] == bytes32(0)) revert Escrow__ChainNotSupported(peerChainId);
        tokenRoute[localToken][peerChainId] = peerToken;
        emit TokenRouteSet(localToken, peerChainId, peerToken);
    }

    /// @inheritdoc IEscrow
    function removeTokenRoute(address localToken, uint256 peerChainId) external onlyAdmin {
        delete tokenRoute[localToken][peerChainId];
        emit TokenRouteRemoved(localToken, peerChainId);
    }

    /// @inheritdoc IEscrow
    function setRouteTiming(uint256 chainId, RouteTiming.Timing calldata timing) external onlyAdmin {
        RouteTiming.validate(timing);
        routeTiming[chainId] = timing;
        emit RouteTimingSet(chainId, timing);
    }

    /// @inheritdoc IEscrow
    function setRootAnchor(IRootAnchor anchor) external onlyAdmin {
        if (address(anchor) == address(0)) revert Escrow__ZeroAddress();
        rootAnchor = anchor;
        emit RootAnchorSet(address(anchor));
    }

    /*//////////////////////////////////////////////////////////////
                                PAYOUTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IEscrow
     * @dev Deliberately not `whenNotPaused`, and the only entry point here that is not.
     *
     *      A pause is the mass-incident brake: it stops orders moving while something is wrong. This
     *      call moves no order state and creates no credit — it hands an already-credited balance to
     *      the account that already owns it. Freezing it does not contain an incident, it only holds
     *      honest users' money hostage while one is investigated (2.3h D1, 03 F9).
     *
     *      `nonReentrant` stays, because this one does move funds.
     */
    function claim(address recipient, address token) external nonReentrant {
        uint256 amount = claimable[recipient][token];
        if (amount == 0) revert Escrow__NothingToClaim();
        claimable[recipient][token] = 0;
        _pushFunds(token, recipient, amount);
        emit PayoutClaimed(recipient, token, amount);
    }

    /// @notice The payout transfer, self-callable only so `_payOrCredit` can catch it.
    function directPayout(address recipient, address token, uint256 amount) external {
        if (msg.sender != address(this)) revert Escrow__SelfCallOnly();
        _pushFunds(token, recipient, amount);
    }

    /// @dev Best-effort push; any failure (reverting recipient, gas, blacklist) credits `claimable`
    ///      instead, so a recipient can never block settlement.
    function _payOrCredit(address recipient, address token, uint256 amount) internal {
        try this.directPayout{gas: _PAYOUT_GAS_LIMIT}(recipient, token, amount) {}
        catch {
            claimable[recipient][token] += amount;
            emit PayoutCredited(recipient, token, amount);
        }
    }

    /// @dev Take `amount` of `token` from the caller: native (exact `msg.value` wrapped) or ERC20.
    function _pullFunds(address token, uint256 amount) internal {
        if (token.isNative()) {
            if (msg.value < amount) revert Escrow__InsufficientLiquidity();
            i_wNativeToken.safeDeposit(amount);
        } else {
            if (msg.value != 0) revert Escrow__InsufficientLiquidity();
            IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        }
    }

    /// @dev Send `amount` of `token` to `to`: unwrap native, or ERC20 transfer.
    function _pushFunds(address token, address to, uint256 amount) internal {
        if (token.isNative()) {
            i_wNativeToken.safeWithdrawTo(amount, to);
        } else {
            IERC20(token).safeTransfer(to, amount);
        }
    }

    /*//////////////////////////////////////////////////////////////
                              ORDER LEDGER
    //////////////////////////////////////////////////////////////*/

    /// @dev `None → Open`, stamping the pause counter the leg's window is measured from; a second
    ///      lock/create of the same hash reverts.
    function _openOrder(bytes32 orderHash) internal {
        if (_orders[orderHash].status != Status.None) revert Escrow__OrderExists(orderHash);
        _orders[orderHash] = Order(Status.Open, pausedSeconds, uint64(block.timestamp));
    }

    /// @dev Append this leg's leaf to the chain's MMR under `domain` (a `LeafDomain` constant).
    function _appendLeaf(bytes32 orderHash, uint256 domain) internal {
        if (!i_merkleManager.appendOrderHash(orderHash, domain)) revert Escrow__MerkleManagerAppendFailed();
    }

    /// @dev One more open leg for `account`. Unchecked: bounded by gas long before 2^256.
    function _countIn(bytes32 account) internal {
        unchecked {
            inFlightOf[account]++;
        }
    }

    /// @dev One fewer open leg. Checked on purpose: an underflow here means the increments and
    ///      decrements no longer mirror, which must surface as a revert, never wrap.
    function _countOut(bytes32 account) internal {
        inFlightOf[account]--;
    }

    /// @dev The route's clocks, or `RouteTiming__NotSet` (the `NoRootVerifier` posture).
    function _timing(uint256 chainId) internal view returns (RouteTiming.Timing storage) {
        return routeTiming.load(chainId);
    }

    /// @dev `now + minWindow ≤ deadline ≤ now + MAX_ORDER_WINDOW` at every lock/create. The floor
    ///      (2.3e D5) makes `cancelNeverLocked`'s "no lock can follow the deadline" hold; the ceiling
    ///      (#453) keeps the order inside the key registry's memory of a dead slot.
    function _requireMinWindow(uint256 chainId, uint256 deadline) internal view {
        uint256 minAllowed = block.timestamp + _timing(chainId).minWindow;
        if (deadline < minAllowed) revert Escrow__DeadlineTooSoon(deadline, minAllowed);
        uint256 maxAllowed = block.timestamp + RouteTiming.MAX_ORDER_WINDOW;
        if (deadline > maxAllowed) revert Escrow__DeadlineTooFar(deadline, maxAllowed);
    }

    /// @dev Reverts unless `at` has been reached.
    function _requireReached(uint256 at) internal view {
        if (block.timestamp < at) revert Escrow__TooEarly(at);
    }

    /// @dev Reverts unless `cutoff` has not been passed (inclusive).
    function _requireNotPast(uint256 cutoff) internal view {
        if (block.timestamp > cutoff) revert Escrow__OrderExpired(cutoff);
    }

    /// @dev The leg is `Open`, in a presentation window, or disputed: evidence may still settle it.
    ///      `Disputed` belongs here because evidence beats arbitration at any time (2.3g D5) —
    ///      including while a ruling's own window runs, which is what makes a ruling overridable.
    function _requirePresentable(bytes32 orderHash) internal view {
        Status s = _orders[orderHash].status;
        if (s != Status.Open && s != Status.Claimed && s != Status.Disputed) {
            revert Escrow__NotClaimable(orderHash, s);
        }
    }

    /// @dev The leg must be exactly `expected` (`Open` before a claim, `None` before a never-locked cancel).
    function _requireStatus(bytes32 orderHash, Status expected) internal view {
        Status s = _orders[orderHash].status;
        if (s != expected) revert Escrow__NotClaimable(orderHash, s);
    }

    /*//////////////////////////////////////////////////////////////
                               PROOF CORE
    //////////////////////////////////////////////////////////////*/

    /// @dev Cheap gates first: the nullifier is fresh and the leg is still settleable (`Open`, or
    ///      `Claimed` — the co-signed unlock is the presentation, 2.3e D2).
    function _requireSettleable(bytes32 orderHash, bytes32 nullifierHash) internal view {
        if (nullifierUsed[nullifierHash]) revert Escrow__NullifierUsed(nullifierHash);
        Status s = _orders[orderHash].status;
        // `Disputed` too (2.3g D5): a co-signed unlock is evidence, and evidence beats arbitration.
        if (s != Status.Open && s != Status.Claimed && s != Status.Disputed) {
            revert Escrow__OrderNotOpen(orderHash);
        }
    }

    /// @dev Gate for the evidence paths: the root must be notarized by the wired anchor (2.3e D7).
    function _requireAnchored(uint256 chainId, bytes32 root) internal view {
        IRootAnchor a = rootAnchor;
        if (address(a) == address(0)) revert Escrow__NoRootAnchor();
        if (!a.isAnchored(chainId, root)) revert Escrow__RootNotAnchored(chainId, root);
    }

    /**
     * @dev The secret-free event proof: `[0, orderHash % p, root, domain]` through the same verifier
     *      as deposits. `domain` is a `LeafDomain` event constant fixed by the caller, never calldata.
     */
    function _requireEventProof(bytes32 targetRoot, bytes32 orderHash, bytes calldata proof, uint256 domain)
        internal
        view
    {
        if (!i_verifier.verify(proof, RequestAuth.buildEventInputs(targetRoot, orderHash, domain))) {
            revert Escrow__InvalidProof();
        }
    }

    /**
     * @dev The ZK deposit proof over `[nullifier, orderHash % p, root, side]`. Callers run
     *      `_requireRootValid` (gate 2, the co-signed root) first; kept as separate calls so an
     *      unlock's frame stays inside the EVM's 16-slot stack.
     * @param side The proof's chain flag (1 = ad chain, 0 = order chain).
     */
    function _requireDepositProof(
        bytes32 orderHash,
        bytes32 nullifierHash,
        bytes32 targetRoot,
        bytes calldata proof,
        uint256 side
    ) internal view {
        bytes32[] memory publicInputs = RequestAuth.buildPublicInputs(nullifierHash, targetRoot, orderHash, side);
        if (!i_verifier.verify(proof, publicInputs)) revert Escrow__InvalidProof();
    }

    /// @dev The state half of a co-signed settlement: consume the nullifier, then `_fill`.
    function _settle(bytes32 orderHash, bytes32 nullifierHash, bytes32 account) internal {
        nullifierUsed[nullifierHash] = true;
        _fill(orderHash, account, false);
    }

    /**
     * @dev `Open | Claimed → Filled`: the window, if any, closes; count out. The evidence path
     *      consumes no nullifier — the terminal status is its replay guard. The SETTLED leaf (2.3e
     *      D8) follows in `_recordSettled`, a separate transaction.
     */
    function _fill(bytes32 orderHash, bytes32 account, bool byEvidence) internal {
        _orders[orderHash].status = Status.Filled;
        delete claims[orderHash];
        _countOut(account);
        emit OrderSettled(orderHash, byEvidence);
    }

    /// @dev Append this leg's SETTLED leaf for a `Filled` order, once (D8): what lets the other
    ///      escrow's presenter prove this one paid. Permissionless; the caller only names the order.
    function _recordSettled(bytes32 orderHash) internal {
        if (_orders[orderHash].status != Status.Filled) revert Escrow__NotFilled(orderHash);
        if (settledRecorded[orderHash]) revert Escrow__SettledRecorded(orderHash);
        settledRecorded[orderHash] = true;
        _appendLeaf(orderHash, LeafDomain.SETTLED);
        emit SettledRecorded(orderHash);
    }

    /// @dev Open a presentation window on an `Open` leg; only a `finalize*` or evidence closes it.
    function _openClaim(bytes32 orderHash, Termination.ClaimEntry entry, uint256 finalizeAt) internal {
        claims[orderHash] = Termination.Claim(uint64(block.timestamp), uint64(finalizeAt), pausedSeconds, entry);
        _orders[orderHash].status = Status.Claimed;
        emit ClaimOpened(orderHash, entry, uint64(finalizeAt));
    }

    /**
     * @dev When the leg's presentation window ends, in real time. Once claimed: the claim's
     *      `finalizeAt` plus every second the escrow has been paused since the claim opened (the
     *      record's counter snapshot makes this exact across any number of pauses). Before a claim,
     *      the primary's deadline-anchored `deadline + buffer` plus every second paused since the leg
     *      was locked (its own snapshot; a pause before the deadline counts too — it froze both
     *      unlocks, and more time for evidence is the safe direction). A pause stops the clocks and
     *      never reopens a closed window: a pause after the end adds its length, but the clock moved
     *      on by the same length. One number serves both sides of the race: the unlock/presentation
     *      cutoff is this minus the margin, the finalize needs this reached.
     */
    function _windowEnd(bytes32 orderHash, uint256 deadline, uint64 buffer) internal view returns (uint256) {
        Order storage o = _orders[orderHash];
        if (o.status == Status.Claimed) return _claimedWindowEnd(orderHash);
        return deadline + buffer + (pausedSeconds - o.pausedAtOpen);
    }

    /// @dev When the leg opened on this chain (0 for a leg that never did).
    function _lockedAt(bytes32 orderHash) internal view returns (uint64) {
        return _orders[orderHash].lockedAt;
    }

    /// @dev The leg's status, for children that gate a view on it.
    function _statusOf(bytes32 orderHash) internal view returns (Status) {
        return _orders[orderHash].status;
    }

    /// @dev The claimed arm of {_windowEnd}, for callers that have already asserted `Claimed`.
    function _claimedWindowEnd(bytes32 orderHash) internal view returns (uint256) {
        Termination.Claim storage c = claims[orderHash];
        return uint256(c.finalizeAt) + (pausedSeconds - c.pausedAtOpen);
    }

    /// @dev The leg must be `Claimed` and its window over; returns nothing, the caller then `_cancel`s.
    ///      No route read: `validate` rejects a zero buffer and nothing ever clears `routeTiming`, so a
    ///      claim record is itself proof the route's clocks were set.
    function _requireFinalizable(bytes32 orderHash) internal view {
        if (_orders[orderHash].status != Status.Claimed) revert Escrow__NotClaimed(orderHash);
        _requireReached(_claimedWindowEnd(orderHash));
    }

    /// @dev `→ Cancelled`: close the window, count out. The leaf and the funds are the caller's.
    function _cancel(bytes32 orderHash, bytes32 account, bool byEvidence) internal {
        _orders[orderHash].status = Status.Cancelled;
        delete claims[orderHash];
        _countOut(account);
        emit OrderCancelled(orderHash, byEvidence);
    }

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IEscrow
    function orders(bytes32 orderHash) external view returns (Status) {
        return _orders[orderHash].status;
    }

    /// @inheritdoc IEscrow
    function orderPausedAtOpen(bytes32 orderHash) external view returns (uint64) {
        return _orders[orderHash].pausedAtOpen;
    }

    /// @inheritdoc IEscrow
    function hasOpenPositions(bytes32 account) external view returns (bool) {
        return inFlightOf[account] > 0;
    }

    /// @inheritdoc IEscrow
    function getHistoricalRoot(uint256 index) external view returns (bytes32) {
        return i_merkleManager.getRootAtIndex(index);
    }

    /// @inheritdoc IEscrow
    function getMerkleLeafCount() external view returns (uint256) {
        return i_merkleManager.getWidth();
    }

    /// @dev Native unwraps land here. No `fallback`: an unknown selector reverts instead of
    ///      silently accepting value (a mis-targeted call must fail loudly).
    receive() external payable {}
}
