// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {EscrowBase} from "./escrow/EscrowBase.sol";
import {IAdManager} from "./interfaces/IAdManager.sol";
import {IDisputeManager} from "./interfaces/IDisputeManager.sol";
import {IKeyRegistry} from "./interfaces/IKeyRegistry.sol";
import {IRootAnchor} from "./interfaces/IRootAnchor.sol";
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
 * @title AdManager (Proofbridge)
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice The maker's leg. Makers post liquidity ads, lock ad funds against EIP-712 orders, and
 *         bridgers unlock the lock on this chain with a proof of their deposit on the order chain.
 *         This leg is the termination primary (2.3e): the only place a clock runs. After the
 *         deadline anyone may claim a cancel, which opens the window `[deadline, deadline + buffer)`;
 *         the co-signed `unlock` (accepted until `deadline + buffer − margin`) or a `presentSettled`
 *         proof settles it; an unchallenged window releases the lock and records the CANCEL leaf the
 *         order leg refunds against; `recordSettled` appends the SETTLED leaf after a fill.
 *         Everything not specific to ads lives in {EscrowBase}.
 */
contract AdManager is EscrowBase, IAdManager {
    using AddressCast for address;
    using AddressCast for bytes32;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice The deposit proof's chain flag on the ad chain (not a leaf domain).
    uint256 private constant _PUBLIC_INPUT_SIDE_AD = 1;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice The BLS key registry consulted whenever an ad's settlement signer is set and at every
    ///         lock (2.3c D2). Admin-set; unset means those paths fail closed.
    IKeyRegistry public keyRegistry;

    /// @notice Ads by id. `maker == address(0)` means the id is free.
    mapping(string adId => Ad) public ads;

    /// @notice The maker's settlement halt (#422). While set, the co-signed `unlock` of every order
    ///         against every ad this maker owns is refused. Custody-authorized, instant both ways,
    ///         never pause-gated. Read by `unlock` and `finalizeCancel` only: every evidence path
    ///         ignores it, so a halt can delay a payout but never keep both sides.
    mapping(address maker => bool) public halted;

    /// @notice When `maker` last halted. `finalizeCancel` treats a halt at or after the claim opened
    ///         as a denied payout even if it was resumed since: the resume may have come after the
    ///         presentation cutoff, when it could no longer help the counterparty.
    mapping(address maker => uint64) public lastHaltedAt;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address admin, IVerifier verifier_, IMerkleManager merkleManager_, IwNativeToken wNativeToken_)
        EscrowBase(admin, verifier_, merkleManager_, wNativeToken_)
    {}

    /*//////////////////////////////////////////////////////////////
                                 ADMIN
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IAdManager
    function setKeyRegistry(IKeyRegistry registry) external onlyAdmin {
        if (address(registry) == address(0)) revert Escrow__ZeroAddress();
        keyRegistry = registry;
        emit KeyRegistrySet(address(registry));
    }

    /*//////////////////////////////////////////////////////////////
                           MAKER ACTIONS — ADS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IAdManager
    function createAd(
        string calldata adId,
        address adToken,
        uint256 initialAmount,
        uint256 orderChainId,
        bytes32 adRecipient,
        bytes32 settlementSigner
    ) external payable nonReentrant whenNotPaused {
        if (adToken == address(0)) revert AdManager__TokenZeroAddress();
        if (adRecipient == bytes32(0)) revert AdManager__RecipientZero();
        if (initialAmount == 0) revert Escrow__ZeroAmount();

        bytes32 routedOrderToken = tokenRoute[adToken][orderChainId];
        if (routedOrderToken == bytes32(0)) revert Escrow__ChainNotSupported(orderChainId);

        Ad storage ad = ads[adId];
        if (ad.maker != address(0)) revert AdManager__UsedAdId();
        _requireRegistered(settlementSigner);

        _pullFunds(adToken, initialAmount);

        ad.maker = msg.sender;
        ad.open = true;
        ad.token = adToken;
        ad.orderChainId = orderChainId;
        ad.adRecipient = adRecipient;
        ad.orderChainToken = routedOrderToken;
        ad.settlementSigner = settlementSigner;
        ad.balance = initialAmount;

        emit AdCreated(adId, msg.sender, adToken, initialAmount, orderChainId, settlementSigner);
    }

    /**
     * @inheritdoc IAdManager
     * @dev Custody-authorized, callable at any time — including with locks in flight (an open order
     *      settles against the signer frozen in its own hash, never against this field, design 01
     *      §1.5) and while paused: like the registry's retirement lever, an incident lever must not
     *      be freezable, and unpause re-enables locks in the same instant it would re-enable this.
     */
    function setSettlementSigner(string calldata adId, bytes32 identity) external nonReentrant {
        Ad storage ad = _getAdOwned(adId, msg.sender);
        _requireRegistered(identity);
        emit SettlementSignerSet(adId, ad.settlementSigner, identity);
        ad.settlementSigner = identity;
    }

    /// @inheritdoc IAdManager
    function fundAd(string calldata adId, uint256 amount) external payable nonReentrant whenNotPaused {
        Ad storage ad = _getAdOwned(adId, msg.sender);
        if (!ad.open) revert AdManager__AdClosed();
        if (amount == 0) revert Escrow__ZeroAmount();

        _pullFunds(ad.token, amount);

        ad.balance += amount;
        emit AdFunded(adId, msg.sender, amount, ad.balance);
    }

    /// @inheritdoc IAdManager
    function withdrawFromAd(string calldata adId, uint256 amount, address to) external nonReentrant whenNotPaused {
        Ad storage ad = _getAdOwned(adId, msg.sender);
        if (to == address(0)) revert AdManager__RecipientZero();
        if (amount == 0) revert Escrow__ZeroAmount();
        if (amount > ad.balance - ad.locked) revert Escrow__InsufficientLiquidity();

        ad.balance -= amount;
        _pushFunds(ad.token, to, amount);

        emit AdWithdrawn(adId, msg.sender, amount, ad.balance);
    }

    /**
     * @inheritdoc IAdManager
     * @dev Custody-authorized and never pause-gated, like `setSettlementSigner`: an incident lever
     *      must not be freezable. Idempotent, so a runbook that fires it twice is not an error; the
     *      stamp moves each time, which only ever lengthens a cancel's wait.
     */
    function haltSettlement() external nonReentrant {
        halted[msg.sender] = true;
        lastHaltedAt[msg.sender] = uint64(block.timestamp);
        emit SettlementHalted(msg.sender);
    }

    /// @inheritdoc IAdManager
    function resumeSettlement() external nonReentrant {
        if (!halted[msg.sender]) revert AdManager__NotHalted();
        halted[msg.sender] = false;
        emit SettlementResumed(msg.sender);
    }

    /// @inheritdoc IAdManager
    function closeAd(string calldata adId, address to) external nonReentrant whenNotPaused {
        Ad storage ad = _getAdOwned(adId, msg.sender);
        if (ad.locked != 0) revert AdManager__ActiveLocks();
        if (to == address(0)) revert AdManager__RecipientZero();

        uint256 remaining = ad.balance;
        ad.balance = 0;
        ad.open = false;
        if (remaining > 0) _pushFunds(ad.token, to, remaining);

        emit AdClosed(adId, msg.sender);
    }

    /// @inheritdoc IAdManager
    function lockForOrder(OrderParams calldata params) external nonReentrant whenNotPaused returns (bytes32 orderHash) {
        Ad storage ad = _getAdOwned(params.adId, msg.sender);
        orderHash = _validateOrder(ad, params);
        _requireMinWindow(params.orderChainId, params.deadline);

        // The signed amount is in order-chain units; the pool accounts in ad-chain units.
        uint256 adAmount = _adAmount(params);
        if (adAmount > ad.balance - ad.locked) revert Escrow__InsufficientLiquidity();

        _openOrder(orderHash);
        ad.locked += adAmount;
        // 2.3c D1: count the settlement identity this escrow's unlock will verify — the ad's signer,
        // asserted equal to `params.adSettlementSigner` in `_validateOrder` (and owned by the maker
        // we authenticated). The custody address needs no counter: no unlock resolves its key. The
        // bridger is counted by the OrderPortal that authenticated them.
        _countIn(params.adSettlementSigner);
        // The lock is consumed on the order side: its leaf carries the ORDER domain.
        _appendLeaf(orderHash, LeafDomain.ORDER);

        emit OrderLocked(params.adId, orderHash, ad.maker, ad.token, adAmount, params.bridger, params.orderRecipient);
    }

    /*//////////////////////////////////////////////////////////////
                     BRIDGER ACTION — UNLOCK WITH PROOF
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IAdManager
    function unlock(
        OrderParams calldata params,
        bytes32 nullifierHash,
        bytes32 targetRoot,
        bytes calldata proof,
        bytes calldata cosigData
    ) external nonReentrant whenNotPaused {
        bytes32 orderHash = _hashOrder(params, block.chainid, address(this));
        // D2: the co-signed unlock is the presentation — valid through the window, minus the margin.
        _requireNotPast(_presentationCutoff(orderHash, params));
        _requireSettleable(orderHash, nullifierHash);
        // #422: the maker's halt refuses the co-signed payout; evidence (`presentSettled`) still pays.
        // One cold read of the maker's flag on the metered path (~2.4k; UnlockGas re-baselined).
        address maker = ads[params.adId].maker;
        if (halted[maker]) revert AdManager__Halted(maker);
        // Gate 2 — root authenticity (the co-signed root); mandatory, reverts NoRootVerifier when unwired.
        _requireRootValid(
            params.orderChainId,
            targetRoot,
            RequestAuth.rootEnvelope(params.adSettlementSigner, params.bridger, cosigData)
        );
        _requireDepositProof(orderHash, nullifierHash, targetRoot, proof, _PUBLIC_INPUT_SIDE_AD);

        // A co-signed unlock is evidence too (D5), and `_requireSettleable` admits `Disputed`, so
        // this path can terminate a disputed order and must close its dispute like any other.
        _closeDisputeByEvidence(
            orderHash, Dispute.Outcome.TradeProceeds, _disputeFiler(orderHash) != ads[params.adId].maker
        );
        _settle(orderHash, nullifierHash, params.adSettlementSigner);
        _payFromAd(params);

        emit OrderUnlocked(orderHash, params.orderRecipient, nullifierHash);
    }

    /*//////////////////////////////////////////////////////////////
                        TERMINATION — THE PRIMARY (2.3e)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IAdManager
    function claimCancel(OrderParams calldata params) external nonReentrant whenNotPaused {
        bytes32 orderHash = _hashOrder(params, block.chainid, address(this));
        _requireStatus(orderHash, Status.Open);
        _requireReached(params.deadline);
        // Deadline-anchored (D1): a late claim cannot shorten the window the fast unlock relies on;
        // a pause that fell inside the window already extended it (`_windowEnd`).
        _openClaim(
            orderHash,
            Termination.ClaimEntry.Deadline,
            _windowEnd(orderHash, params.deadline, _timing(params.orderChainId).buffer)
        );
    }

    /// @inheritdoc IAdManager
    function finalizeCancel(OrderParams calldata params) external nonReentrant whenNotPaused {
        bytes32 orderHash = _hashOrder(params, block.chainid, address(this));
        _requireFinalizable(orderHash);
        // #422 rule 3: when the co-signed payout was denied while the window was open, the cancel
        // waits for the order chain's SETTLED evidence to be anchorable and presented, so a maker
        // paid on the other chain cannot also take the lock back.
        if (_coSignDenied(params, claims[orderHash].openedAt)) {
            _requireReached(_claimedWindowEnd(orderHash) + _evidenceGrace(params.orderChainId));
        }

        Ad storage ad = ads[params.adId];
        uint256 adAmount = _adAmount(params);
        ad.locked -= adAmount;
        _cancel(orderHash, params.adSettlementSigner, false);
        _appendLeaf(orderHash, LeafDomain.CANCEL);

        emit LockCancelled(params.adId, orderHash, adAmount);
    }

    /*//////////////////////////////////////////////////////////////
                              DISPUTES (2.3g)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IAdManager
    function dispute(OrderParams calldata params, bytes32 evidence) external payable nonReentrant whenNotPaused {
        bytes32 orderHash = _hashOrder(params, block.chainid, address(this));
        // Only the order's two parties may file. Without this any address could dispute any live
        // order and, one short challenge period later, cancel it out from under both of them.
        _requireParty(ads[params.adId].maker, params.orderRecipient.toAddressChecked());
        // The amount is validated by the hash the caller had to reproduce, which is why filing
        // starts here and not on the module: only this contract can vouch for it.
        _openDispute(
            orderHash,
            _adAmount(params),
            params.orderChainId,
            evidence,
            uint64(params.deadline),
            _timing(params.orderChainId).buffer
        );
    }

    /// @inheritdoc IAdManager
    function respondToDispute(OrderParams calldata params, bytes32 evidence) external nonReentrant whenNotPaused {
        bytes32 orderHash = _hashOrder(params, block.chainid, address(this));
        _requireStatus(orderHash, Status.Disputed);
        address responder =
            _requireResponder(orderHash, ads[params.adId].maker, params.orderRecipient.toAddressChecked());
        _disputeManager().recordResponse(orderHash, responder, evidence);
    }

    /// @inheritdoc IAdManager
    function finalizeDispute(OrderParams calldata params) external nonReentrant whenNotPaused {
        bytes32 orderHash = _hashOrder(params, block.chainid, address(this));
        _requireStatus(orderHash, Status.Disputed);

        (Dispute.Outcome outcome, bool windowOver, address initiator) =
            _disputeManager().outcomeOf(orderHash, pausedSeconds);
        if (!windowOver) revert Escrow__DisputeNotResolved(orderHash);
        // No ruling means the fallback: a mutual refund, the unified primitive's terminal (D4).
        if (outcome == Dispute.Outcome.None) outcome = Dispute.Outcome.MutualRefund;

        Ad storage ad = ads[params.adId];
        uint256 adAmount = _adAmount(params);
        ad.locked -= adAmount;
        if (outcome == Dispute.Outcome.MakerForfeit) {
            // The maker forfeits its stake: the locked amount leaves the ad for the order's
            // recipient. Every other vacuum outcome just releases the lock back to liquidity,
            // which the decrement above already did.
            ad.balance -= adAmount;
            _payOrCredit(params.orderRecipient.toAddressChecked(), ad.token, adAmount);
        }

        _resolve(orderHash, params.adSettlementSigner);
        // The flag is absolute: was this filed by the bridger? Filing is restricted to the order's
        // two parties, so on the ad leg "not the maker" is exactly "the bridger".
        _disputeManager().settleBond(orderHash, outcome, initiator != ad.maker);

        // Broadcast the outcome to the follower, which has no dispute of its own and acts only on
        // this leaf. CANCEL means "refund the bridger" and already did before 2.3g; FORFEIT is the
        // one outcome that asks the follower for something else, so it is the one that needs a
        // domain of its own. Appending CANCEL here for a forfeit — which is what the first build
        // did — hands the follower a proof of the opposite ruling.
        _appendLeaf(orderHash, outcome == Dispute.Outcome.BridgerForfeit ? LeafDomain.FORFEIT : LeafDomain.CANCEL);
        emit OrderCancelled(orderHash, false);
    }

    /*//////////////////////////////////////////////////////////////
                              DISPUTES (2.3g)
    //////////////////////////////////////////////////////////////*/

    /// @notice The dispute module (2.3g). This escrow reads it and applies its own half of the
    ///         outcome; the module never moves these funds. Unset means disputes are unavailable
    ///         here, which is a safe default rather than a broken one.
    /// @dev Lives on the primary, not on `EscrowBase`. The OrderPortal is the follower and has no
    ///      dispute of its own — giving it this field back is the first step of the mistake review
    ///      pass 1 found, so the type system is where that should be refused.
    IDisputeManager public disputeManager;

    /// @inheritdoc IAdManager
    function setDisputeManager(IDisputeManager manager) external onlyAdmin {
        if (address(manager) == address(0)) revert Escrow__ZeroAddress();
        disputeManager = manager;
        emit DisputeManagerSet(address(manager));
    }

    /// @dev The module, or `NoDisputeManager` — unset means disputes are unavailable here, which is
    ///      a safe default rather than a broken one.
    function _disputeManager() internal view returns (IDisputeManager m) {
        m = disputeManager;
        if (address(m) == address(0)) revert Escrow__NoDisputeManager();
    }

    /**
     * @dev `Open | Claimed → Disputed`, with the bond handed straight to the module.
     *
     *      Note the direction: the escrow calls the module and the module never calls back. An
     *      earlier draft gave the module a permissioned write so it could mark the status itself;
     *      it does not need one, because filing has to start here anyway — only this contract can
     *      hash an order and vouch for its amount, since a leg stores `{status, pausedAtOpen}` and
     *      nothing else. So the trust edge runs one way and carries no callback.
     */
    function _openDispute(
        bytes32 orderHash,
        uint256 amount,
        uint256 peerChainId,
        bytes32 evidence,
        uint64 deadline,
        uint64 buffer
    ) internal {
        Status s = _orders[orderHash].status;
        if (s != Status.Open && s != Status.Claimed) revert Escrow__NotDisputable(orderHash, s);

        // Order matters, and it is the cheap half of keeping the two contracts in step. The module
        // call is the fallible step — an unset route, an underfunded bond — so it runs *before* this
        // contract commits anything. A caller that ever swallowed its revert would then leave the
        // order `Open` with no record, which is merely a failed filing; writing the status first
        // would instead leave it `Disputed` with no record, which is an order nobody can finalize.
        // The invariant "Disputed here implies a record there" is what `Dispute.t.sol` asserts over
        // arbitrary call sequences; this ordering is what makes the bad direction unreachable.
        _disputeManager().openDispute{value: msg.value}(
            orderHash, amount, peerChainId, msg.sender, evidence, deadline, buffer, pausedSeconds
        );
        _orders[orderHash].status = Status.Disputed;
    }

    /// @dev The order's two parties, as this chain knows them: whoever it would pay. Filing and
    ///      responding are both restricted to them (D11), and that restriction is what makes
    ///      `filerIsBridger` provable rather than inferred — with only two possible filers, "not the
    ///      maker" and "is the bridger" are the same statement.
    ///
    ///      Note these are the *payout* addresses on this chain, not the cross-chain identities:
    ///      `adCreator` is who the maker is on the ad chain and need not be anything they control
    ///      here, so it cannot stand in for them on the order leg.
    function _requireParty(address maker, address bridger) internal view {
        if (msg.sender != maker && msg.sender != bridger) revert Escrow__NotAParty(msg.sender);
    }

    /// @dev The party that did not file. Reverts unless the caller is the other one.
    function _requireResponder(bytes32 orderHash, address maker, address bridger) internal view returns (address) {
        _requireParty(maker, bridger);
        return msg.sender;
    }

    /**
     * @dev Evidence terminated a disputed order, so the dispute is over whatever the arbiter
     *      thought. A no-op when nothing was disputed, so every path that admits `Disputed` can call
     *      it unconditionally — and every one of them must, or the bond has no exit at all: once the
     *      status leaves `Disputed`, `finalizeDispute` can never run again and the module would hold
     *      the bond forever.
     *
     *      `outcome` is what the path proved, not what anyone ruled: a settle is `TradeProceeds`, a
     *      cancel-refund is `MutualRefund`. Reading the record's ruling here would route the bond by
     *      a finding this evidence has just overturned.
     */
    function _closeDisputeByEvidence(bytes32 orderHash, Dispute.Outcome outcome, bool filerIsBridger) internal {
        IDisputeManager m = disputeManager;
        if (address(m) != address(0) && m.isDisputed(orderHash)) {
            m.settleBond(orderHash, outcome, filerIsBridger);
        }
    }

    /// @dev Who filed, or the zero address when nothing is disputed here. The escrows need it to
    ///      answer `filerIsBridger` on the evidence paths, where no ruling is involved.
    function _disputeFiler(bytes32 orderHash) internal view returns (address) {
        IDisputeManager m = disputeManager;
        if (address(m) == address(0)) return address(0);
        return m.initiatorOf(orderHash);
    }

    /// @dev `→ Resolved`: the dispute terminal. Mirrors {_cancel}'s bookkeeping — in particular it
    ///      clears `claims`, so "terminal implies no open claim" holds here too. A `Claimed` leg that
    ///      is then disputed and resolved would otherwise keep a live claim with a past `finalizeAt`,
    ///      which #345's conservation sweep and the relayer's projections both read.
    function _resolve(bytes32 orderHash, bytes32 account) internal {
        _orders[orderHash].status = Status.Resolved;
        delete claims[orderHash];
        _countOut(account);
    }

    /// @inheritdoc IAdManager
    function cancelNeverLocked(OrderParams calldata params) external nonReentrant whenNotPaused {
        bytes32 orderHash = _hashOrder(params, block.chainid, address(this));
        _requireStatus(orderHash, Status.None);
        _requireReached(params.deadline);
        // D5: a lock needs `deadline ≥ now + minWindow`, so past the deadline none can follow this.
        if (peerEscrow[params.orderChainId] == bytes32(0)) revert Escrow__ChainNotSupported(params.orderChainId);
        _timing(params.orderChainId);

        _orders[orderHash].status = Status.Cancelled;
        _appendLeaf(orderHash, LeafDomain.CANCEL);
        emit OrderCancelled(orderHash, false);
    }

    /// @inheritdoc IAdManager
    function recordSettled(OrderParams calldata params) external nonReentrant whenNotPaused {
        _recordSettled(_hashOrder(params, block.chainid, address(this)));
    }

    /// @inheritdoc IAdManager
    function presentSettled(OrderParams calldata params, bytes32 targetRoot, bytes calldata proof)
        external
        nonReentrant
        whenNotPaused
    {
        bytes32 orderHash = _hashOrder(params, block.chainid, address(this));
        _requirePresentable(orderHash);
        _requireAnchored(params.orderChainId, targetRoot);
        _requireEventProof(targetRoot, orderHash, proof, LeafDomain.SETTLED);

        // Evidence beats arbitration: if this order was disputed, that dispute is now over and the
        // bond settles on what the proof shows, not on whatever the arbiter had ruled.
        _closeDisputeByEvidence(
            orderHash, Dispute.Outcome.TradeProceeds, _disputeFiler(orderHash) != ads[params.adId].maker
        );
        _fill(orderHash, params.adSettlementSigner, true);
        _payFromAd(params);
    }

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IAdManager
    function availableLiquidity(string calldata adId) external view returns (uint256) {
        Ad storage ad = ads[adId];
        if (ad.maker == address(0)) return 0;
        return ad.balance - ad.locked;
    }

    /*//////////////////////////////////////////////////////////////
                              INTERNAL LOGIC
    //////////////////////////////////////////////////////////////*/

    /// @dev The canonical 17-field order from this leg's params plus the ad-chain context.
    function _hashOrder(OrderParams calldata p, uint256 adChainId, address dstAdManager)
        internal
        pure
        returns (bytes32)
    {
        OrderHash.Order memory o = OrderHash.Order({
            orderChainToken: p.orderChainToken,
            adChainToken: p.adChainToken,
            amount: p.amount,
            bridger: p.bridger,
            orderChainId: p.orderChainId,
            orderPortal: p.srcOrderPortal,
            orderRecipient: p.orderRecipient,
            adChainId: adChainId,
            adManager: dstAdManager.toBytes32(),
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

    /// @dev The signed amount in ad-chain units — what the lock reserved and the payout releases.
    function _adAmount(OrderParams calldata p) private pure returns (uint256) {
        return DecimalScaling.scale(p.amount, p.orderDecimals, p.adDecimals);
    }

    /// @dev Pay the bridger's recipient from the ad, in the units the lock reserved.
    function _payFromAd(OrderParams calldata p) private {
        Ad storage ad = ads[p.adId];
        uint256 adAmount = _adAmount(p);
        ad.balance -= adAmount;
        ad.locked -= adAmount;
        _payOrCredit(p.orderRecipient.toAddressChecked(), ad.token, adAmount);
    }

    /// @dev The last second the co-signed unlock is accepted (D2): the window's end minus the margin.
    ///      Once claimed the end is the claim's frozen `finalizeAt`, so an admin retiming cannot move
    ///      the cutoff across it.
    function _presentationCutoff(bytes32 orderHash, OrderParams calldata p) private view returns (uint256) {
        RouteTiming.Timing storage t = _timing(p.orderChainId);
        return _windowEnd(orderHash, p.deadline, t.buffer) - t.margin;
    }

    /// @dev The registry gate on every settlement-signer set and on every lock (2.3c D2): fails
    ///      closed with no registry, refuses the zero identity, and refuses an account with no live,
    ///      unexpired key on this chain.
    function _requireRegistered(bytes32 signer) private view {
        if (address(keyRegistry) == address(0)) revert AdManager__NoKeyRegistry();
        if (signer == bytes32(0)) revert AdManager__SettlementSignerZero();
        if (!keyRegistry.hasUsableSlot(signer)) revert AdManager__SignerNotRegistered(signer);
    }

    /// @dev Was this order's co-signed payout denied by a maker-side lever while its window was open:
    ///      a halt in force, a halt at or after the claim opened (resumed since or not), or the order's
    ///      settlement signer left with no usable registry slot (a full retirement, lever 2; a rotation
    ///      keeps a usable slot and does not count). No registry wired means no lever 2 to read.
    function _coSignDenied(OrderParams calldata p, uint64 claimOpenedAt) private view returns (bool) {
        address maker = ads[p.adId].maker;
        if (halted[maker] || lastHaltedAt[maker] >= claimOpenedAt) return true;
        IKeyRegistry registry = keyRegistry;
        return address(registry) != address(0) && !registry.hasUsableSlot(p.adSettlementSigner);
    }

    /// @dev How long a denied order's cancel waits past its window: the order chain's anchor delay
    ///      (the floor before a SETTLED root from there is usable here) plus the route's buffer (the
    ///      allowance the route already gives a presenter for anchor cadence and submission). With no
    ///      anchor wired there is no evidence path either; the buffer alone then bounds the wait.
    function _evidenceGrace(uint256 orderChainId) private view returns (uint256) {
        IRootAnchor anchor = rootAnchor;
        uint256 delay = address(anchor) == address(0) ? 0 : anchor.anchorDelay(orderChainId);
        return delay + _timing(orderChainId).buffer;
    }

    /// @dev Load an ad and assert `maker` owns it.
    function _getAdOwned(string calldata adId, address maker) private view returns (Ad storage ad) {
        ad = ads[adId];
        if (ad.maker == address(0)) revert AdManager__AdNotFound();
        if (ad.maker != maker) revert AdManager__NotMaker();
    }

    /// @dev Every lock-time rule, cheapest first; the cross-contract registry read last.
    function _validateOrder(Ad storage ad, OrderParams calldata params) private view returns (bytes32 orderHash) {
        if (!ad.open) revert AdManager__AdClosed();
        if (params.amount == 0) revert Escrow__ZeroAmount();
        if (params.bridger == bytes32(0)) revert AdManager__BridgerZero();
        if (params.orderRecipient == bytes32(0)) revert AdManager__RecipientZero();
        params.orderRecipient.assertEvmAddress();
        DecimalScaling.assertInRange(params.orderDecimals);
        DecimalScaling.assertInRange(params.adDecimals);

        // The peer OrderPortal named in the order must be the one wired for that chain.
        bytes32 peer = peerEscrow[params.orderChainId];
        if (peer == bytes32(0)) revert Escrow__ChainNotSupported(params.orderChainId);
        if (peer != params.srcOrderPortal) revert AdManager__OrderPortalMismatch(peer, params.srcOrderPortal);

        // The ad serves exactly one chain and one route, committed at creation and still live.
        if (params.orderChainId != ad.orderChainId) {
            revert AdManager__OrderChainMismatch(ad.orderChainId, params.orderChainId);
        }
        if (params.orderChainToken != ad.orderChainToken) {
            revert AdManager__RouteMismatch(ad.orderChainToken, params.orderChainToken);
        }
        bytes32 routed = tokenRoute[ad.token][params.orderChainId];
        if (routed == bytes32(0)) revert Escrow__MissingRoute(params.orderChainToken, params.orderChainId);
        if (routed != params.orderChainToken) revert Escrow__PeerTokenMismatch(routed, params.orderChainToken);

        // Identity: custody (adCreator == maker) and the settlement identity the ad declared (2.3c).
        // A lock naming any other signer is refused here, not left to the maker's account policy.
        if (params.adCreator != ad.maker.toBytes32()) revert AdManager__NotMaker();
        if (params.adSettlementSigner != ad.settlementSigner) {
            revert AdManager__SettlementSignerMismatch(ad.settlementSigner, params.adSettlementSigner);
        }
        if (params.adChainToken != ad.token.toBytes32()) {
            revert AdManager__AdTokenMismatch(ad.token.toBytes32(), params.adChainToken);
        }
        if (params.adRecipient != ad.adRecipient) {
            revert AdManager__AdRecipientMismatch(ad.adRecipient, params.adRecipient);
        }
        DecimalScaling.assertMatchesOnChain(ad.token, params.adDecimals);
        OrderHash.checkWidths(params.amount, params.orderChainId, block.chainid, params.deadline);

        // A key retired after the ad was pointed at it (setValidUntil, a watchtower retirement) must
        // not take new locks: the bridger's deposit could never be unlocked (2.3c D2).
        _requireRegistered(ad.settlementSigner);

        orderHash = _hashOrder(params, block.chainid, address(this));
    }
}
