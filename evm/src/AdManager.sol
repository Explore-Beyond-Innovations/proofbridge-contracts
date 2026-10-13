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
import {LeafDomain} from "./libraries/LeafDomain.sol";
import {OrderHash} from "./libraries/OrderHash.sol";
import {ProofBridgeUtils} from "./libraries/ProofBridgeUtils.sol";
import {RequestAuth} from "./libraries/RequestAuth.sol";
import {RouteTiming} from "./libraries/RouteTiming.sol";
import {Dispute} from "./libraries/Dispute.sol";

/**
 * @title AdManager (Proofbridge)
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice The maker's leg. Makers post liquidity ads, lock ad funds against EIP-712 orders, and
 *         bridgers unlock the lock on this chain with a proof of their deposit on the order chain.
 *         This leg is the termination primary (2.3e): the only place a clock runs. After the
 *         deadline anyone may claim a cancel, which opens the window `[deadline, deadline + buffer)`;
 *         the co-signed `unlock` (accepted before `deadline + buffer − margin`) or a `presentSettled`
 *         proof settles it; an unchallenged window releases the lock and records the CANCEL leaf the
 *         order leg refunds against; `recordSettled` appends the SETTLED leaf after a fill.
 *         Everything not specific to ads lives in {EscrowBase}.
 */
contract AdManager is EscrowBase, IAdManager {
    using AddressCast for address;
    using AddressCast for bytes32;
    using RouteTiming for mapping(uint256 => uint32);

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

    /// @notice #465: the key-registry history. `setKeyRegistry` opens epoch `registryEpoch` with the
    ///         new registry; a lock stamps the current epoch on the order, and its denied rule reads
    ///         `registryAt[that epoch]`, so a registry migration mid-order cannot erase a kill.
    uint32 public registryEpoch;
    mapping(uint32 epoch => IKeyRegistry) public registryAt;

    /// @notice Ads by id. `maker == address(0)` means the id is free.
    mapping(string adId => Ad) public ads;

    /// @notice The maker's settlement halt (#422). While set, the co-signed `unlock` of every order
    ///         against every ad this maker owns is refused. Custody-authorized, instant both ways,
    ///         never pause-gated. Read by `unlock`, by the cancel doors (`finalizeCancel`,
    ///         `finalizeDispute`) for their grace, and by `cancelFinalizesAt` / `disputeFinalizesAt`:
    ///         every evidence path ignores it, so a halt can delay a payout but never keep both sides.
    mapping(address maker => bool) public halted;

    /// @notice When `maker` last resumed. A halt in force at any point during an order's life is a
    ///         denied payout even if it was resumed since: either it is still in force, or this stamp
    ///         is at or after the order's lock (a halt from before the lock counts too: the lock never
    ///         reads `halted`). The lock time is stamped by the chain, so nothing the maker does later
    ///         moves the reference.
    mapping(address maker => uint64) public lastResumedAt;

    /// @inheritdoc IAdManager
    FeeConfig public feeConfig;

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
    function setKeyRegistry(IKeyRegistry registry) external timelocked {
        if (address(registry) == address(0)) revert Escrow__ZeroAddress();
        keyRegistry = registry;
        uint32 epoch = registryEpoch + 1;
        registryEpoch = epoch;
        registryAt[epoch] = registry;
        emit KeyRegistrySet(address(registry));
        emit KeyRegistryEpoch(epoch, address(registry));
    }

    /// @inheritdoc IAdManager
    function setProtocolFeePool(address pool) external timelocked {
        if (pool == address(0)) revert Escrow__ZeroAddress();
        feeConfig.pool = pool;
        emit ProtocolFeePoolSet(pool);
    }

    /// @inheritdoc IAdManager
    function setFeeBps(uint16 lpBps, uint16 protocolBps) external timelocked {
        ProofBridgeUtils.setFeeBps(feeConfig, lpBps, protocolBps);
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
        _requireRegistered(settlementSigner, msg.sender);

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
        _requireRegistered(identity, ad.maker);
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
    function withdrawFromAd(string calldata adId, uint256 amount, address to) external nonReentrant {
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
     *      must not be freezable. Idempotent, so a runbook that fires it twice is not an error.
     */
    function haltSettlement() external nonReentrant {
        halted[msg.sender] = true;
        emit SettlementHalted(msg.sender);
    }

    /// @inheritdoc IAdManager
    function resumeSettlement() external nonReentrant {
        if (!halted[msg.sender]) revert AdManager__NotHalted();
        halted[msg.sender] = false;
        lastResumedAt[msg.sender] = uint64(block.timestamp);
        emit SettlementResumed(msg.sender);
    }

    /// @inheritdoc IAdManager
    function closeAd(string calldata adId, address to) external nonReentrant {
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
    function lockForOrder(OrderParams calldata params, uint32 signerSlot)
        external
        nonReentrant
        whenNotPaused
        returns (bytes32 orderHash)
    {
        Ad storage ad = _getAdOwned(params.adId, msg.sender);
        orderHash = _validateOrder(ad, params, signerSlot);
        uint32 version = _requireMinWindow(params.orderChainId, params.deadline);
        // #464: no new order while the order chain's verifier reads another key registry.
        (bool split, address verifierRegistry) =
            ProofBridgeUtils.registrySplit(address(rootVerifier[params.orderChainId]), address(keyRegistry));
        if (split) revert AdManager__RegistrySplit(params.orderChainId, address(keyRegistry), verifierRegistry);

        // The signed amount is in order-chain units; the pool accounts in ad-chain units.
        uint256 adAmount = _adAmount(params);
        if (adAmount > ad.balance - ad.locked) revert Escrow__InsufficientLiquidity();

        Order storage o = _openOrder(orderHash, version);
        // #465: the registry this order is judged against, whatever is wired later.
        o.registryEpoch = registryEpoch;
        // Plan 12 C: the one slot the ad chain's co-signed unlock accepts, checked usable above.
        o.pinnedSlot = signerSlot;
        // The denied grace reads the larger of this and the live delay: a raise lengthens it, a cut never shortens it.
        o.anchorDelay = uint32(_anchorDelayNow(params.orderChainId));
        // The fee this order's payout charges: the bps live now, whatever is set later.
        o.lpFeeBps = feeConfig.lpBps;
        o.protocolFeeBps = feeConfig.protocolBps;
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
    ) external nonReentrant {
        bytes32 orderHash = _orderHash(params);
        // D2: the co-signed unlock is the presentation — valid before the window's end minus the
        // margin. Strict, so it never shares a second with `finalizeCancel` (which needs the end reached).
        {
            uint256 cutoff = _presentationCutoff(orderHash, params);
            if (block.timestamp >= cutoff) revert Escrow__OrderExpired(cutoff);
        }
        _requireSettleable(orderHash, nullifierHash);
        // #422: the maker's halt refuses the co-signed payout; evidence (`presentSettled`) still pays.
        // One cold read of the maker's flag on the metered path (~2.4k; UnlockGas re-baselined).
        address maker = _adOf(params).maker;
        if (halted[maker]) revert AdManager__Halted(maker);
        // Gate 2 — root authenticity (the co-signed root); mandatory, reverts NoRootVerifier when unwired.
        _requireRootValid(
            params.orderChainId,
            targetRoot,
            RequestAuth.rootEnvelope(
                params.adSettlementSigner,
                params.bridger,
                orderHash,
                _orders[orderHash].pinnedSlot, // plan 12 C: the one slot the ad leg accepts
                nullifierHash,
                uint8(_PUBLIC_INPUT_SIDE_AD),
                cosigData
            )
        );
        _requireDepositProof(orderHash, nullifierHash, targetRoot, proof, _PUBLIC_INPUT_SIDE_AD);

        // A co-signed unlock is evidence too (D5), and `_requireSettleable` admits `Disputed`, so
        // this path can terminate a disputed order and must close its dispute like any other.
        _closeDisputeByEvidence(params, orderHash, maker);
        _settle(orderHash, nullifierHash, params.adSettlementSigner);
        _payFromAd(params, orderHash);

        emit OrderUnlocked(orderHash, params.orderRecipient, nullifierHash);
    }

    /*//////////////////////////////////////////////////////////////
                        TERMINATION — THE PRIMARY (2.3e)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IAdManager
    function claimCancel(OrderParams calldata params) external nonReentrant {
        bytes32 orderHash = _orderHash(params);
        _requireStatus(orderHash, Status.Open);
        _requireReached(params.deadline);
        // Deadline-anchored (D1): a late claim cannot shorten the window the fast unlock relies on.
        _openClaim(orderHash, params.deadline + _orderTiming(orderHash, params.orderChainId).buffer);
    }

    /// @inheritdoc IAdManager
    function finalizeCancel(OrderParams calldata params) external nonReentrant {
        bytes32 orderHash = _orderHash(params);
        _requireFinalizable(orderHash);
        // #422 rule 3: when the co-signed payout was denied, the cancel waits for the order chain's
        // SETTLED evidence to be anchorable and presented, so a maker paid on the other chain cannot
        // also take the lock back.
        _requireReached(_finalizesAt(params, orderHash, Status.Claimed));

        Ad storage ad = _adOf(params);
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
    function dispute(OrderParams calldata params, bytes32 evidence) external payable nonReentrant {
        bytes32 orderHash = _orderHash(params);
        // Only the order's two parties may file. Without this any address could dispute any live
        // order and, one short challenge period later, cancel it out from under both of them.
        _requireParty(_adOf(params).maker, params.orderRecipient.toAddressChecked());
        // The deadline is validated by the hash the caller had to reproduce, which is why filing
        // starts here and not on the module: only this contract can vouch for it.
        _openDispute(
            orderHash,
            params.orderChainId,
            evidence,
            uint64(params.deadline),
            _orderTiming(orderHash, params.orderChainId).buffer,
            _adOf(params).token,
            _adAmount(params)
        );
    }

    /// @inheritdoc IAdManager
    function respondToDispute(OrderParams calldata params, bytes32 evidence) external nonReentrant {
        bytes32 orderHash = _orderHash(params);
        _requireStatus(orderHash, Status.Disputed);
        // Either party may call; the module refuses the filer, so only the other one gets through.
        _requireParty(_adOf(params).maker, params.orderRecipient.toAddressChecked());
        disputeModuleOf[orderHash].recordResponse(orderHash, msg.sender, evidence);
    }

    /// @inheritdoc IAdManager
    function finalizeDispute(OrderParams calldata params) external nonReentrant {
        bytes32 orderHash = _orderHash(params);
        _requireStatus(orderHash, Status.Disputed);
        // D5: the module the order was filed under, whatever is wired now.
        (IDisputeManager m, Dispute.Outcome outcome, bool windowOver, address initiator) = _disputeOf(orderHash);
        if (!windowOver) revert Escrow__DisputeNotResolved(orderHash);
        // No ruling means the fallback: a mutual refund, the unified primitive's terminal (D4).
        if (outcome == Dispute.Outcome.None) outcome = Dispute.Outcome.MutualRefund;
        // #422 rule 3, this door too: every outcome but MakerForfeit hands the lock back to the maker,
        // so a denied payout waits the evidence grace past the challenge deadline (review F1). The
        // clock from the module and outcome already in hand: one read, not three.
        _requireReached(_disputeEnd(params, orderHash, m, outcome));

        Ad storage ad = _adOf(params);
        uint256 adAmount = _adAmount(params);
        ad.locked -= adAmount;
        uint256 net;
        uint256 protocolFee;
        if (outcome == Dispute.Outcome.MakerForfeit) {
            // The maker forfeits its stake: the locked amount leaves the ad for the order's
            // recipient, less the fee, as a settlement would. Every other vacuum outcome just
            // releases the lock back to liquidity, which the decrement above already did.
            (net, protocolFee) = _chargeFee(ad, orderHash, adAmount);
        }

        _resolve(orderHash, params.adSettlementSigner);
        // The flag is absolute: was this filed by the bridger? Filing is restricted to the order's
        // two parties, so on the ad leg "not the maker" is exactly "the bridger".
        m.settleBond(orderHash, outcome, initiator != ad.maker, false);
        // Pay once the order and the dispute are closed, so the recipient's hook sees no mid-transition state.
        if (outcome == Dispute.Outcome.MakerForfeit) {
            _payNet(params.orderRecipient.toAddressChecked(), ad.token, net, protocolFee);
        }

        // Broadcast the outcome to the follower, which has no dispute of its own and acts only on
        // this leaf. CANCEL means "refund the bridger" and already did before 2.3g; FORFEIT is the
        // one outcome that asks the follower for something else, so it is the one that needs a
        // domain of its own. Appending CANCEL here for a forfeit — which is what the first build
        // did — hands the follower a proof of the opposite ruling.
        _appendLeaf(orderHash, outcome == Dispute.Outcome.BridgerForfeit ? LeafDomain.FORFEIT : LeafDomain.CANCEL);
        emit OrderCancelled(orderHash, false);
        emit DisputeFinalized(orderHash, outcome);
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

    /// @notice D5: the module each order's dispute was filed under. Every later read for the order
    ///         goes here, so `setDisputeManager` only affects new filings. Zero if never disputed.
    mapping(bytes32 orderHash => IDisputeManager) public disputeModuleOf;

    /// @inheritdoc IAdManager
    function setDisputeManager(IDisputeManager manager) external timelocked {
        if (address(manager) == address(0)) revert Escrow__ZeroAddress();
        disputeManager = manager;
        emit DisputeManagerSet(address(manager));
    }

    /**
     * @dev `Open | Claimed → Disputed`, with the bond handed straight to the module.
     *
     *      Note the direction: the escrow calls the module and the module never calls back. An
     *      earlier draft gave the module a permissioned write so it could mark the status itself;
     *      it does not need one, because filing has to start here anyway — only this contract can
     *      hash an order and vouch for its deadline, which the leg does not store. So the trust edge runs one way and carries no callback.
     */
    function _openDispute(
        bytes32 orderHash,
        uint256 peerChainId,
        bytes32 evidence,
        uint64 deadline,
        uint64 buffer,
        address token,
        uint256 amount
    ) internal {
        Order storage o = _orders[orderHash];
        if (o.status != Status.Open && o.status != Status.Claimed) revert Escrow__NotDisputable(orderHash, o.status);
        // D4: no filing once the primary's window closed (claimed window end once `Claimed`). The
        // window is `[deadline, windowEnd)`: its end belongs to `finalizeCancel` alone.
        uint256 windowEnd = _windowEnd(orderHash, deadline, buffer);
        if (block.timestamp >= windowEnd) revert Escrow__DisputeWindowClosed(orderHash, windowEnd);

        // Order matters, and it is the cheap half of keeping the two contracts in step. The module
        // call is the fallible step — an unset route, an underfunded bond — so it runs *before* this
        // contract commits anything. A caller that ever swallowed its revert would then leave the
        // order `Open` with no record, which is merely a failed filing; writing the status first
        // would instead leave it `Disputed` with no record, which is an order nobody can finalize.
        // The invariant "Disputed here implies a record there" is what `Dispute.t.sol` asserts over
        // arbitrary call sequences; this ordering is what makes the bad direction unreachable.
        IDisputeManager m = disputeManager;
        if (address(m) == address(0)) revert Escrow__NoDisputeManager();
        m.openDispute{value: msg.value}(orderHash, peerChainId, msg.sender, evidence, deadline, buffer, token, amount);
        disputeModuleOf[orderHash] = m;
        o.status = Status.Disputed;
        // A `Claimed` leg's window is over once disputed: nothing reads the claim again, so it goes now
        // rather than lingering as a live record with a `finalizeAt` that no longer means anything.
        delete claims[orderHash];
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

    /**
     * @dev Evidence terminated a disputed order, so the dispute is over whatever the arbiter
     *      thought. A no-op when nothing was disputed, so every path that admits `Disputed` can call
     *      it unconditionally — and every one of them must, or the bond has no exit at all: once the
     *      status leaves `Disputed`, `finalizeDispute` can never run again and the module would hold
     *      the bond forever.
     *
     *      Both callers settle the trade, so the bond routes on `TradeProceeds`: what the path
     *      proved, not what anyone ruled. Reads the order's own module (D5); a never-disputed order
     *      has none. `filerIsBridger` is "not the maker": only the two parties can file (D11).
     *      One exception: a bridger who filed while the maker denied the co-signed payout (the
     *      denial rule at the presentation cutoff) had reason to, so its bond comes back.
     */
    function _closeDisputeByEvidence(OrderParams calldata p, bytes32 orderHash, address maker) internal {
        // `Disputed` here implies an open record on the order's module (filing writes both).
        if (_orders[orderHash].status != Status.Disputed) return;
        IDisputeManager m = disputeModuleOf[orderHash];
        bool byBridger = m.initiatorOf(orderHash) != maker;
        m.settleBond(
            orderHash,
            Dispute.Outcome.TradeProceeds,
            byBridger,
            byBridger && _coSignDenied(p, orderHash, _presentationCutoff(orderHash, p))
        );
    }

    /// @dev `→ Resolved`: the dispute terminal. Only a `Disputed` leg resolves, and filing already
    ///      cleared its claim (`_openDispute`), so "terminal implies no open claim" holds here with
    ///      nothing to delete.
    function _resolve(bytes32 orderHash, bytes32 account) internal {
        _orders[orderHash].status = Status.Resolved;
        _countOut(account);
    }

    /// @inheritdoc IAdManager
    function cancelNeverLocked(
        OrderParams calldata params,
        bytes32 targetRoot,
        bytes32 nullifierHash,
        bytes calldata proof
    ) external nonReentrant {
        bytes32 orderHash = _orderHash(params);
        _requireStatus(orderHash, Status.None);
        _requireReached(params.deadline);
        // D5: a lock needs `deadline ≥ now + minWindow`, so past the deadline none can follow this.
        if (peerEscrow[params.orderChainId] == bytes32(0)) revert Escrow__ChainNotSupported(params.orderChainId);
        timingVersion.current(params.orderChainId);
        // The order is real: its AD leaf is in a notarized order-chain root. Nothing settles, so the
        // nullifier is not consumed; any secret proves the leaf.
        _requireAnchored(params.orderChainId, targetRoot);
        _requireDepositProof(orderHash, nullifierHash, targetRoot, proof, _PUBLIC_INPUT_SIDE_AD);

        _orders[orderHash].status = Status.Cancelled;
        _appendLeaf(orderHash, LeafDomain.CANCEL);
        emit OrderCancelled(orderHash, false);
    }

    /// @inheritdoc IAdManager
    /// @dev No `nonReentrant`: its only outside calls are registry views (STATICCALL), and it moves no funds.
    function repinOrder(OrderParams calldata params) external {
        bytes32 orderHash = _orderHash(params);
        // Q2: before the order leg's last co-signed unlock time; after it no new maker payout lands.
        ProofBridgeUtils.repin(
            _orders[orderHash],
            registryAt,
            _orderTiming(orderHash, params.orderChainId),
            params.adSettlementSigner,
            orderHash,
            params.deadline
        );
    }

    /// @inheritdoc IAdManager
    function recordSettled(OrderParams calldata params) external nonReentrant {
        _recordSettled(_orderHash(params));
    }

    /// @inheritdoc IAdManager
    function presentSettled(OrderParams calldata params, bytes32 targetRoot, bytes calldata proof)
        external
        nonReentrant
    {
        bytes32 orderHash = _orderHash(params);
        _requirePresentable(orderHash);
        _requireAnchored(params.orderChainId, targetRoot);
        _requireEventProof(targetRoot, orderHash, proof, LeafDomain.SETTLED);

        // Evidence beats arbitration: if this order was disputed, that dispute is now over and the
        // bond settles on what the proof shows, not on whatever the arbiter had ruled.
        _closeDisputeByEvidence(params, orderHash, _adOf(params).maker);
        _fill(orderHash, params.adSettlementSigner, true);
        _payFromAd(params, orderHash);
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
        return ProofBridgeUtils.adOrderHash(p, adChainId, dstAdManager);
    }

    /// @dev This escrow's hash of `p`: the ad-chain context is this chain and this contract.
    function _orderHash(OrderParams calldata p) private view returns (bytes32) {
        return _hashOrder(p, block.chainid, address(this));
    }

    /// @dev The order's ad: one keccak-of-calldata-string site instead of eight (EIP-170 margin).
    function _adOf(OrderParams calldata p) private view returns (Ad storage) {
        return ads[p.adId];
    }

    /// @dev The signed amount in ad-chain units — what the lock reserved and the payout releases.
    function _adAmount(OrderParams calldata p) private pure returns (uint256) {
        return ProofBridgeUtils.scale(p.amount, p.orderDecimals, p.adDecimals);
    }

    /// @dev Pay the bridger's recipient from the ad, in the units the lock reserved, less the fee.
    function _payFromAd(OrderParams calldata p, bytes32 orderHash) private {
        Ad storage ad = _adOf(p);
        uint256 adAmount = _adAmount(p);
        ad.locked -= adAmount;
        (uint256 net, uint256 protocolFee) = _chargeFee(ad, orderHash, adAmount);
        _payNet(p.orderRecipient.toAddressChecked(), ad.token, net, protocolFee);
    }

    /// @dev Take the order's fee (the bps it locked under) out of a released lock: the LP fee stays in
    ///      the ad's balance, the rest leaves it. Returns the recipient's net and the protocol's fee.
    function _chargeFee(Ad storage ad, bytes32 orderHash, uint256 adAmount)
        private
        returns (uint256 net, uint256 protocolFee)
    {
        return ProofBridgeUtils.chargeFee(ad, _orders[orderHash], orderHash, adAmount);
    }

    /// @dev The recipient's net, then the protocol's fee (never owed without a pool: `setFeeBps`).
    function _payNet(address recipient, address token, uint256 net, uint256 protocolFee) private {
        _payOrCredit(recipient, token, net);
        if (protocolFee != 0) _payOrCredit(feeConfig.pool, token, protocolFee);
    }

    /// @dev The first second the co-signed unlock is refused (D2): the window's end minus the margin,
    ///      both from the order's own timing version, so an admin retiming cannot move it. It is also
    ///      the inclusive `until` the denial rule passes to `anySlotExpiredWithin`, one second past the
    ///      last accepted second: a slot expiring exactly at the cutoff still counts as a denial. That
    ///      conservatism can only lengthen a maker's own refund (the evidence grace), never move a payout.
    function _presentationCutoff(bytes32 orderHash, OrderParams calldata p) private view returns (uint256) {
        RouteTiming.Timing storage t = _orderTiming(orderHash, p.orderChainId);
        return _windowEnd(orderHash, p.deadline, t.buffer) - t.margin;
    }

    /// @dev The registry gate on every settlement-signer set and on every lock (2.3c D2): fails
    ///      closed with no registry, refuses the zero identity, an account with no live, unexpired key
    ///      on this chain, and a signer other than the maker that has not approved the maker. The body
    ///      lives in the linked `ProofBridgeUtils` for EIP-170 headroom.
    function _requireRegistered(bytes32 signer, address maker) private view {
        ProofBridgeUtils.requireSettlementSigner(keyRegistry, signer, maker.toBytes32());
    }

    /// @dev Was this order's co-signed payout denied by a maker-side lever: the maker's halt in force
    ///      now or at any point since the lock (a resume stamp at or after `lockedAt`), the order
    ///      chain's root verifier unset (`unlock` reverts `NoRootVerifier`), a registry split, or the
    ///      order's pinned slot expiring at or before the payout's cutoff (`expiredAt`, plan 12 C: a
    ///      kill or a shorten of that slot counts; a rotation of any other slot does not, since no
    ///      other slot can co-sign the ad leg), or the pin moved by a re-pin (`repinOrder`: it refuses
    ///      every pair signed under the old pin, and the slot left behind may be dead, so the stamp
    ///      denies on its own). The lock refused a dead slot and a re-pin lands on a usable one, so
    ///      any expiry the rule sees is after the lock. Every reference is one the chain stamped or the caller derives from the
    ///      signed deadline, never one the maker can choose later. No registry wired means no lever 2.
    function _coSignDenied(OrderParams calldata p, bytes32 orderHash, uint256 until) private view returns (bool) {
        address maker = _adOf(p).maker;
        if (halted[maker] || lastResumedAt[maker] >= _lockedAt(orderHash)) return true;
        // An unwired verifier refuses every co-signed unlock, whoever unwired it: deny. So does a
        // verifier changed after the lock's second (unset, rewired or repointed): the gap it opened
        // in the co-signed path counts for the rest of the order's life, however it ended.
        // #465: the registry the order was locked under, not the live one: a migration mid-order would
        // otherwise read a registry that never saw the kill. #464: a verifier on another registry
        // co-signs against keys this one never sees: deny. D16: the payout's own cutoff (the
        // presentation cutoff for a cancel, the challenge deadline for a dispute) bounds the life.
        // Plan 12 C: only the pinned slot can co-sign the ad leg, and the lock refused a dead one, so
        // its own expiry is the one that counts; a re-pin counts on its own. The body lives in the
        // linked `ProofBridgeUtils`.
        Order storage o = _orders[orderHash];
        return ProofBridgeUtils.registryDenies(
            registryAt[o.registryEpoch],
            address(rootVerifier[p.orderChainId]),
            _rootVerifierChangedAt[p.orderChainId],
            p.adSettlementSigner,
            o,
            until
        );
    }

    /// @inheritdoc IAdManager
    function cancelFinalizesAt(OrderParams calldata params) external view returns (uint256) {
        return _finalizesAt(params, _orderHash(params), Status.Claimed);
    }

    /// @inheritdoc IAdManager
    function disputeFinalizesAt(OrderParams calldata params) external view returns (uint256) {
        return _finalizesAt(params, _orderHash(params), Status.Disputed);
    }

    /// @dev The one clock both finalize doors wait on and both views report: the cancel window's end
    ///      or the effective challenge deadline, plus the evidence grace when the co-signed payout was
    ///      denied (#422) and the outcome hands the lock back (all but MakerForfeit). 0 off `status`.
    function _finalizesAt(OrderParams calldata params, bytes32 orderHash, Status status)
        private
        view
        returns (uint256 end)
    {
        if (_statusOf(orderHash) != status) return 0;
        if (status == Status.Claimed) {
            end = claims[orderHash].finalizeAt;
            if (_coSignDenied(params, orderHash, _presentationCutoff(orderHash, params))) {
                end += _evidenceGrace(orderHash, params.orderChainId);
            }
        } else {
            (IDisputeManager m, Dispute.Outcome outcome,,) = _disputeOf(orderHash);
            end = _disputeEnd(params, orderHash, m, outcome);
        }
    }

    /// @dev The dispute half of `_finalizesAt`, for a caller that has already read the module and
    ///      the outcome (`finalizeDispute`): the effective challenge deadline, plus the grace unless
    ///      the ruling is MakerForfeit.
    function _disputeEnd(OrderParams calldata params, bytes32 orderHash, IDisputeManager m, Dispute.Outcome outcome)
        private
        view
        returns (uint256 end)
    {
        end = m.effectiveChallengeDeadline(orderHash);
        if (outcome == Dispute.Outcome.MakerForfeit) return end;
        if (_coSignDenied(params, orderHash, end)) end += _evidenceGrace(orderHash, params.orderChainId);
    }

    /// @dev The module the order was filed under (D5) and its verdict.
    function _disputeOf(bytes32 orderHash)
        private
        view
        returns (IDisputeManager m, Dispute.Outcome outcome, bool windowOver, address initiator)
    {
        m = disputeModuleOf[orderHash];
        (outcome, windowOver, initiator) = m.outcomeOf(orderHash);
    }

    /// @dev How long a denied order's cancel waits past its window: the order chain's anchor delay
    ///      (the floor before a SETTLED root from there is usable here) plus the order's buffer (the
    ///      allowance the route gave a presenter for anchor cadence and submission). The delay is the
    ///      larger of the one at the lock and the live one: raising it is the response to a suspected
    ///      forged anchor or an anchoring outage, so it lengthens every pending grace, and lowering it
    ///      shortens none. With no anchor wired the delay term is 0 and the buffer alone bounds the wait.
    function _evidenceGrace(bytes32 orderHash, uint256 orderChainId) private view returns (uint256) {
        uint256 delay = _anchorDelayNow(orderChainId);
        uint256 atLock = _orders[orderHash].anchorDelay;
        if (atLock > delay) delay = atLock;
        return delay + _orderTiming(orderHash, orderChainId).buffer;
    }

    /// @dev The order chain's live anchor delay; 0 with no anchor wired.
    function _anchorDelayNow(uint256 orderChainId) private view returns (uint256) {
        IRootAnchor anchor = rootAnchor;
        return address(anchor) == address(0) ? 0 : anchor.anchorDelay(orderChainId);
    }

    /// @dev Load an ad and assert `maker` owns it.
    function _getAdOwned(string calldata adId, address maker) private view returns (Ad storage ad) {
        ad = ads[adId];
        if (ad.maker == address(0)) revert AdManager__AdNotFound();
        if (ad.maker != maker) revert AdManager__NotMaker();
    }

    /// @dev Every lock-time rule, cheapest first; the cross-contract registry read last. The body
    ///      lives in the linked `ProofBridgeUtils` for EIP-170 headroom; the wired peer and route are
    ///      read here and handed over.
    function _validateOrder(Ad storage ad, OrderParams calldata params, uint32 signerSlot)
        private
        view
        returns (bytes32 orderHash)
    {
        ProofBridgeUtils.validateLock(
            ad,
            params,
            peerEscrow[params.orderChainId],
            tokenRoute[ad.token][params.orderChainId],
            keyRegistry,
            signerSlot
        );
        orderHash = _orderHash(params);
    }
}
