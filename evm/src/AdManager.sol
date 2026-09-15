// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {EscrowBase} from "./escrow/EscrowBase.sol";
import {IAdManager} from "./interfaces/IAdManager.sol";
import {IKeyRegistry} from "./interfaces/IKeyRegistry.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";
import {IMerkleManager} from "./interfaces/IMerkleManager.sol";
import {IwNativeToken} from "./wNativeToken.sol";
import {AddressCast} from "./libraries/AddressCast.sol";
import {DecimalScaling} from "./libraries/DecimalScaling.sol";
import {LeafDomain} from "./libraries/LeafDomain.sol";
import {OrderHash} from "./libraries/OrderHash.sol";
import {RequestAuth} from "./libraries/RequestAuth.sol";
import {RouteTiming} from "./libraries/RouteTiming.sol";
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
    function setKeyRegistry(IKeyRegistry registry) external onlyRole(ADMIN_ROLE) {
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
        // Gate 2 — root authenticity (the co-signed root); mandatory, reverts NoRootVerifier when unwired.
        _requireRootValid(
            params.orderChainId,
            targetRoot,
            RequestAuth.rootEnvelope(params.adSettlementSigner, params.bridger, cosigData)
        );
        _requireDepositProof(orderHash, nullifierHash, targetRoot, proof, _PUBLIC_INPUT_SIDE_AD);

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
        _requireFinalizable(orderHash, _timing(params.orderChainId).buffer);

        Ad storage ad = ads[params.adId];
        uint256 adAmount = _adAmount(params);
        ad.locked -= adAmount;
        _cancel(orderHash, params.adSettlementSigner, false);
        _appendLeaf(orderHash, LeafDomain.CANCEL);

        emit LockCancelled(params.adId, orderHash, adAmount);
    }

    /// @inheritdoc IAdManager
    function cancelNeverLocked(OrderParams calldata params) external nonReentrant whenNotPaused {
        bytes32 orderHash = _hashOrder(params, block.chainid, address(this));
        _requireStatus(orderHash, Status.None);
        _requireReached(params.deadline);
        // D5: a lock needs `deadline ≥ now + minWindow`, so past the deadline none can follow this.
        if (peerEscrow[params.orderChainId] == bytes32(0)) revert Escrow__ChainNotSupported(params.orderChainId);
        _timing(params.orderChainId);

        orders[orderHash] = Status.Cancelled;
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
