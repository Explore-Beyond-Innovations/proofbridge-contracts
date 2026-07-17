// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {IVerifier} from "./Verifier.sol";
import {IMerkleManager} from "./MerkleManager.sol";
import {IwNativeToken, SafeNativeToken} from "./wNativeToken.sol";
import {DecimalScaling} from "./libraries/DecimalScaling.sol";
import {OrderHash} from "./libraries/OrderHash.sol";
import {RequestAuth} from "./libraries/RequestAuth.sol";
import {AddressCast} from "./libraries/AddressCast.sol";
import {RootVerifierRegistry} from "./libraries/RootVerifierRegistry.sol";
import {TwoStepAdmin} from "./libraries/TwoStepAdmin.sol";

/**
 * @title AdManager (Proofbridge)
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice Makers (LPs) post/close liquidity ads, lock funds against EIP-712 orders,
 *         and bridgers unlock on this chain with a proof checked by an external verifier.
 */
contract AdManager is TwoStepAdmin, Pausable, ReentrancyGuardTransient, RootVerifierRegistry {
    using SafeERC20 for IERC20;
    using SafeNativeToken for IwNativeToken;
    using AddressCast for address;
    using AddressCast for bytes32;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Admin role identifier.
    bytes32 public constant ADMIN_ROLE = DEFAULT_ADMIN_ROLE;

    /// @notice Side flag for proof public inputs on the ad-chain side.
    uint256 private constant _PUBLIC_INPUT_SIDE_AD = 1;

    /// @notice Gas forwarded to the best-effort payout attempt in unlock.
    uint256 private constant _PAYOUT_GAS_LIMIT = 150_000;

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Source-chain configuration (where orders originate).
     * @param supported Whether orders from this chain are accepted.
     * @param orderPortal Counterpart OrderPortal id on the source chain (32-byte cross-chain representation).
     */
    struct ChainInfo {
        bool supported;
        bytes32 orderPortal;
    }

    /**
     * @notice Liquidity ad created by a maker on the ad chain (this chain).
     * @param orderChainId Source chain id this ad serves.
     * @param adRecipient Maker-controlled recipient id on the order chain (32-byte cross-chain representation).
     * @param maker Owner of the ad (local EVM address).
     * @param token ERC20 token escrowed for payouts on this chain.
     * @param balance Total token balance deposited into the ad.
     * @param locked Portion of {balance} currently reserved for open orders.
     * @param open Whether the ad is accepting new locks/funding.
     */
    struct Ad {
        uint256 orderChainId;
        bytes32 adRecipient;
        address maker;
        address token;
        uint256 balance;
        uint256 locked;
        bool open;
        bytes32 orderChainToken;
    }

    /**
     * @notice Parameters describing a cross-chain order to be locked/unlocked.
     * @dev All address-like fields are 32 bytes for cross-chain parity with
     *      chains (e.g. Stellar) whose native addresses are wider than 20 bytes.
     *      For EVM-local values, pass `bytes32(uint256(uint160(addr)))` — the low
     *      20 bytes are the EVM address and the top 12 must be zero.
     */
    struct OrderParams {
        bytes32 orderChainToken;
        bytes32 adChainToken;
        uint256 amount;
        bytes32 bridger;
        uint256 orderChainId;
        bytes32 srcOrderPortal;
        bytes32 orderRecipient;
        string adId;
        bytes32 adCreator;
        bytes32 adRecipient;
        uint256 salt;
        uint8 orderDecimals;
        uint8 adDecimals;
    }

    /// @notice Order lifecycle status.
    enum Status {
        None,
        Open,
        Filled
    }

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice External verifier used to validate zero-knowledge proofs.
    IVerifier public immutable i_verifier;

    /// @notice MerkleManager for chain
    IMerkleManager public immutable i_merkleManager;

    /// @notice Wrapped native token
    IwNativeToken public wNativeToken;

    /// @notice Source-chain configs.
    mapping(uint256 => ChainInfo) public chains;

    /// @notice Supported token routes: ad token (local address) → (orderChainId → Order token id as 32-byte cross-chain representation).
    mapping(address => mapping(uint256 => bytes32)) public tokenRoute;

    /// @notice Ads by id.
    mapping(string => Ad) public ads;

    /// @notice Order status by EIP-712 hash.
    mapping(bytes32 => Status) public orders;

    /// @notice Consumed nullifiers to prevent reuse across proofs.
    mapping(bytes32 => bool) public nullifierUsed;

    /// @notice Ad Ids mapping
    mapping(string => bool) public adIds;

    /// @notice Open (locked, not yet unlocked) orders per universal account id.
    mapping(bytes32 => uint256) public inFlightOf;

    /// @notice Unlocked payouts awaiting claim: recipient => token => amount.
    mapping(address => mapping(address => uint256)) public claimable;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Emitted when a source chain configuration is set/updated.
     */
    event ChainSet(uint256 indexed chainId, bytes32 indexed orderPortal, bool supported);

    /**
     * @notice Emitted when a token route is configured.
     */
    event TokenRouteSet(address indexed adToken, uint256 indexed orderChainId, bytes32 indexed orderChainToken);

    /**
     * @notice Emitted when a token route is removed.
     */
    event TokenRouteRemoved(address indexed adToken, bytes32 indexed orderChainToken, uint256 indexed orderChainId);

    /**
     * @notice Emitted when an ad is created.
     */
    event AdCreated(
        string indexed adId, address indexed maker, address indexed token, uint256 initAmount, uint256 orderChainId
    );

    /**
     * @notice Emitted when an ad is funded.
     */
    event AdFunded(string indexed adId, address indexed maker, uint256 amount, uint256 newBalance);

    /**
     * @notice Emitted when ad funds are withdrawn.
     */
    event AdWithdrawn(string indexed adId, address indexed maker, uint256 amount, uint256 newBalance);

    /**
     * @notice Emitted when an ad is closed.
     */
    event AdClosed(string indexed adId, address indexed maker);

    /**
     * @notice Emitted when liquidity is locked for an order.
     */
    event OrderLocked(
        string indexed adId,
        bytes32 indexed orderHash,
        address maker,
        address token,
        uint256 amount,
        bytes32 bridger,
        bytes32 recipient
    );

    /**
     * @notice Emitted when an order is unlocked by a valid proof.
     */
    event OrderUnlocked(bytes32 indexed orderHash, bytes32 indexed recipient, bytes32 nullifierHash);

    /**
     * @notice Emitted when an unlock credits a claimable payout.
     */
    event PayoutCredited(address indexed recipient, address indexed token, uint256 amount);

    /**
     * @notice Emitted when a payout is claimed.
     */
    event PayoutClaimed(address indexed recipient, address indexed token, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                                  ERRORS
    //////////////////////////////////////////////////////////////*/

    error AdManager__TokenZeroAddress();
    error AdManager__ZeroAmount();
    error AdManager__AdNotFound();
    error AdManager__NotMaker();
    error AdManager__AdClosed();
    error AdManager__InsufficientLiquidity();
    error AdManager__BridgerZero();
    error AdManager__RecipientZero();
    error Admanager__ActiveLocks();

    error AdManager__ChainNotSupported(uint256 chainId);
    error AdManager__OrderPortalMismatch(bytes32 expected, bytes32 provided);
    error AdManager__OrderChainMismatch(uint256 expected, uint256 provided);

    error AdManager__MissingRoute(bytes32 orderChainToken, uint256 adChainId);
    error AdManager__OrderTokenMismatch(bytes32 expected, bytes32 provided);
    error AdManager__AdTokenMismatch(bytes32 expected, bytes32 provided);
    error AdManager__AdRecipientMismatch(bytes32 expected, bytes32 provided);

    error AdManager__OrderExists(bytes32 orderHash);
    error AdManager__OrderNotOpen(bytes32 orderHash);
    error AdManager__NullifierUsed(bytes32 nullifierHash);
    error AdManager__InvalidProof();
    error AdManager__NothingToClaim();
    error AdManager__RouteMismatch(bytes32 committed, bytes32 offered);
    error AdManager__SelfCallOnly();
    error AdManager__ZeroAddress();

    error AdManager__MerkleManagerAppendFailed();
    error AdManager__UsedAdId();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Deploys the AdManager and assigns the admin and verifier.
     */
    constructor(address admin, IVerifier _verifier, IMerkleManager _merkleManager, IwNativeToken _wNativeToken) {
        if (
            admin == address(0) || address(_verifier) == address(0) || address(_merkleManager) == address(0)
                || address(_wNativeToken) == address(0)
        ) {
            revert AdManager__ZeroAddress();
        }
        _initAdmin(admin);
        i_verifier = _verifier;
        i_merkleManager = _merkleManager;
        wNativeToken = _wNativeToken;
    }

    /*//////////////////////////////////////////////////////////////
                              ADMIN: PAUSE
    //////////////////////////////////////////////////////////////*/

    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                              ADMIN: CHAINS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Add or update a source-chain configuration.
     */
    function setChain(uint256 orderChainId, bytes32 orderPortal, bool supported) external onlyRole(ADMIN_ROLE) {
        chains[orderChainId] = ChainInfo({supported: supported, orderPortal: orderPortal});
        emit ChainSet(orderChainId, orderPortal, supported);
    }

    /**
     * @notice Remove a source-chain configuration.
     */
    function removeChain(uint256 orderChainId) external onlyRole(ADMIN_ROLE) {
        delete chains[orderChainId];
        emit ChainSet(orderChainId, bytes32(0), false);
    }

    /**
     * @notice Set the root-verification module for a source chain.
     */
    function setRootVerifier(uint256 chainId, address verifier) external onlyRole(ADMIN_ROLE) {
        _setRootVerifier(chainId, verifier);
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN: TOKEN ROUTES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure a token route mapping from a source chain to this chain.
     */
    function setTokenRoute(address adToken, bytes32 orderToken, uint256 orderChainId) external onlyRole(ADMIN_ROLE) {
        if (orderToken == bytes32(0) || adToken == address(0)) revert AdManager__TokenZeroAddress();
        if (!chains[orderChainId].supported) revert AdManager__ChainNotSupported(orderChainId);
        tokenRoute[adToken][orderChainId] = orderToken;
        emit TokenRouteSet(adToken, orderChainId, orderToken);
    }

    /**
     * @notice Remove a token route mapping.
     */
    function removeTokenRoute(address adToken, uint256 orderChainId) external onlyRole(ADMIN_ROLE) {
        bytes32 orderToken = tokenRoute[adToken][orderChainId];
        delete tokenRoute[adToken][orderChainId];
        emit TokenRouteRemoved(adToken, orderToken, orderChainId);
    }

    /*//////////////////////////////////////////////////////////////
                           MAKER ACTIONS — ADS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a new liquidity ad to serve orders from `orderChainId`.
     */
    function createAd(
        string memory adId,
        address adToken,
        uint256 initialAmount,
        uint256 orderChainId,
        bytes32 adRecipient
    ) external payable nonReentrant whenNotPaused {
        if (adToken == address(0)) revert AdManager__TokenZeroAddress();
        if (adRecipient == bytes32(0)) revert AdManager__RecipientZero();
        if (initialAmount == 0) revert AdManager__ZeroAmount();

        bytes32 routedOrderToken = tokenRoute[adToken][orderChainId];

        if (routedOrderToken == bytes32(0)) {
            revert AdManager__ChainNotSupported(orderChainId);
        }

        if (adIds[adId]) revert AdManager__UsedAdId();

        if (adToken.isNative()) {
            if (msg.value < initialAmount) revert AdManager__InsufficientLiquidity();
            wNativeToken.safeDeposit(initialAmount);
        } else {
            IERC20(adToken).safeTransferFrom(msg.sender, address(this), initialAmount);
        }

        ads[adId] = Ad({
            orderChainId: orderChainId,
            adRecipient: adRecipient,
            maker: msg.sender,
            token: adToken,
            balance: initialAmount,
            locked: 0,
            open: true,
            orderChainToken: routedOrderToken
        });

        adIds[adId] = true;
        emit AdCreated(adId, msg.sender, adToken, initialAmount, orderChainId);
    }

    /**
     * @notice Fund an existing ad with `amount` of its ERC20 token.
     */
    function fundAd(string memory adId, uint256 amount) external payable nonReentrant whenNotPaused {
        Ad storage ad = __getAdOwned(adId, msg.sender);
        if (!ad.open) revert AdManager__AdClosed();
        if (amount == 0) revert AdManager__ZeroAmount();

        if (ad.token.isNative()) {
            if (msg.value < amount) revert AdManager__InsufficientLiquidity();
            wNativeToken.safeDeposit(amount);
        } else {
            IERC20(ad.token).safeTransferFrom(msg.sender, address(this), amount);
        }

        ad.balance += amount;
        emit AdFunded(adId, msg.sender, amount, ad.balance);
    }

    /**
     * @notice Withdraw unfrozen liquidity from an ad.
     */
    function withdrawFromAd(string memory adId, uint256 amount, address to) external nonReentrant whenNotPaused {
        Ad storage ad = __getAdOwned(adId, msg.sender);

        if (to == address(0)) revert AdManager__RecipientZero();
        if (amount == 0) revert AdManager__ZeroAmount();

        uint256 available = ad.balance - ad.locked;
        if (amount > available) revert AdManager__InsufficientLiquidity();

        ad.balance -= amount;

        if (ad.token.isNative()) {
            wNativeToken.safeWithdrawTo(amount, to);
        } else {
            IERC20(ad.token).safeTransfer(to, amount);
        }

        emit AdWithdrawn(adId, msg.sender, amount, ad.balance);
    }

    /**
     * @notice Close an ad and withdraw any remaining funds.
     */
    function closeAd(string memory adId, address to) external nonReentrant whenNotPaused {
        Ad storage ad = __getAdOwned(adId, msg.sender);
        if (ad.locked != 0) revert Admanager__ActiveLocks();
        if (to == address(0)) revert AdManager__RecipientZero();

        uint256 remaining = ad.balance;

        ad.balance = 0;
        ad.open = false;

        if (remaining > 0) {
            if (ad.token.isNative()) {
                wNativeToken.safeWithdrawTo(remaining, to);
            } else {
                IERC20(ad.token).safeTransfer(to, remaining);
            }
        }

        emit AdClosed(adId, msg.sender);
    }

    /**
     * @notice Reserve `params.amount` from `params.adId` to fulfill an order.
     */
    function lockForOrder(OrderParams calldata params) external nonReentrant whenNotPaused returns (bytes32 orderHash) {
        Ad storage ad = __getAdOwned(params.adId, msg.sender);

        orderHash = validateOrder(ad, params);

        // Convert signed `amount` (in orderDecimals) → ad-chain units for pool accounting.
        uint256 adAmount = DecimalScaling.scale(params.amount, params.orderDecimals, params.adDecimals);

        uint256 available = ad.balance - ad.locked;
        if (adAmount > available) revert AdManager__InsufficientLiquidity();

        if (orders[orderHash] != Status.None) revert AdManager__OrderExists(orderHash);

        ad.locked += adAmount;
        orders[orderHash] = Status.Open;
        inFlightOf[params.adCreator]++;
        inFlightOf[params.bridger]++;

        // locks are unlocked on the order side (ad_contract = 0), so bind the leaf with side 0
        if (!i_merkleManager.appendOrderHash(orderHash, 0)) revert AdManager__MerkleManagerAppendFailed();

        emit OrderLocked(params.adId, orderHash, ad.maker, ad.token, adAmount, params.bridger, params.orderRecipient);
    }

    /*//////////////////////////////////////////////////////////////
                     BRIDGER ACTION — UNLOCK WITH PROOF
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Unlock previously reserved funds after presenting a valid zk-proof.
     */
    function unlock(
        OrderParams calldata params,
        bytes32 nullifierHash,
        bytes32 targetRoot,
        bytes calldata proof,
        bytes calldata cosigData
    ) external nonReentrant whenNotPaused {
        bytes32 orderHash = _hashOrder(params, block.chainid, address(this));

        if (orders[orderHash] != Status.Open) revert AdManager__OrderNotOpen(orderHash);
        if (nullifierUsed[nullifierHash]) revert AdManager__NullifierUsed(nullifierHash);

        // Gate 2 — root authenticity. Mandatory: reverts with
        // NoRootVerifier when no module is configured for the source chain.
        _requireRootValid(params.orderChainId, targetRoot, abi.encode(params.adCreator, params.bridger, cosigData));

        bytes32[] memory publicInputs =
            RequestAuth.buildPublicInputs(i_merkleManager, nullifierHash, targetRoot, orderHash, _PUBLIC_INPUT_SIDE_AD);

        if (!i_verifier.verify(proof, publicInputs)) revert AdManager__InvalidProof();

        nullifierUsed[nullifierHash] = true;
        orders[orderHash] = Status.Filled;
        inFlightOf[params.adCreator]--;
        inFlightOf[params.bridger]--;

        // Pay recipient on this chain from the ad's escrowed token.
        // Scale to ad-chain units to match what was reserved in lockForOrder.
        Ad storage ad = ads[params.adId];
        uint256 adAmount = DecimalScaling.scale(params.amount, params.orderDecimals, params.adDecimals);
        ad.balance -= adAmount;
        ad.locked -= adAmount;

        address orderRecipientAddr = params.orderRecipient.toAddressChecked();
        _payOrCredit(orderRecipientAddr, ad.token, adAmount);

        emit OrderUnlocked(orderHash, params.orderRecipient, nullifierHash);
    }

    /**
     * @notice Pay out a credited unlock. Permissionless: funds can only go to
     *         the credited recipient.
     */
    function claim(address recipient, address token) external nonReentrant whenNotPaused {
        uint256 amount = claimable[recipient][token];
        if (amount == 0) revert AdManager__NothingToClaim();
        claimable[recipient][token] = 0;

        if (token.isNative()) {
            wNativeToken.safeWithdrawTo(amount, recipient);
        } else {
            IERC20(token).safeTransfer(recipient, amount);
        }
        emit PayoutClaimed(recipient, token, amount);
    }

    /**
     * @notice Best-effort direct transfer; on any failure the payout becomes
     *         claimable so a recipient can never block settlement.
     */
    function _payOrCredit(address recipient, address token, uint256 amount) private {
        try this.directPayout{gas: _PAYOUT_GAS_LIMIT}(recipient, token, amount) {}
        catch {
            claimable[recipient][token] += amount;
            emit PayoutCredited(recipient, token, amount);
        }
    }

    /**
     * @notice The payout transfer, self-callable only (makes it catchable).
     */
    function directPayout(address recipient, address token, uint256 amount) external {
        if (msg.sender != address(this)) revert AdManager__SelfCallOnly();

        if (token.isNative()) {
            wNativeToken.safeWithdrawTo(amount, recipient);
        } else {
            IERC20(token).safeTransfer(recipient, amount);
        }
    }

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice BLSKeyRegistry revoke guard: true while the account has an
     *         order locked but not yet unlocked.
     */
    function hasOpenPositions(bytes32 account) external view returns (bool) {
        return inFlightOf[account] > 0;
    }

    /**
     * @notice Return the currently available (unlocked) liquidity for an ad.
     */
    function availableLiquidity(string memory adId) external view returns (uint256 amount) {
        Ad storage ad = ads[adId];
        if (ad.maker == address(0)) return 0;
        return ad.balance - ad.locked;
    }

    /**
     * @notice Return the latest merkle manager root
     */
    function getLatestMerkleRoot() external view returns (bytes32 root) {
        root = i_merkleManager.getRoot();
    }

    /**
     * @notice Return the root at merkle leaf index
     */
    function getHistoricalRoot(uint256 index) external view returns (bytes32 root) {
        root = i_merkleManager.getRootAtIndex(index);
    }

    /**
     * @notice Returns merkle leaf count
     */
    function getMerkleLeafCount() external view returns (uint256 count) {
        count = i_merkleManager.getWidth();
    }

    /*//////////////////////////////////////////////////////////////
                              INTERNAL LOGIC
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Compute the EIP-712 order digest. Builds the canonical
     *         cross-chain tuple from this contract's local `OrderParams` plus
     *         the ad-chain-local context, then defers to {OrderHash}.
     * @param p Order parameters (ad-chain layout).
     * @param adChainId Destination/current chain id (usually `block.chainid`).
     * @param dstAdManager Destination/current contract (usually `address(this)`).
     */
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
            adManager: AddressCast.toBytes32(dstAdManager),
            adId: p.adId,
            adCreator: p.adCreator,
            adRecipient: p.adRecipient,
            salt: p.salt,
            orderDecimals: p.orderDecimals,
            adDecimals: p.adDecimals
        });
        return OrderHash.digest(o);
    }

    /**
     * @notice Load an ad and assert `maker` is the owner.
     */
    function __getAdOwned(string memory adId, address maker) internal view returns (Ad storage ad) {
        ad = ads[adId];
        if (ad.maker == address(0)) revert AdManager__AdNotFound();
        if (ad.maker != maker) revert AdManager__NotMaker();
    }

    /**
     * @notice Validates an advertisement order against provided parameters and returns the order hash
     */
    function validateOrder(Ad memory ad, OrderParams calldata params) internal view returns (bytes32 orderHash) {
        if (!ad.open) revert AdManager__AdClosed();
        if (params.amount == 0) revert AdManager__ZeroAmount();
        if (params.bridger == bytes32(0)) revert AdManager__BridgerZero();
        if (params.orderRecipient == bytes32(0)) revert AdManager__RecipientZero();

        // validate recipient address
        params.orderRecipient.assertEvmAddress();

        // Cap both signed decimals to keep the scale factor well inside uint256 headroom.
        DecimalScaling.assertInRange(params.orderDecimals);
        DecimalScaling.assertInRange(params.adDecimals);

        // Source chain must be supported and portal must match (if configured).
        ChainInfo memory ci = chains[params.orderChainId];
        if (!ci.supported) revert AdManager__ChainNotSupported(params.orderChainId);
        if (ci.orderPortal != bytes32(0) && ci.orderPortal != params.srcOrderPortal) {
            revert AdManager__OrderPortalMismatch(ci.orderPortal, params.srcOrderPortal);
        }

        // Ad must serve the provided source chain.
        if (params.orderChainId != ad.orderChainId) {
            revert AdManager__OrderChainMismatch(ad.orderChainId, params.orderChainId);
        }

        // Route must match the ad's creation-time commitment AND the live table.
        if (params.orderChainToken != ad.orderChainToken) {
            revert AdManager__RouteMismatch(ad.orderChainToken, params.orderChainToken);
        }

        bytes32 routed = tokenRoute[ad.token][params.orderChainId];
        if (routed == bytes32(0)) revert AdManager__MissingRoute(params.orderChainToken, block.chainid);
        if (routed != params.orderChainToken) revert AdManager__OrderTokenMismatch(routed, params.orderChainToken);

        // Identity and token checks.
        if (params.adCreator != ad.maker.toBytes32()) revert AdManager__NotMaker();
        if (params.adChainToken != ad.token.toBytes32()) {
            revert AdManager__AdTokenMismatch(ad.token.toBytes32(), params.adChainToken);
        }
        if (params.adRecipient != ad.adRecipient) {
            revert AdManager__AdRecipientMismatch(ad.adRecipient, params.adRecipient);
        }

        // Defense-in-depth: the signed adDecimals must match the on-chain ad token.
        DecimalScaling.assertMatchesOnChain(ad.token, params.adDecimals);

        orderHash = _hashOrder(params, block.chainid, address(this));
    }

    receive() external payable {}
    fallback() external payable {}
}
