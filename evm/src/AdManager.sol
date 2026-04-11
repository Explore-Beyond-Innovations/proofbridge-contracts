// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title AdManager (Proofbridge)
 * @notice Makers (LPs) post/close liquidity ads, lock funds against EIP-712 orders,
 *         and bridgers unlock on this chain with a proof checked by an external verifier.
 */
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {EfficientHashLib} from "solady/utils/EfficientHashLib.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IVerifier} from "./Verifier.sol";
import {IMerkleManager} from "./MerkleManager.sol";
import {IwNativeToken, SafeNativeToken} from "./wNativeToken.sol";

contract AdManager is AccessControl, ReentrancyGuard, EIP712 {
    using SafeERC20 for IERC20;
    using SafeNativeToken for IwNativeToken;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice EIP-712 domain name.
    string private constant _NAME = "Proofbridge";
    /// @notice EIP-712 domain version.
    string private constant _VERSION = "1";

    /// @notice Minimal EIP-712 domain (name, version).
    bytes32 public constant DOMAIN_TYPEHASH_MIN = keccak256("EIP712Domain(string name,string version)");

    /**
     * @notice EIP-712 typehash for `Order` structs.
     */
    bytes32 public constant ORDER_TYPEHASH = keccak256(
        "Order(address orderChainToken,address adChainToken,uint256 amount,address bridger,uint256 orderChainId,address orderPortal,address orderRecipient,uint256 adChainId,address adManager,string adId,address adCreator,address adRecipient,uint256 salt)"
    );

    /// @notice Admin role identifier.
    bytes32 public constant ADMIN_ROLE = DEFAULT_ADMIN_ROLE;

    /// @notice Native token address placeholder.
    address public constant NATIVE_TOKEN_ADDRESS = address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice External verifier used to validate zero-knowledge proofs.
    IVerifier public immutable i_verifier;

    /// @notice MerkleManager for chain
    IMerkleManager public immutable i_merkleManager;

    /// @notice Wrapped native token
    IwNativeToken public wNativeToken;

    /**
     * @notice Source-chain configuration (where orders originate).
     * @param supported Whether orders from this chain are accepted.
     * @param orderPortal Address of the counterpart OrderPortal on the source chain.
     */
    struct ChainInfo {
        bool supported;
        address orderPortal;
    }

    /**
     * @notice Liquidity ad created by a maker on the ad chain (this chain).
     * @param orderChainId Source chain id this ad serves.
     * @param adRecipient Maker-controlled recipient on the order chain.
     * @param maker Owner of the ad.
     * @param token ERC20 token escrowed for payouts on this chain.
     * @param balance Total token balance deposited into the ad.
     * @param locked Portion of {balance} currently reserved for open orders.
     * @param open Whether the ad is accepting new locks/funding.
     */
    struct Ad {
        uint256 orderChainId;
        address adRecipient;
        address maker;
        address token;
        uint256 balance;
        uint256 locked;
        bool open;
    }

    /**
     * @notice Parameters describing a cross-chain order to be locked/unlocked.
     * @dev
     * - `orderChainToken` lives on the source (order) chain.
     * - `adChainToken` lives on this (ad) chain and MUST equal the ad's {token}.
     * - `orderChainId` and `srcOrderPortal` bind the order to its source.
     * - `adId`, `adCreator`, and `adRecipient` bind to the chosen ad on this chain.
     * @param orderChainToken Source-chain token address.
     * @param adChainToken Destination (this chain) token address.
     * @param amount Amount to reserve/release.
     * @param bridger Source-chain user initiating the bridge.
     * @param orderChainId Source chain id.
     * @param srcOrderPortal Source chain OrderPortal.
     * @param orderRecipient Recipient on the ad chain to receive payout upon unlock.
     * @param adId Target ad id on this chain.
     * @param adCreator Expected maker (ad owner).
     * @param adRecipient Expected maker-defined recipient on the order chain.
     * @param salt Unique nonce to avoid hash collisions / replay.
     */
    struct OrderParams {
        address orderChainToken;
        address adChainToken;
        uint256 amount;
        address bridger;
        uint256 orderChainId;
        address srcOrderPortal;
        address orderRecipient;
        string adId;
        address adCreator;
        address adRecipient;
        uint256 salt;
    }

    /// @notice Order lifecycle status.
    enum Status {
        None, // Not present in storage.
        Open, // Reserved liquidity.
        Filled // Unlocked and paid.
    }

    /// @notice Source-chain configs.
    mapping(uint256 => ChainInfo) public chains;

    /// @notice Supported token routes: ad token → (orderChainId → Order token)
    mapping(address => mapping(uint256 => address)) public tokenRoute;

    /// @notice Ads by id.
    mapping(string => Ad) public ads;

    /// @notice Order status by EIP-712 hash.
    mapping(bytes32 => Status) public orders;

    /// @notice Consumed nullifiers to prevent reuse across proofs.
    mapping(bytes32 => bool) public nullifierUsed;

    /// @notice Tracks manager permissions for addresses
    mapping(address => bool) public managers;

    /// @notice Request tokens tracker to prevent replay attacks
    mapping(bytes32 => bool) public requestTokens;

    /// @notice Request hash tracker to prevent replay attacks
    mapping(bytes32 => bool) public requestHashes;

    /// @notice Ad Ids mapping
    mapping(string => bool) public adIds;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Emitted when a source chain configuration is set/updated.
     * @param chainId Source chain id.
     * @param orderPortal Source chain OrderPortal address.
     * @param supported Whether orders from this chain are accepted.
     */
    event ChainSet(uint256 indexed chainId, address indexed orderPortal, bool supported);

    /**
     * @notice Emitted when a token route is configured.
     * @param orderChainToken Token on the order (source) chain.
     * @param adChainId Destination chain id (equals `block.chainid` for this deployment).
     * @param adChainToken Token on this (ad) chain.
     */
    event TokenRouteSet(address indexed orderChainToken, uint256 indexed adChainId, address indexed adChainToken);

    /**
     * @notice Emitted when a token route is removed.
     * @param orderChainToken Token on the order (source) chain.
     * @param adChainId Destination chain id (this chain).
     */
    event TokenRouteRemoved(address indexed adToken, address indexed orderChainToken, uint256 indexed adChainId);

    /**
     * @notice Emitted when an ad is created.
     * @param adId New ad id.
     * @param maker Ad owner.
     * @param token Escrowed token on this chain.
     * @param initAmount Initial amount deposited.
     * @param orderChainId Source chain this ad serves.
     */
    event AdCreated(
        string indexed adId, address indexed maker, address indexed token, uint256 initAmount, uint256 orderChainId
    );

    /**
     * @notice Emitted when an ad is funded.
     * @param adId Ad identifier.
     * @param maker Funder (must be the ad owner).
     * @param amount Amount deposited.
     * @param newBalance New ad balance.
     */
    event AdFunded(string indexed adId, address indexed maker, uint256 amount, uint256 newBalance);

    /**
     * @notice Emitted when ad funds are withdrawn.
     * @param adId Ad identifier.
     * @param maker Withdrawer (must be the ad owner).
     * @param amount Amount withdrawn.
     * @param newBalance New ad balance.
     */
    event AdWithdrawn(string indexed adId, address indexed maker, uint256 amount, uint256 newBalance);

    /**
     * @notice Emitted when an ad is closed.
     * @param adId Ad identifier.
     * @param maker Ad owner.
     */
    event AdClosed(string indexed adId, address indexed maker);

    /**
     * @notice Emitted when liquidity is locked for an order.
     * @param adId Ad used for the lock.
     * @param orderHash EIP-712 order hash.
     * @param maker Ad owner.
     * @param token Escrowed token on this chain.
     * @param amount Amount locked.
     * @param bridger Bridger address from the order.
     * @param recipient Recipient to be paid on unlock (this chain).
     */
    event OrderLocked(
        string indexed adId,
        bytes32 indexed orderHash,
        address maker,
        address token,
        uint256 amount,
        address bridger,
        address recipient
    );

    /**
     * @notice Emitted when an order is unlocked by a valid proof.
     * @param orderHash EIP-712 order hash.
     * @param recipient Recipient paid on this chain.
     * @param nullifierHash Consumed nullifier to prevent reuse.
     */
    event OrderUnlocked(bytes32 indexed orderHash, address indexed recipient, bytes32 nullifierHash);

    /**
     * @notice Emitted when a manager's status is updated
     * @param manager Address of the manager
     * @param status Boolean representing the new manager status
     */
    event UpdateManager(address indexed manager, bool status);

    /*//////////////////////////////////////////////////////////////
                                  ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Zero address provided where non-zero is required.
    error AdManager__TokenZeroAddress();
    /// @notice Amount is zero where non-zero is required.
    error AdManager__ZeroAmount();
    /// @notice Ad does not exist.
    error AdManager__AdNotFound();
    /// @notice Caller is not the ad's maker.
    error AdManager__NotMaker();
    /// @notice Ad is closed.
    error AdManager__AdClosed();
    /// @notice Insufficient available liquidity to perform the action.
    error AdManager__InsufficientLiquidity();
    /// @notice Bridger address is zero.
    error AdManager__BridgerZero();
    /// @notice Recipient address is zero.
    error AdManager__RecipientZero();
    /// @notice Ad has active locked funds.
    error Admanager__ActiveLocks();

    /// @notice Source chain not supported.
    error AdManager__ChainNotSupported(uint256 chainId);
    /// @notice Provided OrderPortal does not match configured source-chain portal.
    error AdManager__OrderPortalMismatch(address expected, address provided);
    /// @notice Provided orderChainId does not match the ad's configured orderChainId.
    error AdManager__OrderChainMismatch(uint256 expected, uint256 provided);

    /// @notice No token route exists for (adToken, orderChainId).
    error AdManager__MissingRoute(address orderChainToken, uint256 adChainId);
    /// @notice Source token mismatches the configured route.
    error AdManager__OrderTokenMismatch(address expected, address provided);
    /// @notice Destination (ad-chain) token mismatches the ad's token.
    error AdManager__AdTokenMismatch(address expected, address provided);
    /// @notice Provided adRecipient mismatches the ad's configured adRecipient.
    error AdManager__AdRecipientMismatch(address expected, address provided);

    /// @notice Order already opened for the computed hash.
    error AdManager__OrderExists(bytes32 orderHash);
    /// @notice Order not open.
    error AdManager__OrderNotOpen(bytes32 orderHash);
    /// @notice Nullifier already used.
    error AdManager__NullifierUsed(bytes32 nullifierHash);
    /// @notice Verifier rejected the proof.
    error AdManager__InvalidProof();
    /// @notice Zero Address error
    error AdManager__ZeroAddress();

    /// @notice Invalid Message error
    error AdManager__InvalidMessage();
    /// @notice Token Already Used error
    error AdManager__TokenAlreadyUsed();
    /// @notice Request Token Expired error
    error AdManager__RequestTokenExpired();
    /// @notice Zero Signer error
    error Admanage__ZeroSigner();
    /// @notice Invalid Signer error
    error Admanager__InvalidSigner();
    /// @notice Request Hashed Processed error
    error Admanager__RequestHashedProcessed();

    /// @notice MerkleManager append failed
    error AdManager__MerkleManagerAppendFailed();
    /// @notice Used Ad Id
    error AdManager__UsedAdId();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Deploys the AdManager and assigns the admin and verifier.
     * @param admin Address granted {ADMIN__ROLE}.
     * @param _verifier External zk-proof verifier contract.
     * @param _merkleManager Merkle manager contract.
     * @param _wNativeToken Wrapped native token contract.
     */
    constructor(address admin, IVerifier _verifier, IMerkleManager _merkleManager, IwNativeToken _wNativeToken)
        EIP712(_NAME, _VERSION)
    {
        if (
            admin == address(0) || address(_verifier) == address(0) || address(_merkleManager) == address(0)
                || address(_wNativeToken) == address(0)
        ) {
            revert AdManager__ZeroAddress();
        }
        _grantRole(ADMIN_ROLE, admin);
        managers[admin] = true;
        i_verifier = _verifier;
        i_merkleManager = _merkleManager;
        wNativeToken = _wNativeToken;
    }

    /*//////////////////////////////////////////////////////////////
                              ADMIN: MANAGERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Sets or unsets an address as a manager
     * @param _manager Address of the manager
     * @param _status Boolean representing the desired manager status
     */
    function setManager(address _manager, bool _status) external onlyRole(ADMIN_ROLE) {
        if (_manager == address(0)) {
            revert AdManager__ZeroAddress();
        }

        managers[_manager] = _status;
        emit UpdateManager(_manager, _status);
    }

    /*//////////////////////////////////////////////////////////////
                              ADMIN: CHAINS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Add or update a source-chain configuration.
     * @param orderChainId Source chain id.
     * @param orderPortal Counterpart OrderPortal on the source chain.
     * @param supported Whether the chain is supported.
     */
    function setChain(uint256 orderChainId, address orderPortal, bool supported) external onlyRole(ADMIN_ROLE) {
        chains[orderChainId] = ChainInfo({supported: supported, orderPortal: orderPortal});
        emit ChainSet(orderChainId, orderPortal, supported);
    }

    /**
     * @notice Remove a source-chain configuration.
     * @param orderChainId Source chain id to remove.
     */
    function removeChain(uint256 orderChainId) external onlyRole(ADMIN_ROLE) {
        delete chains[orderChainId];
        emit ChainSet(orderChainId, address(0), false);
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN: TOKEN ROUTES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure a token route mapping from a source chain to this chain.
     * @dev Sets `tokenRoute[adToken][orderChainId] = orderToken`.
     * @param adToken Token on this (ad) chain.
     * @param orderToken Token on the source (order) chain.
     * @param orderChainId Source chain id.
     */
    function setTokenRoute(address adToken, address orderToken, uint256 orderChainId) external onlyRole(ADMIN_ROLE) {
        if (orderToken == address(0) || adToken == address(0)) revert AdManager__TokenZeroAddress();
        if (!chains[orderChainId].supported) revert AdManager__ChainNotSupported(orderChainId);
        tokenRoute[adToken][orderChainId] = orderToken;
        emit TokenRouteSet(orderToken, orderChainId, adToken);
    }

    /**
     * @notice Remove a token route mapping.
     * @param adToken Token on this (ad) chain.
     * @param orderChainId Source chain id.
     */
    function removeTokenRoute(address adToken, uint256 orderChainId) external onlyRole(ADMIN_ROLE) {
        address orderToken = tokenRoute[adToken][orderChainId];
        delete tokenRoute[adToken][orderChainId];
        emit TokenRouteRemoved(adToken, orderToken, orderChainId);
    }

    /*//////////////////////////////////////////////////////////////
                           MAKER ACTIONS — ADS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a new liquidity ad to serve orders from `orderChainId`.
     * @dev Requires an existing token route for `(adToken, orderChainId)`.
     * @param signature Signature over the request hash.
     * @param authToken Unique token for the delegated action (prevents replay).
     *  @param timeToExpire Expiration time for the token (unix timestamp).
     *  @param adId Returned ad id (sequential).
     * @param adToken ERC20 token to escrow for payouts on this chain.
     * @param orderChainId Source chain id this ad intends to serve.
     * @param adRecipient Maker-defined recipient on the order chain (checked in {lockForOrder}).
     */
    function createAd(
        bytes memory signature,
        bytes32 authToken,
        uint256 timeToExpire,
        string memory adId,
        address adToken,
        uint256 initialAmount,
        uint256 orderChainId,
        address adRecipient
    ) external payable nonReentrant {
        if (adToken == address(0)) revert AdManager__TokenZeroAddress();
        if (adRecipient == address(0)) revert AdManager__RecipientZero();
        if (initialAmount == 0) revert AdManager__ZeroAmount();

        if (tokenRoute[adToken][orderChainId] == address(0)) {
            revert AdManager__ChainNotSupported(orderChainId);
        }

        if (adIds[adId]) {
            revert AdManager__UsedAdId();
        }

        bytes32 message =
            createAdRequestHash(adId, adToken, initialAmount, orderChainId, adRecipient, authToken, timeToExpire);

        if (requestHashes[message]) {
            revert Admanager__RequestHashedProcessed();
        }

        address signer = preAuthValidations(message, authToken, timeToExpire, signature);

        if (!managers[signer]) {
            revert Admanager__InvalidSigner();
        }

        if (isNativeToken(adToken)) {
            if (msg.value < initialAmount) {
                revert AdManager__InsufficientLiquidity();
            }
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
            open: true
        });

        adIds[adId] = true;
        requestHashes[message] = true;
        emit AdCreated(adId, msg.sender, adToken, initialAmount, orderChainId);
    }

    /**
     * @notice Fund an existing ad with `amount` of its ERC20 token.
     * @dev Caller must be the ad's maker/owner.
     * @param signature Signature over the request hash.
     * @param authToken Unique token for the delegated action (prevents replay).
     * @param timeToExpire Expiration time for the token (unix timestamp).
     * @param adId Ad id to fund.
     * @param amount Amount to deposit.
     */
    function fundAd(
        bytes memory signature,
        bytes32 authToken,
        uint256 timeToExpire,
        string memory adId,
        uint256 amount
    ) external payable nonReentrant {
        Ad storage ad = __getAdOwned(adId, msg.sender);
        if (!ad.open) revert AdManager__AdClosed();
        if (amount == 0) revert AdManager__ZeroAmount();

        bytes32 message = fundAdRequestHash(adId, amount, authToken, timeToExpire);

        if (requestHashes[message]) {
            revert Admanager__RequestHashedProcessed();
        }

        address signer = preAuthValidations(message, authToken, timeToExpire, signature);

        if (!managers[signer]) {
            revert Admanager__InvalidSigner();
        }

        if (isNativeToken(ad.token)) {
            if (msg.value < amount) {
                revert AdManager__InsufficientLiquidity();
            }
            wNativeToken.safeDeposit(amount);
        } else {
            IERC20(ad.token).safeTransferFrom(msg.sender, address(this), amount);
        }

        ad.balance += amount;
        requestHashes[message] = true;
        emit AdFunded(adId, msg.sender, amount, ad.balance);
    }

    /**
     * @notice Withdraw unfrozen liquidity from an ad.
     * @dev Caller must be the ad's maker/owner.
     * @param signature Signature over the request hash.
     * @param authToken Unique token for the delegated action (prevents replay).
     * @param timeToExpire Expiration time for the token (unix timestamp).
     * @param adId Ad id to withdraw from.
     * @param amount Amount to withdraw.
     * @param to Recipient address for the withdrawn tokens.
     */
    function withdrawFromAd(
        bytes memory signature,
        bytes32 authToken,
        uint256 timeToExpire,
        string memory adId,
        uint256 amount,
        address to
    ) external payable nonReentrant {
        Ad storage ad = __getAdOwned(adId, msg.sender);

        bytes32 message = withdrawFromAdRequestHash(adId, amount, to, authToken, timeToExpire);

        if (requestHashes[message]) {
            revert Admanager__RequestHashedProcessed();
        }

        if (to == address(0)) revert AdManager__RecipientZero();

        address signer = preAuthValidations(message, authToken, timeToExpire, signature);

        if (amount == 0) revert AdManager__ZeroAmount();

        uint256 available = ad.balance - ad.locked;

        if (amount > available) revert AdManager__InsufficientLiquidity();

        if (!managers[signer]) {
            revert Admanager__InvalidSigner();
        }

        ad.balance -= amount;

        if (isNativeToken(ad.token)) {
            wNativeToken.safeWithdrawTo(amount, to);
        } else {
            IERC20(ad.token).safeTransfer(to, amount);
        }

        requestHashes[message] = true;
        emit AdWithdrawn(adId, msg.sender, amount, ad.balance);
    }

    /**
     * @notice Close an ad and withdraw any remaining funds.
     * @dev Fails if the ad has any locked liquidity.
     * @param adId Ad id to close.
     * @param to Recipient of the remaining tokens.
     */
    function closeAd(bytes memory signature, bytes32 authToken, uint256 timeToExpire, string memory adId, address to)
        external
        payable
        nonReentrant
    {
        Ad storage ad = __getAdOwned(adId, msg.sender);
        if (ad.locked != 0) revert Admanager__ActiveLocks(); // has active locks
        if (to == address(0)) revert AdManager__RecipientZero();

        bytes32 message = closeAdRequestHash(adId, to, authToken, timeToExpire);

        if (requestHashes[message]) {
            revert Admanager__RequestHashedProcessed();
        }

        address signer = preAuthValidations(message, authToken, timeToExpire, signature);

        if (!managers[signer]) {
            revert Admanager__InvalidSigner();
        }

        uint256 remaining = ad.balance;

        ad.balance = 0;
        ad.open = false;

        if (remaining > 0) {
            if (isNativeToken(ad.token)) {
                wNativeToken.safeWithdrawTo(remaining, to);
            } else {
                IERC20(ad.token).safeTransfer(to, remaining);
            }
        }

        requestHashes[message] = true;
        emit AdClosed(adId, msg.sender);
    }

    /**
     * @notice Reserve `params.amount` from `params.adId` to fulfill an order.
     * @dev Validates chain config, portal, route, ad identity, recipients, and liquidity.
     *      Opens the order by setting its status to {Status.Open}.
     * @param params Order parameters (see {OrderParams}).
     * @return orderHash The EIP-712 order hash that identifies this reservation.
     */
    function lockForOrder(bytes memory signature, bytes32 authToken, uint256 timeToExpire, OrderParams calldata params)
        external
        nonReentrant
        returns (bytes32 orderHash)
    {
        Ad storage ad = __getAdOwned(params.adId, msg.sender);

        // Liquidity check.
        uint256 available = ad.balance - ad.locked;
        if (params.amount > available) revert AdManager__InsufficientLiquidity();

        // Open order.
        orderHash = validateOrder(ad, params);

        if (orders[orderHash] != Status.None) revert AdManager__OrderExists(orderHash);

        bytes32 message = lockForOrderRequestHash(params.adId, orderHash, authToken, timeToExpire);

        if (requestHashes[message]) {
            revert Admanager__RequestHashedProcessed();
        }
        address signer = preAuthValidations(message, authToken, timeToExpire, signature);

        if (!managers[signer]) {
            revert Admanager__InvalidSigner();
        }

        ad.locked += params.amount;
        orders[orderHash] = Status.Open;

        // append order hash
        if (!i_merkleManager.appendOrderHash(orderHash)) {
            revert AdManager__MerkleManagerAppendFailed();
        }

        requestHashes[message] = true;

        emit OrderLocked(
            params.adId, orderHash, ad.maker, ad.token, params.amount, params.bridger, params.orderRecipient
        );
    }

    /*//////////////////////////////////////////////////////////////
                     BRIDGER ACTION — UNLOCK WITH PROOF
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Unlock previously reserved funds after presenting a valid zk-proof.
     * @dev Consumes `nullifierHash` and moves order status to {Status.Filled}.
     * @param params Original order parameters that hash to the open `orderHash`.
     * @param nullifierHash One-time nullifier preventing reuse of this proof.
     * @param targetRoot Source chain root of other chain appending the orderHash.
     * @param proof zk-proof bytes for the external verifier.
     */
    function unlock(
        bytes memory signature,
        bytes32 authToken,
        uint256 timeToExpire,
        OrderParams calldata params,
        bytes32 nullifierHash,
        bytes32 targetRoot,
        bytes calldata proof
    ) external payable nonReentrant {
        bytes32 orderHash = _hashOrder(params, block.chainid, address(this));

        if (orders[orderHash] != Status.Open) revert AdManager__OrderNotOpen(orderHash);
        if (nullifierUsed[nullifierHash]) revert AdManager__NullifierUsed(nullifierHash);

        bytes32 message = unlockOrderRequestHash(params.adId, orderHash, targetRoot, authToken, timeToExpire);

        if (requestHashes[message]) {
            revert Admanager__RequestHashedProcessed();
        }

        address signer = preAuthValidations(message, authToken, timeToExpire, signature);

        if (!managers[signer]) {
            revert Admanager__InvalidSigner();
        }

        // Build public inputs for the verifier
        bytes32[] memory publicInputs = buildPublicInputs(nullifierHash, targetRoot, orderHash);

        if (!i_verifier.verify(proof, publicInputs)) revert AdManager__InvalidProof();

        nullifierUsed[nullifierHash] = true;
        orders[orderHash] = Status.Filled;

        requestHashes[message] = true;

        // Pay recipient on this chain from the ad's escrowed token.
        Ad storage ad = ads[params.adId];
        ad.locked -= params.amount;

        if (isNativeToken(ad.token)) {
            wNativeToken.safeWithdrawTo(params.amount, params.orderRecipient);
        } else {
            IERC20(ad.token).safeTransfer(params.orderRecipient, params.amount);
        }

        emit OrderUnlocked(orderHash, params.orderRecipient, nullifierHash);
    }

    /*//////////////////////////////////////////////////////////////
                           VIEWS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Return the currently available (unlocked) liquidity for an ad.
     * @param adId Ad identifier.
     * @return amount Available token amount.
     */
    function availableLiquidity(string memory adId) public view returns (uint256 amount) {
        Ad storage ad = ads[adId];
        if (ad.maker == address(0)) return 0;
        return ad.balance - ad.locked;
    }

    /**
     * @notice Check if a request hash exists
     * @param message The message hash to check
     * @return bool True if the request hash exists, false otherwise
     */
    function checkRequestHashExists(bytes32 message) external view returns (bool) {
        return requestHashes[message];
    }

    /**
     * @notice Return the latest merkle manager root
     */
    function getLatestMerkleRoot() external view returns (bytes32 root) {
        root = i_merkleManager.getRoot();
    }

    /**
     * @notice Return the root at merkle leaf index
     * @param index The index of the root
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
                            VALIDATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validates the message and signature
     * @param _message The message that the user signed
     * @param authToken The unique token for the delegated action
     * @param timeToExpire The time to expire the token
     * @param signature Signature
     * @return address Signer of the message
     */
    function preAuthValidations(bytes32 _message, bytes32 authToken, uint256 timeToExpire, bytes memory signature)
        internal
        returns (address)
    {
        if (_message == bytes32(0)) {
            revert AdManager__InvalidMessage();
        }

        if (requestTokens[authToken]) {
            revert AdManager__TokenAlreadyUsed();
        }

        if (block.timestamp > timeToExpire) {
            revert AdManager__RequestTokenExpired();
        }

        address signer = getSigner(_message, signature);

        if (signer == address(0)) {
            revert Admanage__ZeroSigner();
        }

        requestTokens[authToken] = true;

        return signer;
    }

    /// @notice Find the signer
    /// @param message The message that the user signed
    /// @param signature Signature
    /// @return address Signer of the message
    function getSigner(bytes32 message, bytes memory signature) public pure returns (address) {
        message = MessageHashUtils.toEthSignedMessageHash(message);
        address signer = ECDSA.recover(message, signature);
        return signer;
    }

    /// @notice Get the ID of the executing chain
    /// @return uint256 value
    function getChainID() public view returns (uint256) {
        uint256 id;
        assembly {
            id := chainid()
        }
        return id;
    }

    /*//////////////////////////////////////////////////////////////
                               HASHING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Hash a request for pre-authorization
     * @param authToken Unique token for the delegated action
     * @param timeToExpire The time to expire the token
     * @param _action The action to be performed
     * @param _params Encoded parameters for the action
     * @return bytes32 The hash of the request
     */
    function hashRequest(bytes32 authToken, uint256 timeToExpire, string memory _action, bytes[] memory _params)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(authToken, timeToExpire, _action, _params, getChainID(), address(this)));
    }

    /**
     * @notice Compute the final EIP-712 typed-data digest for an order.
     * @param p Order parameters.
     * @param adChainId Destination/current chain id (typically `block.chainid`).
     * @param dstAdManager Destination/current chain contract (typically `address(this)`).
     * @return digest The EIP-712 order digest.
     */
    function _hashOrder(OrderParams calldata p, uint256 adChainId, address dstAdManager)
        internal
        view
        returns (bytes32 digest)
    {
        return _hashTypedDataV4(_structHash(p, adChainId, dstAdManager));
    }

    /**
     * @notice Compute the struct hash for `Order`.
     * @dev Field order must match {ORDER_TYPEHASH}.
     * @param p Order parameters.
     * @param adChainId Destination/current chain id.
     * @param dstAdManager Destination/current chain contract address.
     * @return structHash Keccak-256 struct hash.
     */
    function _structHash(OrderParams calldata p, uint256 adChainId, address dstAdManager)
        internal
        pure
        returns (bytes32 structHash)
    {
        bytes32[] memory buf = EfficientHashLib.malloc(14);
        EfficientHashLib.set(buf, 0, ORDER_TYPEHASH);
        EfficientHashLib.set(buf, 1, toBytes32(p.orderChainToken));
        EfficientHashLib.set(buf, 2, toBytes32(p.adChainToken));
        EfficientHashLib.set(buf, 3, p.amount);
        EfficientHashLib.set(buf, 4, toBytes32(p.bridger));
        EfficientHashLib.set(buf, 5, p.orderChainId);
        EfficientHashLib.set(buf, 6, toBytes32(p.srcOrderPortal));
        EfficientHashLib.set(buf, 7, toBytes32(p.orderRecipient));
        EfficientHashLib.set(buf, 8, adChainId);
        EfficientHashLib.set(buf, 9, toBytes32(dstAdManager));
        EfficientHashLib.set(buf, 10, keccak256(bytes(p.adId)));
        EfficientHashLib.set(buf, 11, toBytes32(p.adCreator));
        EfficientHashLib.set(buf, 12, toBytes32(p.adRecipient));
        EfficientHashLib.set(buf, 13, p.salt);
        return EfficientHashLib.hash(buf);
    }

    /**
     * @notice Cast an address to bytes32 (left-padded).
     * @param value Address to cast.
     * @return out 32-byte left-padded representation.
     */
    function toBytes32(address value) internal pure returns (bytes32 out) {
        return bytes32(uint256(uint160(value)));
    }

    /**
     * @notice Builds an array of public inputs for zk-proof verification.
     * @dev Encodes the provided nullifierHash, orderHash, targetRoot and constant 1 into a bytes32 array.
     * @param nullifierHash The hash used to prevent proof reuse
     * @param targetRoot The root of the Merkle tree in the source chain
     * @param orderHash The EIP-712 order hash
     * @return inputs Array of 4 bytes32 values: [nullifierHash, orderHash, targetRoot, 1]
     */
    function buildPublicInputs(bytes32 nullifierHash, bytes32 targetRoot, bytes32 orderHash)
        internal
        view
        returns (bytes32[] memory inputs)
    {
        bytes32 orderHashMod = i_merkleManager.fieldMod(orderHash);
        inputs = new bytes32[](4);
        inputs[0] = nullifierHash;
        inputs[1] = orderHashMod;
        inputs[2] = targetRoot;
        inputs[3] = bytes32(uint256(1));
    }

    /**
     * @notice Creates a hash for ad creation requests
     * @dev Generates a unique hash combining ad details and request parameters
     * @param adId Unique identifier for the advertisement
     * @param adToken The token address associated with the advertisement
     * @param orderChainId The chain ID where the order exists
     * @param adRecipient Address that will receive the advertisement
     * @param authToken Token identifier used in hash generation
     * @param timeToExpire Expiration timestamp for the request
     * @return message The generated hash of the ad request
     */
    function createAdRequestHash(
        string memory adId,
        address adToken,
        uint256 initialAmount,
        uint256 orderChainId,
        address adRecipient,
        bytes32 authToken,
        uint256 timeToExpire
    ) public view returns (bytes32 message) {
        string memory action = "createAd";
        bytes[] memory params = new bytes[](5);
        params[0] = abi.encode(adId);
        params[1] = abi.encode(adToken);
        params[2] = abi.encode(initialAmount);
        params[3] = abi.encode(orderChainId);
        params[4] = abi.encode(adRecipient);
        message = hashRequest(authToken, timeToExpire, action, params);
    }
    /**
     * @notice Creates a hash of a fund ad request
     * @dev Uses hashRequest function to create a unique hash for funding an ad
     * @param adId The unique identifier of the advertisement
     * @param amount The funding amount for the advertisement
     * @param authToken The token hash identifier
     * @param timeToExpire The expiration time for the funding request
     * @return message The keccak256 hash of the request parameters
     */

    function fundAdRequestHash(string memory adId, uint256 amount, bytes32 authToken, uint256 timeToExpire)
        public
        view
        returns (bytes32 message)
    {
        string memory action = "fundAd";
        bytes[] memory params = new bytes[](2);
        params[0] = abi.encode(adId);
        params[1] = abi.encode(amount);
        message = hashRequest(authToken, timeToExpire, action, params);
    }

    /**
     * @notice Generates a hash for withdrawing funds from an ad request
     * @dev Creates a unique hash combining ad details, withdrawal amount, recipient, token and expiry
     * @param adId The unique identifier of the advertisement
     * @param amount The amount to withdraw
     * @param to The address that will receive the withdrawn funds
     * @param authToken The token address hash being used for the withdrawal
     * @param timeToExpire The timestamp when this request will expire
     * @return message The keccak256 hash of the encoded withdrawal request
     */
    function withdrawFromAdRequestHash(
        string memory adId,
        uint256 amount,
        address to,
        bytes32 authToken,
        uint256 timeToExpire
    ) public view returns (bytes32 message) {
        string memory action = "withdrawFromAd";
        bytes[] memory params = new bytes[](3);
        params[0] = abi.encode(adId);
        params[1] = abi.encode(amount);
        params[2] = abi.encode(to);
        message = hashRequest(authToken, timeToExpire, action, params);
    }

    /**
     * @notice Generates a hash for closing an advertisement request
     * @dev Combines the ad ID, recipient address, token and expiry time into a standardized hash format
     * @param adId The unique identifier of the advertisement
     * @param to The address that will receive the advertisement closure confirmation
     * @param authToken The token associated with this request
     * @param timeToExpire The timestamp when this request will expire
     * @return message The generated hash of the close advertisement request
     */
    function closeAdRequestHash(string memory adId, address to, bytes32 authToken, uint256 timeToExpire)
        public
        view
        returns (bytes32 message)
    {
        string memory action = "closeAd";
        bytes[] memory params = new bytes[](2);
        params[0] = abi.encode(adId);
        params[1] = abi.encode(to);
        message = hashRequest(authToken, timeToExpire, action, params);
    }

    /**
     * @notice Generates a hash for locking an advertisement for an order
     * @dev Creates a hash combining the ad ID, order hash, token and expiry time
     * @param adId The unique identifier of the advertisement
     * @param orderHash The hash of the order for which the ad should be locked
     * @param authToken The token associated with this request
     * @param timeToExpire The timestamp when this request will expire
     * @return message The generated hash of the lock advertisement request
     */
    function lockForOrderRequestHash(string memory adId, bytes32 orderHash, bytes32 authToken, uint256 timeToExpire)
        public
        view
        returns (bytes32 message)
    {
        string memory action = "lockForOrder";
        bytes[] memory params = new bytes[](2);
        params[0] = abi.encode(adId);
        params[1] = abi.encode(orderHash);
        message = hashRequest(authToken, timeToExpire, action, params);
    }

    /**
     * @notice Generates a hash for unlocking an advertisement order
     * @dev Creates a hash combining the ad ID, order hash, target root, token and expiry time
     * @param adId The unique identifier of the advertisement
     * @param orderHash The hash of the order to unlock
     * @param _targetRoot The merkle root for verification
     * @param authToken The token associated with this request
     * @param timeToExpire The timestamp when this request will expire
     * @return message The generated hash of the unlock order request
     */
    function unlockOrderRequestHash(
        string memory adId,
        bytes32 orderHash,
        bytes32 _targetRoot,
        bytes32 authToken,
        uint256 timeToExpire
    ) public view returns (bytes32 message) {
        string memory action = "unlockOrder";
        bytes[] memory params = new bytes[](3);
        params[0] = abi.encode(adId);
        params[1] = abi.encode(orderHash);
        params[2] = abi.encode(_targetRoot);
        message = hashRequest(authToken, timeToExpire, action, params);
    }

    /*//////////////////////////////////////////////////////////////
                    EIP-712 — MINIMAL DOMAIN (NAME, VERSION)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Compute the minimal domain separator (name, version).
     * @dev Intentionally omits chainId and verifyingContract.
     * @return sep Domain separator used by {_hashTypedDataV4}.
     */
    function _domainSeparatorProofbridge() internal pure returns (bytes32 sep) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH_MIN, keccak256(bytes(_NAME)), keccak256(bytes(_VERSION))));
    }

    /**
     * @inheritdoc EIP712
     * @dev Uses the minimal domain from {_domainSeparatorProofbridge}.
     * @param structHash Struct hash (per EIP-712) to bind with the domain.
     * @return digest Final typed-data digest.
     */
    function _hashTypedDataV4(bytes32 structHash) internal view virtual override returns (bytes32 digest) {
        return MessageHashUtils.toTypedDataHash(_domainSeparatorProofbridge(), structHash);
    }

    /*//////////////////////////////////////////////////////////////
                              INTERNAL GUARDS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Load an ad and assert `maker` is the owner.
     * @param adId Ad identifier.
     * @param maker Expected owner (usually `msg.sender`).
     * @return ad Storage pointer to the ad.
     */
    function __getAdOwned(string memory adId, address maker) internal view returns (Ad storage ad) {
        ad = ads[adId];
        if (ad.maker == address(0)) revert AdManager__AdNotFound();
        if (ad.maker != maker) revert AdManager__NotMaker();
    }

    /**
     * @notice Validates an advertisement order against provided parameters and returns the order hash
     * @dev Internal function used to validate and hash order details
     * @param ad The Ad struct containing advertisement details to be validated
     * @param params The OrderParams struct containing order parameters to validate against
     * @return orderHash The computed hash of the validated order
     */
    function validateOrder(Ad memory ad, OrderParams calldata params) internal view returns (bytes32 orderHash) {
        if (!ad.open) revert AdManager__AdClosed();
        if (params.amount == 0) revert AdManager__ZeroAmount();
        if (params.bridger == address(0)) revert AdManager__BridgerZero();
        if (params.orderRecipient == address(0)) revert AdManager__RecipientZero();

        // Source chain must be supported and portal must match (if configured).
        ChainInfo memory ci = chains[params.orderChainId];
        if (!ci.supported) revert AdManager__ChainNotSupported(params.orderChainId);
        if (ci.orderPortal != address(0) && ci.orderPortal != params.srcOrderPortal) {
            revert AdManager__OrderPortalMismatch(ci.orderPortal, params.srcOrderPortal);
        }

        // Ad must serve the provided source chain.
        if (params.orderChainId != ad.orderChainId) {
            revert AdManager__OrderChainMismatch(ad.orderChainId, params.orderChainId);
        }

        // Token route: adChainToken (this chain) + orderChainId -> orderChainToken (source).
        address routed = tokenRoute[params.adChainToken][params.orderChainId];
        if (routed == address(0)) revert AdManager__MissingRoute(params.orderChainToken, block.chainid);
        if (routed != params.orderChainToken) revert AdManager__OrderTokenMismatch(routed, params.orderChainToken);

        // Identity and token checks.
        if (params.adCreator != ad.maker) revert AdManager__NotMaker();
        if (params.adChainToken != ad.token) revert AdManager__AdTokenMismatch(ad.token, params.adChainToken);
        if (params.adRecipient != ad.adRecipient) {
            revert AdManager__AdRecipientMismatch(ad.adRecipient, params.adRecipient);
        }

        orderHash = _hashOrder(params, getChainID(), address(this));
    }

    /**
     * @notice Check if the given token address represents the native token.
     * @param token The address of the token to check.
     * @return bool True if the token is the native token, false otherwise.
     */
    function isNativeToken(address token) internal pure returns (bool) {
        return token == NATIVE_TOKEN_ADDRESS;
    }

    receive() external payable {}
    fallback() external payable {}
}
