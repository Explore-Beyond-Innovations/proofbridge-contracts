// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {IVerifier} from "./Verifier.sol";
import {IMerkleManager} from "./MerkleManager.sol";
import {IwNativeToken, SafeNativeToken} from "./wNativeToken.sol";
import {DecimalScaling} from "./libraries/DecimalScaling.sol";
import {OrderHash} from "./libraries/OrderHash.sol";
import {RequestAuth} from "./libraries/RequestAuth.sol";
import {AddressCast} from "./libraries/AddressCast.sol";

/**
 * @title OrderPortal (Proofbridge)
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice Allows bridgers to open cross-chain *orders* by depositing `orderChainToken` on this chain.
 *         Makers (ad creators) later *unlock* those funds with proofs on this chain.
 *         The contract computes a minimal-domain EIP-712 order hash that serves as the canonical
 *         order identifier across components. Signatures are verified off-chain by a verifier.
 */
contract OrderPortal is AccessControl, ReentrancyGuardTransient {
    using SafeERC20 for IERC20;
    using SafeNativeToken for IwNativeToken;
    using AddressCast for address;
    using AddressCast for bytes32;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Admin role
    bytes32 public constant ADMIN_ROLE = DEFAULT_ADMIN_ROLE;

    /// @notice Side flag for proof public inputs on the order-chain side.
    uint256 private constant _PUBLIC_INPUT_SIDE_ORDER = 0;

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configuration for supported destination chains.
     */
    struct ChainInfo {
        bool supported;
        bytes32 adManager;
    }

    /**
     * @notice Parameters supplied when creating or unlocking an order.
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
        bytes32 orderRecipient;
        uint256 adChainId;
        bytes32 adManager;
        string adId;
        bytes32 adCreator;
        bytes32 adRecipient;
        uint256 salt;
        uint8 orderDecimals;
        uint8 adDecimals;
    }

    /// @notice Order lifecycle.
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

    /// @notice Destination chain configurations.
    mapping(uint256 => ChainInfo) public chains;

    /// @notice Supported token routes: order token → (adChainId → Ad token as 32-byte cross-chain id).
    mapping(address => mapping(uint256 => bytes32)) public tokenRoute;

    /// @notice Order status by EIP-712 hash.
    mapping(bytes32 => Status) public orders;

    /// @notice Consumed nullifiers to prevent double-use across the system.
    mapping(bytes32 => bool) public nullifierUsed;

    /// @notice Tracks manager permissions for addresses
    mapping(address => bool) public managers;

    /// @notice Request tokens tracker to prevent replay attacks
    mapping(bytes32 => bool) public requestTokens;

    /// @notice Request hash tracker to prevent replay attacks
    mapping(bytes32 => bool) public requestHashes;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Emitted when a destination chain config is set or updated.
     */
    event ChainSet(uint256 indexed chainId, bytes32 indexed adManager, bool supported);

    /**
     * @notice Emitted when a token route is added or updated.
     */
    event TokenRouteSet(address indexed orderChainToken, uint256 indexed adChainId, bytes32 indexed adChainToken);

    /**
     * @notice Emitted when a token route is removed.
     */
    event TokenRouteRemoved(address indexed orderChainToken, uint256 indexed adChainId);

    /**
     * @notice Emitted when an order is created and funded.
     */
    event OrderCreated(
        bytes32 indexed orderHash,
        bytes32 indexed bridger,
        bytes32 indexed orderChainToken,
        uint256 amount,
        uint256 adChainId,
        bytes32 adChainToken,
        bytes32 adManager,
        string adId,
        bytes32 adCreator,
        bytes32 adRecipient
    );

    /**
     * @notice Emitted when an order is unlocked after a valid proof.
     */
    event OrderUnlocked(bytes32 indexed orderHash, bytes32 indexed recipient, bytes32 indexed nullifierHash);

    /**
     * @notice Emitted when a manager's status is updated
     */
    event UpdateManager(address indexed manager, bool status);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error OrderPortal__InvalidProof();
    error OrderPortal__RoutesZeroAddress(address orderToken, bytes32 adToken);
    error OrderPortal__AdChainNotSupported(uint256 adChainId);
    error OrderPortal__ZeroAmount();
    error OrderPortal__AdManagerMismatch(bytes32 expected);
    error OrderPortal__MissingRoute();
    error OrderPortal__AdTokenMismatch();
    error OrderPortal__OrderExists(bytes32 orderHash);
    error OrderPortal__NullifierUsed(bytes32 nullifierHash);
    error OrderPortal__OrderNotOpen(bytes32 orderHash);
    error OrderPortal__ZeroAddress();
    error OrderPortal__BridgerMustBeSender();
    error OrderPortal__TokenAlreadyUsed();
    error OrderPortal__InvalidSigner();
    error OrderPortal__RequestHashedProcessed();
    error OrderPortal__MerkleManagerAppendFailed();
    error OrderPortal__InsufficientLiquidity();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initializes roles and the external verifier.
     */
    constructor(address admin, IVerifier _verifier, IMerkleManager _merkleManager, IwNativeToken _wNativeToken) {
        if (admin == address(0) || address(_verifier) == address(0) || address(_merkleManager) == address(0)) {
            revert OrderPortal__ZeroAddress();
        }
        _grantRole(ADMIN_ROLE, admin);
        i_verifier = _verifier;
        i_merkleManager = _merkleManager;
        managers[admin] = true;
        wNativeToken = _wNativeToken;
    }

    /*//////////////////////////////////////////////////////////////
                              ADMIN: MANAGERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Sets or unsets an address as a manager
     */
    function setManager(address _manager, bool _status) external onlyRole(ADMIN_ROLE) {
        if (_manager == address(0)) revert OrderPortal__ZeroAddress();
        managers[_manager] = _status;
        emit UpdateManager(_manager, _status);
    }

    /*//////////////////////////////////////////////////////////////
                              ADMIN: CHAINS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure a destination chain.
     */
    function setChain(uint256 adChainId, bytes32 adManager, bool supported) external onlyRole(ADMIN_ROLE) {
        if (supported && adManager == bytes32(0)) revert OrderPortal__ZeroAddress();
        chains[adChainId] = ChainInfo({supported: supported, adManager: adManager});
        emit ChainSet(adChainId, adManager, supported);
    }

    /**
     * @notice Remove a destination chain configuration.
     */
    function removeChain(uint256 adChainId) external onlyRole(ADMIN_ROLE) {
        delete chains[adChainId];
        emit ChainSet(adChainId, bytes32(0), false);
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN: TOKEN ROUTES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set or update a token route for a destination chain.
     */
    function setTokenRoute(address orderToken, uint256 adChainId, bytes32 adToken) external onlyRole(ADMIN_ROLE) {
        if (orderToken == address(0) || adToken == bytes32(0)) {
            revert OrderPortal__RoutesZeroAddress(orderToken, adToken);
        }
        if (!chains[adChainId].supported) revert OrderPortal__AdChainNotSupported(adChainId);
        tokenRoute[orderToken][adChainId] = adToken;
        emit TokenRouteSet(orderToken, adChainId, adToken);
    }

    /**
     * @notice Remove a token route.
     */
    function removeTokenRoute(address orderToken, uint256 adChainId) external onlyRole(ADMIN_ROLE) {
        delete tokenRoute[orderToken][adChainId];
        emit TokenRouteRemoved(orderToken, adChainId);
    }

    /*///////////////////////////////////////////////////////////////////
                               BRIDGER ACTION — CREATE ORDER
    ///////////////////////////////////////////////////////////////////*/

    /**
     * @notice Create and fund an order; tokens are transferred to this contract.
     */
    function createOrder(bytes memory signature, bytes32 authToken, uint256 timeToExpire, OrderParams calldata params)
        external
        payable
        nonReentrant
        returns (bytes32 orderHash)
    {
        orderHash = validateOrder(params);

        if (orders[orderHash] != Status.None) revert OrderPortal__OrderExists(orderHash);

        bytes32 message = createOrderRequestHash(params.adId, orderHash, authToken, timeToExpire);

        if (requestHashes[message]) revert OrderPortal__RequestHashedProcessed();

        _consumeAuth(message, authToken, timeToExpire, signature);

        address orderTokenAddr = params.orderChainToken.toAddressChecked();
        if (orderTokenAddr.isNative()) {
            if (msg.value < params.amount) revert OrderPortal__InsufficientLiquidity();
            wNativeToken.safeDeposit(params.amount);
        } else {
            if (msg.value != 0) revert OrderPortal__InsufficientLiquidity();
            IERC20(orderTokenAddr).safeTransferFrom(msg.sender, address(this), params.amount);
        }

        if (!i_merkleManager.appendOrderHash(orderHash)) revert OrderPortal__MerkleManagerAppendFailed();

        orders[orderHash] = Status.Open;

        requestHashes[message] = true;

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

    /**
     * @notice Unlock an order after a valid proof and pay out the destination recipient on this chain.
     */
    function unlock(
        bytes memory signature,
        bytes32 authToken,
        uint256 timeToExpire,
        OrderParams calldata params,
        bytes32 nullifierHash,
        bytes32 targetRoot,
        bytes calldata proof
    ) external nonReentrant {
        bytes32 orderHash = _hashOrder(params, block.chainid, address(this));

        if (nullifierUsed[nullifierHash]) revert OrderPortal__NullifierUsed(nullifierHash);
        if (orders[orderHash] != Status.Open) revert OrderPortal__OrderNotOpen(orderHash);

        bytes32 message = unlockOrderRequestHash(params.adId, orderHash, targetRoot, authToken, timeToExpire);

        if (requestHashes[message]) revert OrderPortal__RequestHashedProcessed();

        _consumeAuth(message, authToken, timeToExpire, signature);

        bytes32[] memory publicInputs = RequestAuth.buildPublicInputs(
            i_merkleManager, nullifierHash, targetRoot, orderHash, _PUBLIC_INPUT_SIDE_ORDER
        );

        if (!i_verifier.verify(proof, publicInputs)) revert OrderPortal__InvalidProof();

        nullifierUsed[nullifierHash] = true;
        orders[orderHash] = Status.Filled;

        requestHashes[message] = true;

        address orderTokenAddr = params.orderChainToken.toAddressChecked();
        address adRecipientAddr = params.adRecipient.toAddressChecked();
        if (orderTokenAddr.isNative()) {
            wNativeToken.safeWithdrawTo(params.amount, adRecipientAddr);
        } else {
            IERC20(orderTokenAddr).safeTransfer(adRecipientAddr, params.amount);
        }

        emit OrderUnlocked(orderHash, params.adRecipient, nullifierHash);
    }

    /*//////////////////////////////////////////////////////////////
                               VIEWS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Return configured destination token for a route.
     */
    function getDestToken(address orderToken, uint256 adChainId) external view returns (bytes32 adChainToken) {
        return tokenRoute[orderToken][adChainId];
    }

    /**
     * @notice Check if a request hash exists
     */
    function checkRequestHashExists(bytes32 message) external view returns (bool) {
        return requestHashes[message];
    }

    /**
     * @notice Return the merkle manager root
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
                              HASH HELPERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Creates a hash for an order request
     */
    function createOrderRequestHash(string memory adId, bytes32 orderHash, bytes32 authToken, uint256 timeToExpire)
        public
        view
        returns (bytes32 message)
    {
        bytes[] memory params = new bytes[](2);
        params[0] = abi.encode(adId);
        params[1] = abi.encode(orderHash);
        message = RequestAuth.hashRequest(authToken, timeToExpire, "createOrder", params, block.chainid, address(this));
    }

    /**
     * @notice Generates a hash for unlocking an advertisement order
     */
    function unlockOrderRequestHash(
        string memory adId,
        bytes32 orderHash,
        bytes32 _targetRoot,
        bytes32 authToken,
        uint256 timeToExpire
    ) public view returns (bytes32 message) {
        bytes[] memory params = new bytes[](3);
        params[0] = abi.encode(adId);
        params[1] = abi.encode(orderHash);
        params[2] = abi.encode(_targetRoot);
        message = RequestAuth.hashRequest(authToken, timeToExpire, "unlockOrder", params, block.chainid, address(this));
    }

    /*//////////////////////////////////////////////////////////////
                              INTERNAL LOGIC
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Compute the EIP-712 order digest. Builds the canonical
     *         cross-chain tuple from this contract's local `OrderParams` plus
     *         the order-chain-local context, then defers to {OrderHash}.
     */
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
            orderPortal: AddressCast.toBytes32(orderPortal),
            orderRecipient: p.orderRecipient,
            adChainId: p.adChainId,
            adManager: p.adManager,
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
     * @notice Verify and consume a pre-authorization: signer must be a
     *         manager, deadline must not have passed, and the authToken must
     *         not have been used before.
     */
    function _consumeAuth(bytes32 message, bytes32 authToken, uint256 timeToExpire, bytes memory signature) internal {
        if (requestTokens[authToken]) revert OrderPortal__TokenAlreadyUsed();
        RequestAuth.assertNotExpired(timeToExpire);
        address signer = RequestAuth.recoverSigner(message, signature);
        if (!managers[signer]) revert OrderPortal__InvalidSigner();
        requestTokens[authToken] = true;
    }

    /**
     * @notice Validates an order and computes its hash
     */
    function validateOrder(OrderParams calldata params) internal view returns (bytes32 orderHash) {
        if (params.amount == 0) revert OrderPortal__ZeroAmount();
        if (params.bridger != msg.sender.toBytes32()) revert OrderPortal__BridgerMustBeSender();
        if (params.adRecipient == bytes32(0)) revert OrderPortal__ZeroAddress();

        // Cap both signed decimals; adDecimals is checked here (not just at scale time on
        // the ad chain) so invalid routes fail fast at create-time too.
        DecimalScaling.assertInRange(params.orderDecimals);
        DecimalScaling.assertInRange(params.adDecimals);

        ChainInfo memory ci = chains[params.adChainId];
        if (!ci.supported) revert OrderPortal__AdChainNotSupported(params.adChainId);
        if (ci.adManager == bytes32(0) || ci.adManager != params.adManager) {
            revert OrderPortal__AdManagerMismatch(ci.adManager);
        }

        // tokenRoute is keyed by the local ERC20 address; params.orderChainToken is
        // the 32-byte cross-chain form — extract the low 20 bytes for lookup.
        address orderTokenAddr = params.orderChainToken.toAddressChecked();
        bytes32 route = tokenRoute[orderTokenAddr][params.adChainId];
        if (route == bytes32(0)) revert OrderPortal__MissingRoute();
        if (route != params.adChainToken) revert OrderPortal__AdTokenMismatch();

        // Defense-in-depth: verify the signed orderDecimals agrees with the on-chain token.
        DecimalScaling.assertMatchesOnChain(orderTokenAddr, params.orderDecimals);

        orderHash = _hashOrder(params, block.chainid, address(this));
    }

    receive() external payable {}
    fallback() external payable {}
}
