// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title OrderPortal (Proofbridge)
 * @notice Allows bridgers to open cross-chain *orders* by depositing `orderChainToken` on this chain.
 *         Makers (ad creators) later *unlock* those funds with proofs on this chain.
 *         The contract computes a minimal-domain EIP-712 order hash that serves as the canonical
 *         order identifier across components. Signatures are verified off-chain by a verifier.
 */
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EfficientHashLib} from "solady/utils/EfficientHashLib.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {MerkleManager} from "./MerkleManager.sol";
import {IVerifier} from "./Verifier.sol";
import {IMerkleManager} from "./MerkleManager.sol";
import {IwNativeToken, SafeNativeToken} from "./wNativeToken.sol";

contract OrderPortal is AccessControl, ReentrancyGuard, EIP712 {
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
     * @notice Primary EIP-712 typehash for orders
     */
    bytes32 public constant ORDER_TYPEHASH = keccak256(
        "Order(address orderChainToken,address adChainToken,uint256 amount,address bridger,uint256 orderChainId,address orderPortal,address orderRecipient,uint256 adChainId,address adManager,string adId,address adCreator,address adRecipient,uint256 salt)"
    );

    /// @notice Admin role
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
     * @notice Configuration for supported destination chains.
     * @param supported Whether the destination chain is supported
     * @param adManager Ad manager contract on the destination chain (counterpart).
     */
    struct ChainInfo {
        bool supported;
        address adManager;
    }

    /**
     * @notice Parameters supplied when creating or unlocking an order.
     * @dev All fields are used when hashing the order (see `_structHash`).
     * @param orderChainToken Current-chain ERC20 token being deposited.
     * @param adChainToken Ad-chain token (routing sanity check).
     * @param amount Amount of `orderChainToken` to deposit.
     * @param bridger Address of the bridger (user opening the order).
     * @param orderRecipient Recipient address of order maker on ad-chain.
     * @param adChainId Ad-chain id.
     * @param adManager Ad-chain ad-manager contract.
     * @param adId Ad-chain Ad id selected by maker.
     * @param adCreator Maker address (ad side notion).
     * @param adRecipient Recipient address of ad creator on on order-chain.
     * @param salt  Unique nonce to avoid hash collisions / replay
     */
    struct OrderParams {
        address orderChainToken;
        address adChainToken;
        uint256 amount;
        address bridger;
        address orderRecipient;
        uint256 adChainId;
        address adManager;
        string adId;
        address adCreator;
        address adRecipient;
        uint256 salt;
    }

    /// @notice Order lifecycle.
    enum Status {
        None, // Unknown / not created
        Open, // Created and funded
        Filled // Unlocked / paid out
    }

    /// @notice Destination chain configurations.
    mapping(uint256 => ChainInfo) public chains;

    /// @notice Supported token routes: order token → (adChainId → Ad token).
    mapping(address => mapping(uint256 => address)) public tokenRoute;

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
     * @param chainId Destination chain id.
     * @param adManager Destination ad-manager contract address.
     * @param supported Whether the chain is supported.
     */
    event ChainSet(uint256 indexed chainId, address indexed adManager, bool supported);

    /**
     * @notice Emitted when a token route is added or updated.
     * @param orderChainToken Source token on this chain.
     * @param adChainId Destination chain id.
     * @param adChainToken Destination token address.
     */
    event TokenRouteSet(address indexed orderChainToken, uint256 indexed adChainId, address indexed adChainToken);

    /**
     * @notice Emitted when a token route is removed.
     * @param orderChainToken Source token on this chain.
     * @param adChainId Destination chain id.
     */
    event TokenRouteRemoved(address indexed orderChainToken, uint256 indexed adChainId);

    /**
     * @notice Emitted when an order is created and funded.
     * @param orderHash EIP-712 order hash.
     * @param bridger Bridger address (msg.sender at creation).
     * @param orderChainToken Deposited token.
     * @param amount Amount deposited.
     * @param adChainId Destination chain id.
     * @param adChainToken Destination token (routing).
     * @param adManager Destination ad-manager address.
     * @param adId Destination ad id.
     * @param adCreator Maker address (destination notion).
     * @param adRecipient Ad maker recipient.
     */
    event OrderCreated(
        bytes32 indexed orderHash,
        address indexed bridger,
        address indexed orderChainToken,
        uint256 amount,
        uint256 adChainId,
        address adChainToken,
        address adManager,
        string adId,
        address adCreator,
        address adRecipient
    );

    /**
     * @notice Emitted when an order is unlocked after a valid proof.
     * @param orderHash EIP-712 order hash.
     * @param recipient Address that received the payout on this chain.
     * @param nullifierHash Consumed nullifier preventing reuse.
     */
    event OrderUnlocked(bytes32 indexed orderHash, address indexed recipient, bytes32 indexed nullifierHash);

    /**
     * @notice Emitted when a manager's status is updated
     * @param manager Address of the manager
     * @param status Boolean representing the new manager status
     */
    event UpdateManager(address indexed manager, bool status);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when the verifier rejects the proof.
    error OrderPortal__InvalidProof();
    /// @notice Thrown when a route is configured with a zero address.
    error OrderPortal__RoutesZeroAddress(address orderToken, address adToken);
    /// @notice Thrown when the destination chain is not supported.
    error OrderPortal__AdChainNotSupported(uint256 adChainId);
    /// @notice Thrown when `amount == 0`.
    error OrderPortal__ZeroAmount();
    /// @notice Thrown when the configured ad-manager does not match the provided one.
    error OrderPortal__AdManagerMismatch(address expected);
    /// @notice Thrown when a required route is missing.
    error OrderPortal__MissingRoute();
    /// @notice Thrown when the provided `adChainToken` does not match the configured route.
    error OrderPortal__AdTokenMismatch();
    /// @notice Thrown when an order already exists for the computed hash.
    error OrderPortal__OrderExists(bytes32 orderHash);
    /// @notice Thrown when a nullifier hash has already been used.
    error OrderPortal__NullifierUsed(bytes32 nullifierHash);
    /// @notice Thrown when the order is not open.
    error OrderPortal__OrderNotOpen(bytes32 orderHash);
    /// @notice Thrown when zero address is passed
    error OrderPortal__ZeroAddress();
    /// @notice Thrown when `bridger` is not `msg.sender`.
    error OrderPortal__BridgerMustBeSender();
    /// @notice Thrown when the ad recipient is the zero address.
    error OrderPortal__InvalidAdRecipient();
    /// @notice Thrown when the message is invalid
    error OrderPortal__InvalidMessage();
    /// @notice Thrown when the token has already been used
    error OrderPortal__TokenAlreadyUsed();
    /// @notice Thrown when the request token has expired
    error OrderPortal__RequestTokenExpired();
    /// @notice Thrown when the signer is the zero address
    error OrderPortal__ZeroSigner();
    /// @notice Thrown when the signer is not authorized as manager
    error OrderPortal__InvalidSigner();
    /// @notice Thrown when a request hash has already been processed
    error OrderPortal__RequestHashedProcessed();
    /// @notice Thrown when trying to append an order fails
    error OrderPortal__MerkleManagerAppendFailed();
    /// @notice Thrown when there is insufficient liquidity in deposits
    error OrderPortal__InsufficientLiquidity();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initializes roles and the external verifier.
     * @param admin Address that receives `ADMIN_ROLE`.
     * @param _verifier External proof verifier contract.
     */
    constructor(address admin, IVerifier _verifier, IMerkleManager _merkleManager, IwNativeToken _wNativeToken)
        EIP712(_NAME, _VERSION)
    {
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
     * @param _manager Address of the manager
     * @param _status Boolean representing the desired manager status
     */
    function setManager(address _manager, bool _status) external onlyRole(ADMIN_ROLE) {
        if (_manager == address(0)) {
            revert OrderPortal__ZeroAddress();
        }

        managers[_manager] = _status;
        emit UpdateManager(_manager, _status);
    }

    /*//////////////////////////////////////////////////////////////
                              ADMIN: CHAINS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure a destination chain.
     * @param adChainId Destination chain id.
     * @param adManager Destination ad-manager contract.
     * @param supported Whether the chain is supported.
     */
    function setChain(uint256 adChainId, address adManager, bool supported) external onlyRole(ADMIN_ROLE) {
        if (supported && adManager == address(0)) {
            revert OrderPortal__ZeroAddress();
        }
        chains[adChainId] = ChainInfo({supported: supported, adManager: adManager});
        emit ChainSet(adChainId, adManager, supported);
    }

    /**
     * @notice Remove a destination chain configuration.
     * @param adChainId Destination chain id to remove.
     */
    function removeChain(uint256 adChainId) external onlyRole(ADMIN_ROLE) {
        delete chains[adChainId];
        emit ChainSet(adChainId, address(0), false);
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN: TOKEN ROUTES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set or update a token route for a destination chain.
     * @param orderToken Source ERC20 token on this chain.
     * @param adChainId Destination chain id.
     * @param adToken Destination token address.
     */
    function setTokenRoute(address orderToken, uint256 adChainId, address adToken) external onlyRole(ADMIN_ROLE) {
        if (orderToken == address(0) || adToken == address(0)) {
            revert OrderPortal__RoutesZeroAddress(orderToken, adToken);
        }
        if (!chains[adChainId].supported) {
            revert OrderPortal__AdChainNotSupported(adChainId);
        }
        tokenRoute[orderToken][adChainId] = adToken;
        emit TokenRouteSet(orderToken, adChainId, adToken);
    }

    /**
     * @notice Remove a token route.
     * @param orderToken Source ERC20 token on this chain.
     * @param adChainId Destination chain id.
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
     * @param signature Signature over the pre-authorization request hash.
     * @param authToken Unique token for the delegated action (prevents replay).
     * @param timeToExpire Expiration time for the token (unix timestamp).
     * @param params See {OrderParams}.
     * @return orderHash The EIP-712 hash that identifies the order.
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

        if (requestHashes[message]) {
            revert OrderPortal__RequestHashedProcessed();
        }

        address signer = preAuthValidations(message, authToken, timeToExpire, signature);
        if (!managers[signer]) {
            revert OrderPortal__InvalidSigner();
        }

        if (isNativeToken(params.orderChainToken)) {
            if (msg.value < params.amount) {
                revert OrderPortal__InsufficientLiquidity();
            }
            wNativeToken.safeDeposit(params.amount);
        } else {
            IERC20(params.orderChainToken).safeTransferFrom(msg.sender, address(this), params.amount);
        }

        // append order hash
        if (!i_merkleManager.appendOrderHash(orderHash)) {
            revert OrderPortal__MerkleManagerAppendFailed();
        }

        orders[orderHash] = Status.Open;

        requestHashes[message] = true;

        emit OrderCreated(
            orderHash,
            msg.sender,
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
     * @dev
     * - The verifier checks the zk-proof against `publicInputs`.
     * - Consumes `nullifierHash` to prevent reuse across the system.
     * @param params The same order parameters used to derive the order hash.
     * @param nullifierHash One-time nullifier to prevent double claims.
     * @param proof proof bytes for the verifier.
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

        if (nullifierUsed[nullifierHash]) revert OrderPortal__NullifierUsed(nullifierHash);
        if (orders[orderHash] != Status.Open) revert OrderPortal__OrderNotOpen(orderHash);

        bytes32 message = unlockOrderRequestHash(params.adId, orderHash, targetRoot, authToken, timeToExpire);

        if (requestHashes[message]) {
            revert OrderPortal__RequestHashedProcessed();
        }

        address signer = preAuthValidations(message, authToken, timeToExpire, signature);

        if (!managers[signer]) {
            revert OrderPortal__InvalidSigner();
        }

        // Build public inputs for the verifier
        bytes32[] memory publicInputs = buildPublicInputs(nullifierHash, targetRoot, orderHash);

        if (!i_verifier.verify(proof, publicInputs)) revert OrderPortal__InvalidProof();

        nullifierUsed[nullifierHash] = true;
        orders[orderHash] = Status.Filled;

        requestHashes[message] = true;

        if (isNativeToken(params.orderChainToken)) {
            wNativeToken.safeWithdrawTo(params.amount, params.adRecipient);
        } else {
            IERC20(params.orderChainToken).safeTransfer(params.adRecipient, params.amount);
        }

        emit OrderUnlocked(orderHash, params.adRecipient, nullifierHash);
    }

    /*//////////////////////////////////////////////////////////////
                               VIEWS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Return configured destination token for a route.
     * @param orderToken Source token on this chain.
     * @param adChainId Destination chain id.
     * @return adChainToken Destination token address (zero if unset).
     */
    function getDestToken(address orderToken, uint256 adChainId) external view returns (address adChainToken) {
        return tokenRoute[orderToken][adChainId];
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
     * @notice Return the merkle manager root
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
            revert OrderPortal__InvalidMessage();
        }

        if (requestTokens[authToken]) {
            revert OrderPortal__TokenAlreadyUsed();
        }

        if (block.timestamp > timeToExpire) {
            revert OrderPortal__RequestTokenExpired();
        }

        address signer = getSigner(_message, signature);

        if (signer == address(0)) {
            revert OrderPortal__ZeroSigner();
        }

        requestTokens[authToken] = true;

        return signer;
    }

    /**
     * @notice Find the signer
     * @param message The message that the user signed
     * @param signature Signature
     * @return address Signer of the message
     */
    function getSigner(bytes32 message, bytes memory signature) public pure returns (address) {
        message = MessageHashUtils.toEthSignedMessageHash(message);
        address signer = ECDSA.recover(message, signature);
        return signer;
    }

    /**
     * @notice Get the ID of the executing chain
     * @return uint256 value
     */
    function getChainID() public view returns (uint256) {
        uint256 id;
        assembly {
            id := chainid()
        }
        return id;
    }

    /**
     * @notice Validates an order and computes its hash
     * @dev Internal view function that validates order parameters and returns order hash
     * @param params The order parameters struct containing details to validate
     * @return orderHash The computed hash of the validated order
     */
    function validateOrder(OrderParams calldata params) internal view returns (bytes32 orderHash) {
        if (params.amount == 0) revert OrderPortal__ZeroAmount();
        if (params.bridger != msg.sender) revert OrderPortal__BridgerMustBeSender();
        if (params.adRecipient == address(0)) revert OrderPortal__ZeroAddress();

        ChainInfo memory ci = chains[params.adChainId];
        if (!ci.supported) revert OrderPortal__AdChainNotSupported(params.adChainId);
        if (ci.adManager == address(0) || ci.adManager != params.adManager) {
            revert OrderPortal__AdManagerMismatch(ci.adManager);
        }

        address route = tokenRoute[params.orderChainToken][params.adChainId];
        if (route == address(0)) revert OrderPortal__MissingRoute();
        if (route != params.adChainToken) revert OrderPortal__AdTokenMismatch();

        orderHash = _hashOrder(params, getChainID(), address(this));
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
     * @notice Compute the final EIP-712 order digest (with minimal domain).
     * @param p Order parameters.
     * @param orderChainId Source chain id (current chain).
     * @param orderPortal Source contract address (this contract).
     * @return digest The typed-data digest.
     */
    function _hashOrder(OrderParams calldata p, uint256 orderChainId, address orderPortal)
        internal
        view
        returns (bytes32 digest)
    {
        return _hashTypedDataV4(_structHash(p, orderChainId, orderPortal));
    }

    /**
     * @notice Compute the `keccak256(abi.encode(..))` struct hash for `Order`.
     * @dev Field order/type MUST match `ORDER_TYPEHASH`.
     */
    function _structHash(OrderParams calldata p, uint256 orderChainId, address orderPortal)
        internal
        pure
        returns (bytes32)
    {
        // Efficient hashing via Solady buffer (14 elements).
        bytes32[] memory buf = EfficientHashLib.malloc(14);
        EfficientHashLib.set(buf, 0, ORDER_TYPEHASH);
        EfficientHashLib.set(buf, 1, toBytes32(p.orderChainToken));
        EfficientHashLib.set(buf, 2, toBytes32(p.adChainToken));
        EfficientHashLib.set(buf, 3, p.amount);
        EfficientHashLib.set(buf, 4, toBytes32(p.bridger));
        EfficientHashLib.set(buf, 5, orderChainId);
        EfficientHashLib.set(buf, 6, toBytes32(orderPortal));
        EfficientHashLib.set(buf, 7, toBytes32(p.orderRecipient));
        EfficientHashLib.set(buf, 8, p.adChainId);
        EfficientHashLib.set(buf, 9, toBytes32(p.adManager));
        EfficientHashLib.set(buf, 10, keccak256(bytes(p.adId)));
        EfficientHashLib.set(buf, 11, toBytes32(p.adCreator));
        EfficientHashLib.set(buf, 12, toBytes32(p.adRecipient));
        EfficientHashLib.set(buf, 13, p.salt);
        return EfficientHashLib.hash(buf);
    }

    /**
     * @notice Cast an address to bytes32 (left-padded).
     * @param value Address value.
     * @return out Bytes32 representation.
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
        inputs[3] = bytes32(uint256(0));
    }

    /**
     * @notice Creates a hash for an order request
     * @dev Generates a unique hash combining ad ID, order hash, token, and expiration time
     * @param adId The identifier of the advertisement
     * @param orderHash The hash of the order details
     * @param authToken The token identifier used for the request
     * @param timeToExpire The timestamp when the request expires
     * @return message The generated hash of the request
     */
    function createOrderRequestHash(string memory adId, bytes32 orderHash, bytes32 authToken, uint256 timeToExpire)
        public
        view
        returns (bytes32 message)
    {
        string memory action = "createOrder";
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
                      EIP-712 (CUSTOM MINIMAL DOMAIN)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Compute the minimal EIP-712 domain separator: `name` + `version`.
     * @dev Omits chainId & verifyingContract on purpose — do NOT remove replay
     *      guards from the struct if you rely on this.
     */
    function _domainSeparatorProofbridge() internal pure returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH_MIN, keccak256(bytes(_NAME)), keccak256(bytes(_VERSION))));
    }

    /**
     * @inheritdoc EIP712
     * @dev Overridden to use the minimal Proofbridge domain separator above.
     */
    function _hashTypedDataV4(bytes32 structHash) internal view virtual override returns (bytes32) {
        return MessageHashUtils.toTypedDataHash(_domainSeparatorProofbridge(), structHash);
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
