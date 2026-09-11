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
import {RootVerifierRegistry} from "./libraries/RootVerifierRegistry.sol";
import {TwoStepAdmin} from "./libraries/TwoStepAdmin.sol";
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
contract OrderPortal is TwoStepAdmin, Pausable, ReentrancyGuardTransient, RootVerifierRegistry {
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

    /// @notice Gas forwarded to the best-effort payout attempt in unlock.
    uint256 private constant _PAYOUT_GAS_LIMIT = 150_000;

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
        uint256 deadline;
        bytes32 adSettlementSigner;
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

    /// @notice Open (created, not yet unlocked) orders per universal account id.
    mapping(bytes32 => uint256) public inFlightOf;

    /// @notice Unlocked payouts awaiting claim: recipient => token => amount.
    mapping(address => mapping(address => uint256)) public claimable;

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

    error OrderPortal__InvalidProof();
    error OrderPortal__OrderExpired(uint256 deadline);
    error OrderPortal__NothingToClaim();
    error OrderPortal__SelfCallOnly();
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
    function createOrder(OrderParams calldata params)
        external
        payable
        nonReentrant
        whenNotPaused
        returns (bytes32 orderHash)
    {
        orderHash = validateOrder(params);

        if (orders[orderHash] != Status.None) revert OrderPortal__OrderExists(orderHash);

        address orderTokenAddr = params.orderChainToken.toAddressChecked();
        if (orderTokenAddr.isNative()) {
            if (msg.value < params.amount) revert OrderPortal__InsufficientLiquidity();
            wNativeToken.safeDeposit(params.amount);
        } else {
            if (msg.value != 0) revert OrderPortal__InsufficientLiquidity();
            IERC20(orderTokenAddr).safeTransferFrom(msg.sender, address(this), params.amount);
        }

        // orders are unlocked on the ad side (ad_contract = 1), so bind the leaf with side 1
        if (!i_merkleManager.appendOrderHash(orderHash, 1)) revert OrderPortal__MerkleManagerAppendFailed();

        orders[orderHash] = Status.Open;
        inFlightOf[params.adCreator]++;
        inFlightOf[params.bridger]++;

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
        OrderParams calldata params,
        bytes32 nullifierHash,
        bytes32 targetRoot,
        bytes calldata proof,
        bytes calldata cosigData
    ) external nonReentrant whenNotPaused {
        bytes32 orderHash = _hashOrder(params, block.chainid, address(this));

        if (nullifierUsed[nullifierHash]) revert OrderPortal__NullifierUsed(nullifierHash);
        if (orders[orderHash] != Status.Open) revert OrderPortal__OrderNotOpen(orderHash);
        if (block.timestamp > params.deadline) revert OrderPortal__OrderExpired(params.deadline);

        // Gate 2 — root authenticity. Mandatory: reverts with
        // NoRootVerifier when no module is configured for the ad chain.
        _requireRootValid(
            params.adChainId, targetRoot, RequestAuth.rootEnvelope(params.adSettlementSigner, params.bridger, cosigData)
        );

        bytes32[] memory publicInputs = RequestAuth.buildPublicInputs(
            i_merkleManager, nullifierHash, targetRoot, orderHash, _PUBLIC_INPUT_SIDE_ORDER
        );

        if (!i_verifier.verify(proof, publicInputs)) revert OrderPortal__InvalidProof();

        nullifierUsed[nullifierHash] = true;
        orders[orderHash] = Status.Filled;
        inFlightOf[params.adCreator]--;
        inFlightOf[params.bridger]--;

        address orderTokenAddr = params.orderChainToken.toAddressChecked();
        address adRecipientAddr = params.adRecipient.toAddressChecked();
        _payOrCredit(adRecipientAddr, orderTokenAddr, params.amount);

        emit OrderUnlocked(orderHash, params.adRecipient, nullifierHash);
    }

    /**
     * @notice Pay out a credited unlock. Permissionless: funds can only go to
     *         the credited recipient.
     */
    function claim(address recipient, address token) external nonReentrant whenNotPaused {
        uint256 amount = claimable[recipient][token];
        if (amount == 0) revert OrderPortal__NothingToClaim();
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
        if (msg.sender != address(this)) revert OrderPortal__SelfCallOnly();

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
     *         order created but not yet unlocked.
     */
    function hasOpenPositions(bytes32 account) external view returns (bool) {
        return inFlightOf[account] > 0;
    }

    /**
     * @notice Return configured destination token for a route.
     */
    function getDestToken(address orderToken, uint256 adChainId) external view returns (bytes32 adChainToken) {
        return tokenRoute[orderToken][adChainId];
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
            adDecimals: p.adDecimals,
            deadline: p.deadline,
            adSettlementSigner: p.adSettlementSigner
        });
        return OrderHash.digest(o);
    }

    /**
     * @notice Validates an order and computes its hash
     */
    function validateOrder(OrderParams calldata params) internal view returns (bytes32 orderHash) {
        if (params.amount == 0) revert OrderPortal__ZeroAmount();
        if (params.bridger != msg.sender.toBytes32()) revert OrderPortal__BridgerMustBeSender();
        OrderHash.checkWidths(params.amount, block.chainid, params.adChainId, params.deadline);
        if (params.adRecipient == bytes32(0)) revert OrderPortal__ZeroAddress();

        // validate recipient address
        params.adRecipient.assertEvmAddress();

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
