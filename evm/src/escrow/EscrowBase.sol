// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {IEscrow} from "../interfaces/IEscrow.sol";
import {IVerifier} from "../interfaces/IVerifier.sol";
import {IMerkleManager} from "../interfaces/IMerkleManager.sol";
import {IwNativeToken, SafeNativeToken} from "../wNativeToken.sol";
import {AddressCast} from "../libraries/AddressCast.sol";
import {RequestAuth} from "../libraries/RequestAuth.sol";
import {RootVerifierRegistry} from "../libraries/RootVerifierRegistry.sol";
import {TwoStepAdmin} from "../libraries/TwoStepAdmin.sol";

/**
 * @title EscrowBase (Proofbridge)
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice Everything the two escrows share: the admin surface (pause, peers, routes, root
 *         verifiers), the order ledger (`orders`, `nullifierUsed`, `inFlightOf`), the pull-payment
 *         escrow (`claimable`), funds in/out for ERC20 and the native sentinel, the proof core an
 *         unlock runs, and the MMR seam. `AdManager` and `OrderPortal` add their own leg on top.
 * @dev Storage is laid out here first; the inheritors append. Immutables never touch storage.
 */
abstract contract EscrowBase is IEscrow, TwoStepAdmin, Pausable, ReentrancyGuardTransient, RootVerifierRegistry {
    using SafeERC20 for IERC20;
    using SafeNativeToken for IwNativeToken;
    using AddressCast for address;
    using AddressCast for bytes32;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Admin role identifier.
    bytes32 public constant ADMIN_ROLE = DEFAULT_ADMIN_ROLE;

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

    /// @notice Order status by EIP-712 hash.
    mapping(bytes32 orderHash => Status) public orders;

    /// @notice Consumed nullifiers; one settlement proof per nullifier, protocol-wide.
    mapping(bytes32 nullifierHash => bool) public nullifierUsed;

    /// @notice Open legs per universal account id — the BLSKeyRegistry revoke guard's source.
    mapping(bytes32 account => uint256) public inFlightOf;

    /// @notice Payouts awaiting `claim`: recipient → token → amount.
    mapping(address recipient => mapping(address token => uint256)) public claimable;

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

    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    /// @inheritdoc IEscrow
    function setPeerEscrow(uint256 chainId, bytes32 peer) external onlyRole(ADMIN_ROLE) {
        peerEscrow[chainId] = peer;
        emit PeerEscrowSet(chainId, peer);
    }

    /// @inheritdoc IEscrow
    function setRootVerifier(uint256 chainId, address verifier) external onlyRole(ADMIN_ROLE) {
        _setRootVerifier(chainId, verifier);
    }

    /// @inheritdoc IEscrow
    function setTokenRoute(address localToken, uint256 peerChainId, bytes32 peerToken) external onlyRole(ADMIN_ROLE) {
        if (localToken == address(0) || peerToken == bytes32(0)) revert Escrow__RouteZeroAddress();
        if (peerEscrow[peerChainId] == bytes32(0)) revert Escrow__ChainNotSupported(peerChainId);
        tokenRoute[localToken][peerChainId] = peerToken;
        emit TokenRouteSet(localToken, peerChainId, peerToken);
    }

    /// @inheritdoc IEscrow
    function removeTokenRoute(address localToken, uint256 peerChainId) external onlyRole(ADMIN_ROLE) {
        delete tokenRoute[localToken][peerChainId];
        emit TokenRouteRemoved(localToken, peerChainId);
    }

    /*//////////////////////////////////////////////////////////////
                                PAYOUTS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IEscrow
    function claim(address recipient, address token) external nonReentrant whenNotPaused {
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

    /// @dev `None → Open`; a second lock/create of the same hash reverts.
    function _openOrder(bytes32 orderHash) internal {
        if (orders[orderHash] != Status.None) revert Escrow__OrderExists(orderHash);
        orders[orderHash] = Status.Open;
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

    function _requireBeforeDeadline(uint256 deadline) internal view {
        if (block.timestamp > deadline) revert Escrow__OrderExpired(deadline);
    }

    /*//////////////////////////////////////////////////////////////
                               PROOF CORE
    //////////////////////////////////////////////////////////////*/

    /// @dev Cheap gates first: the nullifier is fresh and the leg is open.
    function _requireSettleable(bytes32 orderHash, bytes32 nullifierHash) internal view {
        if (nullifierUsed[nullifierHash]) revert Escrow__NullifierUsed(nullifierHash);
        if (orders[orderHash] != Status.Open) revert Escrow__OrderNotOpen(orderHash);
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
        bytes32[] memory publicInputs = RequestAuth.buildPublicInputs(
            i_merkleManager, nullifierHash, targetRoot, orderHash, side
        );
        if (!i_verifier.verify(proof, publicInputs)) revert Escrow__InvalidProof();
    }

    /// @dev The state half of a settlement: consume the nullifier, `Open → Filled`, count out.
    function _settle(bytes32 orderHash, bytes32 nullifierHash, bytes32 account) internal {
        nullifierUsed[nullifierHash] = true;
        orders[orderHash] = Status.Filled;
        _countOut(account);
    }

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IEscrow
    function hasOpenPositions(bytes32 account) external view returns (bool) {
        return inFlightOf[account] > 0;
    }

    /// @inheritdoc IEscrow
    function getLatestMerkleRoot() external view returns (bytes32) {
        return i_merkleManager.getRoot();
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
