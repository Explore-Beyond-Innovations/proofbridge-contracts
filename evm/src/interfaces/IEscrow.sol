// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IVerifier} from "./IVerifier.sol";
import {IMerkleManager} from "./IMerkleManager.sol";
import {IwNativeToken} from "../wNativeToken.sol";

/**
 * @title IEscrow — what both escrows (AdManager, OrderPortal) share.
 * @notice One order = one 17-field EIP-712 hash on both chains; each escrow holds one leg of it,
 *         appends that leg's leaf to the chain's MMR, and settles it on a proof about the other
 *         leg. The types, events and errors here are the shared half; each escrow's own
 *         interface adds its leg.
 */
interface IEscrow {
    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Order lifecycle. `None` is "never seen on this chain".
    enum Status {
        None,
        Open,
        Filled
    }

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice A peer chain's escrow was set (`peer == 0` removes the chain).
    event PeerEscrowSet(uint256 indexed chainId, bytes32 indexed peer);
    /// @notice A token route was set: local token ↔ the peer chain's token id.
    event TokenRouteSet(address indexed localToken, uint256 indexed peerChainId, bytes32 indexed peerToken);
    event TokenRouteRemoved(address indexed localToken, uint256 indexed peerChainId);
    /// @notice An order settled on this chain with a valid proof (the leg is `Filled`).
    event OrderUnlocked(bytes32 indexed orderHash, bytes32 indexed recipient, bytes32 indexed nullifierHash);
    /// @notice A payout could not be pushed and was credited for `claim`.
    event PayoutCredited(address indexed recipient, address indexed token, uint256 amount);
    event PayoutClaimed(address indexed recipient, address indexed token, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error Escrow__ZeroAddress();
    error Escrow__ZeroAmount();
    error Escrow__ChainNotSupported(uint256 chainId);
    error Escrow__RouteZeroAddress();
    error Escrow__MissingRoute(bytes32 peerToken, uint256 peerChainId);
    error Escrow__PeerTokenMismatch(bytes32 expected, bytes32 provided);
    error Escrow__OrderExists(bytes32 orderHash);
    error Escrow__OrderNotOpen(bytes32 orderHash);
    error Escrow__OrderExpired(uint256 deadline);
    error Escrow__NullifierUsed(bytes32 nullifierHash);
    error Escrow__InvalidProof();
    error Escrow__InsufficientLiquidity();
    error Escrow__MerkleManagerAppendFailed();
    error Escrow__NothingToClaim();
    error Escrow__SelfCallOnly();

    /*//////////////////////////////////////////////////////////////
                                 ADMIN
    //////////////////////////////////////////////////////////////*/

    function pause() external;
    function unpause() external;
    /// @notice Set the peer escrow for a chain (the OrderPortal for an AdManager, and vice versa);
    ///         zero removes the chain.
    function setPeerEscrow(uint256 chainId, bytes32 peer) external;
    function setRootVerifier(uint256 chainId, address verifier) external;
    function setTokenRoute(address localToken, uint256 peerChainId, bytes32 peerToken) external;
    function removeTokenRoute(address localToken, uint256 peerChainId) external;

    /*//////////////////////////////////////////////////////////////
                                 ACTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Pay out a credited payout. Permissionless: funds only ever go to the credited recipient.
    function claim(address recipient, address token) external;

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    function i_verifier() external view returns (IVerifier);
    function i_merkleManager() external view returns (IMerkleManager);
    function i_wNativeToken() external view returns (IwNativeToken);
    function peerEscrow(uint256 chainId) external view returns (bytes32);
    function tokenRoute(address localToken, uint256 peerChainId) external view returns (bytes32);
    function orders(bytes32 orderHash) external view returns (Status);
    function nullifierUsed(bytes32 nullifierHash) external view returns (bool);
    function inFlightOf(bytes32 account) external view returns (uint256);
    function claimable(address recipient, address token) external view returns (uint256);
    /// @notice BLSKeyRegistry revoke guard: true while the account has a leg open on this escrow.
    function hasOpenPositions(bytes32 account) external view returns (bool);
    function getLatestMerkleRoot() external view returns (bytes32);
    function getHistoricalRoot(uint256 index) external view returns (bytes32);
    function getMerkleLeafCount() external view returns (uint256);
}
