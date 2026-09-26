// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IVerifier} from "./IVerifier.sol";
import {IMerkleManager} from "./IMerkleManager.sol";
import {IwNativeToken} from "../wNativeToken.sol";
import {IRootAnchor} from "./IRootAnchor.sol";
import {IDisputeManager} from "./IDisputeManager.sol";
import {RouteTiming} from "../libraries/RouteTiming.sol";
import {Termination} from "../libraries/Termination.sol";

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

    /**
     * @notice Order lifecycle. `None` is "never seen on this chain"; `Filled`, `Cancelled` and
     *         `Resolved` are terminal; `Claimed` is a presentation window (2.3e); `Disputed` is an
     *         open dispute on the primary leg and `Resolved` its finalized end (2.3g).
     */
    enum Status {
        None,
        Open,
        Filled,
        Claimed,
        Cancelled,
        Disputed,
        Resolved
    }

    /// @notice The order's leg on this chain, one slot: its status, the escrow's paused-seconds
    ///         counter when the leg opened (a pause stops the window's clock, see `pausedSeconds`),
    ///         and when it opened (#422: a registry kill since then is a denied payout).
    struct Order {
        Status status;
        uint64 pausedAtOpen;
        uint64 lockedAt;
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
    /// @notice The leg reached `Filled`; `byEvidence` is true for `presentSettled` (a proof of the
    ///         other leg), false for the co-signed `unlock`. The SETTLED leaf follows via `recordSettled`.
    event OrderSettled(bytes32 indexed orderHash, bool byEvidence);
    /// @notice The leg's SETTLED leaf was appended (`recordSettled`).
    event SettledRecorded(bytes32 indexed orderHash);
    /// @notice A presentation window opened on this leg; it may be finalized at `finalizeAt`.
    event ClaimOpened(bytes32 indexed orderHash, Termination.ClaimEntry entry, uint64 finalizeAt);
    /// @notice The leg reached `Cancelled`; `byEvidence` is true for the follower's `refundByCancel`
    ///         (a proof of the primary's cancel leaf), false for every clock-driven finalize.
    event OrderCancelled(bytes32 indexed orderHash, bool byEvidence);
    event RouteTimingSet(uint256 indexed chainId, RouteTiming.Timing timing);
    event RootAnchorSet(address indexed rootAnchor);
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
    /// @notice `deadline` is closer than the route's `minWindow` (2.3e D5).
    error Escrow__DeadlineTooSoon(uint256 deadline, uint256 minAllowed);
    error Escrow__DeadlineTooFar(uint256 deadline, uint256 maxAllowed);
    /// @notice The clock the caller relies on has not been reached yet.
    error Escrow__TooEarly(uint256 at);
    /// @notice The order is not in a state this path accepts (`Open`, `Claimed`, or `None`, as documented).
    error Escrow__NotClaimable(bytes32 orderHash, Status status);
    /// @notice No presentation window is open on the order.
    error Escrow__NotClaimed(bytes32 orderHash);
    error Escrow__NoRootAnchor();
    error Escrow__RootNotAnchored(uint256 chainId, bytes32 root);
    /// @notice `recordSettled`: the order is not `Filled`.
    error Escrow__NotFilled(bytes32 orderHash);
    /// @notice `recordSettled`: the order's SETTLED leaf is already in the MMR.
    error Escrow__SettledRecorded(bytes32 orderHash);
    /// @notice The order is not in a state a dispute can be filed on.
    error Escrow__NotDisputable(bytes32 orderHash, Status status);

    /// @notice Only the order's two parties may file or respond to a dispute (2.3g D11).
    error Escrow__NotAParty(address caller);
    /// @notice No dispute module is wired, so disputes are unavailable on this escrow.
    error Escrow__NoDisputeManager();
    /// @notice The dispute has not reached a terminal state yet.
    error Escrow__DisputeNotResolved(bytes32 orderHash);

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
    /// @notice Set the termination clocks for a peer chain (validated; 2.3e D6).
    function setRouteTiming(uint256 chainId, RouteTiming.Timing calldata timing) external;
    /// @notice Set the notary the evidence paths (`presentSettled`, `refundByCancel`) read (2.3e D7).
    function setRootAnchor(IRootAnchor anchor) external;

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
    /// @notice The paused-seconds counter when the leg opened; the window's clock starts there.
    function orderPausedAtOpen(bytes32 orderHash) external view returns (uint64);
    function nullifierUsed(bytes32 nullifierHash) external view returns (bool);
    function inFlightOf(bytes32 account) external view returns (uint256);
    function claimable(address recipient, address token) external view returns (uint256);
    function routeTiming(uint256 chainId)
        external
        view
        returns (uint64 minWindow, uint64 buffer, uint64 margin, uint64 longBackstop, uint64 claimStagger);
    function rootAnchor() external view returns (IRootAnchor);
    function claims(bytes32 orderHash)
        external
        view
        returns (uint64 openedAt, uint64 finalizeAt, uint64 pausedAtOpen, Termination.ClaimEntry entry);
    /// @notice Whether the order's SETTLED leaf is in the MMR.
    function settledRecorded(bytes32 orderHash) external view returns (bool);
    /// @notice The pause clock: seconds the escrow has spent paused. A window's real end moves by
    ///         the pause time since its leg opened (or since its claim, for a backstop).
    function pausedSeconds() external view returns (uint64);
    /// @notice BLSKeyRegistry revoke guard: true while the account has a leg open on this escrow.
    function hasOpenPositions(bytes32 account) external view returns (bool);
    function getHistoricalRoot(uint256 index) external view returns (bytes32);
    function getMerkleLeafCount() external view returns (uint256);
}
