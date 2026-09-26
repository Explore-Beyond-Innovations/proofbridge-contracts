// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IDisputeManager} from "./IDisputeManager.sol";
import {IEscrow} from "./IEscrow.sol";
import {Dispute} from "../libraries/Dispute.sol";
import {IKeyRegistry} from "./IKeyRegistry.sol";

/**
 * @title IAdManager — the maker's leg: liquidity ads, locks, and unlocks by the bridger.
 */
interface IAdManager is IEscrow {
    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Liquidity ad created by a maker on this (ad) chain.
     * @dev Packed: `maker` + `open` share a slot. Field order is the `ads()` tuple order.
     * @param maker Owner of the ad (local EVM address).
     * @param open Whether the ad accepts new locks and funding.
     * @param token ERC20 (or the native sentinel) escrowed for payouts on this chain.
     * @param orderChainId Peer chain the ad serves.
     * @param adRecipient Maker-controlled recipient id on the order chain (32-byte form).
     * @param orderChainToken Order-chain token the ad committed to at creation.
     * @param settlementSigner The account whose settlement key co-signs for the maker; every lock's
     *        `params.adSettlementSigner` must equal it (2.3c). Re-pointable by the maker at any time.
     * @param balance Total token balance deposited into the ad.
     * @param locked Portion of {balance} reserved for open orders.
     */
    struct Ad {
        address maker;
        bool open;
        address token;
        uint256 orderChainId;
        bytes32 adRecipient;
        bytes32 orderChainToken;
        bytes32 settlementSigner;
        uint256 balance;
        uint256 locked;
    }

    /**
     * @notice The order as the ad chain sees it. All address-like fields are 32 bytes for
     *         cross-chain parity; EVM-local values are left-padded (top 12 bytes zero).
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
        uint256 deadline;
        bytes32 adSettlementSigner;
    }

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event AdCreated(
        string indexed adId,
        address indexed maker,
        address indexed token,
        uint256 initAmount,
        uint256 orderChainId,
        bytes32 settlementSigner
    );
    event KeyRegistrySet(address indexed registry);
    /// @notice A maker re-pointed an ad's settlement signer (the third kill lever).
    event SettlementSignerSet(string indexed adId, bytes32 previous, bytes32 next);
    /// @notice The maker halted the co-signed payout of every order against their ads (#422).
    event SettlementHalted(address indexed maker);
    /// @notice The maker lifted their halt.
    event SettlementResumed(address indexed maker);
    event AdFunded(string indexed adId, address indexed maker, uint256 amount, uint256 newBalance);
    event AdWithdrawn(string indexed adId, address indexed maker, uint256 amount, uint256 newBalance);
    event AdClosed(string indexed adId, address indexed maker);
    event OrderLocked(
        string indexed adId,
        bytes32 indexed orderHash,
        address maker,
        address token,
        uint256 amount,
        bytes32 bridger,
        bytes32 recipient
    );
    /// @notice A lock was released back to the ad's free balance by an unchallenged cancel.
    event LockCancelled(string indexed adId, bytes32 indexed orderHash, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error AdManager__TokenZeroAddress();
    error AdManager__AdNotFound();
    error AdManager__NotMaker();
    error AdManager__AdClosed();
    error AdManager__ActiveLocks();
    error AdManager__BridgerZero();
    error AdManager__RecipientZero();
    error AdManager__UsedAdId();
    error AdManager__OrderPortalMismatch(bytes32 expected, bytes32 provided);
    error AdManager__OrderChainMismatch(uint256 expected, uint256 provided);
    error AdManager__RouteMismatch(bytes32 committed, bytes32 offered);
    error AdManager__AdTokenMismatch(bytes32 expected, bytes32 provided);
    error AdManager__AdRecipientMismatch(bytes32 expected, bytes32 provided);
    error AdManager__NoKeyRegistry();
    error AdManager__SettlementSignerZero();
    error AdManager__SignerNotRegistered(bytes32 signer);
    error AdManager__SettlementSignerMismatch(bytes32 expected, bytes32 provided);
    /// @notice The order's maker has halted settlement; only evidence can pay this order now.
    error AdManager__Halted(address maker);
    error AdManager__NotHalted();
    /// @notice #464: the order chain's verifier checks co-signatures against a different registry.
    error AdManager__RegistrySplit(uint256 chainId, address escrowRegistry, address verifierRegistry);

    /*//////////////////////////////////////////////////////////////
                                 FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setKeyRegistry(IKeyRegistry registry) external;

    function createAd(
        string calldata adId,
        address adToken,
        uint256 initialAmount,
        uint256 orderChainId,
        bytes32 adRecipient,
        bytes32 settlementSigner
    ) external payable;
    function setSettlementSigner(string calldata adId, bytes32 identity) external;

    /**
     * @notice Stop the co-signed payout of every open order against every ad the caller owns (#422,
     *         the custody key's brake on what its agent already co-signed). Instant, never
     *         pause-gated, idempotent. Evidence paths are untouched: an order the counterparty can
     *         prove settled on the order chain is still paid here, and a halted order's cancel waits
     *         an evidence grace so that proof always has time to land.
     */
    function haltSettlement() external;

    /// @notice Lift the caller's halt; co-signed payouts resume in the same block.
    function resumeSettlement() external;

    /**
     * @notice When a claimed cancel really finalizes: the claim window's end plus the evidence grace
     *         when the co-signed payout was denied (#422). 0 when the order is not `Claimed`. The
     *         relayer's janitor asks this instead of computing the clock itself.
     */
    function cancelFinalizesAt(OrderParams calldata params) external view returns (uint256);
    function fundAd(string calldata adId, uint256 amount) external payable;
    function withdrawFromAd(string calldata adId, uint256 amount, address to) external;
    function closeAd(string calldata adId, address to) external;
    function lockForOrder(OrderParams calldata params) external returns (bytes32 orderHash);
    function unlock(
        OrderParams calldata params,
        bytes32 nullifierHash,
        bytes32 targetRoot,
        bytes calldata proof,
        bytes calldata cosigData
    ) external;

    /*//////////////////////////////////////////////////////////////
                        TERMINATION — THE PRIMARY (2.3e)
    //////////////////////////////////////////////////////////////*/

    /// @notice Open the cancel window on an `Open` lock at `now ≥ deadline`. Permissionless, no fee.
    ///         The window is deadline-anchored: it may be finalized at `deadline + buffer`.
    function claimCancel(OrderParams calldata params) external;
    /// @notice After an unchallenged window: release the lock, mark `Cancelled`, append the CANCEL
    ///         leaf the follower refunds against.
    function finalizeCancel(OrderParams calldata params) external;
    /// @notice Attest that an order the bridger deposited for was never locked here: `None` and
    ///         `now ≥ deadline` → `Cancelled` + CANCEL leaf. No funds move; nothing was counted.
    function cancelNeverLocked(OrderParams calldata params) external;

    /// @notice Set the dispute module the primary reads (2.3g).
    /// @dev On the primary only. The OrderPortal is the follower and has no dispute of its own — it
    ///      learns how one ended from an anchored proof of this chain's leaf, never from a module.
    function setDisputeManager(IDisputeManager manager) external;
    /// @notice The dispute module, or the zero address when disputes are unavailable here.
    function disputeManager() external view returns (IDisputeManager);
    /// @notice Emitted when the dispute module is (re)pointed.
    event DisputeManagerSet(address indexed disputeManager);

    /// @notice File a dispute on an open or claimed leg, posting the route's bond in native value.
    ///         The bond goes straight to the dispute module; this escrow never holds it.
    function dispute(OrderParams calldata params, bytes32 evidence) external payable;
    /// @notice Record the counterparty's evidence hash on an open dispute. Only the order's other
    ///         party may call it (D11): the responder slot is single, not an append, so anyone able
    ///         to write it could overwrite the genuine response a block before the arbiter reads it.
    function respondToDispute(OrderParams calldata params, bytes32 evidence) external;
    /// @notice Apply the module's outcome once its window is over, and settle the bond.
    function finalizeDispute(OrderParams calldata params) external;
    /// @notice Settle the lock on a secret-free proof that the order leg already paid the maker (its
    ///         SETTLED leaf under a root the anchor notarized). `Open` or `Claimed`; no nullifier.
    function presentSettled(OrderParams calldata params, bytes32 targetRoot, bytes calldata proof) external;
    /// @notice Append the lock's SETTLED leaf after a fill (D8). Permissionless, single-shot, its own
    ///         transaction — the relayer batches it behind the fill.
    function recordSettled(OrderParams calldata params) external;

    function keyRegistry() external view returns (IKeyRegistry);
    function ads(string calldata adId)
        external
        view
        returns (
            address maker,
            bool open,
            address token,
            uint256 orderChainId,
            bytes32 adRecipient,
            bytes32 orderChainToken,
            bytes32 settlementSigner,
            uint256 balance,
            uint256 locked
        );
    function availableLiquidity(string calldata adId) external view returns (uint256);
}
