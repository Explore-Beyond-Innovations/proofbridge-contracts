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
        /// #586: the bridge fee the bridger deposited against (in the order hash, so it is fixed at the
        /// deposit); the AdManager's lock requires it to equal the live fee and its payouts charge it.
        uint16 lpFeeBps;
        uint16 protocolFeeBps;
    }

    /// @notice The bridge fee, taken from the bridger's payout on this chain. `lpBps` stays in the
    ///         maker's ad balance; `protocolBps` goes to `pool`. Each is capped at `MAX_FEE_BPS`.
    struct FeeConfig {
        address pool;
        uint16 lpBps;
        uint16 protocolBps;
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
    /// @notice #465: each `setKeyRegistry` opens a new epoch; an order records the one it locked under.
    event KeyRegistryEpoch(uint32 indexed epoch, address indexed registry);
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
    event ProtocolFeePoolSet(address indexed pool);
    event FeeBpsSet(uint16 lpBps, uint16 protocolBps);
    /// @notice A payout's fee, at the bps the order locked under: `lpFee` stayed in the ad, `protocolFee` went to the pool.
    event FeeCharged(bytes32 indexed orderHash, uint256 lpFee, uint256 protocolFee);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice `DecimalScaling.scale` (via the linked `ProofBridgeUtils`) reverts with this; only AdManager scales. See IEscrow.
    error DecimalScaling__NonExactDownscale(uint256 amount, uint8 fromDec, uint8 toDec);
    /// @notice The order's co-signing pin moved (`repinOrder`).
    event OrderRepinned(bytes32 indexed orderHash, uint32 fromSlot, uint32 toSlot);

    error AdManager__TokenZeroAddress();
    error AdManager__AdNotFound();
    error AdManager__NotMaker();
    error AdManager__AdClosed();
    error AdManager__ActiveLocks();
    error AdManager__BridgerZero();
    error AdManager__RecipientZero();
    /// @notice 643-b1: the order pays the ad's maker or its settlement signer (the dispute roles would collapse).
    error AdManager__RecipientIsMaker();
    error AdManager__UsedAdId();
    error AdManager__OrderPortalMismatch(bytes32 expected, bytes32 provided);
    error AdManager__OrderChainMismatch(uint256 expected, uint256 provided);
    error AdManager__RouteMismatch(bytes32 committed, bytes32 offered);
    error AdManager__AdTokenMismatch(bytes32 expected, bytes32 provided);
    error AdManager__AdRecipientMismatch(bytes32 expected, bytes32 provided);
    error AdManager__NoKeyRegistry();
    error AdManager__SettlementSignerZero();
    error AdManager__SignerNotRegistered(bytes32 signer);
    /// The settlement signer is not the maker and has not approved the maker in the key registry.
    error AdManager__SignerNotApproved(bytes32 signer, bytes32 maker);
    error AdManager__SettlementSignerMismatch(bytes32 expected, bytes32 provided);
    /// @notice The order's maker has halted settlement; only evidence can pay this order now.
    error AdManager__Halted(address maker);
    error AdManager__NotHalted();
    /// @notice #464: the order chain's verifier checks co-signatures against a different registry.
    error AdManager__RegistrySplit(uint256 chainId, address escrowRegistry, address verifierRegistry);
    /// @notice The slot to pin does not exist, is not usable now, or is not the signer's; or, on a
    ///         re-pin, the pin being left has already expired (the kill stands).
    error AdManager__SlotNotUsable(bytes32 signer, uint32 slotId);
    /// @notice No re-pin consent for this order from its current pin.
    error AdManager__NoRepin(bytes32 orderHash);
    /// @notice A fee above `MAX_FEE_BPS`, or a protocol fee with no pool to pay it to.
    error AdManager__InvalidFee();
    /// @notice The order's fee (fixed at the bridger's deposit) is not the AdManager's live fee.
    error AdManager__FeeMismatch(uint16 lpBps, uint16 protocolBps);

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
     *         relayer's janitor asks this instead of computing the clock itself. Plain time; a
     *         pause moves nothing. Raising the order chain's anchor delay can lengthen a denied grace.
     */
    function cancelFinalizesAt(OrderParams calldata params) external view returns (uint256);
    /// @notice `cancelFinalizesAt`'s dispute twin: when `finalizeDispute` can run, grace included; 0 off `Disputed`.
    function disputeFinalizesAt(OrderParams calldata params) external view returns (uint256);
    function fundAd(string calldata adId, uint256 amount) external payable;
    function withdrawFromAd(string calldata adId, uint256 amount, address to) external;
    function closeAd(string calldata adId, address to) external;
    /// @notice Lock the ad's liquidity for an order, pinning `signerSlot`: the settlement signer's
    ///         co-signing slot in the registry the order records. The slot must exist and be usable
    ///         now; the ad chain's co-signed unlock then accepts only that slot's key.
    function lockForOrder(OrderParams calldata params, uint32 signerSlot) external returns (bytes32 orderHash);
    /// @notice Apply the settlement signer's re-pin consent (`approveRepin` on the order's registry):
    ///         move an `Open` order's pin to another usable slot of the same signer, before
    ///         `deadline - claimStagger`. Permissionless; the consent names the order and both slots.
    function repinOrder(OrderParams calldata params) external;
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
    /// @dev The order must be real: `proof` shows its AD leaf (the one the OrderPortal's `createOrder`
    ///      appended) in `targetRoot`, an order-chain root the RootAnchor notarized. Any secret proves
    ///      the leaf, so `nullifierHash` is neither checked against nor added to the used set.
    function cancelNeverLocked(
        OrderParams calldata params,
        bytes32 targetRoot,
        bytes32 nullifierHash,
        bytes calldata proof
    ) external;

    /// @notice Set the dispute module the primary reads (2.3g).
    /// @dev On the primary only. The OrderPortal is the follower and has no dispute of its own — it
    ///      learns how one ended from an anchored proof of this chain's leaf, never from a module.
    function setDisputeManager(IDisputeManager manager) external;

    /// @notice Where the protocol fee is paid. Timelocked; never zero once set.
    function setProtocolFeePool(address pool) external;

    /// @notice The fee split, each at most `MAX_FEE_BPS`; a protocol fee needs the pool set. Timelocked.
    ///         Applies to orders locked after it; a live order keeps the bps it locked under.
    function setFeeBps(uint16 lpBps, uint16 protocolBps) external;

    /// @notice The live fee config (pool, lpBps, protocolBps).
    function feeConfig() external view returns (address pool, uint16 lpBps, uint16 protocolBps);
    /// @notice The dispute module, or the zero address when disputes are unavailable here.
    function disputeManager() external view returns (IDisputeManager);
    /// @notice Emitted when the dispute module is (re)pointed.
    event DisputeManagerSet(address indexed disputeManager);
    /// @notice The module an order's dispute was filed under (D5); zero if never disputed.
    function disputeModuleOf(bytes32 orderHash) external view returns (IDisputeManager);
    /// @notice `finalizeDispute` applied `outcome` (the fallback reads as `MutualRefund`).
    event DisputeFinalized(bytes32 indexed orderHash, Dispute.Outcome outcome);

    /// @notice File a dispute on an open or claimed leg, posting the route's bond in native value.
    ///         The bond goes straight to the dispute module; this escrow never holds it.
    function dispute(OrderParams calldata params, bytes32 evidence) external payable;
    /// @notice Record the counterparty's evidence hash on an open dispute. Only the order's other
    ///         party may call it (D11): the responder slot is single, not an append, so anyone able
    ///         to write it could overwrite the genuine response a block before the arbiter reads it.
    ///         One non-zero answer, before the effective challenge deadline (D5, the module refuses).
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
