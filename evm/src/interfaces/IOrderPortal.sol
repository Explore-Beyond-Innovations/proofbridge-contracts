// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IEscrow} from "./IEscrow.sol";
import {Dispute} from "../libraries/Dispute.sol";

/**
 * @title IOrderPortal — the bridger's leg: deposits against an ad, unlocked by the maker.
 */
interface IOrderPortal is IEscrow {
    /**
     * @notice The order as the order chain sees it. All address-like fields are 32 bytes for
     *         cross-chain parity; EVM-local values are left-padded (top 12 bytes zero).
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
        /// #586: the bridge fee the bridger deposited against (in the order hash, so it is fixed at the
        /// deposit); the AdManager's lock requires it to equal the live fee and its payouts charge it.
        uint16 lpFeeBps;
        uint16 protocolFeeBps;
    }

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

    /// @notice The bridger's deposit went back to them (`Cancelled`).
    event OrderRefunded(bytes32 indexed orderHash, bytes32 indexed bridger, uint256 amount);
    /// @notice `payMakerByForfeit`: the bridger forfeited and the deposit went to the maker (C-14).
    ///         Emitted beside `OrderSettled(orderHash, true)`.
    event OrderForfeited(bytes32 indexed orderHash);

    error OrderPortal__AdManagerMismatch(bytes32 expected);
    error OrderPortal__BridgerMustBeSender();
    /// @notice #586: an order fee share above 1% (the ad chain could never lock it).
    error OrderPortal__InvalidFee();

    function createOrder(OrderParams calldata params) external payable returns (bytes32 orderHash);
    /// @notice The maker's co-signed settlement: `Open` only, until `deadline − claimStagger` (the
    ///         order's own timing version). After that only the ad leg's leaves end this leg.
    function unlock(
        OrderParams calldata params,
        bytes32 nullifierHash,
        bytes32 targetRoot,
        bytes calldata proof,
        bytes calldata cosigData
    ) external;

    /*//////////////////////////////////////////////////////////////
                        TERMINATION — THE FOLLOWER (2.3e)
    //////////////////////////////////////////////////////////////*/

    /// @notice Refund the bridger against a proof of the primary's CANCEL leaf under an anchored
    ///         root. Reads no clock. The follower's only refund: nothing here refunds on time alone.
    function refundByCancel(OrderParams calldata params, bytes32 targetRoot, bytes calldata proof) external;
    /// @notice Settle the deposit to the maker on a proof of the ad leg's SETTLED leaf under an
    ///         anchored root. No nullifier.
    function presentSettled(OrderParams calldata params, bytes32 targetRoot, bytes calldata proof) external;
    /// @notice Append the deposit's SETTLED leaf after a fill (D8). Permissionless, single-shot, its
    ///         own transaction — the relayer batches it behind the fill. A deposit paid by forfeit
    ///         ({payMakerByForfeit}) is already marked recorded, so it is refused like any recorded
    ///         order (`Escrow__SettledRecorded`): that fill settled no trade.
    function recordSettled(OrderParams calldata params) external;

    /**
     * @notice Apply a `BridgerForfeit` ruling made on the ad chain: the deposit goes to the maker.
     * @dev The follower's entire part in a dispute, and proof-only by design — this escrow has no
     *      dispute, no arbiter and no dispute clock. The other rulings all mean "refund the
     *      bridger", which is what a CANCEL leaf already means, so they arrive via
     *      {refundByCancel}.
     */
    function payMakerByForfeit(OrderParams calldata params, bytes32 targetRoot, bytes calldata proof) external;
}
