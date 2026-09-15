// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IEscrow} from "./IEscrow.sol";

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

    error OrderPortal__AdManagerMismatch(bytes32 expected);
    error OrderPortal__BridgerMustBeSender();

    function createOrder(OrderParams calldata params) external payable returns (bytes32 orderHash);
    /// @notice The maker's co-signed settlement: `Open` only, until `deadline − claimStagger`. Never
    ///         inside a backstop window — the package proves the lock, not the ad leg's outcome.
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
    ///         root. Reads no clock. `Open` or `Claimed` (a cancel proof beats a backstop window).
    function refundByCancel(OrderParams calldata params, bytes32 targetRoot, bytes calldata proof) external;
    /// @notice Settle the deposit to the maker on a proof of the ad leg's SETTLED leaf under an
    ///         anchored root. `Open` or `Claimed`; no nullifier.
    function presentSettled(OrderParams calldata params, bytes32 targetRoot, bytes calldata proof) external;
    /// @notice Append the deposit's SETTLED leaf after a fill (D8). Permissionless, single-shot, its
    ///         own transaction — the relayer batches it behind the fill.
    function recordSettled(OrderParams calldata params) external;
    /// @notice Open the backstop window at `now ≥ deadline + longBackstop` (an anchor outage): the
    ///         window is claim-anchored and may be finalized at `now + buffer`. Permissionless.
    function claimBackstop(OrderParams calldata params) external;
    /// @notice After an unchallenged backstop window: refund the bridger.
    function finalizeBackstop(OrderParams calldata params) external;
}
