// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {EscrowBase} from "./escrow/EscrowBase.sol";
import {IOrderPortal} from "./interfaces/IOrderPortal.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";
import {IMerkleManager} from "./interfaces/IMerkleManager.sol";
import {IwNativeToken} from "./wNativeToken.sol";
import {AddressCast} from "./libraries/AddressCast.sol";
import {DecimalScaling} from "./libraries/DecimalScaling.sol";
import {LeafDomain} from "./libraries/LeafDomain.sol";
import {OrderHash} from "./libraries/OrderHash.sol";
import {RequestAuth} from "./libraries/RequestAuth.sol";

/**
 * @title OrderPortal (Proofbridge)
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice The bridger's leg. Bridgers deposit `orderChainToken` against a maker's ad; the maker
 *         unlocks the deposit on this chain with a proof of their lock on the ad chain. Everything
 *         not specific to deposits lives in {EscrowBase}.
 */
contract OrderPortal is EscrowBase, IOrderPortal {
    using AddressCast for address;
    using AddressCast for bytes32;

    /// @notice The deposit proof's chain flag on the order chain (not a leaf domain).
    uint256 private constant _PUBLIC_INPUT_SIDE_ORDER = 0;

    constructor(address admin, IVerifier verifier_, IMerkleManager merkleManager_, IwNativeToken wNativeToken_)
        EscrowBase(admin, verifier_, merkleManager_, wNativeToken_)
    {}

    /*//////////////////////////////////////////////////////////////
                       BRIDGER ACTION — CREATE ORDER
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IOrderPortal
    function createOrder(OrderParams calldata params)
        external
        payable
        nonReentrant
        whenNotPaused
        returns (bytes32 orderHash)
    {
        orderHash = _validateOrder(params);
        _openOrder(orderHash);
        _pullFunds(params.orderChainToken.toAddressChecked(), params.amount);
        // The deposit is consumed on the ad side: its leaf carries the AD domain.
        _appendLeaf(orderHash, LeafDomain.AD);
        // 2.3c D1: count the party this escrow authenticated (the bridger, `msg.sender`); the maker
        // is counted by the AdManager that authenticated them.
        _countIn(params.bridger);

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

    /// @inheritdoc IOrderPortal
    function unlock(
        OrderParams calldata params,
        bytes32 nullifierHash,
        bytes32 targetRoot,
        bytes calldata proof,
        bytes calldata cosigData
    ) external nonReentrant whenNotPaused {
        bytes32 orderHash = _hashOrder(params, block.chainid, address(this));
        _requireBeforeDeadline(params.deadline);
        _requireSettleable(orderHash, nullifierHash);
        // Gate 2 — root authenticity (the co-signed root); mandatory, reverts NoRootVerifier when unwired.
        _requireRootValid(
            params.adChainId, targetRoot, RequestAuth.rootEnvelope(params.adSettlementSigner, params.bridger, cosigData)
        );
        _requireDepositProof(orderHash, nullifierHash, targetRoot, proof, _PUBLIC_INPUT_SIDE_ORDER);

        _settle(orderHash, nullifierHash, params.bridger);
        _payOrCredit(params.adRecipient.toAddressChecked(), params.orderChainToken.toAddressChecked(), params.amount);

        emit OrderUnlocked(orderHash, params.adRecipient, nullifierHash);
    }

    /*//////////////////////////////////////////////////////////////
                              INTERNAL LOGIC
    //////////////////////////////////////////////////////////////*/

    /// @dev The canonical 17-field order from this leg's params plus the order-chain context.
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
            orderPortal: orderPortal.toBytes32(),
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

    /// @dev Every create-time rule, cheapest first.
    function _validateOrder(OrderParams calldata params) private view returns (bytes32 orderHash) {
        if (params.amount == 0) revert Escrow__ZeroAmount();
        if (params.bridger != msg.sender.toBytes32()) revert OrderPortal__BridgerMustBeSender();
        if (params.adRecipient == bytes32(0)) revert Escrow__ZeroAddress();
        params.adRecipient.assertEvmAddress();
        OrderHash.checkWidths(params.amount, block.chainid, params.adChainId, params.deadline);
        // Both signed decimals are checked here so a bad route fails at create time, not at unlock.
        DecimalScaling.assertInRange(params.orderDecimals);
        DecimalScaling.assertInRange(params.adDecimals);

        // The peer AdManager named in the order must be the one wired for that chain.
        bytes32 peer = peerEscrow[params.adChainId];
        if (peer == bytes32(0)) revert Escrow__ChainNotSupported(params.adChainId);
        if (peer != params.adManager) revert OrderPortal__AdManagerMismatch(peer);

        // Routes key on the local ERC20 address; the order carries its 32-byte form.
        address orderTokenAddr = params.orderChainToken.toAddressChecked();
        bytes32 route = tokenRoute[orderTokenAddr][params.adChainId];
        if (route == bytes32(0)) revert Escrow__MissingRoute(params.adChainToken, params.adChainId);
        if (route != params.adChainToken) revert Escrow__PeerTokenMismatch(route, params.adChainToken);
        DecimalScaling.assertMatchesOnChain(orderTokenAddr, params.orderDecimals);

        orderHash = _hashOrder(params, block.chainid, address(this));
    }
}
