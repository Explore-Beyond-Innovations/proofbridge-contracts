// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {EfficientHashLib} from "solady/utils/EfficientHashLib.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title OrderHash
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice EIP-712 hashing for the canonical cross-chain `Order`.
 * @dev Each side (OrderPortal, AdManager) owns its own `OrderParams` layout
 *      tailored to its direction; both collapse into the same 15-field
 *      canonical `Order` tuple before hashing so the digest matches across
 *      chains. Minimal domain (name, version) — no chainId / verifyingContract,
 *      because both chain ids and contract addresses are bound inside the
 *      struct itself.
 */
library OrderHash {
    /// @notice EIP-712 domain name.
    string private constant _NAME = "Proofbridge";
    /// @notice EIP-712 domain version.
    string private constant _VERSION = "1";

    /// @notice Minimal EIP-712 domain (name, version).
    bytes32 internal constant DOMAIN_TYPEHASH_MIN = keccak256("EIP712Domain(string name,string version)");

    /// @notice EIP-712 typehash for `Order`.
    bytes32 internal constant ORDER_TYPEHASH = keccak256(
        "Order(bytes32 orderChainToken,bytes32 adChainToken,uint256 amount,bytes32 bridger,uint256 orderChainId,bytes32 orderPortal,bytes32 orderRecipient,uint256 adChainId,bytes32 adManager,string adId,bytes32 adCreator,bytes32 adRecipient,uint256 salt,uint8 orderDecimals,uint8 adDecimals)"
    );

    /**
     * @notice Canonical `Order` tuple. Both sides build this from their local
     *         `OrderParams` plus local chain-id / contract-address context
     *         before hashing.
     * @dev Field order here matches the `ORDER_TYPEHASH` string exactly.
     */
    struct Order {
        bytes32 orderChainToken;
        bytes32 adChainToken;
        uint256 amount;
        bytes32 bridger;
        uint256 orderChainId;
        bytes32 orderPortal;
        bytes32 orderRecipient;
        uint256 adChainId;
        bytes32 adManager;
        string adId;
        bytes32 adCreator;
        bytes32 adRecipient;
        uint256 salt;
        uint8 orderDecimals;
        uint8 adDecimals;
    }

    /// @notice Compute the minimal EIP-712 domain separator.
    function domainSeparator() internal pure returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH_MIN, keccak256(bytes(_NAME)), keccak256(bytes(_VERSION))));
    }

    /// @notice Compute the `keccak256(abi.encode(...))` struct hash for `Order`.
    function structHash(Order memory o) internal pure returns (bytes32) {
        bytes32[] memory buf = EfficientHashLib.malloc(16);
        EfficientHashLib.set(buf, 0, ORDER_TYPEHASH);
        EfficientHashLib.set(buf, 1, o.orderChainToken);
        EfficientHashLib.set(buf, 2, o.adChainToken);
        EfficientHashLib.set(buf, 3, o.amount);
        EfficientHashLib.set(buf, 4, o.bridger);
        EfficientHashLib.set(buf, 5, o.orderChainId);
        EfficientHashLib.set(buf, 6, o.orderPortal);
        EfficientHashLib.set(buf, 7, o.orderRecipient);
        EfficientHashLib.set(buf, 8, o.adChainId);
        EfficientHashLib.set(buf, 9, o.adManager);
        EfficientHashLib.set(buf, 10, keccak256(bytes(o.adId)));
        EfficientHashLib.set(buf, 11, o.adCreator);
        EfficientHashLib.set(buf, 12, o.adRecipient);
        EfficientHashLib.set(buf, 13, o.salt);
        EfficientHashLib.set(buf, 14, uint256(o.orderDecimals));
        EfficientHashLib.set(buf, 15, uint256(o.adDecimals));
        return EfficientHashLib.hash(buf);
    }

    /// @notice Final EIP-712 typed-data digest for an `Order`.
    function digest(Order memory o) internal pure returns (bytes32) {
        return MessageHashUtils.toTypedDataHash(domainSeparator(), structHash(o));
    }
}
