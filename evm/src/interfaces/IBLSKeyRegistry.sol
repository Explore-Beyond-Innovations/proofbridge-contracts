// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IKeyRegistry} from "./IKeyRegistry.sol";
import {IRootAnchor} from "./IRootAnchor.sol";
import {IVerifier} from "./IVerifier.sol";

/// @title IPositionGuard — an escrow the registry asks before a key may be revoked.
interface IPositionGuard {
    function hasOpenPositions(bytes32 account) external view returns (bool);
}

/**
 * @title IBLSKeyRegistry — registry v2: a 32-byte account id → up to five BLS key slots.
 * @notice State changes are authenticated by the owner's wallet signature plus a BLS proof of
 *         possession, never by the invoker (relayable). `register` / `revoke` consume the account
 *         nonce; `setValidUntil` is shorten-only and nonce-free; `registerByProof` (2.1b) enters
 *         on a home-chain leaf proof and ships switched off.
 */
interface IBLSKeyRegistry is IKeyRegistry {
    enum Scheme {
        Eip712, // EVM-home: typed sig, recovered address must be `account`
        Sep53 // Stellar-home: ed25519 over SHA256("Stellar Signed Message:\n" || hex(digest))
    }

    struct OwnerAuth {
        Scheme scheme;
        bytes data; // Eip712: r||s||v (65 B) · Sep53: abi.encode(r, s, edX, edY)
    }

    struct KeySlot {
        bytes32 commitment; // keccak256(blsPubKey)
        uint64 validUntil; // 0 = no expiry; else usable while block.timestamp < validUntil
        uint64 registeredAt;
    }

    event KeyRegistered(bytes32 indexed account, uint32 indexed slotId, bytes blsPubKey, uint256 nonce);
    event KeyRegisteredByProof(
        bytes32 indexed account, uint32 indexed slotId, bytes blsPubKey, uint64 epoch, uint256 sourceChainId
    );
    event ProofRegistrationSet(address rootAnchor, address verifier, uint256[] sources, bool enabled);
    event SlotValidUntilSet(bytes32 indexed account, uint32 indexed slotId, uint64 validUntil);
    event SlotPruned(bytes32 indexed account, uint32 indexed slotId);
    event Paused(address account);
    event Unpaused(address account);
    event AdminTransferStarted(address indexed from, address indexed to);
    event AdminTransferred(address indexed from, address indexed to);
    event KeyRevoked(bytes32 indexed account, uint256 nonce);
    event PositionGuardsSet(address[] guards);

    error BadNonce();
    error IdentityKey();
    error InvalidPop();
    error OwnerMismatch();
    error NotRegistered();
    error AccountInFlight();
    error BadLength();
    error NotAdmin();
    error NotPendingAdmin();
    error EnforcedPause();
    error RegistryFull();
    error NoSuchSlot();
    error SlotExpired();
    error KeyPreviouslyUsed();
    error BadValidUntil();
    error UnknownScheme();
    error ProofRegistrationDisabled();
    error ProofRegistrationRefsUnset();
    error SourceNotAllowed(uint256 chainId);
    error RootNotAnchored(uint256 chainId, bytes32 root);
    error InvalidLeafProof();

    // admin
    function pause() external;
    function unpause() external;
    function transferAdmin(address to) external;
    function acceptAdmin() external;
    function setPositionGuards(address[] calldata guards) external;
    function setProofRegistration(IRootAnchor anchor_, IVerifier verifier_, uint256[] calldata sources, bool enabled)
        external;

    // key lifecycle
    function register(
        bytes32 account,
        OwnerAuth calldata owner,
        bytes calldata blsPubKey,
        bytes calldata pop,
        uint256 nonce
    ) external returns (uint32 slotId);
    function registerByProof(
        bytes32 account,
        bytes calldata blsPubKey,
        bytes calldata pop,
        uint64 epoch,
        uint256 sourceChainId,
        bytes32 targetRoot,
        bytes calldata proof
    ) external returns (uint32 slotId);
    function setValidUntil(bytes32 account, OwnerAuth calldata owner, uint32 slotId, uint64 validUntil) external;
    function revoke(bytes32 account, OwnerAuth calldata owner, uint256 nonce) external;

    // views
    function admin() external view returns (address);
    function pendingAdmin() external view returns (address);
    function paused() external view returns (bool);
    function nonceOf(bytes32 account) external view returns (uint256);
    function usedCommitment(bytes32 account, bytes32 commitment) external view returns (bool);
    function rootAnchor() external view returns (IRootAnchor);
    function proofVerifier() external view returns (IVerifier);
    function proofRegistrationEnabled() external view returns (bool);
    function proofSources() external view returns (uint256[] memory);
    function commitmentAt(bytes32 account, uint32 slotId) external view returns (bytes32);
    function lookup(bytes32 account, uint32 slotId) external view returns (KeySlot memory slot);
    function liveSlots(bytes32 account) external view returns (uint32[] memory);
    function nextSlotId(bytes32 account) external view returns (uint32);
    function domainSeparator() external view returns (bytes32);
}
