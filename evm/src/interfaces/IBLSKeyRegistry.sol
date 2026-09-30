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
 *         on a home-chain leaf proof and ships switched off. The owner signature is the one both
 *         registries accept (2.6 plan 13): one message whose legs name every registry it is for.
 */
interface IBLSKeyRegistry is IKeyRegistry {
    enum Scheme {
        Secp256k1, // EIP-712 over the key message; the recovered address must be `account`'s low 20 bytes
        Sep53 // ed25519 over SHA256("Stellar Signed Message:\n" || the fixed text); `account` is the key
    }

    /// One registry a signature is for: its chain, its 32-byte id and its nonce for the account.
    struct KeyLeg {
        uint256 chainId;
        bytes32 registry; // EVM address left-padded, or the Soroban contract id
        uint256 nonce;
    }

    struct OwnerAuth {
        Scheme scheme;
        KeyLeg[] legs; // every registry the signature names; a RetireKey names none
        bytes sig; // Secp256k1: r||s||v (65 B) · Sep53: abi.encode(r, s, edX, edY)
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
    /// @notice The constructor was given no admin (C-37).
    error ZeroAdmin();
    error EnforcedPause();
    error RegistryFull();
    error NoSuchSlot();
    error SlotExpired();
    error KeyPreviouslyUsed();
    error BadValidUntil();
    error UnknownScheme();
    /// The signed legs do not name this registry exactly once at its current nonce, or a retirement names legs.
    error LegMismatch();
    /// Review D2: chain time is past the registration's deadline.
    error DeadlineExpired();
    /// Review D2: the deadline is more than MAX_REGISTER_TTL past chain time, whoever signed it.
    error DeadlineTooFar();
    /// Review D3: the environment is not local, testnet or mainnet.
    error BadEnv();
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
        uint256 nonce,
        uint64 deadline
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
    function setValidUntil(bytes32 account, OwnerAuth calldata owner, bytes32 keyCommitment, uint64 validUntil) external;
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
    function slotOfKey(bytes32 account, bytes32 keyCommitment) external view returns (uint32);
    function domainSeparator() external view returns (bytes32);
    function keysEnv() external view returns (string memory);
}
