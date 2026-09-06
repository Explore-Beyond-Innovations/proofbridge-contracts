// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {BLS} from "./libraries/BLS.sol";
import {SCL_EIP6565} from "@scl/lib/libSCL_EIP6565.sol";
import {SCL_sha512} from "@scl/hash/SCL_sha512.sol";
import {p as ED_P} from "@scl/fields/SCL_wei25519.sol";

interface IPositionGuard {
    function hasOpenPositions(bytes32 account) external view returns (bool);
}

/// @title BLSKeyRegistry v2 — maps a 32-byte account id to up to five BLS key slots.
/// @notice State changes are authenticated by the owner's wallet sig + BLS
///         proof-of-possession, never by msg.sender. `register` / `revoke` consume
///         the per-account nonce; `setValidUntil` is shorten-only and nonce-free so
///         a pre-signed retirement never expires (design 03 §3.4, 05 §5.6).
contract BLSKeyRegistry {
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

    struct RegistryEntry {
        uint32 nextSlotId; // monotonic, never reused
        uint32[] liveSlots; // stored slot ids, length <= MAX_ACTIVE_SLOTS
        mapping(uint32 => KeySlot) slots;
    }

    uint32 public constant MAX_ACTIVE_SLOTS = 5;
    uint64 public constant GRACE_PERIOD = 30 days;

    string public constant DST_POP = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    bytes32 private constant REG_TAG = keccak256("ProofBridge.BLSKeyRegistry.Register.v1");
    bytes32 private constant REVOKE_TAG = keccak256("ProofBridge.BLSKeyRegistry.Revoke.v1");
    bytes32 private constant POP_TAG = keccak256("ProofBridge.BLSKeyRegistry.PoP.v1");
    bytes32 private constant SET_VALID_UNTIL_TAG = keccak256("ProofBridge.BLSKeyRegistry.SetValidUntil.v1");

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant REGISTER_TYPEHASH = keccak256("Register(bytes blsPubKey,bytes pop,uint256 nonce)");
    bytes32 private constant REVOKE_TYPEHASH = keccak256("Revoke(uint256 nonce)");
    bytes32 private constant SET_VALID_UNTIL_TYPEHASH = keccak256("SetValidUntil(uint32 slotId,uint64 validUntil)");

    bytes private constant SEP53_PREFIX = "Stellar Signed Message:\n";

    /// ed25519 Edwards d (the SCL field lib only exports the Weierstrass form).
    uint256 private constant ED_D = 37095705934669439343138083508754565189542113879843219016388785533085940283555;

    address public admin;
    IPositionGuard[] public positionGuards;
    address public pendingAdmin;
    bool public paused;

    mapping(bytes32 => RegistryEntry) private entries;
    mapping(bytes32 => uint256) public nonceOf;
    /// Any commitment that ever held a slot for the account can never re-enter one.
    mapping(bytes32 => mapping(bytes32 => bool)) public usedCommitment;

    event KeyRegistered(bytes32 indexed account, uint32 indexed slotId, bytes blsPubKey, uint256 nonce);
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

    constructor(address admin_) {
        admin = admin_;
    }

    function pause() external {
        if (msg.sender != admin) revert NotAdmin();
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external {
        if (msg.sender != admin) revert NotAdmin();
        paused = false;
        emit Unpaused(msg.sender);
    }

    function transferAdmin(address to) external {
        if (msg.sender != admin) revert NotAdmin();
        pendingAdmin = to;
        emit AdminTransferStarted(admin, to);
    }

    function acceptAdmin() external {
        if (msg.sender != pendingAdmin) revert NotPendingAdmin();
        emit AdminTransferred(admin, msg.sender);
        admin = msg.sender;
        pendingAdmin = address(0);
    }

    function setPositionGuards(address[] calldata guards) external {
        if (msg.sender != admin) revert NotAdmin();
        delete positionGuards;
        for (uint256 i = 0; i < guards.length; i++) {
            positionGuards.push(IPositionGuard(guards[i]));
        }
        emit PositionGuardsSet(guards);
    }

    /// Adds a slot; never guarded (additive, design 03 §3.3). Returns the slot id.
    function register(
        bytes32 account,
        OwnerAuth calldata owner,
        bytes calldata blsPubKey,
        bytes calldata pop,
        uint256 nonce
    ) external returns (uint32 slotId) {
        if (paused) revert EnforcedPause();
        if (blsPubKey.length != 128 || pop.length != 256) revert BadLength();
        if (nonce != nonceOf[account]) revert BadNonce();
        if (keccak256(blsPubKey) == keccak256(new bytes(128))) revert IdentityKey();

        bytes memory msgG2 = BLS.hashToG2(popMsg(account, blsPubKey, nonce), bytes(DST_POP));
        if (!BLS.verifySingle(blsPubKey, msgG2, pop)) revert InvalidPop();

        checkOwner(
            account,
            owner,
            keccak256(abi.encode(REGISTER_TYPEHASH, keccak256(blsPubKey), keccak256(pop), nonce)),
            regDigest(account, blsPubKey, nonce)
        );

        slotId = _addSlot(account, keccak256(blsPubKey));
        nonceOf[account] = nonce + 1;
        emit KeyRegistered(account, slotId, blsPubKey, nonce);
    }

    /// Shorten-only, nonce-free, never guarded, and not pausable: the retirement lever
    /// (D6/D9) only ever reduces authority, so a registry pause must not block it.
    function setValidUntil(bytes32 account, OwnerAuth calldata owner, uint32 slotId, uint64 validUntil) external {
        KeySlot storage slot = entries[account].slots[slotId];
        if (slot.commitment == bytes32(0)) revert NoSuchSlot();
        if (validUntil == 0 || (slot.validUntil != 0 && validUntil >= slot.validUntil)) revert BadValidUntil();

        checkOwner(
            account,
            owner,
            keccak256(abi.encode(SET_VALID_UNTIL_TYPEHASH, slotId, validUntil)),
            setValidUntilDigest(account, slotId, validUntil)
        );

        slot.validUntil = validUntil;
        emit SlotValidUntilSet(account, slotId, validUntil);
    }

    /// Leaves the protocol: drops every slot. Still guarded (t1-design §1.8).
    function revoke(bytes32 account, OwnerAuth calldata owner, uint256 nonce) external {
        if (paused) revert EnforcedPause();
        RegistryEntry storage e = entries[account];
        if (e.liveSlots.length == 0) revert NotRegistered();
        if (nonce != nonceOf[account]) revert BadNonce();
        _requireNoOpenPositions(account);

        checkOwner(account, owner, keccak256(abi.encode(REVOKE_TYPEHASH, nonce)), revokeDigest(account, nonce));

        for (uint256 i = 0; i < e.liveSlots.length; i++) {
            delete e.slots[e.liveSlots[i]];
        }
        delete e.liveSlots;
        nonceOf[account] = nonce + 1;
        emit KeyRevoked(account, nonce);
    }

    function _addSlot(bytes32 account, bytes32 commitment) private returns (uint32 slotId) {
        if (usedCommitment[account][commitment]) revert KeyPreviouslyUsed();
        RegistryEntry storage e = entries[account];
        if (e.liveSlots.length >= MAX_ACTIVE_SLOTS) {
            _prune(account, e);
            if (e.liveSlots.length >= MAX_ACTIVE_SLOTS) revert RegistryFull();
        }
        slotId = e.nextSlotId++;
        e.slots[slotId] = KeySlot(commitment, 0, uint64(block.timestamp));
        e.liveSlots.push(slotId);
        usedCommitment[account][commitment] = true;
    }

    /// Drops every slot past validUntil + GRACE_PERIOD (swap-remove; order is not meaningful).
    function _prune(bytes32 account, RegistryEntry storage e) private {
        uint256 i = 0;
        while (i < e.liveSlots.length) {
            uint32 id = e.liveSlots[i];
            uint64 vu = e.slots[id].validUntil;
            if (vu != 0 && block.timestamp > uint256(vu) + GRACE_PERIOD) {
                delete e.slots[id];
                e.liveSlots[i] = e.liveSlots[e.liveSlots.length - 1];
                e.liveSlots.pop();
                emit SlotPruned(account, id);
            } else {
                i++;
            }
        }
    }

    function _requireNoOpenPositions(bytes32 account) private view {
        for (uint256 i = 0; i < positionGuards.length; i++) {
            if (positionGuards[i].hasOpenPositions(account)) revert AccountInFlight();
        }
    }

    // =========================================================================
    // Views
    // =========================================================================

    /// The verifier's one call: the commitment iff the slot exists and is usable now.
    function commitmentAt(bytes32 account, uint32 slotId) external view returns (bytes32) {
        KeySlot storage slot = entries[account].slots[slotId];
        if (slot.commitment == bytes32(0)) revert NoSuchSlot();
        if (slot.validUntil != 0 && block.timestamp >= slot.validUntil) revert SlotExpired();
        return slot.commitment;
    }

    /// True iff at least one live slot is usable now (the "is registered" check for 2.3c).
    function hasUsableSlot(bytes32 account) external view returns (bool) {
        RegistryEntry storage e = entries[account];
        for (uint256 i = 0; i < e.liveSlots.length; i++) {
            uint64 vu = e.slots[e.liveSlots[i]].validUntil;
            if (vu == 0 || block.timestamp < vu) return true;
        }
        return false;
    }

    function lookup(bytes32 account, uint32 slotId) external view returns (KeySlot memory slot) {
        slot = entries[account].slots[slotId];
        if (slot.commitment == bytes32(0)) revert NoSuchSlot();
    }

    function liveSlots(bytes32 account) external view returns (uint32[] memory) {
        return entries[account].liveSlots;
    }

    function nextSlotId(bytes32 account) external view returns (uint32) {
        return entries[account].nextSlotId;
    }

    // =========================================================================
    // Message building
    // =========================================================================

    function registryId() private view returns (bytes32) {
        return bytes32(uint256(uint160(address(this))));
    }

    /// POP_TAG || chainId || registryId || account || pk(128) || nonce
    function popMsg(bytes32 account, bytes calldata blsPubKey, uint256 nonce) private view returns (bytes memory) {
        return bytes.concat(POP_TAG, bytes32(block.chainid), registryId(), account, blsPubKey, bytes32(nonce));
    }

    /// keccak256(REG_TAG || chainId || registryId || account || keccak256(pk) || nonce)
    function regDigest(bytes32 account, bytes calldata blsPubKey, uint256 nonce) private view returns (bytes32) {
        return keccak256(
            bytes.concat(REG_TAG, bytes32(block.chainid), registryId(), account, keccak256(blsPubKey), bytes32(nonce))
        );
    }

    /// keccak256(REVOKE_TAG || chainId || registryId || account || nonce)
    function revokeDigest(bytes32 account, uint256 nonce) private view returns (bytes32) {
        return keccak256(bytes.concat(REVOKE_TAG, bytes32(block.chainid), registryId(), account, bytes32(nonce)));
    }

    /// keccak256(SET_VALID_UNTIL_TAG || chainId || registryId || account || slotId || validUntil)
    function setValidUntilDigest(bytes32 account, uint32 slotId, uint64 validUntil) private view returns (bytes32) {
        return keccak256(
            bytes.concat(
                SET_VALID_UNTIL_TAG,
                bytes32(block.chainid),
                registryId(),
                account,
                bytes32(uint256(slotId)),
                bytes32(uint256(validUntil))
            )
        );
    }

    // =========================================================================
    // Owner auth
    // =========================================================================

    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN_TYPEHASH, keccak256("ProofBridge.BLSKeyRegistry"), keccak256("1"), block.chainid, address(this)
            )
        );
    }

    /// Scheme dispatch; a new scheme is one more branch (design 03 §3.5).
    function checkOwner(bytes32 account, OwnerAuth calldata owner, bytes32 structHash, bytes32 digest) private view {
        if (owner.scheme == Scheme.Eip712) {
            checkEip712Owner(account, structHash, owner.data);
        } else if (owner.scheme == Scheme.Sep53) {
            checkSep53Owner(account, digest, owner.data);
        } else {
            revert UnknownScheme(); // unreachable today: calldata decoding rejects out-of-range enums
        }
    }

    /// `account` must be 12 zero bytes || the recovered signer address.
    function checkEip712Owner(bytes32 account, bytes32 structHash, bytes calldata data) private view {
        if (data.length != 65) revert BadLength();
        if (uint256(account) >> 160 != 0) revert OwnerMismatch();

        bytes32 digest = keccak256(abi.encodePacked(hex"1901", domainSeparator(), structHash));
        address signer = ecrecover(digest, uint8(bytes1(data[64:65])), bytes32(data[0:32]), bytes32(data[32:64]));
        if (signer == address(0) || signer != address(uint160(uint256(account)))) {
            revert OwnerMismatch();
        }
    }

    /// `account` is the raw 32-byte ed25519 pubkey. SEP-53 wallets sign text,
    /// so the message is the digest's lowercase 0x-hex string:
    /// SHA256(prefix || "0x…64hex"). Caller supplies the decompressed Edwards
    /// point; it is checked against `account` and the curve equation, so a
    /// wrong point cannot verify.
    function checkSep53Owner(bytes32 account, bytes32 digest, bytes calldata data) private view {
        if (data.length != 128) revert BadLength();
        (uint256 r, uint256 s, uint256 edX, uint256 edY) = abi.decode(data, (uint256, uint256, uint256, uint256));

        if (SCL_sha512.Swap256(SCL_EIP6565.edCompress([edX, edY])) != uint256(account)) {
            revert OwnerMismatch();
        }
        checkOnEdwardsCurve(edX, edY);

        uint256[5] memory extKpub;
        (extKpub[0], extKpub[1]) = SCL_EIP6565.Edwards2WeierStrass(edX, edY);
        extKpub[4] = uint256(account);

        string memory m = string(bytes.concat(sha256(bytes.concat(SEP53_PREFIX, toHexString(digest)))));
        if (!SCL_EIP6565.Verify_LE(m, r, s, extKpub)) revert OwnerMismatch();
    }

    /// Lowercase "0x" + 64-hex — the exact string a Stellar wallet signs.
    function toHexString(bytes32 b) private pure returns (bytes memory out) {
        bytes16 alphabet = "0123456789abcdef";
        out = new bytes(66);
        out[0] = "0";
        out[1] = "x";
        for (uint256 i = 0; i < 32; i++) {
            out[2 + i * 2] = alphabet[uint8(b[i]) >> 4];
            out[3 + i * 2] = alphabet[uint8(b[i]) & 0x0f];
        }
    }

    /// -x^2 + y^2 == 1 + d*x^2*y^2 (mod p)
    function checkOnEdwardsCurve(uint256 edX, uint256 edY) private pure {
        uint256 x2 = mulmod(edX, edX, ED_P);
        uint256 y2 = mulmod(edY, edY, ED_P);
        if (addmod(ED_P - x2, y2, ED_P) != addmod(1, mulmod(ED_D, mulmod(x2, y2, ED_P), ED_P), ED_P)) {
            revert OwnerMismatch();
        }
    }
}
