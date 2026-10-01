// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {BLS} from "./libraries/BLS.sol";
import {SCL_EIP6565} from "@scl/lib/libSCL_EIP6565.sol";
import {SCL_sha512} from "@scl/hash/SCL_sha512.sol";
import {p as ED_P} from "@scl/fields/SCL_wei25519.sol";
import {IRootAnchor} from "./interfaces/IRootAnchor.sol";
import {IBLSKeyRegistry, IPositionGuard} from "./interfaces/IBLSKeyRegistry.sol";
import {IVerifier} from "./Verifier.sol";
import {RegistrationSubject} from "./libraries/RegistrationSubject.sol";
import {RequestAuth} from "./libraries/RequestAuth.sol";
import {LeafDomain} from "./libraries/LeafDomain.sol";
import {KeyMessages} from "./libraries/KeyMessages.sol";
import {ShortString, ShortStrings} from "@openzeppelin/contracts/utils/ShortStrings.sol";

/// @title BLSKeyRegistry v2 — maps a 32-byte account id to up to five BLS key slots.
/// @notice State changes are authenticated by the owner's wallet sig + BLS
///         proof-of-possession, never by msg.sender. `register` / `revoke` consume
///         the per-account nonce; `setValidUntil` is shorten-only and nonce-free so
///         a pre-signed retirement never expires (design 03 §3.4, 05 §5.6). One owner
///         signature serves both registries (2.6 plan 13, `KeyMessages`).
contract BLSKeyRegistry is IBLSKeyRegistry {
    struct RegistryEntry {
        uint32 nextSlotId; // monotonic, never reused
        uint32[] liveSlots; // stored slot ids, length <= MAX_ACTIVE_SLOTS
        mapping(uint32 => KeySlot) slots;
    }

    uint32 public constant MAX_ACTIVE_SLOTS = 5;
    uint64 public constant GRACE_PERIOD = 30 days;
    /// Review D2: a registration deadline more than this past chain time is refused.
    uint64 public constant MAX_REGISTER_TTL = 7 days;
    /// secp256k1 n / 2: a larger s is the malleable twin, refused (review D1).
    uint256 private constant SECP256K1_HALF_N = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    string public constant DST_POP = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    bytes32 private constant POP_TAG = keccak256("ProofBridge.BLSKeyRegistry.PoP.v1");
    /// keccak256 of the 128-byte G1 identity encoding: never a key (it passes a naive PoP pairing).
    bytes32 private constant IDENTITY_COMMITMENT = 0x012893657d8eb2efad4de0a91bcd0e39ad9837745dec3ea923737ea803fc8e3d;

    bytes private constant SEP53_PREFIX = "Stellar Signed Message:\n";

    /// ed25519 Edwards d (the SCL field lib only exports the Weierstrass form).
    uint256 private constant ED_D = 37095705934669439343138083508754565189542113879843219016388785533085940283555;

    address public admin;
    IPositionGuard[] public positionGuards;
    address public pendingAdmin;
    bool public paused;

    /// Review D3: the environment the key messages are bound to, fixed at deploy (immutable, so it
    /// survives a code move) and its EIP-712 domain separator.
    ShortString private immutable _env;
    bytes32 private immutable _domainSeparator;

    mapping(bytes32 => RegistryEntry) private entries;

    mapping(bytes32 => uint256) public nonceOf;
    /// #422 D14/D14b: when each shortened slot stopped being usable — the later of the date the
    /// shorten named (our own kill names `1`) and the moment of the shorten; a later shorten can only
    /// move it earlier, so a re-kill after a window cannot erase a death inside it.
    mapping(bytes32 => mapping(uint32 => uint64)) private expiries;
    /// Any commitment that ever held a slot for the account can never re-enter one.
    mapping(bytes32 => mapping(bytes32 => bool)) public usedCommitment;
    /// 2.6 D2: the slot a key commitment occupies, plus one (0 = never); `setValidUntil` names the key.
    mapping(bytes32 => mapping(bytes32 => uint32)) private _slotOfKey;

    /// 2.1b — proof-carried registration (design 03 §3.6). Ships flagged OFF: turning it on is a
    /// configuration call, gated in T3 on the anchor writer being the 3.5 quorum, a
    /// registration-specific anchor delay, and the watchtower's registration-leaf monitor.
    IRootAnchor public rootAnchor;
    IVerifier public proofVerifier;
    /// The home chains a leaf may come from — the "one notarized EVM source" invariant as a check.
    uint256[] private _proofSources;
    bool public proofRegistrationEnabled;

    constructor(address admin_, string memory env_) {
        if (admin_ == address(0)) revert ZeroAdmin();
        bytes32 h = keccak256(bytes(env_));
        if (h != keccak256("local") && h != keccak256("testnet") && h != keccak256("mainnet")) revert BadEnv();
        admin = admin_;
        _env = ShortStrings.toShortString(env_);
        _domainSeparator = KeyMessages.domainSeparator(KeyMessages.salt(env_));
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

    /// Wire (or unwire) proof-carried registration: the anchor, the verifier and the home chains a
    /// leaf may come from. Enabling requires all three; the flip is a configuration change, never a
    /// redeploy (2.1b D3). This chain is never a source: its own leaves belong to another registry.
    function setProofRegistration(IRootAnchor anchor_, IVerifier verifier_, uint256[] calldata sources, bool enabled)
        external
    {
        if (msg.sender != admin) revert NotAdmin();
        if (
            enabled && (address(anchor_).code.length == 0 || address(verifier_).code.length == 0 || sources.length == 0)
        ) revert ProofRegistrationRefsUnset();
        for (uint256 i = 0; i < sources.length; i++) {
            if (sources[i] == block.chainid) revert SourceNotAllowed(sources[i]);
        }
        rootAnchor = anchor_;
        proofVerifier = verifier_;
        _proofSources = sources;
        proofRegistrationEnabled = enabled;
        emit ProofRegistrationSet(address(anchor_), address(verifier_), sources, enabled);
    }

    function proofSources() external view returns (uint256[] memory) {
        return _proofSources;
    }

    /// Adds a slot; never guarded (additive, design 03 §3.3). Returns the slot id.
    function register(
        bytes32 account,
        OwnerAuth calldata owner,
        bytes calldata blsPubKey,
        bytes calldata pop,
        uint256 nonce,
        uint64 deadline
    ) external returns (uint32 slotId) {
        if (paused) revert EnforcedPause();
        if (block.timestamp > deadline) revert DeadlineExpired();
        if (deadline > block.timestamp + MAX_REGISTER_TTL) revert DeadlineTooFar();
        if (blsPubKey.length != 128 || pop.length != 256) revert BadLength();
        if (nonce != nonceOf[account]) revert BadNonce();
        bytes32 commitment = keccak256(blsPubKey);
        if (commitment == IDENTITY_COMMITMENT) revert IdentityKey();

        _requirePop(account, blsPubKey, pop, nonce);
        _requireOwnLeg(owner.legs, nonce);
        _checkOwner(account, owner, KeyMessages.Kind.Register, commitment, deadline);

        slotId = _addSlot(account, commitment);
        nonceOf[account] = nonce + 1;
        emit KeyRegistered(account, slotId, blsPubKey, nonce);
    }

    /// Adds a slot on an inclusion proof of the account's home-chain `REGISTERED` leaf against an
    /// anchored root, instead of an owner signature (2.1b, design 03 §3.6). Flagged off in T2.
    /// @dev Cheap rejections first: flag, lengths, identity, the replay guard, the source allow-list and
    ///      the anchor lookup all run before the pairing and the Honk verify. No nonce: `usedCommitment`
    ///      is the replay guard, so a leaf registers its key at most once, and `nonceOf` is untouched.
    ///      The POP binds `epoch` where `register` binds the nonce, so the leaf and the key's proof of
    ///      possession share it (D2, D7). The subject is rebuilt from this chain and registry
    ///      (`RegistrationSubject`), so a leaf is good for exactly one registry.
    function registerByProof(
        bytes32 account,
        bytes calldata blsPubKey,
        bytes calldata pop,
        uint64 epoch,
        uint256 sourceChainId,
        bytes32 targetRoot,
        bytes calldata proof
    ) external returns (uint32 slotId) {
        if (paused) revert EnforcedPause();
        if (!proofRegistrationEnabled) revert ProofRegistrationDisabled();
        if (blsPubKey.length != 128 || pop.length != 256) revert BadLength();
        bytes32 commitment = keccak256(blsPubKey);
        if (commitment == IDENTITY_COMMITMENT) revert IdentityKey();
        if (usedCommitment[account][commitment]) revert KeyPreviouslyUsed();
        if (!_isProofSource(sourceChainId)) revert SourceNotAllowed(sourceChainId);
        if (!rootAnchor.isAnchored(sourceChainId, targetRoot)) revert RootNotAnchored(sourceChainId, targetRoot);

        _requirePop(account, blsPubKey, pop, epoch);
        _requireLeafProof(account, commitment, epoch, targetRoot, proof);

        slotId = _addSlot(account, commitment);
        emit KeyRegisteredByProof(account, slotId, blsPubKey, epoch, sourceChainId);
    }

    /// The key's proof of possession: `nonce` is the account nonce for `register`, the leaf's epoch
    /// for `registerByProof` (2.1b D7).
    function _requirePop(bytes32 account, bytes calldata blsPubKey, bytes calldata pop, uint256 nonce) private view {
        bytes memory msgG2 = BLS.hashToG2(popMsg(account, blsPubKey, nonce), bytes(DST_POP));
        if (!BLS.verifySingle(blsPubKey, msgG2, pop)) revert InvalidPop();
    }

    /// The home-chain leaf's inclusion proof, for the subject this registry would have been named in.
    function _requireLeafProof(
        bytes32 account,
        bytes32 commitment,
        uint64 epoch,
        bytes32 targetRoot,
        bytes calldata proof
    ) private view {
        bytes32 subject = RegistrationSubject.subject(block.chainid, registryId(), account, commitment, epoch);
        bytes32[] memory inputs = RequestAuth.buildEventInputs(targetRoot, subject, LeafDomain.REGISTERED);
        if (!proofVerifier.verify(proof, inputs)) revert InvalidLeafProof();
    }

    function _isProofSource(uint256 chainId) private view returns (bool) {
        uint256[] storage sources = _proofSources;
        for (uint256 i = 0; i < sources.length; i++) {
            if (sources[i] == chainId) return true;
        }
        return false;
    }

    /// Shorten-only, nonce-free, never guarded, and not pausable: the retirement lever
    /// (D6/D9) only ever reduces authority, so a registry pause must not block it. Names the key,
    /// not the slot, so one pre-signed `RetireKey` serves every registry (2.6 D1/D2).
    function setValidUntil(bytes32 account, OwnerAuth calldata owner, bytes32 keyCommitment, uint64 validUntil)
        external
    {
        uint32 slotId = slotOfKey(account, keyCommitment);
        KeySlot storage slot = entries[account].slots[slotId];
        if (validUntil == 0 || (slot.validUntil != 0 && validUntil >= slot.validUntil)) revert BadValidUntil();

        if (owner.legs.length != 0) revert LegMismatch();
        _checkOwner(account, owner, KeyMessages.Kind.Retire, keyCommitment, validUntil);

        slot.validUntil = validUntil;
        uint64 eff = uint64(block.timestamp) > validUntil ? uint64(block.timestamp) : validUntil;
        uint64 prev = expiries[account][slotId];
        expiries[account][slotId] = (prev == 0 || eff < prev) ? eff : prev;
        emit SlotValidUntilSet(account, slotId, validUntil);
    }

    /// Leaves the protocol: drops every slot, guarded while there are slots (t1-design §1.8). With
    /// none it still consumes the nonce, so an owner can kill an unfiled registration (review D2).
    function revoke(bytes32 account, OwnerAuth calldata owner, uint256 nonce) external {
        if (paused) revert EnforcedPause();
        RegistryEntry storage e = entries[account];
        if (nonce != nonceOf[account]) revert BadNonce();
        if (e.liveSlots.length != 0) _requireNoOpenPositions(account);

        _requireOwnLeg(owner.legs, nonce);
        _checkOwner(account, owner, KeyMessages.Kind.Revoke, bytes32(0), 0);

        for (uint256 i = 0; i < e.liveSlots.length; i++) {
            delete e.slots[e.liveSlots[i]];
            delete expiries[account][e.liveSlots[i]];
        }
        delete e.liveSlots;
        nonceOf[account] = nonce + 1;
        emit KeyRevoked(account, nonce);
    }

    /// Kills every outstanding signature naming `nonce` here (a pending registration) by consuming
    /// the nonce; no slot changes, so live keys stay and no guard is asked (review D2).
    function cancel(bytes32 account, OwnerAuth calldata owner, uint256 nonce) external {
        if (paused) revert EnforcedPause();
        if (nonce != nonceOf[account]) revert BadNonce();
        _requireOwnLeg(owner.legs, nonce);
        _checkOwner(account, owner, KeyMessages.Kind.Cancel, bytes32(0), 0);
        nonceOf[account] = nonce + 1;
        emit RegistrationCancelled(account, nonce);
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
        _slotOfKey[account][commitment] = slotId + 1;
    }

    /// When the slot stopped being usable: `0` while unbounded, else the recorded expiry (#422 D14/D14b).
    function _expiredAt(bytes32 account, uint32 id) private view returns (uint64) {
        uint64 vu = entries[account].slots[id].validUntil;
        if (vu == 0) return 0;
        uint64 at = expiries[account][id];
        return at == 0 ? vu : at;
    }

    /// Drops every dead slot the escrows can no longer need: past its expiry + GRACE_PERIOD, or at
    /// once when the guards are wired and none reports open positions for the account (#422 D17 —
    /// no order's cancel can still ask about its history; D17b — with no guard to ask, never at
    /// once). Not in the expiry's own second (D17a): a lock in that second still counts the kill.
    /// Swap-remove; order is not meaningful.
    function _prune(bytes32 account, RegistryEntry storage e) private {
        bool free = positionGuards.length != 0 && !_hasOpenPositions(account);
        uint256 i = 0;
        while (i < e.liveSlots.length) {
            uint32 id = e.liveSlots[i];
            uint64 vu = _expiredAt(account, id);
            if (vu != 0 && (block.timestamp > uint256(vu) + GRACE_PERIOD || (free && block.timestamp > vu))) {
                delete e.slots[id];
                delete expiries[account][id];
                e.liveSlots[i] = e.liveSlots[e.liveSlots.length - 1];
                e.liveSlots.pop();
                emit SlotPruned(account, id);
            } else {
                i++;
            }
        }
    }

    function _requireNoOpenPositions(bytes32 account) private view {
        if (_hasOpenPositions(account)) revert AccountInFlight();
    }

    function _hasOpenPositions(bytes32 account) private view returns (bool) {
        for (uint256 i = 0; i < positionGuards.length; i++) {
            if (positionGuards[i].hasOpenPositions(account)) return true;
        }
        return false;
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

    /// @notice Did any of `account`'s slots expire in `[from, to]` (#422 D12/D14/D14b, `IKeyRegistry`).
    function anySlotExpiredWithin(bytes32 account, uint64 from, uint64 to) external view returns (bool) {
        RegistryEntry storage e = entries[account];
        for (uint256 i = 0; i < e.liveSlots.length; i++) {
            uint64 vu = _expiredAt(account, e.liveSlots[i]);
            if (vu != 0 && vu >= from && vu <= to) return true;
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

    /// The slot a key occupies while it exists; on EVM the fingerprint is the stored commitment.
    function slotOfKey(bytes32 account, bytes32 keyCommitment) public view returns (uint32 slotId) {
        uint32 plusOne = _slotOfKey[account][keyCommitment];
        if (plusOne == 0) revert NoSuchSlot();
        slotId = plusOne - 1;
        if (entries[account].slots[slotId].commitment != keyCommitment) revert NoSuchSlot();
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

    // =========================================================================
    // Owner auth
    // =========================================================================

    /// The key messages' EIP-712 domain ("ProofBridge Keys", "2", salt): no chain or contract (2.6 D3);
    /// the salt binds this registry's environment (review D3).
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparator;
    }

    function keysEnv() public view returns (string memory) {
        return ShortStrings.toString(_env);
    }

    /// D5 check 1: exactly one leg names this registry (chain, id), whatever its nonce (review 50-3),
    /// and that leg carries the current nonce.
    function _requireOwnLeg(KeyLeg[] calldata legs, uint256 nonce) private view {
        uint256 found;
        uint256 at;
        bytes32 self = registryId();
        for (uint256 i = 0; i < legs.length; i++) {
            if (legs[i].chainId == block.chainid && legs[i].registry == self) {
                found++;
                at = i;
            }
        }
        if (found != 1 || legs[at].nonce != nonce) revert LegMismatch();
    }

    /// Scheme dispatch (D5 checks 2–3); the text is built only for the ed25519 path.
    function _checkOwner(
        bytes32 account,
        OwnerAuth calldata owner,
        KeyMessages.Kind kind,
        bytes32 keyCommitment,
        uint64 time
    ) private view {
        if (owner.scheme == Scheme.Secp256k1) {
            checkSecp256k1Owner(
                account, KeyMessages.digest(_domainSeparator, kind, account, keyCommitment, owner.legs, time), owner.sig
            );
        } else if (owner.scheme == Scheme.Sep53) {
            checkSep53Owner(
                account, KeyMessages.text(bytes(keysEnv()), kind, account, keyCommitment, owner.legs, time), owner.sig
            );
        } else {
            revert UnknownScheme(); // unreachable today: calldata decoding rejects out-of-range enums
        }
    }

    /// `account` must be 12 zero bytes || the recovered signer address. Review D1, the rule the TS
    /// verifier and Soroban share: v in {0, 1, 27, 28} (normalized), s in the low half.
    function checkSecp256k1Owner(bytes32 account, bytes32 digest, bytes calldata data) private pure {
        if (data.length != 65) revert BadLength();
        if (uint256(account) >> 160 != 0) revert OwnerMismatch();
        uint8 v = uint8(bytes1(data[64:65]));
        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert OwnerMismatch();
        if (uint256(bytes32(data[32:64])) > SECP256K1_HALF_N) revert OwnerMismatch();

        address signer = ecrecover(digest, v, bytes32(data[0:32]), bytes32(data[32:64]));
        if (signer == address(0) || signer != address(uint160(uint256(account)))) {
            revert OwnerMismatch();
        }
    }

    /// `account` is the raw 32-byte ed25519 pubkey, never a padded EVM shape. SEP-53 wallets sign
    /// text: SHA256(prefix || text). Caller supplies the decompressed Edwards point; it is checked
    /// against `account` and the curve equation, so a wrong point cannot verify.
    function checkSep53Owner(bytes32 account, bytes memory text, bytes calldata data) private view {
        if (data.length != 128) revert BadLength();
        if (uint256(account) >> 160 == 0) revert OwnerMismatch();
        (uint256 r, uint256 s, uint256 edX, uint256 edY) = abi.decode(data, (uint256, uint256, uint256, uint256));

        if (SCL_sha512.Swap256(SCL_EIP6565.edCompress([edX, edY])) != uint256(account)) {
            revert OwnerMismatch();
        }
        checkOnEdwardsCurve(edX, edY);

        uint256[5] memory extKpub;
        (extKpub[0], extKpub[1]) = SCL_EIP6565.Edwards2WeierStrass(edX, edY);
        extKpub[4] = uint256(account);

        string memory m = string(bytes.concat(sha256(bytes.concat(SEP53_PREFIX, text))));
        if (!SCL_EIP6565.Verify_LE(m, r, s, extKpub)) revert OwnerMismatch();
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
