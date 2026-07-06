// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {BLS} from "./libraries/BLS.sol";
import {SCL_EIP6565} from "@scl/lib/libSCL_EIP6565.sol";
import {SCL_sha512} from "@scl/hash/SCL_sha512.sol";
import {p as ED_P} from "@scl/fields/SCL_wei25519.sol";

interface IPositionGuard {
    function hasOpenPositions(bytes32 account) external view returns (bool);
}

/// @title BLSKeyRegistry — maps a 32-byte account id to its one BLS key.
/// @notice State changes are authenticated by the owner's wallet sig + BLS
///         proof-of-possession + per-account nonce, never by msg.sender.
contract BLSKeyRegistry {
    enum Scheme {
        Eip712, // EVM-home: typed sig, recovered address must be `account`
        Sep53 // Stellar-home: ed25519 over SHA256("Stellar Signed Message:\n" || digest)
    }

    struct OwnerAuth {
        Scheme scheme;
        bytes data; // Eip712: r||s||v (65 B) · Sep53: abi.encode(r, s, edX, edY)
    }

    string public constant DST_POP = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    bytes32 private constant REG_TAG = keccak256("ProofBridge.BLSKeyRegistry.Register.v1");
    bytes32 private constant REVOKE_TAG = keccak256("ProofBridge.BLSKeyRegistry.Revoke.v1");
    bytes32 private constant POP_TAG = keccak256("ProofBridge.BLSKeyRegistry.PoP.v1");

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant REGISTER_TYPEHASH = keccak256("Register(bytes blsPubKey,bytes pop,uint256 nonce)");
    bytes32 private constant REVOKE_TYPEHASH = keccak256("Revoke(uint256 nonce)");

    bytes private constant SEP53_PREFIX = "Stellar Signed Message:\n";

    /// ed25519 Edwards d (the SCL field lib only exports the Weierstrass form).
    uint256 private constant ED_D = 37095705934669439343138083508754565189542113879843219016388785533085940283555;

    address public admin;
    IPositionGuard public positionGuard;
    address public pendingAdmin;
    bool public paused;

    mapping(bytes32 => bytes32) private commitments; // keccak256(blsPubKey), 0 = unset
    mapping(bytes32 => uint256) public nonceOf;

    event KeyRegistered(bytes32 indexed account, bytes blsPubKey, uint256 nonce);
    event Paused(address account);
    event Unpaused(address account);
    event AdminTransferStarted(address indexed from, address indexed to);
    event AdminTransferred(address indexed from, address indexed to);
    event KeyRevoked(bytes32 indexed account, uint256 nonce);
    event PositionGuardSet(address guard);

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

    function setPositionGuard(address guard) external {
        if (msg.sender != admin) revert NotAdmin();
        positionGuard = IPositionGuard(guard);
        emit PositionGuardSet(guard);
    }

    function register(
        bytes32 account,
        OwnerAuth calldata owner,
        bytes calldata blsPubKey,
        bytes calldata pop,
        uint256 nonce
    ) external {
        if (paused) revert EnforcedPause();
        if (blsPubKey.length != 128 || pop.length != 256) revert BadLength();
        if (nonce != nonceOf[account]) revert BadNonce();
        if (keccak256(blsPubKey) == keccak256(new bytes(128))) revert IdentityKey();

        bytes memory msgG2 = BLS.hashToG2(popMsg(account, blsPubKey, nonce), bytes(DST_POP));
        if (!BLS.verifySingle(blsPubKey, msgG2, pop)) revert InvalidPop();

        if (owner.scheme == Scheme.Eip712) {
            bytes32 structHash = keccak256(abi.encode(REGISTER_TYPEHASH, keccak256(blsPubKey), keccak256(pop), nonce));
            checkEip712Owner(account, structHash, owner.data);
        } else {
            checkSep53Owner(account, regDigest(account, blsPubKey, nonce), owner.data);
        }

        commitments[account] = keccak256(blsPubKey);
        nonceOf[account] = nonce + 1;
        emit KeyRegistered(account, blsPubKey, nonce);
    }

    function revoke(bytes32 account, OwnerAuth calldata owner, uint256 nonce) external {
        if (paused) revert EnforcedPause();
        if (commitments[account] == bytes32(0)) revert NotRegistered();
        if (nonce != nonceOf[account]) revert BadNonce();
        if (address(positionGuard) != address(0) && positionGuard.hasOpenPositions(account)) {
            revert AccountInFlight();
        }

        if (owner.scheme == Scheme.Eip712) {
            checkEip712Owner(account, keccak256(abi.encode(REVOKE_TYPEHASH, nonce)), owner.data);
        } else {
            checkSep53Owner(account, revokeDigest(account, nonce), owner.data);
        }

        delete commitments[account];
        nonceOf[account] = nonce + 1;
        emit KeyRevoked(account, nonce);
    }

    /// Returns keccak256(blsPubKey) — the full key travels in unlock metadata.
    function keyOf(bytes32 account) external view returns (bytes32) {
        bytes32 c = commitments[account];
        if (c == bytes32(0)) revert NotRegistered();
        return c;
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

    /// `account` is the raw 32-byte ed25519 pubkey (SEP-53: the wallet signs
    /// SHA256(prefix || digest)). Caller supplies the decompressed Edwards
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

        string memory m = string(bytes.concat(sha256(bytes.concat(SEP53_PREFIX, digest))));
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
