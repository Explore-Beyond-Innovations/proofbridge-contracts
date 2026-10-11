// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/// @notice What the parser reverts with.
/// @dev An interface, so the module can inherit it. `setAgentPolicy` reaches the parser by
///      DELEGATECALL and these bubble up through it, but a contract's ABI lists only its own
///      errors: a client holding the module's ABI alone would see an unknown selector.
interface IAgentPolicyCodecErrors {
    error AgentPolicyCodec__BadDomain();
    error AgentPolicyCodec__BadTokenCount(uint8 count);
    error AgentPolicyCodec__BadOrderTokenCount(uint8 count);
    error AgentPolicyCodec__ZeroToken();
    error AgentPolicyCodec__BadAdScope();
    error AgentPolicyCodec__NotAscending();
    error AgentPolicyCodec__TrailingBytes(uint256 got, uint256 want);
    error AgentPolicyCodec__LimitTooWide();
    error AgentPolicyCodec__UnknownAction(uint8 id);
}

/**
 * @title AgentPolicyCodec
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice The canonical byte form of an agent policy, parsed.
 *
 *         One encoding for both chains: Soroban stores the policy as a struct and publishes its
 *         fields, from which the off-chain encoder (order-params) computes these same bytes; the
 *         EVM never stores the bytes at all. The owner hands the bytes to `setAgentPolicy`, which
 *         derives every storage row from them and keeps
 *         `keccak256(policy)` as the policy's identity — so the two can never drift, because the
 *         rows and the fingerprint come out of the same input.
 *
 *         Layout (big-endian, no padding):
 *
 *           bytes32  domain
 *           uint8    actionId                                      today only lockForOrder
 *           uint8    adTokenCount  || rows                         ascending by token, 1..16
 *             bytes32 token, uint256 maxPerOrder, uint256 capacity, uint256 refillPerSecond
 *           uint8    orderTokenCount || bytes32[] tokens           ascending, 1..16
 *           uint8    adScopeKind   0 = every ad this account owns, 1 = the list below
 *           uint8    adScopeCount
 *             uint16 length || utf8 bytes                          ascending, unique
 *           uint64   validUntil    0 = no expiry
 *           bytes32  settlementSigner
 *
 *         Ad tokens carry limits because a lock spends the ad-chain token; order tokens are a plain
 *         list, because the order-chain token is only checked for membership. A token may appear
 *         in both lists.
 *
 *         `revoked` is absent by design: revoking is overwriting the fingerprint, which
 *         invalidates every copy of the policy at once. The live buckets are absent for the
 *         opposite reason — they are the chain's state, not the owner's statement.
 */
library AgentPolicyCodec {
    bytes32 internal constant DOMAIN = keccak256("ProofBridge.AgentPolicy.v3");

    /// @notice Chain-neutral action ids. Soroban names an action with a `Symbol` and the EVM with a
    ///         4-byte selector, so neither side's spelling can be the one that gets hashed.
    uint8 internal constant ACTION_LOCK_FOR_ORDER = 1;

    /// @notice Per list: at most 16 ad tokens and 16 order tokens.
    uint8 internal constant MAX_WHITELIST_TOKENS = 16;
    uint8 internal constant MAX_AD_SCOPE = 16;
    uint16 internal constant MAX_AD_ID_BYTES = 1024;

    uint256 private constant ROW_BYTES = 128;

    struct TokenRow {
        bytes32 token;
        uint256 maxPerOrder;
        uint256 capacity;
        uint256 refillPerSecond;
    }

    /// @notice A policy, decoded whole: what `setAgentPolicy` writes its rows from.
    struct Decoded {
        bytes32 settlementSigner;
        uint64 validUntil;
        bool adScopeAll;
        uint8 actionId;
        TokenRow[] adTokens;
        bytes32[] orderTokens;
        bytes32[] adScopeHashes;
    }

    /**
     * @notice Parse a policy and return every part of it, in one call.
     * @dev **The one `external` function here, and the reason this library is deployed rather than
     *      inlined.** An internal library's code is copied into whatever calls it, so it counts
     *      against the caller's EIP-170 limit; an external one is its own contract, reached by
     *      DELEGATECALL, and does not. The agent module was at 22.5 of 24.5 KB.
     *
     *      It is the right thing to move because it runs only in the owner's `setAgentPolicy` —
     *      never while an agent's operation is validated or executed — so ERC-7562's rules never
     *      reach it and no trade pays for the call. It is pure: bytes in, a struct out.
     *
     *      One call rather than four: each external library call re-sends the policy and
     *      ABI-encodes its answer, and the call sites are what the caller pays for in bytes.
     */
    function decode(bytes calldata policy) external pure returns (Decoded memory d) {
        View memory v = parse(policy);
        d.settlementSigner = v.settlementSigner;
        d.validUntil = v.validUntil;
        d.adScopeAll = v.adScopeAll;
        d.actionId = v.actionId;
        d.adTokens = new TokenRow[](v.tokenCount);
        for (uint256 i = 0; i < v.tokenCount; ++i) {
            d.adTokens[i] = tokenRowAt(policy, v, i);
        }
        d.orderTokens = new bytes32[](v.orderTokenCount);
        for (uint256 i = 0; i < v.orderTokenCount; ++i) {
            d.orderTokens[i] = orderTokenAt(policy, v, i);
        }
        d.adScopeHashes = adScopeHashes(policy, v);
    }

    /// @notice Where each section starts, so callers walk the bytes once.
    struct View {
        uint8 actionId;
        uint256 tokensAt;
        uint8 tokenCount;
        uint256 orderTokensAt;
        uint8 orderTokenCount;
        bool adScopeAll;
        uint8 adScopeCount;
        uint256 adScopeAt;
        uint64 validUntil;
        bytes32 settlementSigner;
    }

    /**
     * @notice Walk the policy once, checking every bound and the canonical ordering.
     * @dev Ordering is checked here rather than trusted: `setAgentPolicy` derives storage rows from
     *      these bytes, and a policy that repeated a token would write one row twice and leave the
     *      owner believing both took effect.
     */
    function parse(bytes calldata policy) internal pure returns (View memory v) {
        if (policy.length < 32 || bytes32(policy[0:32]) != DOMAIN) {
            revert IAgentPolicyCodecErrors.AgentPolicyCodec__BadDomain();
        }
        uint256 at = 32;

        // One action, a fixed field. An id this language does not know would authorize nothing,
        // which Soroban refuses as `BadPolicy`.
        v.actionId = uint8(policy[at]);
        at += 1;
        if (v.actionId != ACTION_LOCK_FOR_ORDER) {
            revert IAgentPolicyCodecErrors.AgentPolicyCodec__UnknownAction(v.actionId);
        }

        v.tokenCount = uint8(policy[at]);
        at += 1;
        if (v.tokenCount == 0 || v.tokenCount > MAX_WHITELIST_TOKENS) {
            revert IAgentPolicyCodecErrors.AgentPolicyCodec__BadTokenCount(v.tokenCount);
        }
        v.tokensAt = at;
        uint256 prevToken;
        for (uint256 i = 0; i < v.tokenCount; ++i) {
            uint256 rowAt = at + i * ROW_BYTES;
            uint256 token = uint256(bytes32(policy[rowAt:rowAt + 32]));
            _checkToken(token, prevToken, i);
            prevToken = token;
            // Soroban's limits are `u128`. The fields are 32 bytes for the EVM's convenience, but a
            // value the other chain cannot hold would make the same policy mean two things — and
            // the bucket's overflow clamp fires at the `u128` ceiling on both sides.
            for (uint256 f = 1; f < 4; ++f) {
                if (uint256(bytes32(policy[rowAt + f * 32:rowAt + f * 32 + 32])) > type(uint128).max) {
                    revert IAgentPolicyCodecErrors.AgentPolicyCodec__LimitTooWide();
                }
            }
        }
        at += uint256(v.tokenCount) * ROW_BYTES;

        v.orderTokenCount = uint8(policy[at]);
        at += 1;
        if (v.orderTokenCount == 0 || v.orderTokenCount > MAX_WHITELIST_TOKENS) {
            revert IAgentPolicyCodecErrors.AgentPolicyCodec__BadOrderTokenCount(v.orderTokenCount);
        }
        v.orderTokensAt = at;
        prevToken = 0;
        for (uint256 i = 0; i < v.orderTokenCount; ++i) {
            uint256 token = uint256(bytes32(policy[at + i * 32:at + i * 32 + 32]));
            _checkToken(token, prevToken, i);
            prevToken = token;
        }
        at += uint256(v.orderTokenCount) * 32;

        uint8 kind = uint8(policy[at]);
        v.adScopeCount = uint8(policy[at + 1]);
        at += 2;
        if (kind == 0) {
            if (v.adScopeCount != 0) revert IAgentPolicyCodecErrors.AgentPolicyCodec__BadAdScope();
            v.adScopeAll = true;
        } else if (kind == 1) {
            if (v.adScopeCount == 0 || v.adScopeCount > MAX_AD_SCOPE) {
                revert IAgentPolicyCodecErrors.AgentPolicyCodec__BadAdScope();
            }
        } else {
            revert IAgentPolicyCodecErrors.AgentPolicyCodec__BadAdScope();
        }
        v.adScopeAt = at;
        uint256 prevAt;
        uint256 prevLen;
        for (uint256 i = 0; i < v.adScopeCount; ++i) {
            uint16 len = uint16(bytes2(policy[at:at + 2]));
            at += 2;
            // 1024 is Soroban's ad id bound; a longer id would be a policy one chain accepts and the
            // other refuses.
            if (len == 0 || len > MAX_AD_ID_BYTES) revert IAgentPolicyCodecErrors.AgentPolicyCodec__BadAdScope();
            // Strictly ascending by raw bytes, the rule both token lists already follow. The first
            // version compared adjacent *hashes*, which catches neither an unsorted scope nor a
            // non-adjacent repeat — and the off-chain encoder always sorts, so such bytes carried a
            // fingerprint it could never produce for what the owner thinks is the same policy.
            if (i > 0 && !_lessThan(policy[prevAt:prevAt + prevLen], policy[at:at + len])) {
                revert IAgentPolicyCodecErrors.AgentPolicyCodec__NotAscending();
            }
            prevAt = at;
            prevLen = len;
            at += len;
        }

        v.validUntil = uint64(bytes8(policy[at:at + 8]));
        at += 8;
        v.settlementSigner = bytes32(policy[at:at + 32]);
        at += 32;

        // A parse that stopped early would call two different byte strings the same policy, which
        // is the one thing a fingerprint must not permit.
        if (at != policy.length) revert IAgentPolicyCodecErrors.AgentPolicyCodec__TrailingBytes(policy.length, at);
    }

    /// @dev Non-zero, and strictly above the previous entry of the same list.
    function _checkToken(uint256 token, uint256 prevToken, uint256 i) private pure {
        if (token == 0) revert IAgentPolicyCodecErrors.AgentPolicyCodec__ZeroToken();
        if (i > 0 && token <= prevToken) revert IAgentPolicyCodecErrors.AgentPolicyCodec__NotAscending();
    }

    /// @dev Lexicographic by byte, a proper prefix sorting first — the order the TypeScript and Rust
    ///      encoders produce. A short final word is zero-padded by the conversion; a real zero byte
    ///      there only ties, and ties fall through to the length.
    function _lessThan(bytes calldata a, bytes calldata b) private pure returns (bool) {
        uint256 n = a.length < b.length ? a.length : b.length;
        for (uint256 i = 0; i < n; i += 32) {
            bytes32 wa = bytes32(a[i:i + 32 > a.length ? a.length : i + 32]);
            bytes32 wb = bytes32(b[i:i + 32 > b.length ? b.length : i + 32]);
            if (wa != wb) return uint256(wa) < uint256(wb);
        }
        return a.length < b.length;
    }

    function orderTokenAt(bytes calldata policy, View memory v, uint256 i) internal pure returns (bytes32) {
        uint256 at = v.orderTokensAt + i * 32;
        return bytes32(policy[at:at + 32]);
    }

    function tokenRowAt(bytes calldata policy, View memory v, uint256 i) internal pure returns (TokenRow memory row) {
        uint256 at = v.tokensAt + i * ROW_BYTES;
        row.token = bytes32(policy[at:at + 32]);
        row.maxPerOrder = uint256(bytes32(policy[at + 32:at + 64]));
        row.capacity = uint256(bytes32(policy[at + 64:at + 96]));
        row.refillPerSecond = uint256(bytes32(policy[at + 96:at + 128]));
    }

    /// @notice `keccak256` of each scoped ad id, in order, so the caller can write one row each.
    function adScopeHashes(bytes calldata policy, View memory v) internal pure returns (bytes32[] memory out) {
        out = new bytes32[](v.adScopeCount);
        uint256 at = v.adScopeAt;
        for (uint256 i = 0; i < v.adScopeCount; ++i) {
            uint16 len = uint16(bytes2(policy[at:at + 2]));
            at += 2;
            out[i] = keccak256(policy[at:at + len]);
            at += len;
        }
    }
}
