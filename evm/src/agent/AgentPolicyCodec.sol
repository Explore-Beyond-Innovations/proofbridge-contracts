// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/**
 * @title AgentPolicyCodec
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice The canonical byte form of an agent policy, parsed.
 *
 *         One encoding drives both chains: Soroban stores the policy as a struct and hashes these
 *         same bytes for parity, the EVM never stores it at all. The owner hands the bytes to
 *         `setAgentPolicy`, which derives every storage row from them and keeps
 *         `keccak256(policy)` as the policy's identity — so the two can never drift, because the
 *         rows and the fingerprint come out of the same input.
 *
 *         Layout (big-endian, no padding):
 *
 *           bytes32  domain
 *           uint8    actionCount   || uint8[] actionIds            ascending, unique
 *           uint8    tokenCount    || rows                         ascending by token
 *             bytes32 token, uint256 maxPerOrder, uint256 capacity, uint256 refillPerSecond
 *           uint8    adScopeKind   0 = every ad this account owns, 1 = the list below
 *           uint8    adScopeCount
 *             uint16 length || utf8 bytes                          ascending, unique
 *           uint64   validUntil    0 = no expiry
 *           bytes32  settlementSigner
 *
 *         `revoked` is absent by design: revoking is overwriting the fingerprint, which
 *         invalidates every copy of the policy at once. The live buckets are absent for the
 *         opposite reason — they are the chain's state, not the owner's statement.
 */
library AgentPolicyCodec {
    bytes32 internal constant DOMAIN = keccak256("ProofBridge.AgentPolicy.v1");

    /// @notice Chain-neutral action ids. Soroban names an action with a `Symbol` and the EVM with a
    ///         4-byte selector, so neither side's spelling can be the one that gets hashed.
    uint8 internal constant ACTION_LOCK_FOR_ORDER = 1;

    uint8 internal constant MAX_ALLOWED_ACTIONS = 4;
    uint8 internal constant MAX_WHITELIST_TOKENS = 16;
    uint8 internal constant MAX_AD_SCOPE = 16;

    uint256 private constant ROW_BYTES = 128;

    error AgentPolicyCodec__BadDomain();
    error AgentPolicyCodec__BadActionCount(uint8 count);
    error AgentPolicyCodec__BadTokenCount(uint8 count);
    error AgentPolicyCodec__BadAdScope();
    error AgentPolicyCodec__NotAscending();
    error AgentPolicyCodec__TrailingBytes(uint256 got, uint256 want);
    error AgentPolicyCodec__LimitTooWide();

    struct TokenRow {
        bytes32 token;
        uint256 maxPerOrder;
        uint256 capacity;
        uint256 refillPerSecond;
    }

    /// @notice Where each section starts, so callers walk the bytes once.
    struct View {
        uint256 actionsAt;
        uint8 actionCount;
        uint256 tokensAt;
        uint8 tokenCount;
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
        if (policy.length < 32 || bytes32(policy[0:32]) != DOMAIN) revert AgentPolicyCodec__BadDomain();
        uint256 at = 32;

        v.actionCount = uint8(policy[at]);
        at += 1;
        if (v.actionCount == 0 || v.actionCount > MAX_ALLOWED_ACTIONS) {
            revert AgentPolicyCodec__BadActionCount(v.actionCount);
        }
        v.actionsAt = at;
        for (uint256 i = 1; i < v.actionCount; ++i) {
            if (uint8(policy[at + i]) <= uint8(policy[at + i - 1])) revert AgentPolicyCodec__NotAscending();
        }
        at += v.actionCount;

        v.tokenCount = uint8(policy[at]);
        at += 1;
        if (v.tokenCount == 0 || v.tokenCount > MAX_WHITELIST_TOKENS) {
            revert AgentPolicyCodec__BadTokenCount(v.tokenCount);
        }
        v.tokensAt = at;
        uint256 prevToken;
        for (uint256 i = 0; i < v.tokenCount; ++i) {
            uint256 rowAt = at + i * ROW_BYTES;
            uint256 token = uint256(bytes32(policy[rowAt:rowAt + 32]));
            if (i > 0 && token <= prevToken) revert AgentPolicyCodec__NotAscending();
            prevToken = token;
            // Soroban's limits are `u128`. The fields are 32 bytes for the EVM's convenience, but a
            // value the other chain cannot hold would make the same policy mean two things — and
            // the bucket's overflow clamp fires at the `u128` ceiling on both sides.
            for (uint256 f = 1; f < 4; ++f) {
                if (uint256(bytes32(policy[rowAt + f * 32:rowAt + f * 32 + 32])) > type(uint128).max) {
                    revert AgentPolicyCodec__LimitTooWide();
                }
            }
        }
        at += uint256(v.tokenCount) * ROW_BYTES;

        uint8 kind = uint8(policy[at]);
        v.adScopeCount = uint8(policy[at + 1]);
        at += 2;
        if (kind == 0) {
            if (v.adScopeCount != 0) revert AgentPolicyCodec__BadAdScope();
            v.adScopeAll = true;
        } else if (kind == 1) {
            if (v.adScopeCount == 0 || v.adScopeCount > MAX_AD_SCOPE) revert AgentPolicyCodec__BadAdScope();
        } else {
            revert AgentPolicyCodec__BadAdScope();
        }
        v.adScopeAt = at;
        bytes32 prevAd;
        for (uint256 i = 0; i < v.adScopeCount; ++i) {
            uint16 len = uint16(bytes2(policy[at:at + 2]));
            at += 2;
            if (len == 0) revert AgentPolicyCodec__BadAdScope();
            bytes32 cur = keccak256(policy[at:at + len]);
            // Hashes, not the strings themselves: the encoder sorts by raw UTF-8 bytes and this
            // only needs "no two are the same", which a hash answers in one word.
            if (i > 0 && cur == prevAd) revert AgentPolicyCodec__BadAdScope();
            prevAd = cur;
            at += len;
        }

        v.validUntil = uint64(bytes8(policy[at:at + 8]));
        at += 8;
        v.settlementSigner = bytes32(policy[at:at + 32]);
        at += 32;

        // A parse that stopped early would call two different byte strings the same policy, which
        // is the one thing a fingerprint must not permit.
        if (at != policy.length) revert AgentPolicyCodec__TrailingBytes(policy.length, at);
    }

    function actionAt(bytes calldata policy, View memory v, uint256 i) internal pure returns (uint8) {
        return uint8(policy[v.actionsAt + i]);
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
