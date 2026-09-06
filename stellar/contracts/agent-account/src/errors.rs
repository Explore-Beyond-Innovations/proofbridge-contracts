use soroban_sdk::contracterror;

#[contracterror]
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AccountError {
    /// No policy installed for the signing agent (or, on secp, a wrong signer).
    NoPolicyForAgent = 1,
    /// The agent was revoked; revocation is sticky per agent id.
    AgentRevoked = 2,
    /// `valid_until` has passed.
    PolicyExpired = 3,
    /// secp recovery id outside 0/1 (27/28). A bad ed25519 signature traps in the host instead.
    BadSignature = 4,
    /// A non-`Contract` auth context on the agent path.
    UnsupportedContext = 5,
    /// `ctx.contract` is not one of the pinned escrows.
    TargetNotAllowed = 6,
    /// `ctx.fn_name` is not in the policy's `allowed_actions`.
    ActionNotAllowed = 7,
    /// Lock args missing a required key, wrong type, or bad decimals.
    BadArgs = 8,
    /// A token in the lock is not on the policy's whitelist.
    TokenNotAllowed = 9,
    /// Ad-side lock amount exceeds `max_per_order`.
    CapExceeded = 10,
    /// The lock's `ad_creator` is not this account, or its settlement identity is not the policy's.
    SettlementSignerMismatch = 11,
    /// `set_policy` input failed validation (lengths, duplicates, reserved selector, zero values, foreign signer, past expiry).
    BadPolicy = 12,
    /// `targets` empty, too long, or naming this account.
    BadTargets = 13,
    /// `owner` is this account: the owner path would need no signature.
    BadOwner = 14,
}
