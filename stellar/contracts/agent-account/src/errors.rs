use soroban_sdk::contracterror;

#[contracterror]
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AccountError {
    /// No policy installed for the signing agent.
    NoPolicyForAgent = 1,
    /// The agent was revoked; revocation is sticky per agent id.
    AgentRevoked = 2,
    /// `valid_until` has passed.
    PolicyExpired = 3,
    /// Agent signature did not verify / recover to a known agent.
    BadSignature = 4,
    /// A non-`Contract` auth context on the agent path.
    UnsupportedContext = 5,
    /// `ctx.contract` is not one of the pinned escrows.
    TargetNotAllowed = 6,
    /// `ctx.fn_name` is not in the policy's `allowed_actions`.
    ActionNotAllowed = 7,
    /// Call args did not decode to the expected lock params.
    BadArgs = 8,
    /// A token in the lock is not on the policy's whitelist.
    TokenNotAllowed = 9,
    /// Ad-side lock amount exceeds `max_per_order`.
    CapExceeded = 10,
    /// The lock's settlement identity is not the policy's `settlement_signer`.
    SettlementSignerMismatch = 11,
    /// `set_policy` input failed validation (lengths, reserved selector, zero values, past expiry).
    BadPolicy = 12,
    /// `targets` empty or too long.
    BadTargets = 13,
}
