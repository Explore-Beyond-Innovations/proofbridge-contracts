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
    /// The lock names an ad outside the policy's `ad_scope`.
    AdNotAllowed = 15,
    /// A volume bucket — the agent's or the account's — cannot cover this lock (2.1d).
    VolumeExceeded = 16,
    /// The ad token is whitelisted but has no configured volume limit, on the policy or the
    /// account. Silence is not permission.
    NoVolumeLimit = 17,
    /// An extractive owner call on a guarded ad with no matured schedule for exactly it (2.1e).
    NotScheduled = 18,
    /// `set_guard_rail` / `schedule_extractive` input failed validation (a zero delay, window,
    /// capacity or refill; an amount on an action that has none; too many guarded ads; an overflow).
    BadGuardRail = 19,
    /// Scheduling against an ad that has no guardrail. Distinct from `NotScheduled`, which
    /// everywhere else means "no matured schedule" — overloading it made the two indistinguishable.
    NoGuardRail = 20,
    /// The ad is on the guarded roster but its settings entry has archived. Refused rather than
    /// read as unguarded (2.3h: absence must not be permission).
    GuardRailArchived = 21,
}
