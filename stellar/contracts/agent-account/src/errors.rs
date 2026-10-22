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
    /// `ctx.fn_name` is not the policy's `allowed_action`.
    ActionNotAllowed = 7,
    /// Call args missing a required key, of the wrong type or arity, or with bad decimals (the lock,
    /// the owner path's escrow calls, and `schedule`'s args for any action).
    BadArgs = 8,
    /// The lock's ad-chain token is not one of the policy's `ad_tokens`, or its order-chain token
    /// is not one of its `order_tokens`.
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
    /// An ad token has no account-wide volume limit: at install, or because the row archived
    /// under a live policy. Silence is not permission.
    NoVolumeLimit = 17,
    /// A delayed owner call with no matured, unexpired schedule committed to exactly its arguments.
    NotScheduled = 18,
    /// `set_guard_rail` / `schedule` input failed validation (a zero delay, window, capacity or
    /// refill; too many guarded ads; a schedule window that overflows).
    BadGuardRail = 19,
    /// Scheduling against an ad that has no guardrail. Distinct from `NotScheduled`, which
    /// everywhere else means "no matured schedule" — overloading it made the two indistinguishable.
    NoGuardRail = 20,
    /// The ad is on the guarded roster but its settings entry has archived. Refused rather than
    /// read as unguarded (2.3h: absence must not be permission).
    GuardRailArchived = 21,
    /// `migrate` found a schema version newer than this code knows: a downgrade it cannot read.
    SchemaTooNew = 22,
    /// `schedule` on an ad scope whose args name a different ad (`args[0]`, or the order's
    /// `ad_id`): a schedule that could never be spent, and an event that would mislead a watcher.
    ScopeMismatch = 23,
    /// Plan 46: `AccountSig::Owner` is no longer accepted. The owner acts through the account's own
    /// functions (`create_ad`, `fund_ad`, `call`, `sweep`), which every wallet can sign.
    OwnerPathRetired = 24,
    /// Plan 46 D2: an owner call left the account holding a different balance of a token it touched.
    /// The account forwards what the owner pays in and never keeps or releases funds at rest.
    FundsLeft = 25,
    /// Plan 46: an approval passed to `call` is not a token `transfer` from this account, an
    /// `open_dispute` whose nested calls are only such transfers, or this account's own
    /// `record_response` for the escrow being called.
    BadApproval = 26,
    /// `call` named a function the account doesn't make: a token's own functions always (no token is
    /// reached as the account; funds at rest leave through `sweep`), and, while any ad is guarded,
    /// any escrow function not on the account's list.
    FunctionNotAllowed = 27,
}
