use soroban_sdk::{contractevent, Address, BytesN, String, Symbol, Vec};

/// `fingerprint` is the canonical policy hash (`policy_fingerprint`), so a watcher can tell which
/// policy was installed without a storage read.
#[contractevent(topics = ["pol_set"], data_format = "vec")]
pub struct PolicySet {
    #[topic]
    pub agent_id: BytesN<32>,
    pub settlement_signer: BytesN<32>,
    pub valid_until: u64,
    pub fingerprint: BytesN<32>,
}

/// 2.1e wires the runtime to fire the owner's pre-signed registry
/// retirements off this event; the event itself lands here.
#[contractevent(topics = ["agent_rev"], data_format = "single-value")]
pub struct AgentRevoked {
    #[topic]
    pub agent_id: BytesN<32>,
}

/// The account-wide volume ceiling for one token changed (2.1d). The numbers ride on the event so
/// a watcher sees a raised ceiling without reading storage.
#[contractevent(topics = ["acct_lim"], data_format = "vec")]
pub struct AccountLimitSet {
    #[topic]
    pub token: BytesN<32>,
    pub capacity: u128,
    pub refill_per_second: u128,
}

/// The owner armed, tightened, loosened or disarmed an ad's guardrail (2.1e).
#[contractevent(topics = ["guard_set"], data_format = "vec")]
pub struct GuardRailSet {
    #[topic]
    pub ad_id: String,
    /// Arming, tightening and disarming all publish here, so the stream has to say which. Without
    /// it a disarm is indistinguishable from a re-arm, and the row a reader would fall back on is
    /// gone — which is the one alert this feature must be able to raise, since disarming is an
    /// attacker's first move.
    pub armed: bool,
    pub threshold: u128,
    pub delay: u64,
    pub window: u64,
}

/// An extractive call was scheduled. **This is the point of the delay** — a window nobody can see
/// start is not a warning, so the amount and the destination ride on the event rather than being
/// left to a storage read.
#[contractevent(topics = ["extr_sched"], data_format = "vec")]
pub struct ExtractiveScheduled {
    #[topic]
    pub ad_id: String,
    #[topic]
    pub action: Symbol,
    pub amount: u128,
    pub to: Address,
    pub ready_at: u64,
    pub expires_at: u64,
}

/// The owner stood a schedule down before it was spent.
#[contractevent(topics = ["extr_cancel"], data_format = "vec")]
pub struct ExtractiveCancelled {
    #[topic]
    pub ad_id: String,
    #[topic]
    pub action: Symbol,
}

/// An above-threshold owner lock was scheduled on a guarded ad, bound to the exact order.
#[contractevent(topics = ["lock_sched"], data_format = "vec")]
pub struct LockScheduled {
    #[topic]
    pub ad_id: String,
    pub amount: u128,
    pub commitment: BytesN<32>,
    pub ready_at: u64,
    pub expires_at: u64,
}

/// An account-wide change (`upgrade`, a loosening `set_policy` / `set_account_limit` /
/// `set_targets`) was scheduled. `commitment` is the wasm hash for `upgrade`.
#[contractevent(topics = ["acct_sched"], data_format = "vec")]
pub struct AccountExtractiveScheduled {
    #[topic]
    pub action: Symbol,
    pub commitment: BytesN<32>,
    pub ready_at: u64,
    pub expires_at: u64,
}

#[contractevent(topics = ["acct_cancel"], data_format = "single-value")]
pub struct AccountExtractiveCancelled {
    #[topic]
    pub action: Symbol,
}

/// The schema marker moved to what the running code expects.
#[contractevent(topics = ["migrated"], data_format = "vec")]
pub struct Migrated {
    pub from: u32,
    pub to: u32,
}

/// Emitted by the constructor and by `set_targets`, so an event-only indexer
/// sees the initial escrow set too.
#[contractevent(topics = ["tgt_set"], data_format = "single-value")]
pub struct TargetsSet {
    pub targets: Vec<Address>,
}

#[contractevent(topics = ["upgraded"], data_format = "single-value")]
pub struct Upgraded {
    pub new_wasm_hash: BytesN<32>,
}
