use soroban_sdk::{contractevent, Address, BytesN, String, Symbol, Val, Vec};

use crate::policy::Scope;

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

/// A delayed owner call was announced. **This is the point of the delay**: a window nobody can see
/// start is not a warning, so the call's arguments ride on the event in clear, beside the
/// commitment the spend will compare. `set_policy` is the exception: a maximal policy's args exceed
/// the network's per-transaction event limit, so its `args` is empty and the policy is published by
/// `PolicySet` when applied. `set_guard_rail`'s guardrail is shown with its bucket zeroed.
#[contractevent(topics = ["scheduled"], data_format = "vec")]
pub struct Scheduled {
    #[topic]
    pub scope: Scope,
    #[topic]
    pub action: Symbol,
    pub args: Vec<Val>,
    pub commitment: BytesN<32>,
    pub ready_at: u64,
    pub expires_at: u64,
}

/// The owner stood a schedule down before it was spent.
#[contractevent(topics = ["cancelled"], data_format = "vec")]
pub struct Cancelled {
    #[topic]
    pub scope: Scope,
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
