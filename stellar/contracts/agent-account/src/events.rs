use soroban_sdk::{contractevent, Address, BytesN, String, Symbol, Vec};

#[contractevent(topics = ["pol_set"], data_format = "vec")]
pub struct PolicySet {
    #[topic]
    pub agent_id: BytesN<32>,
    pub settlement_signer: BytesN<32>,
    pub valid_until: u64,
}

/// 2.1e wires the runtime to fire the owner's pre-signed registry
/// retirements off this event; the event itself lands here.
#[contractevent(topics = ["agent_rev"], data_format = "single-value")]
pub struct AgentRevoked {
    #[topic]
    pub agent_id: BytesN<32>,
}

/// The account-wide volume ceiling for one token changed (2.1d). The numbers stay off the event:
/// an indexer that wants them reads the row, and a limit is not a thing to reconstruct from logs.
#[contractevent(topics = ["acct_lim"], data_format = "single-value")]
pub struct AccountLimitSet {
    #[topic]
    pub token: BytesN<32>,
}

/// The owner armed or changed an ad's guardrail (2.1e). The numbers stay off the event; an
/// indexer that wants them reads the row.
#[contractevent(topics = ["guard_set"], data_format = "single-value")]
pub struct GuardrailSet {
    #[topic]
    pub ad_id: String,
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
