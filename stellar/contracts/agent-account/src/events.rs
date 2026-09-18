use soroban_sdk::{contractevent, Address, BytesN, Vec};

#[contractevent(topics = ["pol_set"], data_format = "vec")]
pub struct PolicySet {
    #[topic]
    pub agent_id: BytesN<32>,
    pub settlement_signer: BytesN<32>,
    pub valid_until: u64,
    pub max_per_order: u128,
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
