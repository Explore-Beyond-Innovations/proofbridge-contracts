//! Event types for the RootAnchor contract

use soroban_sdk::{contractevent, Address, BytesN, Vec};

#[contractevent(topics = ["init"], data_format = "vec")]
pub struct Initialized {
    #[topic]
    pub admin: Address,
    pub threshold: u32,
}

/// One signer approved (chain, root). The watchtower cross-checks every approval against the
/// live source chain — root ∈ real history is one RPC read.
#[contractevent(topics = ["anch_appr"], data_format = "vec")]
pub struct AnchorApproved {
    #[topic]
    pub chain_id: u128,
    #[topic]
    pub root: BytesN<32>,
    pub signer: Address,
    pub approvals: u32,
}

/// The threshold was reached; the anchor is usable `delay` seconds after `anchored_at`.
#[contractevent(topics = ["anchored"], data_format = "vec")]
pub struct Anchored {
    #[topic]
    pub chain_id: u128,
    #[topic]
    pub root: BytesN<32>,
    pub ledger_seq: u64,
    pub anchored_at: u64,
}

/// The admin discarded a root's record — the response to an anchor proven absent from real history.
#[contractevent(topics = ["anch_rvk"], data_format = "single-value")]
pub struct AnchorRevoked {
    #[topic]
    pub chain_id: u128,
    #[topic]
    pub root: BytesN<32>,
    pub gen: u32,
}

/// The notary set changed — a ladder rung, never a redeploy. Pending approvals stop counting.
#[contractevent(topics = ["signers"], data_format = "vec")]
pub struct SignersSet {
    pub signers: Vec<Address>,
    pub threshold: u32,
    pub epoch: u32,
}

#[contractevent(topics = ["delay_set"], data_format = "single-value")]
pub struct AnchorDelaySet {
    #[topic]
    pub chain_id: u128,
    pub delay: u64,
}

#[contractevent(topics = ["mono_set"], data_format = "single-value")]
pub struct MonotonicSet {
    pub monotonic: bool,
}

#[contractevent(topics = ["seq_reset"], data_format = "single-value")]
pub struct LatestSeqReset {
    #[topic]
    pub chain_id: u128,
    pub seq: u64,
}

#[contractevent(topics = ["paused"], data_format = "single-value")]
pub struct Paused {
    pub admin: Address,
}

#[contractevent(topics = ["unpaused"], data_format = "single-value")]
pub struct Unpaused {
    pub admin: Address,
}

#[contractevent(topics = ["adm_start"], data_format = "single-value")]
pub struct AdminTransferStarted {
    #[topic]
    pub from: Address,
    pub to: Address,
}

#[contractevent(topics = ["adm_done"], data_format = "single-value")]
pub struct AdminTransferred {
    #[topic]
    pub from: Address,
    pub to: Address,
}
