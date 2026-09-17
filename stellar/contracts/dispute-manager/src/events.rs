//! Events for the DisputeManager. Mirrors the EVM module's event surface.

use proofbridge_core::types::{DisputeOutcome, DisputeParams};
use soroban_sdk::{contractevent, Address, BytesN};

#[contractevent(topics = ["escrow_set"], data_format = "vec")]
pub struct EscrowSet {
    #[topic]
    pub escrow: Address,
    pub allowed: bool,
}

#[contractevent(topics = ["dparams"], data_format = "vec")]
pub struct DisputeParamsSet {
    #[topic]
    pub chain_id: u128,
    pub params: DisputeParams,
}

#[contractevent(topics = ["arbiter"], data_format = "single-value")]
pub struct ArbiterSet {
    pub arbiter: Address,
}

#[contractevent(topics = ["feepool"], data_format = "single-value")]
pub struct ProtocolFeePoolSet {
    pub pool: Address,
}

#[contractevent(topics = ["dsp_file"], data_format = "vec")]
pub struct DisputeFiled {
    #[topic]
    pub order_hash: BytesN<32>,
    pub initiator: Address,
    pub bond: u128,
    pub challenge_deadline: u64,
}

#[contractevent(topics = ["dsp_resp"], data_format = "vec")]
pub struct DisputeResponded {
    #[topic]
    pub order_hash: BytesN<32>,
    pub responder: Address,
    pub evidence: BytesN<32>,
}

#[contractevent(topics = ["dsp_rule"], data_format = "vec")]
pub struct DisputeRuled {
    #[topic]
    pub order_hash: BytesN<32>,
    pub outcome: DisputeOutcome,
    pub finalize_at: u64,
}

#[contractevent(topics = ["dsp_clm"], data_format = "vec")]
pub struct DisputeClaimed {
    #[topic]
    pub order_hash: BytesN<32>,
    pub finalize_at: u64,
}

#[contractevent(topics = ["bond_rt"], data_format = "vec")]
pub struct BondRouted {
    #[topic]
    pub order_hash: BytesN<32>,
    pub to: Address,
    pub amount: u128,
    pub returned_to_filer: bool,
}

#[contractevent(topics = ["pay_cred"], data_format = "vec")]
pub struct PayoutCredited {
    #[topic]
    pub recipient: Address,
    pub amount: u128,
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
