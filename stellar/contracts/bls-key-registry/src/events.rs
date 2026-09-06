//! Event types for the BLSKeyRegistry contract

use soroban_sdk::{contractevent, Address, BytesN, Vec};

#[contractevent(topics = ["init"], data_format = "vec")]
pub struct Initialized {
    #[topic]
    pub admin: Address,
    pub chain_id: u128,
}

/// Carries the full key — storage holds only the keccak commitment.
#[contractevent(topics = ["key_reg"], data_format = "vec")]
pub struct KeyRegistered {
    #[topic]
    pub account: BytesN<32>,
    #[topic]
    pub slot_id: u32,
    pub bls_pub_key: BytesN<96>,
    pub nonce: u64,
}

#[contractevent(topics = ["slot_vu"], data_format = "single-value")]
pub struct SlotValidUntilSet {
    #[topic]
    pub account: BytesN<32>,
    #[topic]
    pub slot_id: u32,
    pub valid_until: u64,
}

#[contractevent(topics = ["slot_prn"], data_format = "single-value")]
pub struct SlotPruned {
    #[topic]
    pub account: BytesN<32>,
    pub slot_id: u32,
}

#[contractevent(topics = ["key_rev"], data_format = "single-value")]
pub struct KeyRevoked {
    #[topic]
    pub account: BytesN<32>,
    pub nonce: u64,
}

#[contractevent(topics = ["guard_set"], data_format = "single-value")]
pub struct PositionGuardsSet {
    pub guards: Vec<Address>,
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
