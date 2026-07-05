//! Event types for the BLSKeyRegistry contract

use soroban_sdk::{contractevent, Address, BytesN};

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
    pub bls_pub_key: BytesN<96>,
    pub nonce: u64,
}

#[contractevent(topics = ["key_rev"], data_format = "single-value")]
pub struct KeyRevoked {
    #[topic]
    pub account: BytesN<32>,
    pub nonce: u64,
}

#[contractevent(topics = ["guard_set"], data_format = "single-value")]
pub struct PositionGuardSet {
    pub guard: Address,
}
