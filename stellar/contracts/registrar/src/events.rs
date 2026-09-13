//! Event types for the Registrar contract

use soroban_sdk::{contractevent, Address, BytesN};

#[contractevent(topics = ["init"], data_format = "single-value")]
pub struct Initialized {
    pub merkle_manager: Address,
}

/// A registration leaf was appended to the home MMR under the account's own authorization.
#[contractevent(topics = ["reg_leaf"], data_format = "vec")]
pub struct RegistrationLeaf {
    #[topic]
    pub account32: BytesN<32>,
    #[topic]
    pub bls_commitment: BytesN<32>,
    pub epoch: u64,
    pub subject: BytesN<32>,
}
