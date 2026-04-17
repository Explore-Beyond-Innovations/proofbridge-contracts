//! Minimal SAC-convention fungible token used by the cross-chain E2E test.
//!
//! This is the same contract inlined in `tests/integration_test.rs`, extracted
//! as a deployable WASM so the live localnet can use it.

#![no_std]

use soroban_sdk::{contract, contractimpl, Address, Env, MuxedAddress, String};
use stellar_tokens::fungible::{Base, FungibleToken};

#[contract]
pub struct TokenContract;

#[contractimpl]
impl TokenContract {
    pub fn __constructor(
        e: &Env,
        owner: Address,
        initial_supply: i128,
        decimals: u32,
        name: String,
        symbol: String,
    ) {
        Base::set_metadata(e, decimals, name, symbol);
        Base::mint(e, &owner, initial_supply);
    }

    pub fn mint(e: &Env, to: Address, amount: i128) {
        Base::mint(e, &to, amount);
    }
}

#[contractimpl(contracttrait)]
impl FungibleToken for TokenContract {
    type ContractType = Base;
}
