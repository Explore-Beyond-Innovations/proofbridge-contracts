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
    /// Mint `initial_supply` to `owner` on deploy.
    pub fn __constructor(e: &Env, owner: Address, initial_supply: i128) {
        Base::mint(e, &owner, initial_supply);
    }

    /// Mint additional tokens to `to`. No auth — intended for tests only.
    pub fn mint(e: &Env, to: Address, amount: i128) {
        Base::mint(e, &to, amount);
    }
}

#[contractimpl(contracttrait)]
impl FungibleToken for TokenContract {
    type ContractType = Base;
}
