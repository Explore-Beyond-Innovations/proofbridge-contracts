//! Shared utilities for ProofBridge Stellar/Soroban contracts
//!
//! This crate contains common code used by both the AdManager and OrderPortal
//! contracts, including EIP-712 hashing, token operations, authentication
//! helpers, cross-contract client definitions, and shared types.

#![no_std]

extern crate alloc;

pub mod auth;
pub mod cross_contract;
pub mod eip712;
pub mod errors;
pub mod token;
pub mod types;

#[cfg(test)]
mod test;
