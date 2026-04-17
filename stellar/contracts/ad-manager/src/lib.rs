//! AdManager Contract for Stellar/Soroban
//!
//! This contract manages liquidity advertisements for the Proofbridge cross-chain bridge.
//! Makers (LPs) post liquidity ads, lock funds against orders, and bridgers unlock
//! funds by presenting ZK proofs of deposits on the source chain.
//!
//! ## Cross-Chain Compatibility
//!
//! This contract is designed to be interoperable with the EVM AdManager contract.
//! Order hashes are computed using EIP-712 encoding to ensure compatibility.

#![no_std]

extern crate alloc;

mod auth;
mod cross_contract;
mod eip712;
mod errors;
mod events;
mod storage;
mod token;
mod types;
mod validation;

use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, String};

pub use errors::AdManagerError;
pub use types::{Ad, ChainInfo, ContractConfig, OrderParams, Status, NATIVE_TOKEN_ADDRESS};

// =============================================================================
// Contract Definition
// =============================================================================

/// The AdManager contract
#[contract]
pub struct AdManagerContract;

#[contractimpl]
impl AdManagerContract {
    // =========================================================================
    // Initialization
    // =========================================================================

    /// Initialize the contract with admin and external contract addresses.
    ///
    /// Can only be called once. Sets up admin (granted manager role),
    /// verifier, merkle manager, wrapped native token, and chain ID.
    pub fn initialize(
        env: Env,
        admin: Address,
        verifier: Address,
        merkle_manager: Address,
        w_native_token: Address,
        chain_id: u128,
    ) -> Result<(), AdManagerError> {
        if storage::is_initialized(&env) {
            return Err(AdManagerError::AlreadyInitialized);
        }

        admin.require_auth();

        let config = ContractConfig {
            admin: admin.clone(),
            verifier,
            merkle_manager,
            w_native_token,
            chain_id,
        };
        storage::set_config(&env, &config);
        storage::set_manager(&env, &admin, true);
        storage::set_initialized(&env);

        events::Initialized {
            admin: admin.clone(),
            verifier: config.verifier.clone(),
            merkle_manager: config.merkle_manager.clone(),
            chain_id,
        }
        .publish(&env);

        storage::extend_instance_ttl(&env);
        Ok(())
    }

    // =========================================================================
    // Admin Functions
    // =========================================================================

    /// Set or unset an address as a manager.
    pub fn set_manager(env: Env, manager: Address, status: bool) -> Result<(), AdManagerError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();

        storage::set_manager(&env, &manager, status);

        events::ManagerUpdated {
            manager: manager.clone(),
            status,
        }
        .publish(&env);

        storage::extend_instance_ttl(&env);
        Ok(())
    }

    /// Add or update a source chain configuration.
    pub fn set_chain(
        env: Env,
        order_chain_id: u128,
        order_portal: BytesN<32>,
        supported: bool,
    ) -> Result<(), AdManagerError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();

        if supported && auth::is_zero_bytes32(&order_portal) {
            return Err(AdManagerError::ZeroAddress);
        }

        let chain_info = ChainInfo {
            supported,
            order_portal: order_portal.clone(),
        };
        storage::set_chain(&env, order_chain_id, &chain_info);

        events::ChainSet {
            chain_id: order_chain_id,
            order_portal: order_portal.clone(),
            supported,
        }
        .publish(&env);

        storage::extend_instance_ttl(&env);
        Ok(())
    }

    /// Remove a source chain configuration.
    pub fn remove_chain(env: Env, order_chain_id: u128) -> Result<(), AdManagerError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();

        storage::remove_chain(&env, order_chain_id);

        events::ChainSet {
            chain_id: order_chain_id,
            order_portal: BytesN::from_array(&env, &[0u8; 32]),
            supported: false,
        }
        .publish(&env);

        storage::extend_instance_ttl(&env);
        Ok(())
    }

    /// Set a token route mapping.
    pub fn set_token_route(
        env: Env,
        ad_token: BytesN<32>,
        order_token: BytesN<32>,
        order_chain_id: u128,
    ) -> Result<(), AdManagerError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();

        if auth::is_zero_bytes32(&ad_token) || auth::is_zero_bytes32(&order_token) {
            return Err(AdManagerError::TokenZeroAddress);
        }

        let chain_info =
            storage::get_chain(&env, order_chain_id).ok_or(AdManagerError::ChainNotSupported)?;
        if !chain_info.supported {
            return Err(AdManagerError::ChainNotSupported);
        }

        storage::set_token_route(&env, &ad_token, order_chain_id, &order_token);

        events::TokenRouteSet {
            ad_token: ad_token.clone(),
            order_token: order_token.clone(),
            order_chain_id,
        }
        .publish(&env);

        storage::extend_instance_ttl(&env);
        Ok(())
    }

    /// Remove a token route mapping.
    pub fn remove_token_route(
        env: Env,
        ad_token: BytesN<32>,
        order_chain_id: u128,
    ) -> Result<(), AdManagerError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();

        let order_token = storage::get_token_route(&env, &ad_token, order_chain_id)
            .unwrap_or_else(|| BytesN::from_array(&env, &[0u8; 32]));

        storage::remove_token_route(&env, &ad_token, order_chain_id);

        events::TokenRouteRemoved {
            ad_token: ad_token.clone(),
            order_token: order_token.clone(),
            order_chain_id,
        }
        .publish(&env);

        storage::extend_instance_ttl(&env);
        Ok(())
    }

    // =========================================================================
    // Maker Functions - Ads
    // =========================================================================

    /// Create a new liquidity ad.
    ///
    /// `creator` is the ad creator's Stellar account. The ed25519 `signature`
    /// is a manager's pre-authorization, not the creator's — mirroring the EVM
    /// contract where `msg.sender` is the creator and `signer` from
    /// `preAuthValidations` is merely a manager-role check. `creator.require_auth()`
    /// is called at the root so the SAC `transfer(creator → contract)` sub-invocation
    /// has proper authorization on live networks.
    pub fn create_ad(
        env: Env,
        signature: BytesN<64>,
        public_key: BytesN<32>,
        auth_token: BytesN<32>,
        time_to_expire: u64,
        creator: Address,
        ad_id: String,
        ad_token: BytesN<32>,
        initial_amount: u128,
        order_chain_id: u128,
        ad_recipient: BytesN<32>,
    ) -> Result<(), AdManagerError> {
        let config = storage::get_config(&env)?;

        if auth::is_zero_bytes32(&ad_token) {
            return Err(AdManagerError::TokenZeroAddress);
        }
        if auth::is_zero_bytes32(&ad_recipient) {
            return Err(AdManagerError::RecipientZero);
        }
        if initial_amount == 0 {
            return Err(AdManagerError::ZeroAmount);
        }
        if storage::get_token_route(&env, &ad_token, order_chain_id).is_none() {
            return Err(AdManagerError::ChainNotSupported);
        }
        if storage::is_ad_id_used(&env, &ad_id) {
            return Err(AdManagerError::UsedAdId);
        }

        // Creator authorizes the call (and the downstream SAC transfer).
        creator.require_auth();

        let contract_bytes = eip712::contract_address_to_bytes32(&env);
        let message = auth::create_ad_request_hash(
            &env,
            &ad_id,
            &ad_token,
            initial_amount,
            order_chain_id,
            &ad_recipient,
            &auth_token,
            time_to_expire,
            config.chain_id,
            &contract_bytes,
        );

        // Manager role check (signer is only validated as a registered manager).
        Self::verify_request(
            &env,
            &message,
            &auth_token,
            time_to_expire,
            &signature,
            &public_key,
        )?;

        token::transfer_from_user_bytes32(
            &env,
            &ad_token,
            &config.w_native_token,
            &creator,
            initial_amount,
        )?;

        let ad = Ad {
            order_chain_id,
            ad_recipient: ad_recipient.clone(),
            maker: creator.clone(),
            token: ad_token.clone(),
            balance: initial_amount,
            locked: 0,
            open: true,
        };
        storage::set_ad(&env, &ad_id, &ad);
        storage::set_ad_id_used(&env, &ad_id);
        storage::set_request_hash_used(&env, &message);

        events::AdCreated {
            ad_id: ad_id.clone(),
            maker: creator.clone(),
            token: ad_token.clone(),
            init_amount: initial_amount,
            order_chain_id,
        }
        .publish(&env);

        storage::extend_instance_ttl(&env);
        Ok(())
    }

    /// Fund an existing ad with additional liquidity.
    ///
    /// The ad's maker must authorize the call. `signer` from `verify_request`
    /// is only used to confirm a registered manager pre-authorized the action.
    pub fn fund_ad(
        env: Env,
        signature: BytesN<64>,
        public_key: BytesN<32>,
        auth_token: BytesN<32>,
        time_to_expire: u64,
        ad_id: String,
        amount: u128,
    ) -> Result<(), AdManagerError> {
        let config = storage::get_config(&env)?;

        let mut ad = storage::get_ad(&env, &ad_id).ok_or(AdManagerError::AdNotFound)?;
        if !ad.open {
            return Err(AdManagerError::AdClosed);
        }
        if amount == 0 {
            return Err(AdManagerError::ZeroAmount);
        }

        // Maker authorizes the call (and the downstream SAC transfer).
        ad.maker.require_auth();

        let contract_bytes = eip712::contract_address_to_bytes32(&env);
        let message = auth::fund_ad_request_hash(
            &env,
            &ad_id,
            amount,
            &auth_token,
            time_to_expire,
            config.chain_id,
            &contract_bytes,
        );

        // Manager role check.
        Self::verify_request(
            &env,
            &message,
            &auth_token,
            time_to_expire,
            &signature,
            &public_key,
        )?;

        token::transfer_from_user_bytes32(
            &env,
            &ad.token,
            &config.w_native_token,
            &ad.maker,
            amount,
        )?;

        ad.balance += amount;
        storage::set_ad(&env, &ad_id, &ad);
        storage::set_request_hash_used(&env, &message);

        events::AdFunded {
            ad_id: ad_id.clone(),
            maker: ad.maker.clone(),
            amount,
            new_balance: ad.balance,
        }
        .publish(&env);

        storage::extend_instance_ttl(&env);
        Ok(())
    }

    /// Withdraw available (unlocked) liquidity from an ad.
    pub fn withdraw_from_ad(
        env: Env,
        signature: BytesN<64>,
        public_key: BytesN<32>,
        auth_token: BytesN<32>,
        time_to_expire: u64,
        ad_id: String,
        amount: u128,
        to: Address,
    ) -> Result<(), AdManagerError> {
        let config = storage::get_config(&env)?;

        let mut ad = storage::get_ad(&env, &ad_id).ok_or(AdManagerError::AdNotFound)?;
        if amount == 0 {
            return Err(AdManagerError::ZeroAmount);
        }

        let available = ad.balance - ad.locked;
        if amount > available {
            return Err(AdManagerError::InsufficientLiquidity);
        }

        // Maker authorizes the withdrawal.
        ad.maker.require_auth();

        let contract_bytes = eip712::contract_address_to_bytes32(&env);
        let message = auth::withdraw_from_ad_request_hash(
            &env,
            &ad_id,
            amount,
            &to,
            &auth_token,
            time_to_expire,
            config.chain_id,
            &contract_bytes,
        );

        // Manager role check.
        Self::verify_request(
            &env,
            &message,
            &auth_token,
            time_to_expire,
            &signature,
            &public_key,
        )?;

        ad.balance -= amount;
        storage::set_ad(&env, &ad_id, &ad);

        token::transfer_to_user_bytes32(&env, &ad.token, &config.w_native_token, &to, amount)?;

        storage::set_request_hash_used(&env, &message);

        events::AdWithdrawn {
            ad_id: ad_id.clone(),
            maker: ad.maker.clone(),
            amount,
            new_balance: ad.balance,
        }
        .publish(&env);

        storage::extend_instance_ttl(&env);
        Ok(())
    }

    /// Close an ad and withdraw all remaining funds.
    pub fn close_ad(
        env: Env,
        signature: BytesN<64>,
        public_key: BytesN<32>,
        auth_token: BytesN<32>,
        time_to_expire: u64,
        ad_id: String,
        to: Address,
    ) -> Result<(), AdManagerError> {
        let config = storage::get_config(&env)?;

        let mut ad = storage::get_ad(&env, &ad_id).ok_or(AdManagerError::AdNotFound)?;
        if ad.locked != 0 {
            return Err(AdManagerError::ActiveLocks);
        }

        // Maker authorizes the close.
        ad.maker.require_auth();

        let contract_bytes = eip712::contract_address_to_bytes32(&env);
        let message = auth::close_ad_request_hash(
            &env,
            &ad_id,
            &to,
            &auth_token,
            time_to_expire,
            config.chain_id,
            &contract_bytes,
        );

        // Manager role check.
        Self::verify_request(
            &env,
            &message,
            &auth_token,
            time_to_expire,
            &signature,
            &public_key,
        )?;

        let remaining = ad.balance;
        let ad_token = ad.token.clone();
        let maker = ad.maker.clone();

        ad.balance = 0;
        ad.open = false;
        storage::set_ad(&env, &ad_id, &ad);

        if remaining > 0 {
            token::transfer_to_user_bytes32(
                &env,
                &ad_token,
                &config.w_native_token,
                &to,
                remaining,
            )?;
        }

        storage::set_request_hash_used(&env, &message);

        events::AdClosed {
            ad_id: ad_id.clone(),
            maker,
        }
        .publish(&env);

        storage::extend_instance_ttl(&env);
        Ok(())
    }

    // =========================================================================
    // Maker Functions - Orders
    // =========================================================================

    /// Lock liquidity for an order.
    pub fn lock_for_order(
        env: Env,
        signature: BytesN<64>,
        public_key: BytesN<32>,
        auth_token: BytesN<32>,
        time_to_expire: u64,
        params: OrderParams,
    ) -> Result<BytesN<32>, AdManagerError> {
        let config = storage::get_config(&env)?;

        let mut ad = storage::get_ad(&env, &params.ad_id).ok_or(AdManagerError::AdNotFound)?;

        validation::validate_order(&env, &ad, &params)?;
        Self::assert_ad_decimals(&env, &params, &config.w_native_token)?;

        // Scale the signed order-chain amount into ad-chain precision for
        // pool accounting and transfers on this chain.
        let ad_amount = proofbridge_core::decimal_scaling::scale(
            params.amount,
            params.order_decimals,
            params.ad_decimals,
        )
        .map_err(proofbridge_core::errors::map_decimal_scaling_error::<AdManagerError>)?;

        let available = ad.balance - ad.locked;
        if ad_amount > available {
            return Err(AdManagerError::InsufficientLiquidity);
        }

        // Maker authorizes the lock.
        ad.maker.require_auth();

        let contract_bytes = eip712::contract_address_to_bytes32(&env);
        let order_hash = eip712::hash_order(&env, &params, config.chain_id, &contract_bytes);

        if storage::get_order_status(&env, &order_hash) != Status::None {
            return Err(AdManagerError::OrderExists);
        }

        let message = auth::lock_for_order_request_hash(
            &env,
            &params.ad_id,
            &order_hash,
            &auth_token,
            time_to_expire,
            config.chain_id,
            &contract_bytes,
        );

        // Manager role check.
        Self::verify_request(
            &env,
            &message,
            &auth_token,
            time_to_expire,
            &signature,
            &public_key,
        )?;

        let maker = ad.maker.clone();
        let ad_token = ad.token.clone();
        ad.locked += ad_amount;
        storage::set_ad(&env, &params.ad_id, &ad);
        storage::set_order_status(&env, &order_hash, Status::Open);

        cross_contract::append_to_merkle(&env, &config.merkle_manager, &order_hash)?;

        storage::set_request_hash_used(&env, &message);

        events::OrderLocked {
            order_hash: order_hash.clone(),
            ad_id: params.ad_id.clone(),
            maker,
            token: ad_token,
            amount: ad_amount,
            bridger: params.bridger.clone(),
            recipient: params.order_recipient.clone(),
        }
        .publish(&env);

        storage::extend_instance_ttl(&env);
        Ok(order_hash)
    }

    // =========================================================================
    // Bridger Functions
    // =========================================================================

    /// Unlock funds with a ZK proof.
    pub fn unlock(
        env: Env,
        signature: BytesN<64>,
        public_key: BytesN<32>,
        auth_token: BytesN<32>,
        time_to_expire: u64,
        params: OrderParams,
        nullifier_hash: BytesN<32>,
        target_root: BytesN<32>,
        proof: Bytes,
    ) -> Result<(), AdManagerError> {
        let config = storage::get_config(&env)?;

        // The order recipient on this (ad) chain authorizes the unlock —
        // mirrors the OrderPortal side where the ad recipient authorizes.
        let order_recipient_addr =
            proofbridge_core::token::bytes32_to_account_address(&env, &params.order_recipient);
        order_recipient_addr.require_auth();

        Self::assert_ad_decimals(&env, &params, &config.w_native_token)?;

        let contract_bytes = eip712::contract_address_to_bytes32(&env);
        let order_hash = eip712::hash_order(&env, &params, config.chain_id, &contract_bytes);

        if storage::get_order_status(&env, &order_hash) != Status::Open {
            return Err(AdManagerError::OrderNotOpen);
        }
        if storage::is_nullifier_used(&env, &nullifier_hash) {
            return Err(AdManagerError::NullifierUsed);
        }

        let message = auth::unlock_order_request_hash(
            &env,
            &params.ad_id,
            &order_hash,
            &target_root,
            &auth_token,
            time_to_expire,
            config.chain_id,
            &contract_bytes,
        );

        // Manager role check.
        Self::verify_request(
            &env,
            &message,
            &auth_token,
            time_to_expire,
            &signature,
            &public_key,
        )?;

        // Build public inputs and verify ZK proof
        let public_inputs = cross_contract::build_public_inputs(
            &env,
            &config.merkle_manager,
            &nullifier_hash,
            &target_root,
            &order_hash,
        );
        cross_contract::verify_proof(&env, &config.verifier, &public_inputs, &proof)?;

        storage::set_nullifier_used(&env, &nullifier_hash);
        storage::set_order_status(&env, &order_hash, Status::Filled);
        storage::set_request_hash_used(&env, &message);

        // Update ad and transfer tokens (scale signed amount to ad-chain precision)
        let ad_amount = proofbridge_core::decimal_scaling::scale(
            params.amount,
            params.order_decimals,
            params.ad_decimals,
        )
        .map_err(proofbridge_core::errors::map_decimal_scaling_error::<AdManagerError>)?;

        let mut ad = storage::get_ad(&env, &params.ad_id).ok_or(AdManagerError::AdNotFound)?;
        let ad_token = ad.token.clone();
        ad.locked -= ad_amount;
        ad.balance -= ad_amount;
        storage::set_ad(&env, &params.ad_id, &ad);

        token::transfer_to_recipient_bytes32(
            &env,
            &ad_token,
            &config.w_native_token,
            &params.order_recipient,
            ad_amount,
        )?;

        events::OrderUnlocked {
            order_hash: order_hash.clone(),
            recipient: params.order_recipient.clone(),
            nullifier_hash: nullifier_hash.clone(),
        }
        .publish(&env);

        storage::extend_instance_ttl(&env);
        Ok(())
    }

    // =========================================================================
    // View Functions
    // =========================================================================

    /// Get available (unlocked) liquidity for an ad.
    pub fn available_liquidity(env: Env, ad_id: String) -> u128 {
        if let Some(ad) = storage::get_ad(&env, &ad_id) {
            ad.balance - ad.locked
        } else {
            0
        }
    }

    /// Check if a request hash has been processed.
    pub fn check_request_hash_exists(env: Env, message: BytesN<32>) -> bool {
        storage::is_request_hash_used(&env, &message)
    }

    /// Get the latest merkle root.
    pub fn get_latest_merkle_root(env: Env) -> Result<BytesN<32>, AdManagerError> {
        let config = storage::get_config(&env)?;
        Ok(cross_contract::get_merkle_root(
            &env,
            &config.merkle_manager,
        ))
    }

    /// Get historical root at index.
    pub fn get_historical_root(env: Env, index: u128) -> Result<BytesN<32>, AdManagerError> {
        let config = storage::get_config(&env)?;
        Ok(cross_contract::get_merkle_root_at_index(
            &env,
            &config.merkle_manager,
            index,
        ))
    }

    /// Get merkle leaf count.
    pub fn get_merkle_leaf_count(env: Env) -> Result<u128, AdManagerError> {
        let config = storage::get_config(&env)?;
        Ok(cross_contract::get_merkle_width(
            &env,
            &config.merkle_manager,
        ))
    }

    /// Get ad details.
    pub fn get_ad(env: Env, ad_id: String) -> Option<Ad> {
        storage::get_ad(&env, &ad_id)
    }

    /// Get chain configuration.
    pub fn get_chain(env: Env, chain_id: u128) -> Option<ChainInfo> {
        storage::get_chain(&env, chain_id)
    }

    /// Get order status.
    pub fn get_order_status(env: Env, order_hash: BytesN<32>) -> Status {
        storage::get_order_status(&env, &order_hash)
    }

    /// Check if address is a manager.
    pub fn is_manager(env: Env, addr: Address) -> bool {
        storage::is_manager(&env, &addr)
    }

    /// Get chain ID.
    pub fn get_chain_id(env: Env) -> Result<u128, AdManagerError> {
        let config = storage::get_config(&env)?;
        Ok(config.chain_id)
    }

    /// Get contract configuration.
    pub fn get_config(env: Env) -> Result<ContractConfig, AdManagerError> {
        storage::get_config(&env)
    }

    // =========================================================================
    // Internal Helpers
    // =========================================================================

    /// Verify the signed `ad_decimals` matches the ad-chain token's on-chain
    /// decimals. Guards against decimal spoofing that would otherwise let a
    /// malicious relayer forge a scale factor.
    fn assert_ad_decimals(
        env: &Env,
        params: &OrderParams,
        w_native_addr: &Address,
    ) -> Result<(), AdManagerError> {
        let on_chain = proofbridge_core::token::token_decimals_bytes32::<AdManagerError>(
            env,
            &params.ad_chain_token,
            w_native_addr,
        )?;
        if on_chain != params.ad_decimals {
            return Err(AdManagerError::AdDecimalsMismatch);
        }
        Ok(())
    }

    /// Verify a pre-authorized request: check hash uniqueness, then validate
    /// signature and manager status. Returns the signer address on success.
    fn verify_request(
        env: &Env,
        message: &BytesN<32>,
        auth_token: &BytesN<32>,
        time_to_expire: u64,
        signature: &BytesN<64>,
        public_key: &BytesN<32>,
    ) -> Result<Address, AdManagerError> {
        if storage::is_request_hash_used(env, message) {
            return Err(AdManagerError::RequestHashProcessed);
        }

        auth::pre_auth_validations(
            env,
            message,
            auth_token,
            time_to_expire,
            signature,
            public_key,
        )
    }
}

#[cfg(test)]
mod test;
