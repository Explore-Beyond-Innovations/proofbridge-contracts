//! OrderPortal Contract for Stellar/Soroban
//!
//! This contract allows bridgers to open cross-chain orders by depositing tokens.
//! Makers (ad creators) later unlock those funds with proofs on this chain.
//!
//! ## Cross-Chain Compatibility
//!
//! This contract is designed to be interoperable with the EVM OrderPortal contract.
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

use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env};

pub use errors::OrderPortalError;
pub use types::{ChainInfo, ContractConfig, OrderParams, Status, NATIVE_TOKEN_ADDRESS};

// =============================================================================
// Contract Definition
// =============================================================================

#[contract]
pub struct OrderPortalContract;

#[contractimpl]
impl OrderPortalContract {
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
    ) -> Result<(), OrderPortalError> {
        if storage::is_initialized(&env) {
            return Err(OrderPortalError::AlreadyInitialized);
        }

        if admin == env.current_contract_address() {
            return Err(OrderPortalError::ZeroAddress);
        }

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

        storage::extend_instance_ttl(&env);
        Ok(())
    }

    // =========================================================================
    // Admin Functions - Managers
    // =========================================================================

    /// Set or unset a manager.
    pub fn set_manager(env: Env, manager: Address, status: bool) -> Result<(), OrderPortalError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();

        if manager == env.current_contract_address() {
            return Err(OrderPortalError::ZeroAddress);
        }

        storage::set_manager(&env, &manager, status);

        events::ManagerUpdated {
            manager: manager.clone(),
            status,
        }
        .publish(&env);

        storage::extend_instance_ttl(&env);
        Ok(())
    }

    // =========================================================================
    // Admin Functions - Chains
    // =========================================================================

    /// Configure a destination (ad) chain.
    pub fn set_chain(
        env: Env,
        ad_chain_id: u128,
        ad_manager: BytesN<32>,
        supported: bool,
    ) -> Result<(), OrderPortalError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();

        if supported && auth::is_zero_bytes32(&ad_manager) {
            return Err(OrderPortalError::ZeroAddress);
        }

        let chain_info = ChainInfo {
            supported,
            ad_manager: ad_manager.clone(),
        };
        storage::set_chain(&env, ad_chain_id, &chain_info);

        events::ChainSet {
            chain_id: ad_chain_id,
            ad_manager: ad_manager.clone(),
            supported,
        }
        .publish(&env);

        storage::extend_instance_ttl(&env);
        Ok(())
    }

    /// Remove a destination chain configuration.
    pub fn remove_chain(env: Env, ad_chain_id: u128) -> Result<(), OrderPortalError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();

        storage::remove_chain(&env, ad_chain_id);

        events::ChainSet {
            chain_id: ad_chain_id,
            ad_manager: BytesN::from_array(&env, &[0u8; 32]),
            supported: false,
        }
        .publish(&env);

        storage::extend_instance_ttl(&env);
        Ok(())
    }

    // =========================================================================
    // Admin Functions - Token Routes
    // =========================================================================

    /// Set a token route for a destination chain.
    pub fn set_token_route(
        env: Env,
        order_token: BytesN<32>,
        ad_chain_id: u128,
        ad_token: BytesN<32>,
    ) -> Result<(), OrderPortalError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();

        if auth::is_zero_bytes32(&order_token) || auth::is_zero_bytes32(&ad_token) {
            return Err(OrderPortalError::RoutesZeroAddress);
        }

        let chain_info =
            storage::get_chain(&env, ad_chain_id).ok_or(OrderPortalError::AdChainNotSupported)?;
        if !chain_info.supported {
            return Err(OrderPortalError::AdChainNotSupported);
        }

        storage::set_token_route(&env, &order_token, ad_chain_id, &ad_token);

        events::TokenRouteSet {
            order_token: order_token.clone(),
            ad_token: ad_token.clone(),
            ad_chain_id,
        }
        .publish(&env);

        storage::extend_instance_ttl(&env);
        Ok(())
    }

    /// Remove a token route.
    pub fn remove_token_route(
        env: Env,
        order_token: BytesN<32>,
        ad_chain_id: u128,
    ) -> Result<(), OrderPortalError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();

        storage::remove_token_route(&env, &order_token, ad_chain_id);

        events::TokenRouteRemoved {
            order_token: order_token.clone(),
            ad_chain_id,
        }
        .publish(&env);

        storage::extend_instance_ttl(&env);
        Ok(())
    }

    // =========================================================================
    // Bridger Functions - Create Order
    // =========================================================================

    /// Create and fund an order.
    ///
    /// Bridger deposits tokens and creates an order that can be unlocked
    /// by a maker with a ZK proof on this chain.
    pub fn create_order(
        env: Env,
        signature: BytesN<64>,
        public_key: BytesN<32>,
        auth_token: BytesN<32>,
        time_to_expire: u64,
        params: OrderParams,
    ) -> Result<BytesN<32>, OrderPortalError> {
        let config = storage::get_config(&env)?;

        // Validate order parameters
        validation::validate_order(&env, &params)?;

        // Compute order hash
        let contract_bytes = eip712::contract_address_to_bytes32(&env);
        let order_hash = eip712::hash_order(&env, &params, config.chain_id, &contract_bytes);

        // Check order doesn't exist
        if storage::get_order_status(&env, &order_hash) != Status::None {
            return Err(OrderPortalError::OrderExists);
        }

        // Build request hash
        let message = auth::create_order_request_hash(
            &env,
            &params.ad_id,
            &order_hash,
            &auth_token,
            time_to_expire,
            config.chain_id,
            &contract_bytes,
        );

        let _signer = Self::verify_request(
            &env,
            &message,
            &auth_token,
            time_to_expire,
            &signature,
            &public_key,
        )?;

        // Transfer tokens from bridger to contract
        let bridger_addr = token::bytes32_to_account_address(&env, &params.bridger);
        token::transfer_from_user_bytes32(
            &env,
            &params.order_chain_token,
            &config.w_native_token,
            &bridger_addr,
            params.amount,
        )?;

        // Append to merkle tree
        cross_contract::append_to_merkle(&env, &config.merkle_manager, &order_hash)?;

        // Set order status
        storage::set_order_status(&env, &order_hash, Status::Open);
        storage::set_request_hash_used(&env, &message);

        events::OrderCreated {
            order_hash: order_hash.clone(),
            bridger: params.bridger.clone(),
            order_chain_token: params.order_chain_token.clone(),
            amount: params.amount,
            ad_chain_id: params.ad_chain_id,
            ad_chain_token: params.ad_chain_token.clone(),
            ad_manager: params.ad_manager.clone(),
            ad_id: params.ad_id.clone(),
            ad_creator: params.ad_creator.clone(),
            ad_recipient: params.ad_recipient.clone(),
        }
        .publish(&env);

        storage::extend_instance_ttl(&env);
        Ok(order_hash)
    }

    // =========================================================================
    // Maker Functions - Unlock with Proof
    // =========================================================================

    /// Unlock an order with a ZK proof.
    ///
    /// Maker provides proof of deposit on the ad chain and receives
    /// the deposited tokens on this chain.
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
    ) -> Result<(), OrderPortalError> {
        let config = storage::get_config(&env)?;

        let contract_bytes = eip712::contract_address_to_bytes32(&env);
        let order_hash = eip712::hash_order(&env, &params, config.chain_id, &contract_bytes);

        if storage::get_order_status(&env, &order_hash) != Status::Open {
            return Err(OrderPortalError::OrderNotOpen);
        }
        if storage::is_nullifier_used(&env, &nullifier_hash) {
            return Err(OrderPortalError::NullifierUsed);
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

        // Transfer tokens to ad_recipient (the maker's recipient on this chain)
        token::transfer_to_recipient_bytes32(
            &env,
            &params.order_chain_token,
            &config.w_native_token,
            &params.ad_recipient,
            params.amount,
        )?;

        events::OrderUnlocked {
            order_hash: order_hash.clone(),
            recipient: params.ad_recipient.clone(),
            nullifier_hash: nullifier_hash.clone(),
        }
        .publish(&env);

        storage::extend_instance_ttl(&env);
        Ok(())
    }

    // =========================================================================
    // View Functions
    // =========================================================================

    /// Get destination token for a route.
    pub fn get_dest_token(env: Env, order_token: BytesN<32>, ad_chain_id: u128) -> BytesN<32> {
        storage::get_token_route(&env, &order_token, ad_chain_id)
            .unwrap_or(BytesN::from_array(&env, &[0u8; 32]))
    }

    /// Check if a request hash has been processed.
    pub fn check_request_hash_exists(env: Env, message: BytesN<32>) -> bool {
        storage::is_request_hash_used(&env, &message)
    }

    /// Get the latest merkle root.
    pub fn get_latest_merkle_root(env: Env) -> Result<BytesN<32>, OrderPortalError> {
        let config = storage::get_config(&env)?;
        Ok(cross_contract::get_merkle_root(
            &env,
            &config.merkle_manager,
        ))
    }

    /// Get historical root at index.
    pub fn get_historical_root(env: Env, index: u128) -> Result<BytesN<32>, OrderPortalError> {
        let config = storage::get_config(&env)?;
        Ok(cross_contract::get_merkle_root_at_index(
            &env,
            &config.merkle_manager,
            index,
        ))
    }

    /// Get merkle leaf count.
    pub fn get_merkle_leaf_count(env: Env) -> Result<u128, OrderPortalError> {
        let config = storage::get_config(&env)?;
        Ok(cross_contract::get_merkle_width(
            &env,
            &config.merkle_manager,
        ))
    }

    /// Get order status.
    pub fn get_order_status(env: Env, order_hash: BytesN<32>) -> Status {
        storage::get_order_status(&env, &order_hash)
    }

    /// Get chain info.
    pub fn get_chain(env: Env, chain_id: u128) -> Option<ChainInfo> {
        storage::get_chain(&env, chain_id)
    }

    /// Check if address is a manager.
    pub fn is_manager(env: Env, addr: Address) -> bool {
        storage::is_manager(&env, &addr)
    }

    /// Get chain ID.
    pub fn get_chain_id(env: Env) -> Result<u128, OrderPortalError> {
        let config = storage::get_config(&env)?;
        Ok(config.chain_id)
    }

    /// Get contract configuration.
    pub fn get_config(env: Env) -> Result<ContractConfig, OrderPortalError> {
        storage::get_config(&env)
    }

    /// Check if initialized.
    pub fn is_initialized(env: Env) -> bool {
        storage::is_initialized(&env)
    }

    // =========================================================================
    // Internal Helpers
    // =========================================================================

    /// Verify a pre-authorized request: check hash uniqueness, then validate
    /// signature and manager status. Returns the signer address on success.
    fn verify_request(
        env: &Env,
        message: &BytesN<32>,
        auth_token: &BytesN<32>,
        time_to_expire: u64,
        signature: &BytesN<64>,
        public_key: &BytesN<32>,
    ) -> Result<Address, OrderPortalError> {
        if storage::is_request_hash_used(env, message) {
            return Err(OrderPortalError::RequestHashProcessed);
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
