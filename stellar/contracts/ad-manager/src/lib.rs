//! AdManager Contract for Stellar/Soroban
//!
//! This contract manages liquidity advertisements for the Proofbridge cross-chain bridge.
//! Makers (LPs) post liquidity ads, lock funds against orders, and bridgers unlock
//! funds by presenting ZK proofs of deposits on the source chain.
//!
//! ## Cross-Chain Compatibility
//!
//! Order hashes are computed using EIP-712 encoding to ensure cross-chain
//! compatibility.

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
    /// Can only be called once. Sets up admin, verifier, merkle manager,
    /// wrapped native token, and chain ID.
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

    pub fn pause(env: Env) -> Result<(), AdManagerError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();
        storage::set_paused(&env, true);
        events::Paused {
            admin: config.admin,
        }
        .publish(&env);
        Ok(())
    }

    pub fn unpause(env: Env) -> Result<(), AdManagerError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();
        storage::set_paused(&env, false);
        events::Unpaused {
            admin: config.admin,
        }
        .publish(&env);
        Ok(())
    }

    pub fn transfer_admin(env: Env, to: Address) -> Result<(), AdManagerError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();
        storage::set_pending_admin(&env, &to);
        events::AdminTransferStarted {
            from: config.admin,
            to,
        }
        .publish(&env);
        Ok(())
    }

    pub fn accept_admin(env: Env) -> Result<(), AdManagerError> {
        let pending = storage::get_pending_admin(&env).ok_or(AdManagerError::NotPendingAdmin)?;
        pending.require_auth();
        let mut config = storage::get_config(&env)?;
        let old = config.admin.clone();
        config.admin = pending.clone();
        storage::set_config(&env, &config);
        storage::clear_pending_admin(&env);
        events::AdminTransferred {
            from: old,
            to: pending,
        }
        .publish(&env);
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
    pub fn set_root_verifier(
        env: Env,
        chain_id: u128,
        module: Address,
    ) -> Result<(), AdManagerError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();
        storage::set_root_verifier(&env, chain_id, &module);
        events::RootVerifierSet { chain_id, module }.publish(&env);
        Ok(())
    }

    /// Set the key registry consulted when an ad's settlement signer is set (2.3c D2).
    pub fn set_key_registry(env: Env, registry: Address) -> Result<(), AdManagerError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();
        storage::set_key_registry(&env, &registry);
        events::KeyRegistrySet { registry }.publish(&env);
        Ok(())
    }

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
    pub fn create_ad(
        env: Env,
        creator: Address,
        ad_id: String,
        ad_token: BytesN<32>,
        initial_amount: u128,
        order_chain_id: u128,
        ad_recipient: BytesN<32>,
        settlement_signer: BytesN<32>,
    ) -> Result<(), AdManagerError> {
        if storage::is_paused(&env) {
            return Err(AdManagerError::ContractPaused);
        }
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
        let routed_order_token = storage::get_token_route(&env, &ad_token, order_chain_id);
        if routed_order_token.is_none() {
            return Err(AdManagerError::ChainNotSupported);
        }
        if storage::is_ad_id_used(&env, &ad_id) {
            return Err(AdManagerError::UsedAdId);
        }

        // Creator authorizes the call (and the downstream SAC transfer).
        creator.require_auth();
        validation::require_registered(&env, &settlement_signer)?;

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
            order_chain_token: routed_order_token.unwrap(),
            settlement_signer: settlement_signer.clone(),
        };
        storage::set_ad(&env, &ad_id, &ad);
        storage::set_ad_id_used(&env, &ad_id);

        events::AdCreated {
            ad_id: ad_id.clone(),
            maker: creator.clone(),
            token: ad_token.clone(),
            init_amount: initial_amount,
            order_chain_id,
            settlement_signer,
        }
        .publish(&env);

        storage::extend_instance_ttl(&env);
        Ok(())
    }

    /// Re-point an ad's settlement signer. Custody-authorized, callable at any time — including
    /// with locks in flight: an open order settles against the signer frozen in its own hash,
    /// never against this field (design 01 §1.5, the third kill lever).
    pub fn set_settlement_signer(
        env: Env,
        ad_id: String,
        identity: BytesN<32>,
    ) -> Result<(), AdManagerError> {
        // Not pause-gated: like the registry's retirement lever, an incident lever must not be
        // freezable, and unpause re-enables locks in the same instant it would re-enable this.
        let mut ad = storage::get_ad(&env, &ad_id).ok_or(AdManagerError::AdNotFound)?;
        ad.maker.require_auth();
        validation::require_registered(&env, &identity)?;

        let previous = ad.settlement_signer.clone();
        ad.settlement_signer = identity.clone();
        storage::set_ad(&env, &ad_id, &ad);

        events::SettlementSignerSet {
            ad_id,
            previous,
            next: identity,
        }
        .publish(&env);

        storage::extend_instance_ttl(&env);
        Ok(())
    }

    /// Fund an existing ad with additional liquidity.
    pub fn fund_ad(env: Env, ad_id: String, amount: u128) -> Result<(), AdManagerError> {
        if storage::is_paused(&env) {
            return Err(AdManagerError::ContractPaused);
        }
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

        token::transfer_from_user_bytes32(
            &env,
            &ad.token,
            &config.w_native_token,
            &ad.maker,
            amount,
        )?;

        ad.balance += amount;
        storage::set_ad(&env, &ad_id, &ad);

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
        ad_id: String,
        amount: u128,
        to: Address,
    ) -> Result<(), AdManagerError> {
        if storage::is_paused(&env) {
            return Err(AdManagerError::ContractPaused);
        }
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

        ad.balance -= amount;
        storage::set_ad(&env, &ad_id, &ad);

        token::transfer_to_user_bytes32(&env, &ad.token, &config.w_native_token, &to, amount)?;

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
    pub fn close_ad(env: Env, ad_id: String, to: Address) -> Result<(), AdManagerError> {
        if storage::is_paused(&env) {
            return Err(AdManagerError::ContractPaused);
        }
        let config = storage::get_config(&env)?;

        let mut ad = storage::get_ad(&env, &ad_id).ok_or(AdManagerError::AdNotFound)?;
        if ad.locked != 0 {
            return Err(AdManagerError::ActiveLocks);
        }

        // Maker authorizes the close.
        ad.maker.require_auth();

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
    pub fn lock_for_order(env: Env, params: OrderParams) -> Result<BytesN<32>, AdManagerError> {
        if storage::is_paused(&env) {
            return Err(AdManagerError::ContractPaused);
        }
        let config = storage::get_config(&env)?;

        let mut ad = storage::get_ad(&env, &params.ad_id).ok_or(AdManagerError::AdNotFound)?;

        validation::validate_order(&env, &ad, &params)?;
        // A key retired after the ad was pointed at it (set_valid_until, a watchtower retirement)
        // must not take new locks: the bridger's deposit could never be unlocked (2.3c D2).
        validation::require_registered(&env, &ad.settlement_signer)?;
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

        let maker = ad.maker.clone();
        let ad_token = ad.token.clone();
        ad.locked += ad_amount;
        storage::set_ad(&env, &params.ad_id, &ad);
        storage::set_order_status(&env, &order_hash, Status::Open);
        // 2.3c D1: count the settlement identity this escrow's unlock will verify — the ad's
        // signer, asserted equal to `params.ad_settlement_signer` in validate_order (and owned by
        // the maker we authenticated). The custody address needs no counter: no unlock resolves
        // its key. The bridger is counted by the order-portal that authenticated them; a lock
        // naming a stranger must not move the stranger's counter.
        storage::set_in_flight(
            &env,
            &params.ad_settlement_signer,
            storage::get_in_flight(&env, &params.ad_settlement_signer) + 1,
        );

        cross_contract::append_to_merkle(&env, &config.merkle_manager, &order_hash, 0)?;

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
        params: OrderParams,
        nullifier_hash: BytesN<32>,
        target_root: BytesN<32>,
        proof: Bytes,
        cosig_data: Bytes,
    ) -> Result<(), AdManagerError> {
        if storage::is_paused(&env) {
            return Err(AdManagerError::ContractPaused);
        }
        let config = storage::get_config(&env)?;

        // Permissionless (EVM parity): the recipient is hash-bound, so anyone may submit.
        Self::assert_ad_decimals(&env, &params, &config.w_native_token)?;

        let contract_bytes = eip712::contract_address_to_bytes32(&env);
        let order_hash = eip712::hash_order(&env, &params, config.chain_id, &contract_bytes);

        if storage::get_order_status(&env, &order_hash) != Status::Open {
            return Err(AdManagerError::OrderNotOpen);
        }
        if storage::is_nullifier_used(&env, &nullifier_hash) {
            return Err(AdManagerError::NullifierUsed);
        }
        if env.ledger().timestamp() > params.deadline {
            return Err(AdManagerError::OrderExpired);
        }

        // Gate 2 - root authenticity (BLS co-signature). Mandatory: unlock is
        // impossible until the route's verifier module is configured.
        let module = storage::get_root_verifier(&env, params.order_chain_id)
            .ok_or(AdManagerError::RootVerifierNotSet)?;
        if !proofbridge_core::cross_contract::is_root_valid(
            &env,
            &module,
            params.order_chain_id,
            &target_root,
            &params.ad_settlement_signer,
            &params.bridger,
            &cosig_data,
        ) {
            return Err(AdManagerError::RootNotValid);
        }

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
        // Mirrors lock_for_order (2.3c D1).
        storage::set_in_flight(
            &env,
            &params.ad_settlement_signer,
            storage::get_in_flight(&env, &params.ad_settlement_signer) - 1,
        );

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

        Self::pay_or_credit(
            &env,
            &config.w_native_token,
            &params.order_recipient,
            &ad_token,
            ad_amount,
        );

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

    /// BLSKeyRegistry revoke guard: true while the account has an order
    /// locked but not yet unlocked.

    /// Best-effort direct transfer; on failure the payout becomes claimable so
    /// a recipient can never block settlement.
    fn pay_or_credit(
        env: &Env,
        w_native: &Address,
        recipient: &BytesN<32>,
        token: &BytesN<32>,
        amount: u128,
    ) {
        if proofbridge_core::token::try_transfer_to_recipient_bytes32(
            env, token, w_native, recipient, amount,
        ) {
            return;
        }
        let owed = storage::get_claimable(env, recipient, token);
        storage::set_claimable(env, recipient, token, owed + amount);
        events::PayoutCredited {
            recipient: recipient.clone(),
            token: token.clone(),
            amount,
        }
        .publish(env);
    }

    /// Pay out a credited unlock. Permissionless: funds can only go to the
    /// credited recipient.
    pub fn claim(env: Env, recipient: BytesN<32>, token: BytesN<32>) -> Result<(), AdManagerError> {
        if storage::is_paused(&env) {
            return Err(AdManagerError::ContractPaused);
        }
        let config = storage::get_config(&env)?;
        let amount = storage::get_claimable(&env, &recipient, &token);
        if amount == 0 {
            return Err(AdManagerError::NothingToClaim);
        }
        storage::set_claimable(&env, &recipient, &token, 0);
        token::transfer_to_recipient_bytes32(
            &env,
            &token,
            &config.w_native_token,
            &recipient,
            amount,
        )?;
        events::PayoutClaimed {
            recipient,
            token,
            amount,
        }
        .publish(&env);
        Ok(())
    }

    pub fn has_open_positions(env: Env, account: BytesN<32>) -> bool {
        storage::get_in_flight(&env, &account) > 0
    }

    /// Get available (unlocked) liquidity for an ad.
    pub fn available_liquidity(env: Env, ad_id: String) -> u128 {
        if let Some(ad) = storage::get_ad(&env, &ad_id) {
            ad.balance - ad.locked
        } else {
            0
        }
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
}

#[cfg(test)]
mod test;
