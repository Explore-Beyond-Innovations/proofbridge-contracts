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
//!
//! ## Termination (2.3e)
//!
//! This leg is the primary: the only place a clock runs. After the deadline anyone may
//! `claim_cancel`, which opens the window `[deadline, deadline + buffer)`; the co-signed `unlock`
//! (accepted until `deadline + buffer - margin`) or a `present_settled` proof settles it; an
//! unchallenged window releases the lock and records the CANCEL leaf the order leg refunds
//! against. Every `Filled` gets a SETTLED leaf, appended by `record_settled` in its own
//! transaction (Soroban's per-tx budget; EVM appends it inside the fill). The same state machine
//! as EVM:
//!
//! ```text
//!   None ──lock──▶ Open ──claim_cancel──▶ Claimed ──finalize_cancel──▶ Cancelled (+ CANCEL leaf)
//!     │             │                       │
//!     │             └──unlock / present_settled──┘──▶ Filled ──record_settled──▶ (+ SETTLED leaf)
//!     └──cancel_never_locked──▶ Cancelled (+ CANCEL leaf)
//! ```

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

use proofbridge_core::cross_contract::{
    LEAF_DOMAIN_CANCEL, LEAF_DOMAIN_ORDER, LEAF_DOMAIN_SETTLED,
};
use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, String};

pub use errors::AdManagerError;
pub use types::{
    Ad, ChainInfo, ClaimEntry, ClaimRecord, ContractConfig, OrderParams, PauseSpan, RouteTiming,
    Status, NATIVE_TOKEN_ADDRESS,
};

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
        if !storage::is_paused(&env) {
            storage::set_pause(
                &env,
                storage::pause_count(&env),
                &PauseSpan {
                    start: env.ledger().timestamp(),
                    end: 0,
                },
            );
        }
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
        // A pause freezes evidence, so it stops the clocks: the seconds spent paused move every
        // window that was open by exactly that much (see `window_end`).
        if storage::is_paused(&env) {
            let now = env.ledger().timestamp();
            let last = storage::pause_count(&env) - 1;
            let mut span =
                storage::get_pause(&env, last).unwrap_or(PauseSpan { start: now, end: 0 });
            span.end = now;
            storage::set_pause(&env, last, &span);
            storage::set_paused_seconds(
                &env,
                storage::get_paused_seconds(&env).saturating_add(now.saturating_sub(span.start)),
            );
        }
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

    /// Set the termination clocks for a peer chain (2.3e D6). Validated; unset fails closed.
    pub fn set_route_timing(
        env: Env,
        chain_id: u128,
        timing: RouteTiming,
    ) -> Result<(), AdManagerError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();
        proofbridge_core::timing::validate(&timing).map_err(|_| AdManagerError::InvalidTiming)?;
        storage::set_route_timing(&env, chain_id, &timing);
        events::RouteTimingSet { chain_id, timing }.publish(&env);
        storage::extend_instance_ttl(&env);
        Ok(())
    }

    /// Set the notary the evidence paths read (2.3e D7). Settlement never touches it.
    pub fn set_root_anchor(env: Env, anchor: Address) -> Result<(), AdManagerError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();
        storage::set_root_anchor(&env, &anchor);
        events::RootAnchorSet { anchor }.publish(&env);
        storage::extend_instance_ttl(&env);
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
        // 2.3e D5: the window bound that makes cancel_never_locked's "no lock can follow the
        // deadline" hold.
        Self::require_min_window(&env, params.order_chain_id, params.deadline)?;

        // Scale the signed order-chain amount into ad-chain precision for
        // pool accounting and transfers on this chain.
        let ad_amount = Self::ad_amount(&params)?;

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

        // The lock is consumed on the order side: its leaf carries the ORDER domain.
        cross_contract::append_to_merkle(
            &env,
            &config.merkle_manager,
            &order_hash,
            LEAF_DOMAIN_ORDER,
        )?;

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

        Self::require_settleable(&env, &order_hash)?;
        if storage::is_nullifier_used(&env, &nullifier_hash) {
            return Err(AdManagerError::NullifierUsed);
        }
        // 2.3e D2: the co-signed unlock is the presentation — valid through the window, minus
        // the margin. Once claimed the end is the claim's frozen `finalize_at`, so a retiming
        // cannot move the cutoff across it. With margin 0 the window's last second is shared
        // with finalize_cancel; the first transaction wins.
        let t = Self::timing(&env, params.order_chain_id)?;
        let cutoff =
            Self::window_end(&env, &order_hash, params.deadline, t.buffer).saturating_sub(t.margin);
        if env.ledger().timestamp() > cutoff {
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
        Self::fill(&env, &order_hash, &params.ad_settlement_signer, false);
        Self::pay_from_ad(&env, &config, &params)?;

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
    // Termination — the primary (2.3e)
    // =========================================================================

    /// Open the cancel window on an `Open` lock at `now >= deadline`. Permissionless, no fee.
    /// Deadline-anchored (D1): finalizable at `deadline + buffer` whenever the claim lands, so a
    /// late claim cannot shorten the window the fast unlock relies on.
    pub fn claim_cancel(env: Env, params: OrderParams) -> Result<(), AdManagerError> {
        Self::require_not_paused(&env)?;
        let config = storage::get_config(&env)?;
        let order_hash = Self::order_hash(&env, &config, &params);
        Self::require_status(&env, &order_hash, Status::Open)?;
        Self::require_reached(&env, params.deadline)?;
        // Deadline-anchored (D1); a pause that fell inside the window already extended it.
        let t = Self::timing(&env, params.order_chain_id)?;
        let finalize_at = Self::window_end(&env, &order_hash, params.deadline, t.buffer);
        Self::open_claim(&env, &order_hash, ClaimEntry::Deadline, finalize_at);
        storage::extend_instance_ttl(&env);
        Ok(())
    }

    /// After an unchallenged window: release the lock, mark `Cancelled`, append the CANCEL leaf
    /// the order leg refunds against.
    pub fn finalize_cancel(env: Env, params: OrderParams) -> Result<(), AdManagerError> {
        Self::require_not_paused(&env)?;
        let config = storage::get_config(&env)?;
        let order_hash = Self::order_hash(&env, &config, &params);
        let buffer = Self::timing(&env, params.order_chain_id)?.buffer;
        Self::require_finalizable(&env, &order_hash, buffer)?;

        let ad_amount = Self::ad_amount(&params)?;
        let mut ad = storage::get_ad(&env, &params.ad_id).ok_or(AdManagerError::AdNotFound)?;
        ad.locked -= ad_amount;
        storage::set_ad(&env, &params.ad_id, &ad);

        Self::cancel(&env, &order_hash, &params.ad_settlement_signer, false);
        cross_contract::append_to_merkle(
            &env,
            &config.merkle_manager,
            &order_hash,
            LEAF_DOMAIN_CANCEL,
        )?;

        events::LockCancelled {
            order_hash,
            ad_id: params.ad_id,
            amount: ad_amount,
        }
        .publish(&env);
        storage::extend_instance_ttl(&env);
        Ok(())
    }

    /// Attest that an order the bridger deposited for was never locked here: `None` and
    /// `now >= deadline` → `Cancelled` + CANCEL leaf. No funds move; nothing was counted.
    pub fn cancel_never_locked(env: Env, params: OrderParams) -> Result<(), AdManagerError> {
        Self::require_not_paused(&env)?;
        let config = storage::get_config(&env)?;
        let order_hash = Self::order_hash(&env, &config, &params);
        Self::require_status(&env, &order_hash, Status::None)?;
        Self::require_reached(&env, params.deadline)?;
        // D5: a lock needs `deadline >= now + min_window`, so past the deadline none can follow.
        let chain = storage::get_chain(&env, params.order_chain_id)
            .ok_or(AdManagerError::ChainNotSupported)?;
        if !chain.supported {
            return Err(AdManagerError::ChainNotSupported);
        }
        Self::timing(&env, params.order_chain_id)?;

        storage::set_order_status(&env, &order_hash, Status::Cancelled);
        cross_contract::append_to_merkle(
            &env,
            &config.merkle_manager,
            &order_hash,
            LEAF_DOMAIN_CANCEL,
        )?;
        events::OrderCancelled {
            order_hash,
            by_evidence: false,
        }
        .publish(&env);
        storage::extend_instance_ttl(&env);
        Ok(())
    }

    /// Settle the lock on a secret-free proof that the order leg already paid the maker (its
    /// SETTLED leaf under a root the anchor notarized). `Open` or `Claimed`; not window-gated
    /// (D3); consumes no nullifier — the terminal status is the replay guard.
    pub fn present_settled(
        env: Env,
        params: OrderParams,
        target_root: BytesN<32>,
        proof: Bytes,
    ) -> Result<(), AdManagerError> {
        Self::require_not_paused(&env)?;
        let config = storage::get_config(&env)?;
        Self::assert_ad_decimals(&env, &params, &config.w_native_token)?;
        let order_hash = Self::order_hash(&env, &config, &params);
        Self::require_presentable(&env, &order_hash)?;
        Self::require_anchored(&env, params.order_chain_id, &target_root)?;

        let inputs = proofbridge_core::cross_contract::build_event_public_inputs(
            &env,
            &target_root,
            &order_hash,
            LEAF_DOMAIN_SETTLED,
        );
        cross_contract::verify_proof(&env, &config.verifier, &inputs, &proof)?;

        Self::fill(&env, &order_hash, &params.ad_settlement_signer, true);
        Self::pay_from_ad(&env, &config, &params)?;
        storage::extend_instance_ttl(&env);
        Ok(())
    }

    /// Append this leg's SETTLED leaf for a `Filled` order (D8), so the other escrow's presenter
    /// can prove this one paid. Permissionless, single-shot, its own transaction: on Soroban a
    /// verify plus a Poseidon2 MMR append does not fit the 100M-instruction budget, so the leaf
    /// follows the fill instead of riding in it (EVM appends it inside the fill).
    pub fn record_settled(env: Env, params: OrderParams) -> Result<(), AdManagerError> {
        Self::require_not_paused(&env)?;
        let config = storage::get_config(&env)?;
        let order_hash = Self::order_hash(&env, &config, &params);
        if storage::get_order_status(&env, &order_hash) != Status::Filled {
            return Err(AdManagerError::NotFilled);
        }
        if storage::is_settled_recorded(&env, &order_hash) {
            return Err(AdManagerError::SettledRecorded);
        }
        storage::set_settled_recorded(&env, &order_hash);
        cross_contract::append_to_merkle(
            &env,
            &config.merkle_manager,
            &order_hash,
            LEAF_DOMAIN_SETTLED,
        )?;
        events::SettledRecorded { order_hash }.publish(&env);
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

    /// The termination clocks for a peer chain, if set.
    pub fn get_route_timing(env: Env, chain_id: u128) -> Option<RouteTiming> {
        storage::get_route_timing(&env, chain_id)
    }

    /// The notary the evidence paths read, if set.
    pub fn get_root_anchor(env: Env) -> Option<Address> {
        storage::get_root_anchor(&env)
    }

    /// The open presentation window on an order, if any.
    pub fn get_claim(env: Env, order_hash: BytesN<32>) -> Option<ClaimRecord> {
        storage::get_claim(&env, &order_hash)
    }

    /// The pause history: the count, and each span (`end == 0` while paused).
    pub fn pause_count(env: Env) -> u32 {
        storage::pause_count(&env)
    }

    pub fn get_pause(env: Env, index: u32) -> Option<PauseSpan> {
        storage::get_pause(&env, index)
    }

    /// Seconds the escrow has spent paused in total.
    pub fn paused_seconds(env: Env) -> u64 {
        storage::get_paused_seconds(&env)
    }

    /// Whether the order's SETTLED leaf is in the MMR.
    pub fn is_settled_recorded(env: Env, order_hash: BytesN<32>) -> bool {
        storage::is_settled_recorded(&env, &order_hash)
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

    fn require_not_paused(env: &Env) -> Result<(), AdManagerError> {
        if storage::is_paused(env) {
            return Err(AdManagerError::ContractPaused);
        }
        Ok(())
    }

    /// The canonical 17-field order hash from this leg's params plus the ad-chain context.
    fn order_hash(env: &Env, config: &ContractConfig, params: &OrderParams) -> BytesN<32> {
        let contract_bytes = eip712::contract_address_to_bytes32(env);
        eip712::hash_order(env, params, config.chain_id, &contract_bytes)
    }

    /// The signed amount in ad-chain units — what the lock reserved and the payout releases.
    fn ad_amount(params: &OrderParams) -> Result<u128, AdManagerError> {
        proofbridge_core::decimal_scaling::scale(
            params.amount,
            params.order_decimals,
            params.ad_decimals,
        )
        .map_err(proofbridge_core::errors::map_decimal_scaling_error::<AdManagerError>)
    }

    /// Pay the bridger's recipient from the ad, in the units the lock reserved.
    fn pay_from_ad(
        env: &Env,
        config: &ContractConfig,
        params: &OrderParams,
    ) -> Result<(), AdManagerError> {
        let ad_amount = Self::ad_amount(params)?;
        let mut ad = storage::get_ad(env, &params.ad_id).ok_or(AdManagerError::AdNotFound)?;
        let ad_token = ad.token.clone();
        ad.locked -= ad_amount;
        ad.balance -= ad_amount;
        storage::set_ad(env, &params.ad_id, &ad);
        Self::pay_or_credit(
            env,
            &config.w_native_token,
            &params.order_recipient,
            &ad_token,
            ad_amount,
        );
        Ok(())
    }

    // ---- termination core (2.3e), mirrored by the order-portal ----

    /// The route's clocks, or `NoRouteTiming` (the `RootVerifierNotSet` posture).
    fn timing(env: &Env, chain_id: u128) -> Result<RouteTiming, AdManagerError> {
        storage::get_route_timing(env, chain_id).ok_or(AdManagerError::NoRouteTiming)
    }

    fn require_min_window(env: &Env, chain_id: u128, deadline: u64) -> Result<(), AdManagerError> {
        let t = Self::timing(env, chain_id)?;
        if deadline < env.ledger().timestamp() + t.min_window {
            return Err(AdManagerError::DeadlineTooSoon);
        }
        Ok(())
    }

    fn require_reached(env: &Env, at: u64) -> Result<(), AdManagerError> {
        if env.ledger().timestamp() < at {
            return Err(AdManagerError::TooEarly);
        }
        Ok(())
    }

    /// The leg must be exactly `expected` (`Open` before a claim, `None` before a never-locked cancel).
    fn require_status(
        env: &Env,
        order_hash: &BytesN<32>,
        expected: Status,
    ) -> Result<(), AdManagerError> {
        if storage::get_order_status(env, order_hash) != expected {
            return Err(AdManagerError::NotClaimable);
        }
        Ok(())
    }

    /// `Open` or in a presentation window: evidence may still settle it.
    fn require_presentable(env: &Env, order_hash: &BytesN<32>) -> Result<(), AdManagerError> {
        match storage::get_order_status(env, order_hash) {
            Status::Open | Status::Claimed => Ok(()),
            _ => Err(AdManagerError::NotClaimable),
        }
    }

    /// The co-signed unlock's status gate: `Open`, or `Claimed` (the unlock is the presentation).
    fn require_settleable(env: &Env, order_hash: &BytesN<32>) -> Result<(), AdManagerError> {
        match storage::get_order_status(env, order_hash) {
            Status::Open | Status::Claimed => Ok(()),
            _ => Err(AdManagerError::OrderNotOpen),
        }
    }

    /// When the leg's presentation window ends, in real time. Once claimed: the claim's
    /// `finalize_at` plus every second the escrow has been paused since the claim opened (exact
    /// across any number of pauses). Before a claim: `deadline + buffer` plus every pause's
    /// overlap with the window. A pause stops the clocks and never reopens a closed window.
    /// One number serves both sides of the race: the unlock cutoff is this minus the margin, the
    /// finalize needs it reached. Saturating: a far deadline never panics (EVM uses uint256).
    fn window_end(env: &Env, order_hash: &BytesN<32>, deadline: u64, buffer: u64) -> u64 {
        if storage::get_order_status(env, order_hash) == Status::Claimed {
            if let Some(claim) = storage::get_claim(env, order_hash) {
                let since = storage::get_paused_seconds(env).saturating_sub(claim.paused_at_open);
                return claim.finalize_at.saturating_add(since);
            }
        }
        deadline
            .saturating_add(buffer)
            .saturating_add(Self::paused_since(env, deadline))
    }

    /// Seconds paused after `from`: every span's overlap with `[from, now]`, newest first, stopping
    /// at the first span that ended before `from`. One read per pause since `from`.
    fn paused_since(env: &Env, from: u64) -> u64 {
        let mut total: u64 = 0;
        let mut i = storage::pause_count(env);
        while i > 0 {
            i -= 1;
            let span = match storage::get_pause(env, i) {
                Some(span) => span,
                None => break,
            };
            if span.end <= from {
                break;
            }
            total = total.saturating_add(span.end.saturating_sub(span.start.max(from)));
        }
        total
    }

    /// `Claimed` and the window is over.
    fn require_finalizable(
        env: &Env,
        order_hash: &BytesN<32>,
        buffer: u64,
    ) -> Result<(), AdManagerError> {
        if storage::get_order_status(env, order_hash) != Status::Claimed {
            return Err(AdManagerError::NotClaimed);
        }
        Self::require_reached(env, Self::window_end(env, order_hash, 0, buffer))
    }

    /// Gate for the evidence paths: the root must be notarized by the wired anchor (D7).
    fn require_anchored(
        env: &Env,
        chain_id: u128,
        root: &BytesN<32>,
    ) -> Result<(), AdManagerError> {
        let anchor = storage::get_root_anchor(env).ok_or(AdManagerError::NoRootAnchor)?;
        if !proofbridge_core::cross_contract::is_anchored(env, &anchor, chain_id, root) {
            return Err(AdManagerError::RootNotAnchored);
        }
        Ok(())
    }

    fn open_claim(env: &Env, order_hash: &BytesN<32>, entry: ClaimEntry, finalize_at: u64) {
        storage::set_claim(
            env,
            order_hash,
            &ClaimRecord {
                opened_at: env.ledger().timestamp(),
                finalize_at,
                paused_at_open: storage::get_paused_seconds(env),
                entry,
            },
        );
        storage::set_order_status(env, order_hash, Status::Claimed);
        events::ClaimOpened {
            order_hash: order_hash.clone(),
            entry,
            finalize_at,
        }
        .publish(env);
    }

    /// `Open | Claimed → Filled`: close the window, count out. The SETTLED leaf (D8) is appended
    /// by `record_settled`, a separate call: a verify plus a Poseidon2 MMR append does not fit
    /// Soroban's 100M-instruction transaction budget (measured 105.8M against a 96.1M unlock).
    fn fill(env: &Env, order_hash: &BytesN<32>, account: &BytesN<32>, by_evidence: bool) {
        storage::set_order_status(env, order_hash, Status::Filled);
        storage::remove_claim(env, order_hash);
        // Mirrors lock_for_order (2.3c D1).
        storage::set_in_flight(env, account, storage::get_in_flight(env, account) - 1);
        events::OrderSettled {
            order_hash: order_hash.clone(),
            by_evidence,
        }
        .publish(env);
    }

    /// `→ Cancelled`: close the window, count out. The leaf and the funds are the caller's.
    fn cancel(env: &Env, order_hash: &BytesN<32>, account: &BytesN<32>, by_evidence: bool) {
        storage::set_order_status(env, order_hash, Status::Cancelled);
        storage::remove_claim(env, order_hash);
        storage::set_in_flight(env, account, storage::get_in_flight(env, account) - 1);
        events::OrderCancelled {
            order_hash: order_hash.clone(),
            by_evidence,
        }
        .publish(env);
    }

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
