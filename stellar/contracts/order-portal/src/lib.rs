//! OrderPortal Contract for Stellar/Soroban
//!
//! This contract allows bridgers to open cross-chain orders by depositing tokens.
//! Makers (ad creators) later unlock those funds with proofs on this chain.
//!
//! ## Cross-Chain Compatibility
//!
//! Order hashes are computed using EIP-712 encoding to ensure cross-chain
//! compatibility.
//!
//! ## Termination (2.3e)
//!
//! This leg is the follower: it refunds only against a proof of the ad leg's CANCEL leaf under an
//! anchored root, never on a clock; the maker's co-signed `unlock` stops `claim_stagger` before
//! the deadline so a cancel claim always leaves time to land it; and a far backstop
//! (`deadline + long_backstop`) opens a window, never a bare refund. Every `Filled` gets a
//! SETTLED leaf, appended by `record_settled` in its own transaction (Soroban's per-tx budget;
//! EVM appends it inside the fill). The same state machine as EVM:
//!
//! ```text
//!   None ──create──▶ Open ──claim_backstop──▶ Claimed ──finalize_backstop──▶ Cancelled (refund)
//!                     │                         │
//!                     ├──refund_by_cancel (proof, no clock)──┘──▶ Cancelled (refund)
//!                     └──unlock / present_settled──┘──▶ Filled ──record_settled──▶ (+ SETTLED leaf)
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

use proofbridge_core::cross_contract::{LEAF_DOMAIN_AD, LEAF_DOMAIN_CANCEL, LEAF_DOMAIN_SETTLED};
use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env};

pub use errors::OrderPortalError;
pub use types::{
    ChainInfo, ClaimEntry, ClaimRecord, ContractConfig, OrderParams, PauseSpan, RouteTiming,
    Status, NATIVE_TOKEN_ADDRESS,
};

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
    /// Can only be called once. Sets up admin, verifier, merkle manager,
    /// wrapped native token, and chain ID.
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
        storage::set_initialized(&env);

        storage::extend_instance_ttl(&env);
        Ok(())
    }

    // =========================================================================
    // Admin Functions
    // =========================================================================

    pub fn pause(env: Env) -> Result<(), OrderPortalError> {
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

    pub fn unpause(env: Env) -> Result<(), OrderPortalError> {
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

    pub fn transfer_admin(env: Env, to: Address) -> Result<(), OrderPortalError> {
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

    pub fn accept_admin(env: Env) -> Result<(), OrderPortalError> {
        let pending = storage::get_pending_admin(&env).ok_or(OrderPortalError::NotPendingAdmin)?;
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
    pub fn set_root_verifier(
        env: Env,
        chain_id: u128,
        module: Address,
    ) -> Result<(), OrderPortalError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();
        storage::set_root_verifier(&env, chain_id, &module);
        events::RootVerifierSet { chain_id, module }.publish(&env);
        Ok(())
    }

    /// Set the termination clocks for a peer chain (2.3e D6). Validated; unset fails closed.
    pub fn set_route_timing(
        env: Env,
        chain_id: u128,
        timing: RouteTiming,
    ) -> Result<(), OrderPortalError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();
        proofbridge_core::timing::validate(&timing).map_err(|_| OrderPortalError::InvalidTiming)?;
        storage::set_route_timing(&env, chain_id, &timing);
        events::RouteTimingSet { chain_id, timing }.publish(&env);
        storage::extend_instance_ttl(&env);
        Ok(())
    }

    /// Set the notary the evidence paths read (2.3e D7). Settlement never touches it.
    pub fn set_root_anchor(env: Env, anchor: Address) -> Result<(), OrderPortalError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();
        storage::set_root_anchor(&env, &anchor);
        events::RootAnchorSet { anchor }.publish(&env);
        storage::extend_instance_ttl(&env);
        Ok(())
    }

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
    pub fn create_order(env: Env, params: OrderParams) -> Result<BytesN<32>, OrderPortalError> {
        if storage::is_paused(&env) {
            return Err(OrderPortalError::ContractPaused);
        }
        let config = storage::get_config(&env)?;

        // Validate order parameters (incl. decimal range ≤ MAX).
        validation::validate_order(&env, &params)?;
        // Verify signed orderDecimals matches on-chain token decimals.
        Self::assert_order_decimals(&env, &params, &config.w_native_token)?;
        // 2.3e D5: the window bound.
        Self::require_min_window(&env, params.ad_chain_id, params.deadline)?;

        let order_hash = Self::order_hash(&env, &config, &params);

        if storage::get_order_status(&env, &order_hash) != Status::None {
            return Err(OrderPortalError::OrderExists);
        }

        let bridger_addr =
            token::bytes32_to_account_address::<OrderPortalError>(&env, &params.bridger)?;

        // Root-level auth for the SAC transfer sub-invocation that will call
        // `from.require_auth()` internally. When the bridger is also the tx
        // source account this is auto-satisfied; otherwise the bridger must
        // supply an explicit auth entry for this invocation.
        bridger_addr.require_auth();

        token::transfer_from_user_bytes32(
            &env,
            &params.order_chain_token,
            &config.w_native_token,
            &bridger_addr,
            params.amount,
        )?;

        // The deposit is consumed on the ad side: its leaf carries the AD domain.
        cross_contract::append_to_merkle(
            &env,
            &config.merkle_manager,
            &order_hash,
            LEAF_DOMAIN_AD,
        )?;

        storage::set_order_status(&env, &order_hash, Status::Open);
        // 2.3c D1: count only the party this escrow authenticated (the bridger). The maker is
        // counted by the ad-manager that authenticated them.
        storage::set_in_flight(
            &env,
            &params.bridger,
            storage::get_in_flight(&env, &params.bridger) + 1,
        );

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
        params: OrderParams,
        nullifier_hash: BytesN<32>,
        target_root: BytesN<32>,
        proof: Bytes,
        cosig_data: Bytes,
    ) -> Result<(), OrderPortalError> {
        if storage::is_paused(&env) {
            return Err(OrderPortalError::ContractPaused);
        }
        let config = storage::get_config(&env)?;

        // Permissionless (EVM parity): the recipient is hash-bound, so anyone may submit.
        Self::assert_order_decimals(&env, &params, &config.w_native_token)?;

        let order_hash = Self::order_hash(&env, &config, &params);

        Self::require_settleable(&env, &order_hash)?;
        if storage::is_nullifier_used(&env, &nullifier_hash) {
            return Err(OrderPortalError::NullifierUsed);
        }
        if env.ledger().timestamp() > Self::unlock_cutoff(&env, &order_hash, &params)? {
            return Err(OrderPortalError::OrderExpired);
        }

        let public_inputs = cross_contract::build_public_inputs(
            &env,
            &config.merkle_manager,
            &nullifier_hash,
            &target_root,
            &order_hash,
        );
        // Gate 2 - root authenticity (BLS co-signature). Mandatory: unlock is
        // impossible until the route's verifier module is configured.
        let module = storage::get_root_verifier(&env, params.ad_chain_id)
            .ok_or(OrderPortalError::RootVerifierNotSet)?;
        if !proofbridge_core::cross_contract::is_root_valid(
            &env,
            &module,
            params.ad_chain_id,
            &target_root,
            &params.ad_settlement_signer,
            &params.bridger,
            &cosig_data,
        ) {
            return Err(OrderPortalError::RootNotValid);
        }

        cross_contract::verify_proof(&env, &config.verifier, &public_inputs, &proof)?;

        storage::set_nullifier_used(&env, &nullifier_hash);
        Self::fill(&env, &order_hash, &params.bridger, false);
        Self::pay_maker(&env, &config, &params);

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
    // Termination — the follower (2.3e)
    // =========================================================================

    /// Refund the bridger against a proof of the primary's CANCEL leaf under an anchored root.
    /// Reads no clock (D4). `Open` or `Claimed`: a cancel proof beats a backstop window.
    pub fn refund_by_cancel(
        env: Env,
        params: OrderParams,
        target_root: BytesN<32>,
        proof: Bytes,
    ) -> Result<(), OrderPortalError> {
        Self::require_not_paused(&env)?;
        let config = storage::get_config(&env)?;
        let order_hash = Self::order_hash(&env, &config, &params);
        Self::require_presentable(&env, &order_hash)?;
        Self::require_anchored(&env, params.ad_chain_id, &target_root)?;

        let inputs = proofbridge_core::cross_contract::build_event_public_inputs(
            &env,
            &target_root,
            &order_hash,
            LEAF_DOMAIN_CANCEL,
        );
        cross_contract::verify_proof(&env, &config.verifier, &inputs, &proof)?;

        Self::cancel(&env, &order_hash, &params.bridger, true);
        Self::refund_bridger(&env, &config, &order_hash, &params);
        storage::extend_instance_ttl(&env);
        Ok(())
    }

    /// Settle the deposit to the maker on a proof of the ad leg's SETTLED leaf under an anchored
    /// root. `Open` or `Claimed`; not window-gated (D3); no nullifier.
    pub fn present_settled(
        env: Env,
        params: OrderParams,
        target_root: BytesN<32>,
        proof: Bytes,
    ) -> Result<(), OrderPortalError> {
        Self::require_not_paused(&env)?;
        let config = storage::get_config(&env)?;
        let order_hash = Self::order_hash(&env, &config, &params);
        Self::require_presentable(&env, &order_hash)?;
        Self::require_anchored(&env, params.ad_chain_id, &target_root)?;

        let inputs = proofbridge_core::cross_contract::build_event_public_inputs(
            &env,
            &target_root,
            &order_hash,
            LEAF_DOMAIN_SETTLED,
        );
        cross_contract::verify_proof(&env, &config.verifier, &inputs, &proof)?;

        Self::fill(&env, &order_hash, &params.bridger, true);
        Self::pay_maker(&env, &config, &params);
        storage::extend_instance_ttl(&env);
        Ok(())
    }

    /// Open the backstop window at `now >= deadline + long_backstop` (an anchor outage). The
    /// window is claim-anchored (D1: this clock starts days late; no evidence race straddles it)
    /// and may be finalized at `now + buffer`. Permissionless.
    pub fn claim_backstop(env: Env, params: OrderParams) -> Result<(), OrderPortalError> {
        Self::require_not_paused(&env)?;
        let config = storage::get_config(&env)?;
        let order_hash = Self::order_hash(&env, &config, &params);
        Self::require_status(&env, &order_hash, Status::Open)?;
        let t = Self::timing(&env, params.ad_chain_id)?;
        Self::require_reached(&env, params.deadline.saturating_add(t.long_backstop))?;
        let now = env.ledger().timestamp();
        Self::open_claim(
            &env,
            &order_hash,
            ClaimEntry::Backstop,
            now.saturating_add(t.buffer),
        );
        storage::extend_instance_ttl(&env);
        Ok(())
    }

    /// After an unchallenged backstop window: refund the bridger.
    pub fn finalize_backstop(env: Env, params: OrderParams) -> Result<(), OrderPortalError> {
        Self::require_not_paused(&env)?;
        let config = storage::get_config(&env)?;
        let order_hash = Self::order_hash(&env, &config, &params);
        let buffer = Self::timing(&env, params.ad_chain_id)?.buffer;
        Self::require_finalizable(&env, &order_hash, buffer)?;
        Self::cancel(&env, &order_hash, &params.bridger, false);
        Self::refund_bridger(&env, &config, &order_hash, &params);
        storage::extend_instance_ttl(&env);
        Ok(())
    }

    /// Append this leg's SETTLED leaf for a `Filled` order (D8), so the other escrow's presenter
    /// can prove this one paid. Permissionless, single-shot, its own transaction: on Soroban a
    /// verify plus a Poseidon2 MMR append does not fit the 100M-instruction budget, so the leaf
    /// follows the fill instead of riding in it (EVM appends it inside the fill).
    pub fn record_settled(env: Env, params: OrderParams) -> Result<(), OrderPortalError> {
        Self::require_not_paused(&env)?;
        let config = storage::get_config(&env)?;
        let order_hash = Self::order_hash(&env, &config, &params);
        if storage::get_order_status(&env, &order_hash) != Status::Filled {
            return Err(OrderPortalError::NotFilled);
        }
        if storage::is_settled_recorded(&env, &order_hash) {
            return Err(OrderPortalError::SettledRecorded);
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

    /// Get destination token for a route.
    /// BLSKeyRegistry revoke guard: true while the account has an order
    /// created but not yet unlocked.

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
    pub fn claim(
        env: Env,
        recipient: BytesN<32>,
        token: BytesN<32>,
    ) -> Result<(), OrderPortalError> {
        if storage::is_paused(&env) {
            return Err(OrderPortalError::ContractPaused);
        }
        let config = storage::get_config(&env)?;
        let amount = storage::get_claimable(&env, &recipient, &token);
        if amount == 0 {
            return Err(OrderPortalError::NothingToClaim);
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

    pub fn get_dest_token(env: Env, order_token: BytesN<32>, ad_chain_id: u128) -> BytesN<32> {
        storage::get_token_route(&env, &order_token, ad_chain_id)
            .unwrap_or(BytesN::from_array(&env, &[0u8; 32]))
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

    /// Get chain info.
    pub fn get_chain(env: Env, chain_id: u128) -> Option<ChainInfo> {
        storage::get_chain(&env, chain_id)
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

    fn require_not_paused(env: &Env) -> Result<(), OrderPortalError> {
        if storage::is_paused(env) {
            return Err(OrderPortalError::ContractPaused);
        }
        Ok(())
    }

    /// The canonical 17-field order hash from this leg's params plus the order-chain context.
    fn order_hash(env: &Env, config: &ContractConfig, params: &OrderParams) -> BytesN<32> {
        let contract_bytes = eip712::contract_address_to_bytes32(env);
        eip712::hash_order(env, params, config.chain_id, &contract_bytes)
    }

    /// The maker's payout: the deposit, to the ad's recipient.
    fn pay_maker(env: &Env, config: &ContractConfig, params: &OrderParams) {
        Self::pay_or_credit(
            env,
            &config.w_native_token,
            &params.ad_recipient,
            &params.order_chain_token,
            params.amount,
        );
    }

    /// The bridger's refund: the deposit, back to them.
    fn refund_bridger(
        env: &Env,
        config: &ContractConfig,
        order_hash: &BytesN<32>,
        params: &OrderParams,
    ) {
        Self::pay_or_credit(
            env,
            &config.w_native_token,
            &params.bridger,
            &params.order_chain_token,
            params.amount,
        );
        events::OrderRefunded {
            order_hash: order_hash.clone(),
            bridger: params.bridger.clone(),
            amount: params.amount,
        }
        .publish(env);
    }

    /// The last second the co-signed unlock is accepted (D2). `Open`: `deadline - claim_stagger`,
    /// so the maker's cancel claim on the ad chain always leaves the watchtower time to land this
    /// leg. `Claimed` (a backstop window): up to `finalize_at - margin`.
    fn unlock_cutoff(
        env: &Env,
        order_hash: &BytesN<32>,
        params: &OrderParams,
    ) -> Result<u64, OrderPortalError> {
        let t = Self::timing(env, params.ad_chain_id)?;
        if storage::get_order_status(env, order_hash) == Status::Claimed {
            return Ok(Self::window_end(env, order_hash, 0, t.buffer).saturating_sub(t.margin));
        }
        Ok(params.deadline.saturating_sub(t.claim_stagger))
    }

    // ---- termination core (2.3e), mirrored by the ad-manager ----

    /// The route's clocks, or `NoRouteTiming` (the `RootVerifierNotSet` posture).
    fn timing(env: &Env, chain_id: u128) -> Result<RouteTiming, OrderPortalError> {
        storage::get_route_timing(env, chain_id).ok_or(OrderPortalError::NoRouteTiming)
    }

    fn require_min_window(
        env: &Env,
        chain_id: u128,
        deadline: u64,
    ) -> Result<(), OrderPortalError> {
        let t = Self::timing(env, chain_id)?;
        if deadline < env.ledger().timestamp() + t.min_window {
            return Err(OrderPortalError::DeadlineTooSoon);
        }
        Ok(())
    }

    fn require_reached(env: &Env, at: u64) -> Result<(), OrderPortalError> {
        if env.ledger().timestamp() < at {
            return Err(OrderPortalError::TooEarly);
        }
        Ok(())
    }

    /// The leg must be exactly `expected` (`Open` before a claim).
    fn require_status(
        env: &Env,
        order_hash: &BytesN<32>,
        expected: Status,
    ) -> Result<(), OrderPortalError> {
        if storage::get_order_status(env, order_hash) != expected {
            return Err(OrderPortalError::NotClaimable);
        }
        Ok(())
    }

    /// `Open` or in a presentation window: evidence may still settle or refund it.
    fn require_presentable(env: &Env, order_hash: &BytesN<32>) -> Result<(), OrderPortalError> {
        match storage::get_order_status(env, order_hash) {
            Status::Open | Status::Claimed => Ok(()),
            _ => Err(OrderPortalError::NotClaimable),
        }
    }

    /// The co-signed unlock's status gate: `Open`, or `Claimed` (inside a backstop window).
    fn require_settleable(env: &Env, order_hash: &BytesN<32>) -> Result<(), OrderPortalError> {
        match storage::get_order_status(env, order_hash) {
            Status::Open | Status::Claimed => Ok(()),
            _ => Err(OrderPortalError::OrderNotOpen),
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
    ) -> Result<(), OrderPortalError> {
        if storage::get_order_status(env, order_hash) != Status::Claimed {
            return Err(OrderPortalError::NotClaimed);
        }
        Self::require_reached(env, Self::window_end(env, order_hash, 0, buffer))
    }

    /// Gate for the evidence paths: the root must be notarized by the wired anchor (D7).
    fn require_anchored(
        env: &Env,
        chain_id: u128,
        root: &BytesN<32>,
    ) -> Result<(), OrderPortalError> {
        let anchor = storage::get_root_anchor(env).ok_or(OrderPortalError::NoRootAnchor)?;
        if !proofbridge_core::cross_contract::is_anchored(env, &anchor, chain_id, root) {
            return Err(OrderPortalError::RootNotAnchored);
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
        // Mirrors create_order (2.3c D1).
        storage::set_in_flight(env, account, storage::get_in_flight(env, account) - 1);
        events::OrderSettled {
            order_hash: order_hash.clone(),
            by_evidence,
        }
        .publish(env);
    }

    /// `→ Cancelled`: close the window, count out. The follower appends no leaf of its own —
    /// nothing follows it; the refund is the caller's.
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

    /// Verify the signed `order_decimals` matches the order-chain token's
    /// on-chain decimals. Guards against decimal spoofing that would otherwise
    /// let a malicious relayer forge a scale factor.
    fn assert_order_decimals(
        env: &Env,
        params: &OrderParams,
        w_native_addr: &Address,
    ) -> Result<(), OrderPortalError> {
        let on_chain = proofbridge_core::token::token_decimals_bytes32::<OrderPortalError>(
            env,
            &params.order_chain_token,
            w_native_addr,
        )?;
        if on_chain != params.order_decimals {
            return Err(OrderPortalError::OrderDecimalsMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod test;
