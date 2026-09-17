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
//! the deadline, in every state, so a cancel claim always leaves time to land it — the package
//! proves the lock, not the outcome; and a far backstop (`deadline + long_backstop`) opens a
//! window in which only outcome evidence counts (a settled-leaf proof pays the maker, a cancel-leaf
//! proof refunds the bridger, silence refunds the bridger), never a bare refund. Every `Filled` gets a
//! SETTLED leaf, appended by `record_settled` in its own transaction (to match the EVM leg so the
//! relayer batches one shape — not Soroban's per-tx budget, which is 400M on the network and was
//! misread as the harness default of 100M;
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

use proofbridge_core::cross_contract::{
    LEAF_DOMAIN_AD, LEAF_DOMAIN_CANCEL, LEAF_DOMAIN_FORFEIT, LEAF_DOMAIN_SETTLED,
};
use proofbridge_core::escrow_ops as ops;
use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env};

pub use errors::OrderPortalError;
pub use types::{
    ChainInfo, ClaimEntry, ClaimRecord, ContractConfig, OrderParams, OrderRecord, RouteTiming,
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
        ops::pause(&env, &config);
        Ok(())
    }

    pub fn unpause(env: Env) -> Result<(), OrderPortalError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();
        ops::unpause(&env, &config);
        Ok(())
    }

    pub fn transfer_admin(env: Env, to: Address) -> Result<(), OrderPortalError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();
        ops::transfer_admin(&env, &config, to);
        Ok(())
    }

    pub fn accept_admin(env: Env) -> Result<(), OrderPortalError> {
        let pending = ops::pending_admin(&env)?;
        pending.require_auth();
        let mut config = storage::get_config(&env)?;
        ops::accept_admin(&env, &mut config, pending);
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

    pub fn set_root_verifier(
        env: Env,
        chain_id: u128,
        module: Address,
    ) -> Result<(), OrderPortalError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();
        ops::set_root_verifier(&env, chain_id, module);
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
        Ok(ops::set_route_timing(&env, chain_id, timing)?)
    }

    /// The order hash this leg computes for these params — what the dispute module is keyed by.
    pub fn hash_order(env: Env, params: OrderParams) -> Result<BytesN<32>, OrderPortalError> {
        let config = storage::get_config(&env)?;
        Ok(Self::order_hash(&env, &config, &params))
    }

    /// Set the notary the evidence paths read (2.3e D7). Settlement never touches it.
    pub fn set_root_anchor(env: Env, anchor: Address) -> Result<(), OrderPortalError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();
        ops::set_root_anchor(&env, anchor);
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

        storage::open_order(&env, &order_hash);
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

        // `Open` only: after the deadline the co-signed package says nothing about the ad leg's
        // outcome, so a backstop window (`Claimed`) never reopens it.
        if storage::get_order_status(&env, &order_hash) != Status::Open {
            return Err(OrderPortalError::OrderNotOpen);
        }
        if storage::is_nullifier_used(&env, &nullifier_hash) {
            return Err(OrderPortalError::NullifierUsed);
        }
        // D2: stop `claim_stagger` before the deadline so the maker's cancel claim on the ad chain
        // always leaves the watchtower time to land this leg.
        let t = Self::timing(&env, params.ad_chain_id)?;
        if env.ledger().timestamp() > params.deadline.saturating_sub(t.claim_stagger) {
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
    // =========================================================================
    // Disputes (2.3g) — the follower's entire part, and it is proof-only
    // =========================================================================

    /// Apply a `BridgerForfeit` ruling made on the ad chain: the deposit goes to the maker.
    ///
    /// This escrow has no dispute, no arbiter and no dispute clock. The ad-manager is the head and
    /// this is the follower, and the follower never originates a termination — it learns how a
    /// dispute ended the way it learns every other cross-chain fact, from an anchored proof of the
    /// primary's leaf.
    ///
    /// Only `BridgerForfeit` arrives here. Every other ruling means "refund the bridger", which is
    /// what a CANCEL leaf has always meant, so those come through `refund_by_cancel` unchanged.
    pub fn pay_maker_by_forfeit(
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
            LEAF_DOMAIN_FORFEIT,
        );
        cross_contract::verify_proof(&env, &config.verifier, &inputs, &proof)?;

        // No deadline read: like the cancel refund, this is the primary's decision arriving, and it
        // is valid whenever it arrives.
        Self::fill(&env, &order_hash, &params.bridger, true);
        Self::pay_maker(&env, &config, &params);
        storage::extend_instance_ttl(&env);
        Ok(())
    }

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

    pub fn record_settled(env: Env, params: OrderParams) -> Result<(), OrderPortalError> {
        Self::require_not_paused(&env)?;
        let config = storage::get_config(&env)?;
        let order_hash = Self::order_hash(&env, &config, &params);
        ops::record_settled(&env, &config.merkle_manager, &order_hash)
    }

    // =========================================================================
    // View Functions
    // =========================================================================

    /// Get destination token for a route.
    /// BLSKeyRegistry revoke guard: true while the account has an order
    /// created but not yet unlocked.

    fn pay_or_credit(
        env: &Env,
        w_native: &Address,
        recipient: &BytesN<32>,
        token: &BytesN<32>,
        amount: u128,
    ) {
        ops::pay_or_credit(env, w_native, recipient, token, amount)
    }

    /// Pay out a credited unlock. Permissionless: funds can only go to the
    /// credited recipient.
    pub fn claim(
        env: Env,
        recipient: BytesN<32>,
        token: BytesN<32>,
    ) -> Result<(), OrderPortalError> {
        Self::require_not_paused(&env)?;
        let config = storage::get_config(&env)?;
        ops::claim(&env, &config, recipient, token)
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

    /// The order's leg: status plus the pause-counter snapshot its window is measured from.
    pub fn get_order(env: Env, order_hash: BytesN<32>) -> OrderRecord {
        storage::get_order(&env, &order_hash)
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
        Ok(ops::require_not_paused(env)?)
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

    // ---- termination core (2.3e), mirrored by the ad-manager ----

    /// The route's clocks, or `NoRouteTiming` (the `RootVerifierNotSet` posture).
    fn timing(env: &Env, chain_id: u128) -> Result<RouteTiming, OrderPortalError> {
        Ok(ops::timing(env, chain_id)?)
    }

    fn require_min_window(
        env: &Env,
        chain_id: u128,
        deadline: u64,
    ) -> Result<(), OrderPortalError> {
        Ok(ops::require_min_window(env, chain_id, deadline)?)
    }

    fn require_reached(env: &Env, at: u64) -> Result<(), OrderPortalError> {
        Ok(ops::require_reached(env, at)?)
    }

    fn require_status(
        env: &Env,
        order_hash: &BytesN<32>,
        expected: Status,
    ) -> Result<(), OrderPortalError> {
        Ok(ops::require_status(env, order_hash, expected)?)
    }

    fn require_presentable(env: &Env, order_hash: &BytesN<32>) -> Result<(), OrderPortalError> {
        Ok(ops::require_presentable(env, order_hash)?)
    }

    fn require_finalizable(
        env: &Env,
        order_hash: &BytesN<32>,
        buffer: u64,
    ) -> Result<(), OrderPortalError> {
        Ok(ops::require_finalizable(env, order_hash, buffer)?)
    }

    fn require_anchored(
        env: &Env,
        chain_id: u128,
        root: &BytesN<32>,
    ) -> Result<(), OrderPortalError> {
        Ok(ops::require_anchored(env, chain_id, root)?)
    }

    fn open_claim(env: &Env, order_hash: &BytesN<32>, entry: ClaimEntry, finalize_at: u64) {
        ops::open_claim(env, order_hash, entry, finalize_at)
    }

    fn fill(env: &Env, order_hash: &BytesN<32>, account: &BytesN<32>, by_evidence: bool) {
        ops::fill(env, order_hash, account, by_evidence)
    }

    fn cancel(env: &Env, order_hash: &BytesN<32>, account: &BytesN<32>, by_evidence: bool) {
        ops::cancel(env, order_hash, account, by_evidence)
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
