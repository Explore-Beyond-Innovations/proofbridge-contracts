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
//! This leg is the follower and has no clock of its own after the deadline: it refunds only against
//! a proof of the ad leg's CANCEL leaf, pays the maker on its SETTLED or FORFEIT leaf, each under an
//! anchored root; the maker's co-signed `unlock` stops `claim_stagger` before the deadline, so a
//! cancel claim always leaves time to land it. While no root is anchored, refunds wait. Every `Filled` gets a
//! SETTLED leaf, appended by `record_settled` in its own transaction (to match the EVM leg so the
//! relayer batches one shape — not Soroban's per-tx budget, which is 400M on the network and was
//! misread as the harness default of 100M;
//! EVM appends it inside the fill). The same state machine as EVM:
//!
//! ```text
//!   None ──create──▶ Open ──refund_by_cancel (proof, no clock)──▶ Cancelled (refund)
//!                     ├──unlock / present_settled / pay_maker_by_forfeit──▶ Filled
//!                     │                                    └──record_settled──▶ (+ SETTLED leaf)
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
use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, IntoVal, Symbol, Val, Vec};

pub use errors::OrderPortalError;
pub use types::{
    ChainInfo, ClaimRecord, ContractConfig, OrderParams, OrderRecord, RouteTiming, Status,
    NATIVE_TOKEN_ADDRESS,
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

    // ── the 24-hour delay (#586) ─────────────────────────────────────────

    /// Close the setup bypass for good. Admin only; not itself delayed.
    pub fn activate_timelock(env: Env) -> Result<(), OrderPortalError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();
        proofbridge_core::timelock::activate(&env)?;
        storage::extend_instance_ttl(&env);
        Ok(())
    }

    /// Queue a timelocked call: its function name and its exact argument list. Admin only; closes
    /// the bypass if still open. Executable by anyone 24 hours later by calling the function itself.
    pub fn propose_action(
        env: Env,
        fn_name: Symbol,
        args: Vec<Val>,
    ) -> Result<BytesN<32>, OrderPortalError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();
        let id = proofbridge_core::timelock::propose(&env, fn_name, args)?;
        storage::extend_instance_ttl(&env);
        Ok(id)
    }

    /// Drop a pending proposal. Admin only.
    pub fn cancel_action(env: Env, id: BytesN<32>) -> Result<(), OrderPortalError> {
        let config = storage::get_config(&env)?;
        config.admin.require_auth();
        Ok(proofbridge_core::timelock::cancel(&env, id)?)
    }

    pub fn timelock_active(env: Env) -> bool {
        proofbridge_core::timelock::is_active(&env)
    }

    /// The earliest execution time of a pending proposal; 0 = none.
    pub fn timelock_eta(env: Env, id: BytesN<32>) -> u64 {
        proofbridge_core::timelock::eta(&env, &id)
    }

    /// Configure a destination (ad) chain.
    pub fn set_chain(
        env: Env,
        ad_chain_id: u128,
        ad_manager: BytesN<32>,
    ) -> Result<(), OrderPortalError> {
        let config = storage::get_config(&env)?;
        proofbridge_core::timelock::gate(
            &env,
            &config.admin,
            "set_chain",
            (ad_chain_id, ad_manager.clone()).into_val(&env),
        )?;

        // A stored entry is what makes the chain supported, so it must name a counterpart.
        if auth::is_zero_bytes32(&ad_manager) {
            return Err(OrderPortalError::ZeroAddress);
        }

        let chain_info = ChainInfo {
            ad_manager: ad_manager.clone(),
        };
        storage::set_chain(&env, ad_chain_id, &chain_info);

        events::ChainSet {
            chain_id: ad_chain_id,
            ad_manager: ad_manager.clone(),
            supported: true,
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
        proofbridge_core::timelock::gate(
            &env,
            &config.admin,
            "set_root_verifier",
            (chain_id, module.clone()).into_val(&env),
        )?;
        ops::set_root_verifier(&env, chain_id, module);
        Ok(())
    }

    /// The root verifier wired for `chain_id`, if any (#465: the deploy CLIs read it to refuse a
    /// registry split).
    pub fn root_verifier(env: Env, chain_id: u128) -> Option<Address> {
        storage::get_root_verifier(&env, chain_id)
    }

    /// #466: every chain a root verifier was ever set for, once each, in first-wired order.
    pub fn wired_chains(env: Env) -> soroban_sdk::Vec<u128> {
        storage::get_wired_chains(&env)
    }

    /// Set the termination clocks for a peer chain (2.3e D6). Validated; unset fails closed.
    pub fn set_route_timing(
        env: Env,
        chain_id: u128,
        timing: RouteTiming,
    ) -> Result<(), OrderPortalError> {
        let config = storage::get_config(&env)?;
        proofbridge_core::timelock::gate(
            &env,
            &config.admin,
            "set_route_timing",
            (chain_id, timing.clone()).into_val(&env),
        )?;
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
        proofbridge_core::timelock::gate(
            &env,
            &config.admin,
            "set_root_anchor",
            (anchor.clone(),).into_val(&env),
        )?;
        ops::set_root_anchor(&env, anchor);
        Ok(())
    }

    pub fn remove_chain(env: Env, ad_chain_id: u128) -> Result<(), OrderPortalError> {
        let config = storage::get_config(&env)?;
        proofbridge_core::timelock::gate(
            &env,
            &config.admin,
            "remove_chain",
            (ad_chain_id,).into_val(&env),
        )?;

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
        proofbridge_core::timelock::gate(
            &env,
            &config.admin,
            "set_token_route",
            (order_token.clone(), ad_chain_id, ad_token.clone()).into_val(&env),
        )?;

        if auth::is_zero_bytes32(&order_token) || auth::is_zero_bytes32(&ad_token) {
            return Err(OrderPortalError::RoutesZeroAddress);
        }

        storage::get_chain(&env, ad_chain_id).ok_or(OrderPortalError::AdChainNotSupported)?;

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
        proofbridge_core::timelock::gate(
            &env,
            &config.admin,
            "remove_token_route",
            (order_token.clone(), ad_chain_id).into_val(&env),
        )?;

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
        // The one entry here: a pause stops new orders, never exits.
        if storage::is_paused(&env) {
            return Err(OrderPortalError::ContractPaused);
        }
        let config = storage::get_config(&env)?;

        // Validate order parameters (incl. decimal range ≤ MAX).
        validation::validate_order(&env, &params)?;
        // Verify signed orderDecimals matches on-chain token decimals.
        Self::assert_order_decimals(&env, &params, &config.w_native_token)?;
        // 2.3e D5: the window bound.
        let timing_version = Self::require_min_window(&env, params.ad_chain_id, params.deadline)?;

        let order_hash = Self::order_hash(&env, &config, &params);

        if storage::get_order_status(&env, &order_hash) != Status::None {
            return Err(OrderPortalError::OrderExists);
        }

        let bridger_addr = token::bytes32_to_account_address(&env, &params.bridger)?;

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

        storage::open_order(&env, &order_hash, timing_version, 0, 0, 0, (0, 0));
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
        let config = storage::get_config(&env)?;

        // Permissionless (EVM parity): the recipient is hash-bound, so anyone may submit. Decimals
        // were checked at create; the payout is the deposited amount.

        let order_hash = Self::order_hash(&env, &config, &params);

        // `Open` only: the co-signed package proves the lock, not the outcome.
        if storage::get_order_status(&env, &order_hash) != Status::Open {
            return Err(OrderPortalError::OrderNotOpen);
        }
        if storage::is_nullifier_used(&env, &nullifier_hash) {
            return Err(OrderPortalError::NullifierUsed);
        }
        // D2: stop `claim_stagger` before the deadline so the maker's cancel claim on the ad chain
        // always leaves the watchtower time to land this leg. The order's own timing version.
        let t = ops::order_timing(&env, &order_hash, params.ad_chain_id)?;
        if env.ledger().timestamp() > params.deadline.saturating_sub(t.claim_stagger) {
            return Err(OrderPortalError::OrderExpired);
        }

        let public_inputs =
            cross_contract::build_public_inputs(&env, &nullifier_hash, &target_root, &order_hash)?;
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
            &order_hash,
            proofbridge_core::cross_contract::UNPINNED,
            &nullifier_hash,
            proofbridge_core::cross_contract::ENVELOPE_SIDE_ORDER,
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
    /// Reads no clock (D4): the only refund this leg has.
    pub fn refund_by_cancel(
        env: Env,
        params: OrderParams,
        target_root: BytesN<32>,
        proof: Bytes,
    ) -> Result<(), OrderPortalError> {
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
    /// root. Not window-gated (D3); no nullifier.
    pub fn present_settled(
        env: Env,
        params: OrderParams,
        target_root: BytesN<32>,
        proof: Bytes,
    ) -> Result<(), OrderPortalError> {
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
        // No trade settled, so no SETTLED leaf may follow: mark the order recorded without
        // appending, and `record_settled` refuses it as any recorded order (`SettledRecorded`).
        storage::set_settled_recorded(&env, &order_hash);
        Self::pay_maker(&env, &config, &params);
        // C-14: `OrderSettled` alone cannot tell a forfeit from a settle.
        events::OrderForfeited { order_hash }.publish(&env);
        storage::extend_instance_ttl(&env);
        Ok(())
    }

    pub fn record_settled(env: Env, params: OrderParams) -> Result<(), OrderPortalError> {
        let config = storage::get_config(&env)?;
        let order_hash = Self::order_hash(&env, &config, &params);
        ops::record_settled(&env, &config.merkle_manager, &order_hash).map_err(Into::into)
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

    /// Withdraw a credited balance. Permissionless: funds can only go to the credited recipient.
    ///
    /// Not pause-gated: a pause stops entries only, and this hands an already-credited balance to
    /// the account that owns it.
    pub fn claim(
        env: Env,
        recipient: BytesN<32>,
        token: BytesN<32>,
    ) -> Result<(), OrderPortalError> {
        let config = storage::get_config(&env)?;
        ops::claim(&env, &config, recipient, token).map_err(Into::into)
    }

    pub fn has_open_positions(env: Env, account: BytesN<32>) -> bool {
        storage::get_in_flight(&env, &account) > 0
    }

    /// C-15: what `claim` would pay `recipient` in `token` right now.
    pub fn claimable(env: Env, recipient: BytesN<32>, token: BytesN<32>) -> u128 {
        storage::get_claimable(&env, &recipient, &token)
    }

    /// C-35: whether a proof's nullifier has been spent here.
    pub fn nullifier_used(env: Env, nullifier_hash: BytesN<32>) -> bool {
        storage::is_nullifier_used(&env, &nullifier_hash)
    }

    /// C-35: the account's open-position count (the EVM `inFlightOf`).
    pub fn in_flight_of(env: Env, account: BytesN<32>) -> u64 {
        storage::get_in_flight(&env, &account)
    }

    /// C-35: the peer token routed from `token` for `peer_chain_id`, if any.
    pub fn token_route(env: Env, token: BytesN<32>, peer_chain_id: u128) -> Option<BytesN<32>> {
        storage::get_token_route(&env, &token, peer_chain_id)
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

    /// The route's current timing version (0 = unset).
    pub fn timing_version(env: Env, chain_id: u128) -> u32 {
        storage::get_timing_version(&env, chain_id)
    }

    /// Any version's clocks; an order's own is `route_timing_at(chain, get_order(h).timing_version)`.
    pub fn route_timing_at(env: Env, chain_id: u128, version: u32) -> Option<RouteTiming> {
        storage::get_route_timing_at(&env, chain_id, version)
    }

    /// The notary the evidence paths read, if set.
    pub fn get_root_anchor(env: Env) -> Option<Address> {
        storage::get_root_anchor(&env)
    }

    /// The open presentation window on an order, if any (none on this leg since it has no clock).
    pub fn get_claim(env: Env, order_hash: BytesN<32>) -> Option<ClaimRecord> {
        storage::get_claim(&env, &order_hash)
    }

    /// The order's leg: status, open time and the timing version its windows read.
    pub fn get_order(env: Env, order_hash: BytesN<32>) -> OrderRecord {
        storage::get_order(&env, &order_hash)
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

    fn require_min_window(
        env: &Env,
        chain_id: u128,
        deadline: u64,
    ) -> Result<u32, OrderPortalError> {
        Ok(ops::require_min_window(env, chain_id, deadline)?)
    }

    fn require_presentable(env: &Env, order_hash: &BytesN<32>) -> Result<(), OrderPortalError> {
        Ok(ops::require_presentable(env, order_hash)?)
    }

    fn require_anchored(
        env: &Env,
        chain_id: u128,
        root: &BytesN<32>,
    ) -> Result<(), OrderPortalError> {
        Ok(ops::require_anchored(env, chain_id, root)?)
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
        let on_chain = proofbridge_core::token::token_decimals_bytes32(
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
