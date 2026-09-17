//! DisputeManager — the dispute lifecycle for both escrows on this chain (2.3g).
//!
//! A module contract, the same shape as `RootAnchor`: the escrows *read* it and apply their own
//! half of the outcome; it never moves their funds and never writes their state. The escrows call
//! in; nothing here calls back.
//!
//! Three rules carry the design, each enforced somewhere below:
//!
//! 1. **Evidence beats arbitration.** A proof that the trade settled terminates a dispute
//!    immediately. The escrow's evidence paths accept `Disputed` and close the record through
//!    `settle_bond`; nothing here can stop them, and no ruling survives one.
//! 2. **The arbiter rules only the vacuum.** `resolve_dispute` refuses `TradeProceeds` under any
//!    input — that outcome is reachable by evidence alone.
//! 3. **A ruling opens a window; it does not pay.** Evidence inside that window overrides it.
//!
//! Why one module for both escrows: the inline draft duplicated all five entry points across
//! `ad-manager` and `order-portal`. One implementation means one outcome table to audit, one
//! arbiter key, and one bond pot — and on the EVM side it is what returned AdManager's size margin.

#![no_std]

mod errors;
mod events;
mod storage;

#[cfg(test)]
mod test;

use proofbridge_core::dispute;
use proofbridge_core::types::{DisputeOutcome, DisputeParams, DisputeRecord};
use soroban_sdk::{contract, contractimpl, token, Address, BytesN, Env};

pub use errors::DisputeManagerError as Error;

#[contract]
pub struct DisputeManagerContract;

#[contractimpl]
impl DisputeManagerContract {
    /// Wire the module. `w_native` is the token bonds are held in — the same one the escrows wrap
    /// native value into, so a bond needs no new transfer path.
    pub fn initialize(env: Env, admin: Address, w_native: Address) -> Result<(), Error> {
        if storage::get_admin(&env).is_some() {
            return Err(Error::AlreadyInitialized);
        }
        storage::set_admin(&env, &admin);
        storage::set_w_native(&env, &w_native);
        storage::extend_instance_ttl(&env);
        Ok(())
    }

    // ── admin ────────────────────────────────────────────────────────────

    pub fn set_escrow(env: Env, escrow: Address, allowed: bool) -> Result<(), Error> {
        Self::require_admin(&env)?;
        storage::set_escrow(&env, &escrow, allowed);
        events::EscrowSet { escrow, allowed }.publish(&env);
        storage::extend_instance_ttl(&env);
        Ok(())
    }

    /// Per-route parameters, validated at the write. Fail-closed: an unset route cannot be disputed
    /// rather than being disputed for free.
    pub fn set_dispute_params(
        env: Env,
        chain_id: u128,
        params: DisputeParams,
    ) -> Result<(), Error> {
        Self::require_admin(&env)?;
        dispute::validate(&params).map_err(|f| match f {
            1 => Error::InvalidChallengePeriod,
            2 => Error::InvalidBondFloor,
            _ => Error::InvalidBondBps,
        })?;
        storage::set_params(&env, chain_id, &params);
        events::DisputeParamsSet { chain_id, params }.publish(&env);
        storage::extend_instance_ttl(&env);
        Ok(())
    }

    /// The only account that may rule. Never an agent key, and never the admin: an arbiter must not
    /// be able to pause an escrow, re-route tokens or re-point the anchor, and keeping it here is
    /// what bounds its blast radius.
    pub fn set_arbiter(env: Env, arbiter: Address) -> Result<(), Error> {
        Self::require_admin(&env)?;
        storage::set_arbiter(&env, &arbiter);
        events::ArbiterSet { arbiter }.publish(&env);
        storage::extend_instance_ttl(&env);
        Ok(())
    }

    pub fn set_protocol_fee_pool(env: Env, pool: Address) -> Result<(), Error> {
        Self::require_admin(&env)?;
        storage::set_fee_pool(&env, &pool);
        events::ProtocolFeePoolSet { pool }.publish(&env);
        storage::extend_instance_ttl(&env);
        Ok(())
    }

    pub fn transfer_admin(env: Env, to: Address) -> Result<(), Error> {
        let admin = Self::require_admin(&env)?;
        storage::set_pending_admin(&env, &to);
        events::AdminTransferStarted { from: admin, to }.publish(&env);
        Ok(())
    }

    pub fn accept_admin(env: Env) -> Result<(), Error> {
        let pending = storage::get_pending_admin(&env).ok_or(Error::NotInitialized)?;
        pending.require_auth();
        let old = storage::get_admin(&env).ok_or(Error::NotInitialized)?;
        storage::set_admin(&env, &pending);
        storage::clear_pending_admin(&env);
        events::AdminTransferred {
            from: old,
            to: pending,
        }
        .publish(&env);
        Ok(())
    }

    // ── the escrow-facing edge ───────────────────────────────────────────

    /// Open a dispute on an order the escrow has already hashed and checked, taking the bond.
    ///
    /// Escrow-only. The escrow must pass `amount` because it does not store one — an order's leg is
    /// `{status, paused_at_open}` and the amount lives in the caller's params, validated against the
    /// hash. So the escrow is the only party that can vouch for it, which is why filing starts there
    /// and this contract is never the entry point.
    pub fn open_dispute(
        env: Env,
        escrow: Address,
        order_hash: BytesN<32>,
        amount: u128,
        peer_chain_id: u128,
        filer: Address,
        evidence: BytesN<32>,
    ) -> Result<u128, Error> {
        Self::require_escrow(&env, &escrow)?;
        if storage::get_dispute(&env, &order_hash).is_some() {
            return Err(Error::DisputeExists);
        }
        let p = storage::get_params(&env, peer_chain_id).ok_or(Error::NoDisputeParams)?;
        let bond = dispute::bond_for(amount, &p);

        // The filer funds the bond directly into this contract: it never rests in the escrow, which
        // keeps "the escrow's balance is its order escrow" a single-contract invariant for 2.3h.
        filer.require_auth();
        let w = storage::get_w_native(&env).ok_or(Error::NotInitialized)?;
        token::Client::new(&env, &w).transfer(
            &filer,
            &env.current_contract_address(),
            &(bond as i128),
        );

        let challenge_deadline = env.ledger().timestamp() + p.challenge_period;
        storage::set_dispute(
            &env,
            &order_hash,
            &DisputeRecord {
                initiator: filer.clone(),
                bond,
                challenge_deadline,
                paused_at_open: storage::get_paused_seconds(&env),
                initiator_evidence: evidence,
                responder_evidence: BytesN::from_array(&env, &[0u8; 32]),
                ruling: DisputeOutcome::None,
                escrow,
            },
        );
        events::DisputeFiled {
            order_hash,
            initiator: filer,
            bond,
            challenge_deadline,
        }
        .publish(&env);
        storage::extend_instance_ttl(&env);
        Ok(bond)
    }

    /// Settle the bond for a dispute the escrow has just finalized, and close the record.
    ///
    /// Escrow-only, and the one direction funds move: out of this module, never out of the escrow.
    /// `filer_was_counterparty` is the escrow's answer, because only it knows which party it
    /// authenticates.
    pub fn settle_bond(
        env: Env,
        escrow: Address,
        order_hash: BytesN<32>,
        filer_is_bridger: bool,
    ) -> Result<(), Error> {
        Self::require_escrow(&env, &escrow)?;
        let d = storage::get_dispute(&env, &order_hash).ok_or(Error::NotDisputed)?;
        if d.escrow != escrow {
            return Err(Error::WrongEscrow);
        }

        let outcome = if d.ruling == DisputeOutcome::None {
            DisputeOutcome::MutualRefund
        } else {
            d.ruling
        };
        storage::remove_dispute(&env, &order_hash);

        if d.bond != 0 {
            let to_filer = dispute::bond_returns_to_filer(outcome, filer_is_bridger);
            // An unset fee pool must not strand the bond; the filer keeps it rather than this
            // contract holding it forever.
            let to = if to_filer {
                d.initiator.clone()
            } else {
                storage::get_fee_pool(&env).unwrap_or(d.initiator.clone())
            };
            Self::pay_or_credit(&env, &to, d.bond)?;
            events::BondRouted {
                order_hash,
                to,
                amount: d.bond,
                returned_to_filer: to_filer,
            }
            .publish(&env);
        }
        storage::extend_instance_ttl(&env);
        Ok(())
    }

    // ── the dispute itself ───────────────────────────────────────────────

    /// Record the counterparty's evidence hash. Moves no funds, posts no bond.
    pub fn respond_to_dispute(
        env: Env,
        order_hash: BytesN<32>,
        responder: Address,
        evidence: BytesN<32>,
    ) -> Result<(), Error> {
        responder.require_auth();
        let mut d = storage::get_dispute(&env, &order_hash).ok_or(Error::NotDisputed)?;
        if d.initiator == responder {
            return Err(Error::NotResponder);
        }
        d.responder_evidence = evidence.clone();
        storage::set_dispute(&env, &order_hash, &d);
        events::DisputeResponded {
            order_hash,
            responder,
            evidence,
        }
        .publish(&env);
        Ok(())
    }

    /// Rule the vacuum. Opens a presentation window; it does not pay.
    pub fn resolve_dispute(
        env: Env,
        order_hash: BytesN<32>,
        outcome: DisputeOutcome,
    ) -> Result<(), Error> {
        let arbiter = storage::get_arbiter(&env).ok_or(Error::NotInitialized)?;
        arbiter.require_auth();
        if outcome == DisputeOutcome::TradeProceeds || outcome == DisputeOutcome::None {
            return Err(Error::ArbiterCannotSettle);
        }
        let mut d = storage::get_dispute(&env, &order_hash).ok_or(Error::NotDisputed)?;
        let until = Self::effective_challenge_deadline_of(&env, &d);
        if env.ledger().timestamp() >= until {
            return Err(Error::ChallengeClosed);
        }
        d.ruling = outcome;
        d.challenge_deadline = until;
        storage::set_dispute(&env, &order_hash, &d);
        events::DisputeRuled {
            order_hash,
            outcome,
            finalize_at: until,
        }
        .publish(&env);
        Ok(())
    }

    /// Open the fallback window once the challenge period expired with no ruling.
    /// Permissionless: an unresolved dispute must not depend on the arbiter ever showing up.
    pub fn claim_dispute(env: Env, order_hash: BytesN<32>) -> Result<(), Error> {
        let d = storage::get_dispute(&env, &order_hash).ok_or(Error::NotDisputed)?;
        if d.ruling != DisputeOutcome::None {
            return Err(Error::ChallengeClosed);
        }
        let until = Self::effective_challenge_deadline_of(&env, &d);
        if env.ledger().timestamp() < until {
            return Err(Error::ChallengeOpen);
        }
        events::DisputeClaimed {
            order_hash,
            finalize_at: until,
        }
        .publish(&env);
        Ok(())
    }

    // ── views ────────────────────────────────────────────────────────────

    /// How a dispute has ended, if it has: the ruling, whether its window is over in real time, and
    /// who filed. The escrow's whole dependency on this module.
    pub fn outcome_of(env: Env, order_hash: BytesN<32>) -> (DisputeOutcome, bool, Option<Address>) {
        match storage::get_dispute(&env, &order_hash) {
            None => (DisputeOutcome::None, false, None),
            Some(d) => {
                let over =
                    env.ledger().timestamp() >= Self::effective_challenge_deadline_of(&env, &d);
                (d.ruling, over, Some(d.initiator))
            }
        }
    }

    pub fn is_disputed(env: Env, order_hash: BytesN<32>) -> bool {
        storage::get_dispute(&env, &order_hash).is_some()
    }

    /// The challenge deadline in real time: the recorded one plus every second this module has been
    /// paused since the dispute opened.
    pub fn effective_challenge_deadline(env: Env, order_hash: BytesN<32>) -> u64 {
        match storage::get_dispute(&env, &order_hash) {
            None => 0,
            Some(d) => Self::effective_challenge_deadline_of(&env, &d),
        }
    }

    pub fn get_dispute(env: Env, order_hash: BytesN<32>) -> Option<DisputeRecord> {
        storage::get_dispute(&env, &order_hash)
    }

    /// Whether this escrow may file here. The EVM twin exposes the same thing as a public mapping;
    /// the deploy CLI reads it to make the escrow ↔ module wiring idempotent.
    pub fn is_escrow(env: Env, escrow: Address) -> bool {
        storage::is_escrow(&env, &escrow)
    }

    /// The dispute parameters for a peer route. `None` = disputes are not configured for it, which
    /// the filing path treats as fail-closed.
    pub fn dispute_params(env: Env, chain_id: u128) -> Option<DisputeParams> {
        storage::get_params(&env, chain_id)
    }

    pub fn claimable(env: Env, who: Address) -> u128 {
        storage::get_claimable(&env, &who)
    }

    /// Withdraw a credited bond payout.
    pub fn claim(env: Env, recipient: Address) -> Result<(), Error> {
        let amount = storage::get_claimable(&env, &recipient);
        if amount == 0 {
            return Err(Error::NothingToClaim);
        }
        storage::set_claimable(&env, &recipient, 0);
        let w = storage::get_w_native(&env).ok_or(Error::NotInitialized)?;
        token::Client::new(&env, &w).transfer(
            &env.current_contract_address(),
            &recipient,
            &(amount as i128),
        );
        Ok(())
    }

    // ── internal ─────────────────────────────────────────────────────────

    fn require_admin(env: &Env) -> Result<Address, Error> {
        let admin = storage::get_admin(env).ok_or(Error::NotInitialized)?;
        admin.require_auth();
        Ok(admin)
    }

    /// The caller must be an escrow this module serves.
    ///
    /// The escrow names itself and the host proves it: `require_auth` on a contract address succeeds
    /// only when that contract actually made the call, because a contract invoking another is
    /// treated as authorizing it. That is stronger than the EVM side's `msg.sender == escrow`
    /// check rather than merely equivalent — there is no address to spoof, only a call to actually
    /// make.
    fn require_escrow(env: &Env, escrow: &Address) -> Result<(), Error> {
        escrow.require_auth();
        if !storage::is_escrow(env, escrow) {
            return Err(Error::NotEscrow);
        }
        Ok(())
    }

    fn effective_challenge_deadline_of(env: &Env, d: &DisputeRecord) -> u64 {
        d.challenge_deadline
            .saturating_add(storage::get_paused_seconds(env).saturating_sub(d.paused_at_open))
    }

    /// Best effort, then credit — a recipient that cannot be paid must not brick a resolution.
    fn pay_or_credit(env: &Env, to: &Address, amount: u128) -> Result<(), Error> {
        let w = storage::get_w_native(env).ok_or(Error::NotInitialized)?;
        let client = token::Client::new(env, &w);
        if client
            .try_transfer(&env.current_contract_address(), to, &(amount as i128))
            .is_ok()
        {
            return Ok(());
        }
        let owed = storage::get_claimable(env, to);
        storage::set_claimable(env, to, owed + amount);
        events::PayoutCredited {
            recipient: to.clone(),
            amount,
        }
        .publish(env);
        Ok(())
    }
}
