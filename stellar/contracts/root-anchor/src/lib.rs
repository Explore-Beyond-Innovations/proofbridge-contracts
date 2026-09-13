//! RootAnchor — the protocol's authenticator for proofs about facts no counterparty co-signed
//! (2.3f, cancellation-proofs §5).
//!
//! A signer set notarizes "the source chain's MMR root was `root` at ledger `ledger_seq`"; the
//! anchor becomes usable only `delay` seconds later, so a fraudulent anchor must survive the
//! watchtower's inspection window before any refund can cite it. Consumers only ever call
//! `is_anchored`: the writer is swapped up the ladder (admin key → listener quorum → light client)
//! with `set_signers`, never by redeploying this module or the escrows. Settlement never touches
//! this — co-signed roots keep their own oracle.
//!
//! Approvals accumulate per authenticated signer up to `threshold` (2.3f D1). Monotonicity is
//! enforced when a root's first approval fixes its sequence. `is_anchored` is never pausable: it
//! sits on the refund path, and a pause must not be able to freeze a claim (D4).

#![no_std]

mod errors;
mod events;
mod storage;

#[cfg(test)]
mod test;

use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, Vec};

use proofbridge_core::ttl;

pub use errors::RootAnchorError;
pub use storage::AnchorRec;

#[contract]
pub struct RootAnchor;

#[contractimpl]
impl RootAnchor {
    // =========================================================================
    // Initialization
    // =========================================================================

    pub fn initialize(
        env: Env,
        admin: Address,
        signers: Vec<Address>,
        threshold: u32,
    ) -> Result<(), RootAnchorError> {
        if storage::is_initialized(&env) {
            return Err(RootAnchorError::AlreadyInitialized);
        }
        apply_signers(&env, &signers, threshold)?;
        storage::set_admin(&env, &admin);
        storage::set_monotonic(&env, true);
        storage::set_initialized(&env);
        events::Initialized { admin, threshold }.publish(&env);
        ttl::extend_instance(&env);
        Ok(())
    }

    // =========================================================================
    // Admin
    // =========================================================================

    /// Gates `anchor` only; `is_anchored` keeps answering.
    pub fn pause(env: Env) -> Result<(), RootAnchorError> {
        let admin = require_admin(&env)?;
        storage::set_paused(&env, true);
        events::Paused { admin }.publish(&env);
        Ok(())
    }

    pub fn unpause(env: Env) -> Result<(), RootAnchorError> {
        let admin = require_admin(&env)?;
        storage::set_paused(&env, false);
        events::Unpaused { admin }.publish(&env);
        Ok(())
    }

    pub fn transfer_admin(env: Env, to: Address) -> Result<(), RootAnchorError> {
        let admin = require_admin(&env)?;
        storage::set_pending_admin(&env, &to);
        events::AdminTransferStarted { from: admin, to }.publish(&env);
        Ok(())
    }

    pub fn accept_admin(env: Env) -> Result<(), RootAnchorError> {
        let pending = storage::get_pending_admin(&env).ok_or(RootAnchorError::NotPendingAdmin)?;
        pending.require_auth();
        let old = storage::get_admin(&env);
        storage::set_admin(&env, &pending);
        storage::clear_pending_admin(&env);
        events::AdminTransferred {
            from: old,
            to: pending,
        }
        .publish(&env);
        Ok(())
    }

    /// Replace the notary set — the ladder rung (admin key → quorum → light client).
    pub fn set_signers(
        env: Env,
        signers: Vec<Address>,
        threshold: u32,
    ) -> Result<(), RootAnchorError> {
        require_admin(&env)?;
        apply_signers(&env, &signers, threshold)
    }

    /// Seconds an anchor of `source_chain_id` must age before it is usable.
    pub fn set_anchor_delay(
        env: Env,
        source_chain_id: u128,
        delay: u64,
    ) -> Result<(), RootAnchorError> {
        require_admin(&env)?;
        storage::set_delay(&env, source_chain_id, delay);
        events::AnchorDelaySet {
            chain_id: source_chain_id,
            delay,
        }
        .publish(&env);
        Ok(())
    }

    pub fn set_monotonic(env: Env, monotonic: bool) -> Result<(), RootAnchorError> {
        require_admin(&env)?;
        storage::set_monotonic(&env, monotonic);
        events::MonotonicSet { monotonic }.publish(&env);
        Ok(())
    }

    // =========================================================================
    // Notary
    // =========================================================================

    /// Approve `root` as the source chain's MMR root at `ledger_seq`. Reaching the threshold
    /// stamps `anchored_at`; the anchor is usable `delay` seconds later.
    ///
    /// Re-anchoring an anchored root is a no-op so a retrying publisher never fails. The first
    /// approval fixes the sequence; later approvals must agree with it.
    pub fn anchor(
        env: Env,
        signer: Address,
        source_chain_id: u128,
        root: BytesN<32>,
        ledger_seq: u64,
    ) -> Result<(), RootAnchorError> {
        if !storage::is_initialized(&env) {
            return Err(RootAnchorError::NotInitialized);
        }
        if storage::is_paused(&env) {
            return Err(RootAnchorError::ContractPaused);
        }
        signer.require_auth();
        if !storage::get_signers(&env).iter().any(|s| s == signer) {
            return Err(RootAnchorError::NotSigner);
        }

        let mut rec = storage::get_anchor(&env, source_chain_id, &root).unwrap_or(AnchorRec {
            ledger_seq: 0,
            anchored_at: 0,
            approvals: 0,
        });
        if rec.anchored_at != 0 {
            return Ok(());
        }

        let latest = storage::get_latest_seq(&env, source_chain_id);
        if rec.approvals == 0 {
            if storage::get_monotonic(&env) && ledger_seq <= latest {
                return Err(RootAnchorError::SeqNotMonotonic);
            }
            rec.ledger_seq = ledger_seq;
        } else if ledger_seq != rec.ledger_seq {
            return Err(RootAnchorError::SeqMismatch);
        }

        if storage::is_approved(&env, source_chain_id, &root, &signer) {
            return Ok(());
        }
        storage::set_approved(&env, source_chain_id, &root, &signer);
        rec.approvals += 1;
        events::AnchorApproved {
            chain_id: source_chain_id,
            root: root.clone(),
            signer,
            approvals: rec.approvals,
        }
        .publish(&env);

        if rec.approvals >= storage::get_threshold(&env) {
            rec.anchored_at = env.ledger().timestamp();
            if ledger_seq > latest {
                storage::set_latest_seq(&env, source_chain_id, ledger_seq);
            }
            events::Anchored {
                chain_id: source_chain_id,
                root: root.clone(),
                ledger_seq,
                anchored_at: rec.anchored_at,
            }
            .publish(&env);
        }

        storage::set_anchor(&env, source_chain_id, &root, &rec);
        ttl::extend_instance(&env);
        Ok(())
    }

    // =========================================================================
    // Views
    // =========================================================================

    /// The whole consumer surface. Deliberately not gated by pause (D4).
    pub fn is_anchored(env: Env, source_chain_id: u128, root: BytesN<32>) -> bool {
        match storage::get_anchor(&env, source_chain_id, &root) {
            Some(rec) if rec.anchored_at != 0 => {
                env.ledger().timestamp()
                    >= rec.anchored_at + storage::get_delay(&env, source_chain_id)
            }
            _ => false,
        }
    }

    /// The anchor record, for the watchtower's cross-check against real history.
    pub fn anchor_of(env: Env, source_chain_id: u128, root: BytesN<32>) -> Option<AnchorRec> {
        storage::get_anchor(&env, source_chain_id, &root)
    }

    pub fn signers(env: Env) -> Vec<Address> {
        storage::get_signers(&env)
    }

    pub fn threshold(env: Env) -> u32 {
        storage::get_threshold(&env)
    }

    pub fn anchor_delay(env: Env, source_chain_id: u128) -> u64 {
        storage::get_delay(&env, source_chain_id)
    }

    pub fn monotonic(env: Env) -> bool {
        storage::get_monotonic(&env)
    }

    pub fn latest_seq(env: Env, source_chain_id: u128) -> u64 {
        storage::get_latest_seq(&env, source_chain_id)
    }

    pub fn admin(env: Env) -> Address {
        storage::get_admin(&env)
    }

    pub fn is_initialized(env: Env) -> bool {
        storage::is_initialized(&env)
    }
}

fn require_admin(env: &Env) -> Result<Address, RootAnchorError> {
    if !storage::is_initialized(env) {
        return Err(RootAnchorError::NotInitialized);
    }
    let admin = storage::get_admin(env);
    admin.require_auth();
    Ok(admin)
}

/// Validate and store a signer set: threshold in `1..=len`, no duplicates.
fn apply_signers(env: &Env, signers: &Vec<Address>, threshold: u32) -> Result<(), RootAnchorError> {
    let n = signers.len();
    if threshold == 0 || threshold > n {
        return Err(RootAnchorError::BadThreshold);
    }
    for i in 0..n {
        for j in (i + 1)..n {
            if signers.get_unchecked(i) == signers.get_unchecked(j) {
                return Err(RootAnchorError::DuplicateSigner);
            }
        }
    }
    storage::set_signers(env, signers);
    storage::set_threshold(env, threshold);
    events::SignersSet {
        signers: signers.clone(),
        threshold,
    }
    .publish(env);
    Ok(())
}
