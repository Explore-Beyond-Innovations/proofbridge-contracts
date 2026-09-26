//! RootAnchor — the protocol's authenticator for proofs about facts no counterparty co-signed
//! (2.3f, cancellation-proofs §5).
//!
//! A signer set notarizes "the source chain's MMR root was `root` at ledger `ledger_seq`"; the
//! anchor becomes usable only `delay` seconds later, so a fraudulent anchor must survive the
//! watchtower's inspection window before any refund can cite it — and the admin can `revoke_anchor`
//! what the watchtower catches, during the delay or after. Consumers only ever call `is_anchored`:
//! the writer is swapped up the ladder (admin key → listener quorum → light client) with
//! `set_signers`, never by redeploying this module or the escrows. Settlement never touches this —
//! co-signed roots keep their own oracle.
//!
//! Approvals accumulate per authenticated signer up to `threshold` (2.3f D1) and count only under
//! the current signer set and the root's current generation, so rotating a compromised notary out
//! or revoking a root discards its work. Any ledger sequence is accepted for a pending root and the
//! highest is recorded (independent publishers read a quiet chain's root at different ledgers);
//! monotonicity is checked at the first approval and again when the threshold is reached.
//! `is_anchored` is never pausable: it sits on the refund path, and a pause must not be able to
//! freeze a claim (D4). The delay is read at query time, so lowering it un-delays anchored roots
//! retroactively — an admin power, deliberately.

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

/// Upper bound on a route's delay: keeps `is_anchored` arithmetic trivially safe and an incident
/// stopgap from becoming a silent brick. 7 days (#453): the escrows' evidence grace adds it to the
/// route buffer, and the sum must stay inside the key registry's 30-day memory of a dead slot.
pub const MAX_ANCHOR_DELAY: u64 = 7 * 24 * 60 * 60;

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

    /// Replace the notary set — the ladder rung (admin key → quorum → light client). Pending
    /// approvals from the previous set stop counting.
    pub fn set_signers(
        env: Env,
        signers: Vec<Address>,
        threshold: u32,
    ) -> Result<(), RootAnchorError> {
        require_admin(&env)?;
        apply_signers(&env, &signers, threshold)
    }

    /// Discard a root's record — the response to an anchor the watchtower proves absent from real
    /// history, usable during the delay or after. Its approvals never count again; a fresh
    /// anchoring needs a fresh threshold. `latest_seq` is left for `reset_latest_seq`.
    pub fn revoke_anchor(
        env: Env,
        source_chain_id: u128,
        root: BytesN<32>,
    ) -> Result<(), RootAnchorError> {
        require_admin(&env)?;
        let mut rec = storage::get_anchor(&env, source_chain_id, &root)
            .ok_or(RootAnchorError::NoSuchAnchor)?;
        if !rec.anchored && rec.approvals == 0 {
            return Err(RootAnchorError::NoSuchAnchor);
        }
        rec.gen += 1;
        rec.approvals = 0;
        rec.anchored = false;
        rec.anchored_at = 0;
        rec.ledger_seq = 0;
        storage::set_anchor(&env, source_chain_id, &root, &rec);
        events::AnchorRevoked {
            chain_id: source_chain_id,
            root,
            gen: rec.gen,
        }
        .publish(&env);
        Ok(())
    }

    /// Recover a route whose sequence was pinned wrongly (a buggy or compromised publisher).
    pub fn reset_latest_seq(
        env: Env,
        source_chain_id: u128,
        seq: u64,
    ) -> Result<(), RootAnchorError> {
        require_admin(&env)?;
        storage::set_latest_seq(&env, source_chain_id, seq);
        events::LatestSeqReset {
            chain_id: source_chain_id,
            seq,
        }
        .publish(&env);
        Ok(())
    }

    /// Seconds an anchor of `source_chain_id` must age before it is usable; bounded by
    /// `MAX_ANCHOR_DELAY`.
    pub fn set_anchor_delay(
        env: Env,
        source_chain_id: u128,
        delay: u64,
    ) -> Result<(), RootAnchorError> {
        require_admin(&env)?;
        if delay > MAX_ANCHOR_DELAY {
            return Err(RootAnchorError::DelayTooLong);
        }
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
    /// Re-anchoring an anchored root is a no-op so a retrying publisher never fails. A repeat
    /// approval by the same signer adds nothing but still evaluates the threshold, so a lowered
    /// threshold can complete a pending root.
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
            anchored: false,
            anchored_at: 0,
            approvals: 0,
            set_epoch: 0,
            gen: 0,
        });
        if rec.anchored {
            return Ok(());
        }

        // Approvals from an earlier signer set do not carry over (A1).
        let set_epoch = storage::get_set_epoch(&env);
        if rec.set_epoch != set_epoch {
            rec.set_epoch = set_epoch;
            rec.approvals = 0;
        }

        let latest = storage::get_latest_seq(&env, source_chain_id);
        if rec.approvals == 0 {
            if storage::get_monotonic(&env) && ledger_seq <= latest {
                return Err(RootAnchorError::SeqNotMonotonic);
            }
            rec.ledger_seq = ledger_seq;
        } else if ledger_seq > rec.ledger_seq {
            // Independent publishers read the same root at different ledgers on a quiet chain (A6).
            rec.ledger_seq = ledger_seq;
        }

        let stamp = ((rec.set_epoch as u64) << 32) | rec.gen as u64;
        if storage::get_approval_stamp(&env, source_chain_id, &root, &signer) != Some(stamp) {
            storage::set_approval_stamp(&env, source_chain_id, &root, &signer, stamp);
            rec.approvals += 1;
            events::AnchorApproved {
                chain_id: source_chain_id,
                root: root.clone(),
                signer,
                approvals: rec.approvals,
            }
            .publish(&env);
        }

        if rec.approvals >= storage::get_threshold(&env) {
            // A newer root may have anchored while this one was pending (A2).
            if storage::get_monotonic(&env) && rec.ledger_seq <= latest {
                return Err(RootAnchorError::SeqNotMonotonic);
            }
            rec.anchored = true;
            rec.anchored_at = env.ledger().timestamp();
            if rec.ledger_seq > latest {
                storage::set_latest_seq(&env, source_chain_id, rec.ledger_seq);
            }
            events::Anchored {
                chain_id: source_chain_id,
                root: root.clone(),
                ledger_seq: rec.ledger_seq,
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

    /// The whole consumer surface. Deliberately not gated by pause (D4), and never traps: the delay
    /// is bounded and the age is computed by subtraction. Bumps the instance so a quiet route's
    /// configuration never archives under a consumer's read.
    pub fn is_anchored(env: Env, source_chain_id: u128, root: BytesN<32>) -> bool {
        ttl::extend_instance(&env);
        match storage::get_anchor(&env, source_chain_id, &root) {
            Some(rec) if rec.anchored => {
                let now = env.ledger().timestamp();
                now >= rec.anchored_at
                    && now - rec.anchored_at >= storage::get_delay(&env, source_chain_id)
            }
            _ => false,
        }
    }

    /// The timestamp the root reached the threshold, or 0 if it is not anchored — for a consumer
    /// that needs a longer age than the route's delay.
    pub fn anchored_at(env: Env, source_chain_id: u128, root: BytesN<32>) -> u64 {
        match storage::get_anchor(&env, source_chain_id, &root) {
            Some(rec) if rec.anchored => rec.anchored_at,
            _ => 0,
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

    pub fn signer_set_epoch(env: Env) -> u32 {
        storage::get_set_epoch(&env)
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

/// Validate and store a signer set: threshold in `1..=len`, no duplicates. Bumps the epoch.
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
    let epoch = storage::bump_set_epoch(env);
    events::SignersSet {
        signers: signers.clone(),
        threshold,
        epoch,
    }
    .publish(env);
    Ok(())
}
