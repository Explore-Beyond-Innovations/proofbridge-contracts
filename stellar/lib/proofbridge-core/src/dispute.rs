//! Dispute parameter validation and the bond maths (2.3g), shared by the dispute module and
//! mirrored by `libraries/Dispute.sol` on EVM.
//!
//! The two implementations are kept honest by the shared vectors, not by this file — which is why
//! the rules are written here in one place rather than inline at each call site.

use crate::types::{DisputeOutcome, DisputeParams};

/// A challenge period shorter than this leaves no room to gather evidence.
pub const MIN_CHALLENGE_PERIOD: u64 = 60 * 60;

/// Bond ceiling: 10%. Above this a bond deters honest disputes as much as frivolous ones.
pub const MAX_BOND_BPS: u32 = 1000;

const BPS_DENOMINATOR: u128 = 10_000;

/// Which field failed: 1 challenge_period, 2 bond_floor, 3 bond_bps.
///
/// Fail-closed, the same shape as `timing::validate`: a zero `challenge_period` is what an unset
/// route reads as, so it can never be a legal written value.
pub fn validate(p: &DisputeParams) -> Result<(), u8> {
    if p.challenge_period < MIN_CHALLENGE_PERIOD {
        return Err(1);
    }
    if p.bond_floor == 0 {
        return Err(2);
    }
    if p.bond_bps > MAX_BOND_BPS {
        return Err(3);
    }
    Ok(())
}

/// The bond a filer must post: `max(floor, bps * amount)`.
///
/// Both terms are per route and admin-tuned, which is the pricing mechanism the design allows in
/// place of an oracle — the percentage is meaningful where the route's token tracks native, and the
/// floor dominates where it does not. Rounds down, so the floor is what guarantees a non-zero bond.
pub fn bond_for(amount: u128, p: &DisputeParams) -> u128 {
    let scaled = amount.saturating_mul(p.bond_bps as u128) / BPS_DENOMINATOR;
    if scaled > p.bond_floor {
        scaled
    } else {
        p.bond_floor
    }
}

/// Whether the filer's position was vindicated, which is what routes the bond.
///
/// There is no separate "frivolous" discretion anywhere: the outcome *is* the finding. A mutual
/// refund returns the bond because neither side was shown wrong; a forfeit returns it only when the
/// forfeited party is the one the filer accused.
pub fn bond_returns_to_filer(outcome: DisputeOutcome, filer_is_bridger: bool) -> bool {
    match outcome {
        DisputeOutcome::MutualRefund => true,
        // The filer accused the other side; the ruling agreeing means that side forfeits.
        DisputeOutcome::MakerForfeit => filer_is_bridger,
        DisputeOutcome::BridgerForfeit => !filer_is_bridger,
        // TradeProceeds: the trade was provably fine, so the filer disputed a settleable trade.
        _ => false,
    }
}
