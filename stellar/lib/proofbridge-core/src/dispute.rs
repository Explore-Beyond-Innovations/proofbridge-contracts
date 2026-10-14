//! Dispute parameter validation and the bond rule (2.3g), shared by the dispute module and
//! mirrored by `libraries/Dispute.sol` on EVM.
//!
//! The two implementations are kept honest by the shared vectors, not by this file — which is why
//! the rules are written here in one place rather than inline at each call site.

use crate::types::{BondConfig, DisputeOutcome, DisputeParams};

/// A challenge period shorter than this leaves no room to gather evidence.
pub const MIN_CHALLENGE_PERIOD: u64 = 60 * 60;

/// Bounds how long a dispute can delay the other party.
pub const MAX_CHALLENGE_PERIOD: u64 = 7 * 24 * 60 * 60;

/// The DisputeManager's `#[contracterror]` numbers the escrows relay (49S-3), defined once. The
/// module's enum needs literals, so its test pins each variant to the constant here.
pub mod error_code {
    pub const NOT_ESCROW: u32 = 3;
    pub const DISPUTE_EXISTS: u32 = 10;
    pub const NOT_RESPONDER: u32 = 16;
    pub const NO_DISPUTE_PARAMS: u32 = 17;
    pub const WRONG_ESCROW: u32 = 21;
    pub const BOND_TRANSFER_FAILED: u32 = 24;
    pub const RESPONSE_WINDOW_CLOSED: u32 = 25;
    pub const ALREADY_RESPONDED: u32 = 26;
    pub const ZERO_RESPONSE: u32 = 27;
    pub const ALREADY_RULED: u32 = 23;
}

/// Which field failed: 1 challenge_period, 2 bond_floor. 3 is retired (the old percentage term).
///
/// Fail-closed, the same shape as `timing::validate`: a zero `challenge_period` is what an unset
/// route reads as, so it can never be a legal written value.
pub fn validate(p: &DisputeParams) -> Result<(), u8> {
    if p.challenge_period < MIN_CHALLENGE_PERIOD || p.challenge_period > MAX_CHALLENGE_PERIOD {
        return Err(1);
    }
    // No business ceiling on the floor: it is in the route token's units, so no one number fits every
    // token. It is moved as an i128, though, so a floor above i128's maximum could never be pulled (#586).
    if p.bond_floor == 0 || p.bond_floor > i128::MAX as u128 {
        return Err(2);
    }
    Ok(())
}

/// The bond a filer must post: the route's flat floor, whatever the order's size.
///
/// A percentage of the order amount would mix the ad token's raw units with native ones, and pricing
/// it properly needs an oracle. Routes that carry large orders get a higher floor.
pub fn bond_for(p: &DisputeParams) -> u128 {
    p.bond_floor
}

/// The ceiling on a route's `bond_bps` (5% of the order).
pub const MAX_BOND_BPS: u32 = 500;

/// `{0, 0}` clears the route's config (back to the flat floor); otherwise the floor is non-zero and
/// the ratio at most `MAX_BOND_BPS`. `false` = refused.
pub fn validate_bond(c: &BondConfig) -> bool {
    if c.min_bond == 0 {
        c.bond_bps == 0
    } else {
        // DA-2: the bond is moved as an i128; a floor above it could never be pulled.
        c.bond_bps <= MAX_BOND_BPS && c.min_bond <= i128::MAX as u128
    }
}

/// The scaled bond in the order's token: `max(min_bond, amount × bond_bps / 10,000)`, the ratio
/// rounded down. The floor keeps small orders bondable; the ratio scales large ones.
pub fn route_bond(c: &BondConfig, amount: u128) -> u128 {
    let scaled = crate::fees::bps_of(amount, c.bond_bps);
    scaled.max(c.min_bond)
}

/// Whether the filer's position was vindicated, which is what routes the bond.
///
/// There is no separate "frivolous" discretion anywhere: the outcome *is* the finding. A mutual
/// refund returns the bond because neither side was shown wrong; a forfeit returns it only when the
/// forfeited party is the one the filer accused. `return_to_filer` is the escrow's own finding on
/// an evidence close: the bridger filed against a co-signed payout the maker denied, so filing was
/// justified even though the trade then settled.
pub fn bond_returns_to_filer(
    outcome: DisputeOutcome,
    filer_is_bridger: bool,
    return_to_filer: bool,
) -> bool {
    if return_to_filer {
        return true;
    }
    match outcome {
        DisputeOutcome::MutualRefund => true,
        // The filer accused the other side; the ruling agreeing means that side forfeits.
        DisputeOutcome::MakerForfeit => filer_is_bridger,
        DisputeOutcome::BridgerForfeit => !filer_is_bridger,
        // TradeProceeds: the trade was provably fine, so the filer disputed a settleable trade.
        _ => false,
    }
}
