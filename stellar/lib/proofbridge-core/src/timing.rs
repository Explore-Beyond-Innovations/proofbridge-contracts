//! Route-timing validation (2.3e D6): the same rules as `RouteTiming.validate` on EVM.

use crate::types::RouteTiming;

/// A presentation window can never be shorter than this.
pub const MIN_BUFFER: u64 = 30 * 60;

/// #453: nor longer than this.
pub const MAX_BUFFER: u64 = 24 * 60 * 60;

/// #453: the longest `deadline - now` a lock/create accepts. `min_window` is at most half of it, so
/// a deadline at twice the min window (the lock lands after the create) still fits.
pub const MAX_ORDER_WINDOW: u64 = 7 * 24 * 60 * 60;

/// Which field failed: 1 buffer, 2 margin, 4 claim_stagger, 5 min_window (3 is retired: the old
/// backstop rule). Rules: `MIN_BUFFER <= buffer <= MAX_BUFFER`, `margin <= buffer / 2` (the bridger
/// always keeps at least half the window for the co-signed unlock),
/// `claim_stagger < min_window` when the stagger is on (`0` = off, always legal),
/// `margin <= min_window <= MAX_ORDER_WINDOW / 2` (the upper bounds are #453's).
pub fn validate(t: &RouteTiming) -> Result<(), u8> {
    if t.buffer < MIN_BUFFER || t.buffer > MAX_BUFFER {
        return Err(1);
    }
    if t.margin > t.buffer / 2 {
        return Err(2);
    }
    if t.claim_stagger != 0 && t.claim_stagger >= t.min_window {
        return Err(4);
    }
    if t.min_window < t.margin || t.min_window > MAX_ORDER_WINDOW / 2 {
        return Err(5);
    }
    Ok(())
}
