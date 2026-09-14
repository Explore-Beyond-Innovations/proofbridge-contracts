//! Route-timing validation (2.3e D6): the same rules as `RouteTiming.validate` on EVM.

use crate::types::RouteTiming;

/// A presentation window can never be shorter than this.
pub const MIN_BUFFER: u64 = 30 * 60;

/// Which field failed: 1 buffer, 2 margin, 3 long_backstop, 4 claim_stagger, 5 min_window.
/// Rules: `buffer >= MIN_BUFFER`, `margin < buffer`, `long_backstop >= buffer`,
/// `claim_stagger < min_window` when the stagger is on (`0` = off, always legal),
/// `min_window >= margin`.
pub fn validate(t: &RouteTiming) -> Result<(), u8> {
    if t.buffer < MIN_BUFFER {
        return Err(1);
    }
    if t.margin >= t.buffer {
        return Err(2);
    }
    if t.long_backstop < t.buffer {
        return Err(3);
    }
    if t.claim_stagger != 0 && t.claim_stagger >= t.min_window {
        return Err(4);
    }
    if t.min_window < t.margin {
        return Err(5);
    }
    Ok(())
}
