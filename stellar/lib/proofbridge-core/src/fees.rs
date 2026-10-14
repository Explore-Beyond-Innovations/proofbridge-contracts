//! The bridge fee on the ad chain's payouts (#586), mirrored by `ProofBridgeUtils.splitFee` on EVM.

/// The ceiling on each fee, in bps (1%).
pub const MAX_FEE_BPS: u32 = 100;

/// `(lp_fee, protocol_fee)` on `amount`, each rounded down, so the rounding dust stays with the
/// recipient.
pub fn split_fee(amount: u128, lp_bps: u32, protocol_bps: u32) -> (u128, u128) {
    (bps_of(amount, lp_bps), bps_of(amount, protocol_bps))
}

/// `floor(amount × bps / 10,000)` without the product: exact for every u128 amount and any bps up to
/// u32 (DA-2). With `amount = q × 10,000 + r` it is `q × bps + floor(r × bps / 10,000)`; neither
/// product can overflow while `bps ≤ 10,000`, and the escrows' bps are at most 500.
pub fn bps_of(amount: u128, bps: u32) -> u128 {
    let bps = bps as u128;
    amount / 10_000 * bps + amount % 10_000 * bps / 10_000
}

/// `set_fee_bps`'s rule: each at most `MAX_FEE_BPS`, and a protocol fee only with a pool to pay.
pub fn fees_valid(lp_bps: u32, protocol_bps: u32, pool_set: bool) -> bool {
    lp_bps <= MAX_FEE_BPS && protocol_bps <= MAX_FEE_BPS && (protocol_bps == 0 || pool_set)
}
