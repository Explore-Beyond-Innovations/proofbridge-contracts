//! Storage TTL policy shared by the contracts (the escrows' and the registry's numbers).

use soroban_sdk::{Env, IntoVal, Val};

pub const INSTANCE_LIFETIME_THRESHOLD: u32 = 17_280; // ~1 day
pub const INSTANCE_BUMP_AMOUNT: u32 = 518_400; // ~30 days
pub const PERSISTENT_LIFETIME_THRESHOLD: u32 = 518_400; // ~30 days
pub const PERSISTENT_BUMP_AMOUNT: u32 = 3_110_400; // ~180 days

/// Call on every entry point of a contract whose instance must outlive idle periods.
pub fn extend_instance(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
}

/// Re-extend a persistent record on write and at use time (no-op below the threshold).
pub fn extend_persistent<K: IntoVal<Env, Val>>(env: &Env, key: &K) {
    env.storage().persistent().extend_ttl(
        key,
        PERSISTENT_LIFETIME_THRESHOLD,
        PERSISTENT_BUMP_AMOUNT,
    );
}
