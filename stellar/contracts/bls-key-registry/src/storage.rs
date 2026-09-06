//! Storage helpers for the BLSKeyRegistry contract (v2: per-account key slots).

use soroban_sdk::{contracttype, symbol_short, Address, BytesN, Env, Symbol, Vec};

const KEY_INIT: Symbol = symbol_short!("init");
const KEY_ADMIN: Symbol = symbol_short!("admin");
const KEY_CHAIN: Symbol = symbol_short!("chain");
const KEY_GUARD: Symbol = symbol_short!("guard");
/// Pause flag for register/revoke/set_valid_until.
const KEY_PAUSED: Symbol = symbol_short!("paused");
/// Pending admin for the two-step handover.
const KEY_PENDADM: Symbol = symbol_short!("pendadm");

/// (KEY_ENTRY, account) -> RegistryEntry
const KEY_ENTRY: Symbol = symbol_short!("entry");
/// (KEY_SLOT, account, slot_id) -> KeySlot
const KEY_SLOT: Symbol = symbol_short!("slot");
/// (KEY_NONCE, account) -> u64
const KEY_NONCE: Symbol = symbol_short!("nonce");
/// (KEY_USED, account, commitment) -> bool; a commitment never re-enters a slot.
const KEY_USED: Symbol = symbol_short!("used");

/// Every write (and every use-time read) re-extends the account's records; the
/// T1 registry never did, and an archived slot would strand settlement.
const PERSISTENT_LIFETIME_THRESHOLD: u32 = 518_400; // ~30 days
const PERSISTENT_BUMP_AMOUNT: u32 = 3_110_400; // ~180 days

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeySlot {
    /// keccak256(bls_pub_key)
    pub commitment: BytesN<32>,
    /// 0 = no expiry; else usable while ledger timestamp < valid_until
    pub valid_until: u64,
    pub registered_at: u64,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct RegistryEntry {
    /// monotonic, never reused
    pub next_slot_id: u32,
    /// stored slot ids, len <= MAX_ACTIVE_SLOTS
    pub live: Vec<u32>,
}

pub fn is_initialized(env: &Env) -> bool {
    env.storage().instance().has(&KEY_INIT)
}

pub fn set_initialized(env: &Env) {
    env.storage().instance().set(&KEY_INIT, &true);
}

pub fn set_admin(env: &Env, admin: &Address) {
    env.storage().instance().set(&KEY_ADMIN, admin);
}

pub fn get_admin(env: &Env) -> Address {
    env.storage().instance().get(&KEY_ADMIN).unwrap()
}

pub fn set_chain_id(env: &Env, chain_id: u128) {
    env.storage().instance().set(&KEY_CHAIN, &chain_id);
}

pub fn get_chain_id(env: &Env) -> u128 {
    env.storage().instance().get(&KEY_CHAIN).unwrap()
}

pub fn set_guards(env: &Env, guards: &Vec<Address>) {
    env.storage().instance().set(&KEY_GUARD, guards);
}

pub fn get_guards(env: &Env) -> Option<Vec<Address>> {
    env.storage().instance().get(&KEY_GUARD)
}

// ---- per-account records ----

pub fn get_entry(env: &Env, account: &BytesN<32>) -> RegistryEntry {
    env.storage()
        .persistent()
        .get(&(KEY_ENTRY, account.clone()))
        .unwrap_or(RegistryEntry {
            next_slot_id: 0,
            live: Vec::new(env),
        })
}

pub fn set_entry(env: &Env, account: &BytesN<32>, entry: &RegistryEntry) {
    let key = (KEY_ENTRY, account.clone());
    env.storage().persistent().set(&key, entry);
    bump(env, &key);
}

pub fn get_slot(env: &Env, account: &BytesN<32>, slot_id: u32) -> Option<KeySlot> {
    env.storage()
        .persistent()
        .get(&(KEY_SLOT, account.clone(), slot_id))
}

pub fn set_slot(env: &Env, account: &BytesN<32>, slot_id: u32, slot: &KeySlot) {
    let key = (KEY_SLOT, account.clone(), slot_id);
    env.storage().persistent().set(&key, slot);
    bump(env, &key);
}

pub fn remove_slot(env: &Env, account: &BytesN<32>, slot_id: u32) {
    env.storage()
        .persistent()
        .remove(&(KEY_SLOT, account.clone(), slot_id));
}

/// Nonce starts at 0 for a never-seen account; bumps on register / revoke.
pub fn get_nonce(env: &Env, account: &BytesN<32>) -> u64 {
    env.storage()
        .persistent()
        .get(&(KEY_NONCE, account.clone()))
        .unwrap_or(0)
}

pub fn set_nonce(env: &Env, account: &BytesN<32>, nonce: u64) {
    let key = (KEY_NONCE, account.clone());
    env.storage().persistent().set(&key, &nonce);
    bump(env, &key);
}

pub fn is_used(env: &Env, account: &BytesN<32>, commitment: &BytesN<32>) -> bool {
    env.storage()
        .persistent()
        .has(&(KEY_USED, account.clone(), commitment.clone()))
}

pub fn set_used(env: &Env, account: &BytesN<32>, commitment: &BytesN<32>) {
    let key = (KEY_USED, account.clone(), commitment.clone());
    env.storage().persistent().set(&key, &true);
    bump(env, &key);
}

/// Re-extend the account's live records at use time (unlock) so an active
/// account never archives between writes.
pub fn touch(env: &Env, account: &BytesN<32>, slot_id: u32) {
    bump(env, &(KEY_ENTRY, account.clone()));
    bump(env, &(KEY_SLOT, account.clone(), slot_id));
}

fn bump<K: soroban_sdk::IntoVal<Env, soroban_sdk::Val>>(env: &Env, key: &K) {
    env.storage().persistent().extend_ttl(
        key,
        PERSISTENT_LIFETIME_THRESHOLD,
        PERSISTENT_BUMP_AMOUNT,
    );
}

pub fn is_paused(env: &Env) -> bool {
    env.storage().instance().get(&KEY_PAUSED).unwrap_or(false)
}

pub fn set_paused(env: &Env, paused: bool) {
    env.storage().instance().set(&KEY_PAUSED, &paused);
}

pub fn get_pending_admin(env: &Env) -> Option<Address> {
    env.storage().instance().get(&KEY_PENDADM)
}

pub fn set_pending_admin(env: &Env, admin: &Address) {
    env.storage().instance().set(&KEY_PENDADM, admin);
}

pub fn clear_pending_admin(env: &Env) {
    env.storage().instance().remove(&KEY_PENDADM);
}
