//! The canonical policy encoding, and its fingerprint.
//!
//! Soroban stores a policy as a struct and has no need of a hash. The EVM module (2.1g) cannot
//! store one at all — ERC-7562 forbids reading a list out of storage during validation — so it
//! keeps `keccak256(canonicalBytes)` in one slot and derives its rows from the same input.
//!
//! This file exists so the two are the same bytes rather than two encodings that happen to agree
//! today. `@proofbridge/order-params` owns the encoder off chain and
//! `../../../test-vectors/agent-policy.json` is the oracle all three read.
//!
//! Layout (big-endian, no padding):
//!
//! ```text
//! bytes32  domain = keccak256("ProofBridge.AgentPolicy.v1")
//! u8       actionCount || u8[] actionIds              ascending, unique
//! u8       tokenCount  || rows                        ascending by token
//!   bytes32 token, u256 maxPerOrder, u256 capacity, u256 refillPerSecond
//! u8       adScopeKind  0 = every ad this account owns, 1 = the list below
//! u8       adScopeCount
//!   u16 length || utf8 bytes                          ascending, unique
//! u64      validUntil
//! bytes32  settlementSigner
//! ```
//!
//! `revoked` and the live buckets are deliberately absent. Revoking is overwriting the
//! fingerprint, which invalidates every copy of a policy at once, so a flag would add nothing; the
//! buckets are the chain's state rather than the owner's statement, and a policy carrying them
//! would need a new fingerprint per trade.

use soroban_sdk::{Bytes, BytesN, Env, String, Symbol, Vec};

use crate::errors::AccountError;
use crate::policy::{AgentPolicy, TokenLimit};

/// Longest ad id this encoder will hash, matching `eip712::abi_encode_string`.
const MAX_AD_ID: usize = 1024;

/// Chain-neutral action ids. Soroban names an action with a `Symbol` and the EVM with a 4-byte
/// selector, so neither side's own spelling can be the thing that gets hashed.
pub const ACTION_LOCK_FOR_ORDER: u8 = 1;

fn action_id(env: &Env, action: &Symbol) -> Result<u8, AccountError> {
    if *action == Symbol::new(env, "lock_for_order") {
        return Ok(ACTION_LOCK_FOR_ORDER);
    }
    Err(AccountError::BadPolicy)
}

fn domain(env: &Env) -> BytesN<32> {
    env.crypto()
        .keccak256(&Bytes::from_slice(env, b"ProofBridge.AgentPolicy.v1"))
        .to_bytes()
}

fn push_u16(out: &mut Bytes, v: u16) {
    out.append(&Bytes::from_array(&out.env().clone(), &v.to_be_bytes()));
}

fn push_u64(env: &Env, out: &mut Bytes, v: u64) {
    out.append(&Bytes::from_array(env, &v.to_be_bytes()));
}

/// u128 widened to 32 bytes, so the field is the EVM's natural width and the value is one Soroban
/// can hold. A limit above `u128::MAX` is not representable here and the encoder off chain refuses
/// it for the same reason.
fn push_u256(env: &Env, out: &mut Bytes, v: u128) {
    let mut buf = [0u8; 32];
    buf[16..32].copy_from_slice(&v.to_be_bytes());
    out.append(&Bytes::from_array(env, &buf));
}

/// The ad id's UTF-8 bytes, or `BadPolicy` if it is longer than this encoder can hash.
fn ad_bytes(s: &String) -> Result<([u8; MAX_AD_ID], usize), AccountError> {
    let len = s.len() as usize;
    if len == 0 || len > MAX_AD_ID {
        return Err(AccountError::BadPolicy);
    }
    let mut buf = [0u8; MAX_AD_ID];
    s.copy_into_slice(&mut buf[..len]);
    Ok((buf, len))
}

/// `limits` ordered ascending by token, as the canonical form requires. Insertion sort: the list is
/// bounded by `MAX_WHITELIST_TOKENS` (16), and a sort that allocates would need `alloc` in a wasm
/// build that does not have it.
fn sorted_limits(env: &Env, limits: &Vec<TokenLimit>) -> Vec<TokenLimit> {
    let mut out: Vec<TokenLimit> = Vec::new(env);
    for l in limits.iter() {
        let key = l.token.to_array();
        let mut at = out.len();
        for i in 0..out.len() {
            if key < out.get(i).unwrap().token.to_array() {
                at = i;
                break;
            }
        }
        out.insert(at, l);
    }
    out
}

/// Ad ids ordered ascending by their UTF-8 bytes, same reasoning.
fn sorted_ads(env: &Env, ads: &Vec<String>) -> Result<Vec<String>, AccountError> {
    let mut out: Vec<String> = Vec::new(env);
    for a in ads.iter() {
        let (buf, len) = ad_bytes(&a)?;
        let mut at = out.len();
        for i in 0..out.len() {
            let (other, other_len) = ad_bytes(&out.get(i).unwrap())?;
            if buf[..len] < other[..other_len] {
                at = i;
                break;
            }
        }
        out.insert(at, a);
    }
    Ok(out)
}

/// Action ids ascending.
fn sorted_actions(env: &Env, actions: &Vec<Symbol>) -> Result<Vec<u32>, AccountError> {
    let mut out: Vec<u32> = Vec::new(env);
    for a in actions.iter() {
        let id = action_id(env, &a)? as u32;
        let mut at = out.len();
        for i in 0..out.len() {
            if id < out.get(i).unwrap() {
                at = i;
                break;
            }
        }
        out.insert(at, id);
    }
    Ok(out)
}

/// The canonical bytes for a policy.
pub fn encode(env: &Env, p: &AgentPolicy) -> Result<Bytes, AccountError> {
    let mut out = Bytes::new(env);
    out.append(&domain(env).into());

    let actions = sorted_actions(env, &p.allowed_actions)?;
    out.push_back(actions.len() as u8);
    for id in actions.iter() {
        out.push_back(id as u8);
    }

    let limits = sorted_limits(env, &p.limits);
    out.push_back(limits.len() as u8);
    for l in limits.iter() {
        out.append(&l.token.clone().into());
        push_u256(env, &mut out, l.max_per_order);
        push_u256(env, &mut out, l.rate.capacity);
        push_u256(env, &mut out, l.rate.refill_per_second);
    }

    match &p.ad_scope {
        None => {
            out.push_back(0);
            out.push_back(0);
        }
        Some(ads) => {
            let ads = sorted_ads(env, ads)?;
            out.push_back(1);
            out.push_back(ads.len() as u8);
            for a in ads.iter() {
                let (buf, len) = ad_bytes(&a)?;
                push_u16(&mut out, len as u16);
                out.append(&Bytes::from_slice(env, &buf[..len]));
            }
        }
    }

    push_u64(env, &mut out, p.valid_until);
    out.append(&p.settlement_signer.clone().into());
    Ok(out)
}

/// What the EVM module stores for this policy.
pub fn fingerprint(env: &Env, p: &AgentPolicy) -> Result<BytesN<32>, AccountError> {
    Ok(env.crypto().keccak256(&encode(env, p)?).to_bytes())
}
