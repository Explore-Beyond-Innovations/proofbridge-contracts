//! T-60, layer 2: `check_contract_call` against the shared policy fixture.
//!
//! Three implementations decide whether an agent's lock is allowed: this account, the EVM module,
//! and a TypeScript copy the relayer asks first. `../../../test-vectors/agent-policy-parity.json`
//! holds policy + lock → accept or reject, with every verdict written by hand, and all three read
//! it. A case carries exactly one fault, because the implementations check in different orders.
//!
//! Driven through `__check_auth` with a real agent signature, as the escrow's `require_auth` would.
//! A passing check debits the buckets, so a case's steps are naturally a sequence.

extern crate std;

use std::format;
use std::string::{String as StdString, ToString};

use ad_manager::OrderParams;
use ed25519_dalek::{Signer, SigningKey};
use proofbridge_core::eip712::address_to_bytes32;
use proofbridge_core::rate_limit::Limit;
use serde_json::Value;
use soroban_sdk::{
    auth::{Context, ContractContext},
    testutils::{Address as _, Ledger as _},
    vec, Address, BytesN, Env, IntoVal, InvokeError, String, Symbol, Val, Vec,
};

use crate::auth::{AccountSig, Ed25519Sig};
use crate::errors::AccountError;
use crate::policy::TokenLimit;
use crate::{AgentAccount, AgentAccountClient};

const VECTORS: &str = include_str!("../../../../test-vectors/agent-policy-parity.json");
const PROTOCOL: u32 = 28;

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn hex32(env: &Env, s: &str) -> BytesN<32> {
    let s = s.strip_prefix("0x").unwrap();
    assert_eq!(s.len(), 64, "not 32 bytes of hex: {s}");
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    BytesN::from_array(env, &out)
}

fn u128_of(v: &Value) -> u128 {
    v.as_str().unwrap().parse().unwrap()
}

/// The shared word for a refusal, as this implementation's error. An unknown name has to fail
/// here rather than match nothing.
fn account_error(name: &str) -> AccountError {
    match name {
        "TargetNotAllowed" => AccountError::TargetNotAllowed,
        "ActionNotAllowed" => AccountError::ActionNotAllowed,
        "TokenNotAllowed" => AccountError::TokenNotAllowed,
        "CapExceeded" => AccountError::CapExceeded,
        "BadArgs" => AccountError::BadArgs,
        "VolumeExceeded" => AccountError::VolumeExceeded,
        "PolicyExpired" => AccountError::PolicyExpired,
        "AgentRevoked" => AccountError::AgentRevoked,
        "SettlementSignerMismatch" => AccountError::SettlementSignerMismatch,
        "AdNotAllowed" => AccountError::AdNotAllowed,
        "NoVolumeLimit" => AccountError::NoVolumeLimit,
        "BadPolicy" => AccountError::BadPolicy,
        other => panic!("an error name this reader does not know: {other}"),
    }
}

struct Rig {
    env: Env,
    client: AgentAccountClient<'static>,
    account: Address,
    pinned: Address,
    unpinned: Address,
    key: SigningKey,
    agent_id: BytesN<32>,
    /// What `policy` means for a lock's signer here: the account itself, the only signer this
    /// chain installs a policy with.
    signer: BytesN<32>,
}

/// A fresh account at `start`, with the case's ceilings set. No policy yet: installing one is what
/// the `installs` table is about.
fn rig(start: u64, ceilings: &Value) -> Rig {
    let env = Env::default();
    env.ledger().set_timestamp(start);
    env.mock_all_auths();
    env.ledger().set_protocol_version(PROTOCOL);

    let owner = Address::generate(&env);
    let pinned = Address::generate(&env);
    let unpinned = Address::generate(&env);
    let account = env.register(AgentAccount, (owner, vec![&env, pinned.clone()]));
    let client = AgentAccountClient::new(&env, &account);

    for c in ceilings.as_array().unwrap() {
        client.set_account_limit(
            &hex32(&env, c["token"].as_str().unwrap()),
            &Limit {
                capacity: u128_of(&c["capacity"]),
                refill_per_second: u128_of(&c["refillPerSecond"]),
            },
        );
    }

    let mut seed = [0u8; 32];
    seed[0] = 7;
    seed[31] = 0x5a;
    let key = SigningKey::from_bytes(&seed);
    let agent_id = BytesN::from_array(&env, &key.verifying_key().to_bytes());
    let signer = address_to_bytes32(&env, &account);

    Rig {
        env,
        client,
        account,
        pinned,
        unpinned,
        key,
        agent_id,
        signer,
    }
}

/// Install the fixture's policy, returning this chain's refusal if there is one.
fn install(r: &Rig, policy: &Value) -> Result<(), AccountError> {
    let env = &r.env;
    let mut actions: Vec<Symbol> = Vec::new(env);
    for a in policy["actions"].as_array().unwrap() {
        actions.push_back(Symbol::new(env, a.as_str().unwrap()));
    }
    let mut tokens: Vec<BytesN<32>> = Vec::new(env);
    let mut limits: Vec<TokenLimit> = Vec::new(env);
    for l in policy["limits"].as_array().unwrap() {
        let token = hex32(env, l["token"].as_str().unwrap());
        tokens.push_back(token.clone());
        limits.push_back(TokenLimit {
            token,
            max_per_order: u128_of(&l["maxPerOrder"]),
            rate: Limit {
                capacity: u128_of(&l["capacity"]),
                refill_per_second: u128_of(&l["refillPerSecond"]),
            },
        });
    }
    let ad_scope: Option<Vec<String>> = policy["adScope"].as_array().map(|ads| {
        let mut v = Vec::new(env);
        for a in ads {
            v.push_back(String::from_str(env, a.as_str().unwrap()));
        }
        v
    });

    match r.client.try_set_policy(
        &r.agent_id,
        &actions,
        &tokens,
        &policy["validUntil"].as_u64().unwrap(),
        &r.signer,
        &ad_scope,
        &limits,
    ) {
        Ok(_) => Ok(()),
        Err(Ok(e)) => Err(e),
        Err(Err(e)) => panic!("set_policy failed outside the contract's own errors: {e:?}"),
    }
}

/// One lock, judged by `__check_auth` with the agent's signature.
fn judge(r: &Rig, lock: &Value) -> Result<(), AccountError> {
    let env = &r.env;
    let signer = match lock["signer"].as_str().unwrap() {
        "policy" => r.signer.clone(),
        "other" => hex32(env, vectors()["constants"]["otherSigner"].as_str().unwrap()),
        other => panic!("signer: {other}"),
    };
    let params = OrderParams {
        order_chain_token: hex32(env, lock["orderChainToken"].as_str().unwrap()),
        ad_chain_token: hex32(env, lock["adChainToken"].as_str().unwrap()),
        amount: u128_of(&lock["amount"]),
        bridger: BytesN::from_array(env, &[0xDD; 32]),
        order_chain_id: 1,
        src_order_portal: BytesN::from_array(env, &[0xFF; 32]),
        order_recipient: BytesN::from_array(env, &[0xEE; 32]),
        ad_id: String::from_str(env, lock["adId"].as_str().unwrap()),
        // Always this account: the maker is not what any case here is about.
        ad_creator: r.signer.clone(),
        ad_recipient: BytesN::from_array(env, &[0xCC; 32]),
        salt: soroban_sdk::U256::from_u128(env, 42),
        order_decimals: lock["orderDecimals"].as_u64().unwrap() as u32,
        ad_decimals: lock["adDecimals"].as_u64().unwrap() as u32,
        deadline: 4_102_444_800,
        ad_settlement_signer: signer,
    };
    let target = match lock["target"].as_str().unwrap() {
        "pinned" => r.pinned.clone(),
        "unpinned" => r.unpinned.clone(),
        other => panic!("target: {other}"),
    };
    let fn_name = match lock["action"].as_str().unwrap() {
        "lock_for_order" => Symbol::new(env, "lock_for_order"),
        // A real function of the escrow's, and one no policy can list.
        "other" => Symbol::new(env, "withdraw_from_ad"),
        other => panic!("action: {other}"),
    };
    let args: Vec<Val> = vec![env, params.into_val(env)];
    let contexts = vec![
        env,
        Context::Contract(ContractContext {
            contract: target,
            fn_name,
            args,
        }),
    ];

    let payload = BytesN::from_array(env, &[0x01; 32]);
    let sig = AccountSig::Agent(Ed25519Sig {
        pubkey: r.agent_id.clone(),
        sig: BytesN::from_array(env, &r.key.sign(&payload.to_array()).to_bytes()),
    });
    match env.try_invoke_contract_check_auth::<AccountError>(
        &r.account,
        &payload,
        sig.into_val(env),
        &contexts,
    ) {
        Ok(()) => Ok(()),
        Err(Ok(e)) => Err(e),
        Err(Err(e)) => {
            let e: InvokeError = e;
            panic!("__check_auth failed outside the contract's own errors: {e:?}")
        }
    }
}

/// This reader's expectation for a step: one word for everyone, or a word per reader.
fn expected(step: &Value) -> StdString {
    match &step["expect"] {
        Value::String(s) => s.to_string(),
        Value::Object(per) => per["soroban"]
            .as_str()
            .expect("the fixture names this reader and gives it no expectation")
            .to_string(),
        other => panic!("expect: {other}"),
    }
}

fn reads(entry: &Value) -> bool {
    entry["readers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r == "soroban")
}

#[test]
fn check_contract_call_matches_the_shared_policy_fixture() {
    let v = vectors();
    let (mut ran_cases, mut ran_steps) = (0u64, 0u64);

    for case in v["cases"].as_array().unwrap() {
        if !reads(case) {
            continue;
        }
        let name = case["name"].as_str().unwrap();
        let start = case["startTime"].as_u64().unwrap();
        let r = rig(start, &case["accountCeilings"]);
        install(&r, &case["policy"]).unwrap_or_else(|e| panic!("{name}: did not install: {e:?}"));

        let mut now = start;
        for (i, step) in case["steps"].as_array().unwrap().iter().enumerate() {
            now += step["warp"].as_u64().unwrap();
            r.env.ledger().set_timestamp(now);
            ran_steps += 1;

            if step["op"] == "revoke" {
                r.client.revoke_agent(&r.agent_id);
                continue;
            }
            let at = format!("{name} [step {i}]");
            let got = judge(&r, &step["lock"]);
            let want = expected(step);
            if want == "accept" {
                assert_eq!(got, Ok(()), "{at}");
            } else {
                let word = v["reasons"][&want]["soroban"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{at}: no Soroban word for {want}"));
                assert_eq!(got, Err(account_error(word)), "{at}: want {want}");
            }
        }
        ran_cases += 1;
    }

    // Zero cases is a failure, and so is some: a reader that skipped half the file would pass.
    assert!(ran_cases > 0, "no case ran");
    assert_eq!(
        ran_cases,
        v["counts"]["soroban"]["cases"].as_u64().unwrap(),
        "cases ran"
    );
    assert_eq!(
        ran_steps,
        v["counts"]["soroban"]["steps"].as_u64().unwrap(),
        "steps ran"
    );
}

#[test]
fn installing_a_policy_matches_the_shared_fixture() {
    let v = vectors();
    let mut ran = 0u64;

    for entry in v["installs"].as_array().unwrap() {
        if !reads(entry) {
            continue;
        }
        let name = entry["name"].as_str().unwrap();
        let r = rig(
            entry["startTime"].as_u64().unwrap(),
            &entry["accountCeilings"],
        );
        let got = install(&r, &entry["policy"]);

        let want = entry["expect"].as_str().unwrap();
        if want == "installs" {
            assert_eq!(got, Ok(()), "{name}");
        } else {
            let word = v["installReasons"][want]["soroban"]
                .as_str()
                .unwrap_or_else(|| panic!("{name}: no Soroban word for {want}"));
            assert_eq!(got, Err(account_error(word)), "{name}: want {want}");
        }
        ran += 1;
    }

    assert!(ran > 0, "no install ran");
    assert_eq!(
        ran,
        v["counts"]["soroban"]["installs"].as_u64().unwrap(),
        "installs ran"
    );
}
