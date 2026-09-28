//! T-60, layer 2: `check_contract_call` against the shared policy fixture.
//!
//! Three implementations decide whether an agent's lock is allowed: this account, the EVM module,
//! and a TypeScript copy the relayer asks first. `../../../test-vectors/agent-policy-parity.json`
//! holds policy + lock → accept or reject, with every verdict written by hand, and all three read
//! it. A case carries exactly one fault, except the precedence cases, which pin the one order all three
//! share. A case this reader does not run names the reason in `skips`, and the reader asserts it.
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
    /// What `policy` means for a lock's signer here: the fixture's owner-named signer, the same
    /// one the EVM policy bytes carry (2.6 D9: it need not be the account).
    signer: BytesN<32>,
    /// The account's own id: what `maker: account` means for a lock's `ad_creator`.
    account_id: BytesN<32>,
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
    let signer = hex32(
        &env,
        vectors()["constants"]["evmSettlementSigner"]
            .as_str()
            .unwrap(),
    );
    let account_id = address_to_bytes32(&env, &account);

    Rig {
        env,
        client,
        account,
        pinned,
        unpinned,
        key,
        agent_id,
        signer,
        account_id,
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

/// One lock as the contract context the escrow's `require_auth` would hand the account.
fn context(r: &Rig, lock: &Value) -> Context {
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
        // The ad's maker: this account, or a stranger (02-agent-account.md §6 step 4).
        ad_creator: match lock["maker"].as_str().unwrap() {
            "account" => r.account_id.clone(),
            "other" => hex32(env, vectors()["constants"]["otherSigner"].as_str().unwrap()),
            other => panic!("maker: {other}"),
        },
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
    Context::Contract(ContractContext {
        contract: target,
        fn_name,
        args,
    })
}

/// One request, judged by `__check_auth` with the agent's signature: every lock is a context of the
/// same auth entry, which is what "one request" means on this chain.
fn judge(r: &Rig, locks: &[&Value]) -> Result<(), AccountError> {
    let env = &r.env;
    let mut contexts: Vec<Context> = Vec::new(env);
    for lock in locks {
        contexts.push_back(context(r, lock));
    }

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

/// A case this reader does not run has to say why, or it is a silent skip (C-41).
fn skip_reason(case: &Value) -> &str {
    case["skips"]["soroban"]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            panic!(
                "{}: not read here, and no reason says why",
                case["name"].as_str().unwrap()
            )
        })
}

#[test]
fn check_contract_call_matches_the_shared_policy_fixture() {
    let v = vectors();
    let (mut ran_cases, mut ran_steps, mut skipped) = (0u64, 0u64, 0u64);

    for case in v["cases"].as_array().unwrap() {
        if !reads(case) {
            skip_reason(case);
            skipped += 1;
            continue;
        }
        assert!(
            case["skips"].get("soroban").is_none(),
            "{}: read here and marked as not",
            case["name"].as_str().unwrap()
        );
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
            if step["op"] == "reinstall" {
                // The owner installs the same policy again: a fresh bucket for the agent, while the
                // account's ceiling keeps what was spent. Or, for a revoked id, a refusal.
                let got = install(&r, &case["policy"]);
                match step["expect"].as_str() {
                    None => assert_eq!(got, Ok(()), "{at}: did not reinstall"),
                    Some(want) => {
                        let word = v["installReasons"][want]["soroban"]
                            .as_str()
                            .unwrap_or_else(|| panic!("{at}: no Soroban word for {want}"));
                        assert_eq!(got, Err(account_error(word)), "{at}: want {want}");
                    }
                }
                continue;
            }
            if step["op"] == "setCeiling" {
                r.client.set_account_limit(
                    &hex32(&r.env, step["token"].as_str().unwrap()),
                    &Limit {
                        capacity: u128_of(&step["capacity"]),
                        refill_per_second: u128_of(&step["refillPerSecond"]),
                    },
                );
                continue;
            }
            if step["op"] == "dropCeiling" {
                // What an idle account's persistent entry archiving looks like to the account: the
                // row is simply not there (06-volume-buckets.md §5).
                let key = crate::policy::DataKey::AccountVolume(hex32(
                    &r.env,
                    step["token"].as_str().unwrap(),
                ));
                r.env.as_contract(&r.account, || {
                    assert!(
                        r.env.storage().persistent().has(&key),
                        "{at}: no row to drop"
                    );
                    r.env.storage().persistent().remove(&key);
                });
                continue;
            }
            let locks: std::vec::Vec<&Value> = match step["op"].as_str().unwrap() {
                "lock" => std::vec![&step["lock"]],
                // Soroban's error names no context, so `refusedAt` is the EVM reader's to check.
                "request" => step["locks"].as_array().unwrap().iter().collect(),
                other => panic!("{at}: an op this reader does not know: {other}"),
            };
            let got = judge(&r, &locks);
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
    assert_eq!(
        ran_cases + skipped,
        v["counts"]["total"]["cases"].as_u64().unwrap(),
        "every case run or skipped with a reason"
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
