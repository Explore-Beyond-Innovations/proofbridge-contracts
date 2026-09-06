//! Two paths:
//!   - `__check_auth` driven directly via `env.try_invoke_contract_check_auth`
//!     with contexts shaped exactly like the escrow's `lock_for_order` call;
//!   - the real path via `env.set_auths` + the escrow, which is the only way
//!     `require_auth` -> `__check_auth` is exercised end to end
//!     (`mock_auths` swaps in a no-op account, `mock_all_auths` never calls it).

#![cfg(test)]

extern crate std;

use super::*;
use ad_manager::OrderParams;
use ed25519_dalek::{Signer, SigningKey};
use proofbridge_core::eip712::address_to_bytes32;
use soroban_sdk::{
    auth::ContractContext,
    testutils::{Address as _, Events as _, Ledger as _, MockAuthContract},
    vec,
    xdr::{
        self, HashIdPreimage, HashIdPreimageSorobanAuthorization, InvokeContractArgs, Limits,
        ScAddress, ScBytes, ScSymbol, ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry,
        SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials, VecM, WriteXdr,
    },
    Address, Bytes, BytesN, Env, InvokeError, Map, String, Symbol, TryFromVal, Val, Vec,
};

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

const T0: u64 = 1_700_000_000;

fn b32(env: &Env, fill: u8) -> BytesN<32> {
    BytesN::from_array(env, &[fill; 32])
}

struct Agent {
    key: SigningKey,
}

impl Agent {
    fn new(seed: u8) -> Self {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        bytes[31] = 0x5a;
        Agent {
            key: SigningKey::from_bytes(&bytes),
        }
    }
    fn id(&self, env: &Env) -> AgentId {
        BytesN::from_array(env, &self.key.verifying_key().to_bytes())
    }
    fn sign(&self, env: &Env, payload: &BytesN<32>) -> AccountSig {
        let sig = self.key.sign(&payload.to_array()).to_bytes();
        AccountSig::Agent(Ed25519Sig {
            pubkey: self.id(env),
            sig: BytesN::from_array(env, &sig),
        })
    }
}

struct Fixture {
    env: Env,
    owner: Address,
    target: Address,
    account: Address,
    client: AgentAccountClient<'static>,
    agent: Agent,
    ad_token: BytesN<32>,
    order_token: BytesN<32>,
    signer: BytesN<32>,
}

fn lock_sym(env: &Env) -> Symbol {
    lock_for_order(env)
}

fn deploy(
    env: &Env,
    owner: &Address,
    targets: &Vec<Address>,
) -> (Address, AgentAccountClient<'static>) {
    let id = env.register(AgentAccount, (owner.clone(), targets.clone()));
    let client = AgentAccountClient::new(env, &id);
    (id, client)
}

/// Account + one pinned target + one installed agent policy (cap 1_000_000
/// ad units, both tokens listed, no expiry).
fn fixture() -> Fixture {
    let env = Env::default();
    env.ledger().set_timestamp(T0);
    env.mock_all_auths();

    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    let (account, client) = deploy(&env, &owner, &vec![&env, target.clone()]);

    let agent = Agent::new(7);
    let ad_token = b32(&env, 0xAA);
    let order_token = b32(&env, 0xBB);
    let signer = address_to_bytes32(&env, &account);
    client.set_policy(
        &agent.id(&env),
        &vec![&env, lock_sym(&env)],
        &vec![&env, ad_token.clone(), order_token.clone()],
        &1_000_000_u128,
        &0_u64,
        &signer,
    );

    Fixture {
        env,
        owner,
        target,
        account,
        client,
        agent,
        ad_token,
        order_token,
        signer,
    }
}

fn params(f: &Fixture) -> OrderParams {
    OrderParams {
        order_chain_token: f.order_token.clone(),
        ad_chain_token: f.ad_token.clone(),
        amount: 500_000,
        bridger: b32(&f.env, 0xDD),
        order_chain_id: 1,
        src_order_portal: b32(&f.env, 0xFF),
        order_recipient: b32(&f.env, 0xEE),
        ad_id: String::from_str(&f.env, "ad-1"),
        ad_creator: f.signer.clone(),
        ad_recipient: b32(&f.env, 0xCC),
        salt: 42,
        order_decimals: 7,
        ad_decimals: 7,
    }
}

/// The lock argument as the map the account decodes (what the escrow's
/// `OrderParams` encodes to on the wire).
fn lock_map(f: &Fixture) -> Map<Symbol, Val> {
    let v: Val = params(f).into_val(&f.env);
    Map::<Symbol, Val>::try_from_val(&f.env, &v).unwrap()
}

fn lock_ctx(env: &Env, target: &Address, args: Vec<Val>) -> Vec<Context> {
    vec![
        env,
        Context::Contract(ContractContext {
            contract: target.clone(),
            fn_name: lock_sym(env),
            args,
        }),
    ]
}

fn check(
    f: &Fixture,
    sig: AccountSig,
    ctxs: &Vec<Context>,
) -> Result<(), Result<AccountError, InvokeError>> {
    let payload = b32(&f.env, 0x01);
    f.env.try_invoke_contract_check_auth::<AccountError>(
        &f.account,
        &payload,
        sig.into_val(&f.env),
        ctxs,
    )
}

/// Sign a fixed payload with the fixture agent and run `__check_auth` on the
/// given contexts.
fn agent_check(f: &Fixture, ctxs: &Vec<Context>) -> Result<(), Result<AccountError, InvokeError>> {
    let payload = b32(&f.env, 0x01);
    let sig = f.agent.sign(&f.env, &payload);
    f.env.try_invoke_contract_check_auth::<AccountError>(
        &f.account,
        &payload,
        sig.into_val(&f.env),
        ctxs,
    )
}

fn expect_err(r: Result<(), Result<AccountError, InvokeError>>, e: AccountError) {
    assert_eq!(r, Err(Ok(e)));
}

/// Topics of the first / last event this contract emitted, as XDR.
fn event_topics(env: &Env, contract: &Address, last: bool) -> std::vec::Vec<ScVal> {
    let all = env.events().all().filter_by_contract(contract);
    let evs = all.events();
    let ev = if last { evs.last() } else { evs.first() }.unwrap().clone();
    match ev.body {
        xdr::ContractEventBody::V0(v0) => v0.topics.to_vec(),
    }
}

fn sym(s: &str) -> ScVal {
    ScVal::Symbol(ScSymbol(s.try_into().unwrap()))
}

fn bytes32(b: &BytesN<32>) -> ScVal {
    ScVal::Bytes(ScBytes(b.to_array().to_vec().try_into().unwrap()))
}

// ---------------------------------------------------------------------------
// owner-gated entry points
// ---------------------------------------------------------------------------

#[test]
fn constructor_pins_owner_and_targets() {
    let f = fixture();
    assert_eq!(f.client.owner(), f.owner);
    assert_eq!(f.client.targets(), vec![&f.env, f.target.clone()]);
}

#[test]
#[should_panic(expected = "Error(Contract, #13)")]
fn constructor_rejects_empty_targets() {
    let env = Env::default();
    let owner = Address::generate(&env);
    deploy(&env, &owner, &Vec::new(&env));
}

#[test]
#[should_panic(expected = "Error(Contract, #13)")]
fn constructor_rejects_three_targets() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let t = || Address::generate(&env);
    deploy(&env, &owner, &vec![&env, t(), t(), t()]);
}

/// F1: `owner == self` would make the owner path pass the host's direct-invoker
/// rule with no signature at all.
#[test]
#[should_panic(expected = "Error(Contract, #14)")]
fn constructor_rejects_self_as_owner() {
    let env = Env::default();
    let at = Address::generate(&env);
    let target = Address::generate(&env);
    env.register_at(&at, AgentAccount, (at.clone(), vec![&env, target]));
}

#[test]
#[should_panic(expected = "Error(Contract, #13)")]
fn constructor_rejects_self_as_target() {
    let env = Env::default();
    let at = Address::generate(&env);
    let owner = Address::generate(&env);
    env.register_at(&at, AgentAccount, (owner, vec![&env, at.clone()]));
}

#[test]
fn constructor_emits_targets_and_pins_schema_version() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    let (account, client) = deploy(&env, &owner, &vec![&env, target]);
    // events() holds the last invocation's events: read before any other call
    let topics = event_topics(&env, &account, false);
    assert_eq!(topics[0], sym("tgt_set"));
    assert_eq!(client.schema_version(), SCHEMA_VERSION);
}

#[test]
fn set_policy_stores_and_emits() {
    let f = fixture();
    let p = f.client.policy(&f.agent.id(&f.env)).unwrap();
    assert_eq!(p.max_per_order, 1_000_000);
    assert_eq!(p.settlement_signer, f.signer);
    assert!(!p.revoked);
    assert!(!f.client.is_revoked(&f.agent.id(&f.env)));
}

#[test]
fn non_owner_cannot_set_policy_revoke_or_set_targets() {
    let f = fixture();
    // Drop the blanket mock: nothing is authorized now.
    f.env.set_auths(&[]);
    let id = f.agent.id(&f.env);
    assert!(f
        .client
        .try_set_policy(
            &id,
            &vec![&f.env, lock_sym(&f.env)],
            &vec![&f.env, f.ad_token.clone()],
            &1_u128,
            &0_u64,
            &f.signer,
        )
        .is_err());
    assert!(f.client.try_revoke_agent(&id).is_err());
    assert!(f
        .client
        .try_set_targets(&vec![&f.env, f.target.clone()])
        .is_err());
    // Unchanged.
    assert_eq!(f.client.policy(&id).unwrap().max_per_order, 1_000_000);
}

/// T-03: a policy naming `register` (or any selector other than
/// lock_for_order) is rejected at install.
#[test]
fn set_policy_rejects_reserved_and_unknown_selectors() {
    let f = fixture();
    let id = b32(&f.env, 0x02);
    for bad in [
        "register",
        "revoke",
        "set_policy",
        "withdraw_from_ad",
        "close_ad",
    ] {
        let r = f.client.try_set_policy(
            &id,
            &vec![&f.env, lock_sym(&f.env), Symbol::new(&f.env, bad)],
            &vec![&f.env, f.ad_token.clone()],
            &1_u128,
            &0_u64,
            &f.signer,
        );
        assert_eq!(r, Err(Ok(AccountError::BadPolicy)), "{bad}");
    }
    assert!(f.client.policy(&id).is_none());
}

#[test]
fn set_policy_validates_lengths_and_zero_values() {
    let f = fixture();
    let id = b32(&f.env, 0x03);
    let ok_actions = vec![&f.env, lock_sym(&f.env)];
    let ok_tokens = vec![&f.env, f.ad_token.clone()];

    // empty actions / 5 actions
    let r = f
        .client
        .try_set_policy(&id, &Vec::new(&f.env), &ok_tokens, &1, &0, &f.signer);
    assert_eq!(r, Err(Ok(AccountError::BadPolicy)));
    let mut five = Vec::new(&f.env);
    for _ in 0..5 {
        five.push_back(lock_sym(&f.env));
    }
    let r = f
        .client
        .try_set_policy(&id, &five, &ok_tokens, &1, &0, &f.signer);
    assert_eq!(r, Err(Ok(AccountError::BadPolicy)));

    // empty tokens / 17 tokens / zero token
    let r = f
        .client
        .try_set_policy(&id, &ok_actions, &Vec::new(&f.env), &1, &0, &f.signer);
    assert_eq!(r, Err(Ok(AccountError::BadPolicy)));
    let mut seventeen = Vec::new(&f.env);
    for i in 1..=17u8 {
        seventeen.push_back(b32(&f.env, i));
    }
    let r = f
        .client
        .try_set_policy(&id, &ok_actions, &seventeen, &1, &0, &f.signer);
    assert_eq!(r, Err(Ok(AccountError::BadPolicy)));
    let r = f.client.try_set_policy(
        &id,
        &ok_actions,
        &vec![&f.env, b32(&f.env, 0)],
        &1,
        &0,
        &f.signer,
    );
    assert_eq!(r, Err(Ok(AccountError::BadPolicy)));

    // zero cap / zero signer / expiry in the past
    let r = f
        .client
        .try_set_policy(&id, &ok_actions, &ok_tokens, &0, &0, &f.signer);
    assert_eq!(r, Err(Ok(AccountError::BadPolicy)));
    let r = f
        .client
        .try_set_policy(&id, &ok_actions, &ok_tokens, &1, &0, &b32(&f.env, 0));
    assert_eq!(r, Err(Ok(AccountError::BadPolicy)));
    let r = f
        .client
        .try_set_policy(&id, &ok_actions, &ok_tokens, &1, &T0, &f.signer);
    assert_eq!(r, Err(Ok(AccountError::BadPolicy)));
    // foreign settlement signer (F5: until 2.3b only this account may be named)
    let r = f
        .client
        .try_set_policy(&id, &ok_actions, &ok_tokens, &1, &0, &b32(&f.env, 0x77));
    assert_eq!(r, Err(Ok(AccountError::BadPolicy)));
    // duplicate selector
    let dup = vec![&f.env, lock_sym(&f.env), lock_sym(&f.env)];
    let r = f
        .client
        .try_set_policy(&id, &dup, &ok_tokens, &1, &0, &f.signer);
    assert_eq!(r, Err(Ok(AccountError::BadPolicy)));
    // and the boundary that is fine
    f.client
        .set_policy(&id, &ok_actions, &ok_tokens, &1, &(T0 + 1), &f.signer);
}

#[test]
fn set_targets_replaces_and_bounds() {
    let f = fixture();
    let a = Address::generate(&f.env);
    let b = Address::generate(&f.env);
    f.client.set_targets(&vec![&f.env, a.clone(), b.clone()]);
    assert_eq!(f.client.targets(), vec![&f.env, a.clone(), b.clone()]);
    assert_eq!(
        f.client.try_set_targets(&Vec::new(&f.env)),
        Err(Ok(AccountError::BadTargets))
    );
    let c = Address::generate(&f.env);
    assert_eq!(
        f.client.try_set_targets(&vec![&f.env, a.clone(), b, c]),
        Err(Ok(AccountError::BadTargets))
    );
    // never the account itself (F1)
    assert_eq!(
        f.client
            .try_set_targets(&vec![&f.env, a, f.account.clone()]),
        Err(Ok(AccountError::BadTargets))
    );
}

/// Only the owner may replace the code; the wasm hash is validated by the host.
#[test]
fn upgrade_is_owner_only() {
    let f = fixture();
    f.env.set_auths(&[]);
    assert!(f.client.try_upgrade(&b32(&f.env, 0x42)).is_err());
    assert_eq!(f.client.schema_version(), SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// agent path: check_contract_call
// ---------------------------------------------------------------------------

#[test]
fn in_policy_lock_authorizes() {
    let f = fixture();
    let p = params(&f);
    let ctxs = lock_ctx(&f.env, &f.target, vec![&f.env, p.into_val(&f.env)]);
    agent_check(&f, &ctxs).unwrap();
}

#[test]
fn cap_exceeded_rejected_in_ad_units() {
    let f = fixture();
    let mut p = params(&f);
    // 1_000_001 in ad units is over the cap.
    p.amount = 1_000_001;
    expect_err(
        agent_check(
            &f,
            &lock_ctx(&f.env, &f.target, vec![&f.env, p.into_val(&f.env)]),
        ),
        AccountError::CapExceeded,
    );

    // The cap is in ad units: 100_000_000 at 9 order decimals is exactly
    // 1_000_000 at 7 ad decimals (passes); 100 more order units is over.
    let mut p = params(&f);
    p.amount = 100_000_000;
    p.order_decimals = 9;
    agent_check(
        &f,
        &lock_ctx(&f.env, &f.target, vec![&f.env, p.into_val(&f.env)]),
    )
    .unwrap();
    let mut p = params(&f);
    p.amount = 100_000_100;
    p.order_decimals = 9;
    expect_err(
        agent_check(
            &f,
            &lock_ctx(&f.env, &f.target, vec![&f.env, p.into_val(&f.env)]),
        ),
        AccountError::CapExceeded,
    );

    // Exactly the cap passes.
    let mut p = params(&f);
    p.amount = 1_000_000;
    agent_check(
        &f,
        &lock_ctx(&f.env, &f.target, vec![&f.env, p.into_val(&f.env)]),
    )
    .unwrap();
}

#[test]
fn token_not_whitelisted_rejected_on_either_side() {
    let f = fixture();
    let mut p = params(&f);
    p.ad_chain_token = b32(&f.env, 0x99);
    expect_err(
        agent_check(
            &f,
            &lock_ctx(&f.env, &f.target, vec![&f.env, p.into_val(&f.env)]),
        ),
        AccountError::TokenNotAllowed,
    );
    let mut p = params(&f);
    p.order_chain_token = b32(&f.env, 0x99);
    expect_err(
        agent_check(
            &f,
            &lock_ctx(&f.env, &f.target, vec![&f.env, p.into_val(&f.env)]),
        ),
        AccountError::TokenNotAllowed,
    );
}

#[test]
fn expired_policy_rejected_at_boundary() {
    let f = fixture();
    let id = f.agent.id(&f.env);
    f.client.set_policy(
        &id,
        &vec![&f.env, lock_sym(&f.env)],
        &vec![&f.env, f.ad_token.clone(), f.order_token.clone()],
        &1_000_000,
        &(T0 + 100),
        &f.signer,
    );
    let ctxs = lock_ctx(&f.env, &f.target, vec![&f.env, params(&f).into_val(&f.env)]);

    f.env.ledger().set_timestamp(T0 + 99);
    agent_check(&f, &ctxs).unwrap();
    f.env.ledger().set_timestamp(T0 + 100);
    expect_err(agent_check(&f, &ctxs), AccountError::PolicyExpired);
}

/// T-05, account half: revoke -> next signed call fails; sticky; idempotent.
#[test]
fn revoked_agent_rejected_and_revocation_is_sticky() {
    let f = fixture();
    let id = f.agent.id(&f.env);
    let ctxs = lock_ctx(&f.env, &f.target, vec![&f.env, params(&f).into_val(&f.env)]);
    agent_check(&f, &ctxs).unwrap();

    f.client.revoke_agent(&id);
    // the event 2.1e consumes: topics ["agent_rev", agent_id]
    let topics = event_topics(&f.env, &f.account, true);
    assert_eq!(topics[0], sym("agent_rev"));
    assert_eq!(topics[1], bytes32(&id));
    assert!(f.client.is_revoked(&id));
    assert!(f.client.policy(&id).unwrap().revoked);
    expect_err(agent_check(&f, &ctxs), AccountError::AgentRevoked);

    // Idempotent.
    f.client.revoke_agent(&id);
    assert!(f.client.is_revoked(&id));

    // Re-install is refused; the key stays dead.
    let r = f.client.try_set_policy(
        &id,
        &vec![&f.env, lock_sym(&f.env)],
        &vec![&f.env, f.ad_token.clone()],
        &1,
        &0,
        &f.signer,
    );
    assert_eq!(r, Err(Ok(AccountError::AgentRevoked)));
    expect_err(agent_check(&f, &ctxs), AccountError::AgentRevoked);

    // A never-installed id cannot be revoked, and is not "revoked".
    assert_eq!(
        f.client.try_revoke_agent(&b32(&f.env, 0x55)),
        Err(Ok(AccountError::NoPolicyForAgent))
    );
    assert!(!f.client.is_revoked(&b32(&f.env, 0x55)));
}

/// D5 via the transitional `ad_creator` field (2.3b swaps it for
/// `ad_settlement_signer`).
#[test]
fn settlement_signer_mismatch_rejected_ad_creator_until_2_3b() {
    let f = fixture();
    let mut p = params(&f);
    p.ad_creator = b32(&f.env, 0x78);
    expect_err(
        agent_check(
            &f,
            &lock_ctx(&f.env, &f.target, vec![&f.env, p.into_val(&f.env)]),
        ),
        AccountError::SettlementSignerMismatch,
    );
}

#[test]
fn wrong_target_rejected() {
    let f = fixture();
    let other = Address::generate(&f.env);
    expect_err(
        agent_check(
            &f,
            &lock_ctx(&f.env, &other, vec![&f.env, params(&f).into_val(&f.env)]),
        ),
        AccountError::TargetNotAllowed,
    );
}

#[test]
fn wrong_selector_rejected() {
    let f = fixture();
    let ctxs = vec![
        &f.env,
        Context::Contract(ContractContext {
            contract: f.target.clone(),
            fn_name: Symbol::new(&f.env, "withdraw_from_ad"),
            args: vec![&f.env],
        }),
    ];
    expect_err(agent_check(&f, &ctxs), AccountError::ActionNotAllowed);
}

#[test]
fn bad_args_fail_closed() {
    let f = fixture();
    // no args
    expect_err(
        agent_check(&f, &lock_ctx(&f.env, &f.target, vec![&f.env])),
        AccountError::BadArgs,
    );
    // two args
    let p = params(&f);
    expect_err(
        agent_check(
            &f,
            &lock_ctx(
                &f.env,
                &f.target,
                vec![&f.env, p.clone().into_val(&f.env), 1u32.into_val(&f.env)],
            ),
        ),
        AccountError::BadArgs,
    );
    // wrong type
    expect_err(
        agent_check(
            &f,
            &lock_ctx(&f.env, &f.target, vec![&f.env, 7u32.into_val(&f.env)]),
        ),
        AccountError::BadArgs,
    );
    // decimals out of range
    let mut p = params(&f);
    p.ad_decimals = 31;
    expect_err(
        agent_check(
            &f,
            &lock_ctx(&f.env, &f.target, vec![&f.env, p.into_val(&f.env)]),
        ),
        AccountError::BadArgs,
    );
    // a required key missing
    let mut m = lock_map(&f);
    m.remove(Symbol::new(&f.env, "amount"));
    expect_err(
        agent_check(
            &f,
            &lock_ctx(&f.env, &f.target, vec![&f.env, m.into_val(&f.env)]),
        ),
        AccountError::BadArgs,
    );
    // a required key of the wrong type
    let mut m = lock_map(&f);
    m.set(Symbol::new(&f.env, "amount"), 7u32.into_val(&f.env));
    expect_err(
        agent_check(
            &f,
            &lock_ctx(&f.env, &f.target, vec![&f.env, m.into_val(&f.env)]),
        ),
        AccountError::BadArgs,
    );
}

/// F4a: the decoder reads only the keys the policy needs, so the 2.3b
/// 17-field order (or any wider shape) passes unchanged.
#[test]
fn wider_order_shape_decodes() {
    let f = fixture();
    let mut m = lock_map(&f);
    for k in ["ad_settlement_signer", "deadline", "extra_a", "extra_b"] {
        m.set(Symbol::new(&f.env, k), b32(&f.env, 0x33).into_val(&f.env));
    }
    assert_eq!(m.len(), 17);
    agent_check(
        &f,
        &lock_ctx(&f.env, &f.target, vec![&f.env, m.into_val(&f.env)]),
    )
    .unwrap();
}

#[test]
fn non_contract_and_empty_contexts_rejected_on_agent_path() {
    let f = fixture();
    expect_err(
        agent_check(&f, &Vec::new(&f.env)),
        AccountError::UnsupportedContext,
    );
    let ctxs = vec![
        &f.env,
        Context::CreateContractHostFn(soroban_sdk::auth::CreateContractHostFnContext {
            executable: soroban_sdk::auth::ContractExecutable::Wasm(b32(&f.env, 0x10)),
            salt: b32(&f.env, 0x11),
        }),
    ];
    expect_err(agent_check(&f, &ctxs), AccountError::UnsupportedContext);
}

#[test]
fn every_context_must_pass() {
    let f = fixture();
    let good = params(&f);
    let mut bad = params(&f);
    bad.amount = 1_000_001;
    let ctxs = vec![
        &f.env,
        Context::Contract(ContractContext {
            contract: f.target.clone(),
            fn_name: lock_sym(&f.env),
            args: vec![&f.env, good.into_val(&f.env)],
        }),
        Context::Contract(ContractContext {
            contract: f.target.clone(),
            fn_name: lock_sym(&f.env),
            args: vec![&f.env, bad.into_val(&f.env)],
        }),
    ];
    expect_err(agent_check(&f, &ctxs), AccountError::CapExceeded);
}

#[test]
fn unknown_agent_and_bad_signature_rejected() {
    let f = fixture();
    let ctxs = lock_ctx(&f.env, &f.target, vec![&f.env, params(&f).into_val(&f.env)]);
    // Signed by a key with no policy.
    let stranger = Agent::new(9);
    let payload = b32(&f.env, 0x01);
    let r = f.env.try_invoke_contract_check_auth::<AccountError>(
        &f.account,
        &payload,
        stranger.sign(&f.env, &payload).into_val(&f.env),
        &ctxs,
    );
    expect_err(r, AccountError::NoPolicyForAgent);
    // Right pubkey, wrong signature: the host traps ed25519_verify -> an
    // InvokeError, never Ok.
    let forged = AccountSig::Agent(Ed25519Sig {
        pubkey: f.agent.id(&f.env),
        sig: BytesN::from_array(&f.env, &[3u8; 64]),
    });
    assert!(check(&f, forged, &ctxs).is_err());
}

// ---------------------------------------------------------------------------
// agent path: secp256k1 agent
// ---------------------------------------------------------------------------

struct SecpAgent {
    key: k256::ecdsa::SigningKey,
}

impl SecpAgent {
    fn new(seed: u8) -> Self {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        bytes[31] = 0x3c;
        SecpAgent {
            key: k256::ecdsa::SigningKey::from_bytes((&bytes).into()).unwrap(),
        }
    }
    /// EVM address left-padded to 32.
    fn id(&self, env: &Env) -> AgentId {
        let pk = self.key.verifying_key().to_encoded_point(false);
        let hash = env
            .crypto()
            .keccak256(&Bytes::from_slice(env, &pk.as_bytes()[1..]))
            .to_array();
        let mut id = [0u8; 32];
        id[12..].copy_from_slice(&hash[12..]);
        BytesN::from_array(env, &id)
    }
    fn sign_with(&self, env: &Env, payload: &BytesN<32>, eth_style: bool) -> AccountSig {
        let (sig, rid) = self
            .key
            .sign_prehash_recoverable(&payload.to_array())
            .unwrap();
        let v = rid.to_byte() as u32;
        AccountSig::AgentSecp(SecpSig {
            sig: BytesN::from_array(env, &sig.to_bytes().into()),
            recovery_id: if eth_style { v + 27 } else { v },
        })
    }
    fn sign(&self, env: &Env, payload: &BytesN<32>) -> AccountSig {
        self.sign_with(env, payload, true)
    }
}

#[test]
fn secp256k1_agent_authorizes_and_wrong_signer_has_no_policy() {
    let f = fixture();
    let secp = SecpAgent::new(4);
    f.client.set_policy(
        &secp.id(&f.env),
        &vec![&f.env, lock_sym(&f.env)],
        &vec![&f.env, f.ad_token.clone(), f.order_token.clone()],
        &1_000_000,
        &0,
        &f.signer,
    );
    let ctxs = lock_ctx(&f.env, &f.target, vec![&f.env, params(&f).into_val(&f.env)]);
    let payload = b32(&f.env, 0x01);
    f.env
        .try_invoke_contract_check_auth::<AccountError>(
            &f.account,
            &payload,
            secp.sign(&f.env, &payload).into_val(&f.env),
            &ctxs,
        )
        .unwrap();

    // raw 0/1 recovery id is accepted too
    f.env
        .try_invoke_contract_check_auth::<AccountError>(
            &f.account,
            &payload,
            secp.sign_with(&f.env, &payload, false).into_val(&f.env),
            &ctxs,
        )
        .unwrap();
    // the id is the left-padded EVM address
    assert_eq!(secp.id(&f.env).to_array()[..12], [0u8; 12]);

    let other = SecpAgent::new(5);
    let r = f.env.try_invoke_contract_check_auth::<AccountError>(
        &f.account,
        &payload,
        other.sign(&f.env, &payload).into_val(&f.env),
        &ctxs,
    );
    expect_err(r, AccountError::NoPolicyForAgent);

    let bad_v = AccountSig::AgentSecp(SecpSig {
        sig: BytesN::from_array(&f.env, &[1u8; 64]),
        recovery_id: 5,
    });
    expect_err(check(&f, bad_v, &ctxs), AccountError::BadSignature);
}

// ---------------------------------------------------------------------------
// owner path (direct)
// ---------------------------------------------------------------------------

#[test]
fn owner_path_accepts_any_context_including_token_transfer() {
    let f = fixture();
    let token = Address::generate(&f.env);
    let ctxs = vec![
        &f.env,
        Context::Contract(ContractContext {
            contract: f.target.clone(),
            fn_name: Symbol::new(&f.env, "create_ad"),
            args: vec![&f.env],
        }),
        Context::Contract(ContractContext {
            contract: token,
            fn_name: Symbol::new(&f.env, "transfer"),
            args: vec![&f.env],
        }),
    ];
    // mock_all_auths satisfies the nested owner.require_auth_for_args.
    check(&f, AccountSig::Owner, &ctxs).unwrap();
    // Owner sig without owner authorization: rejected.
    f.env.set_auths(&[]);
    assert!(check(&f, AccountSig::Owner, &ctxs).is_err());
}

// ---------------------------------------------------------------------------
// real auth path against the escrow
// ---------------------------------------------------------------------------

struct Escrow {
    env: Env,
    owner: Address,
    account: Address,
    ad_manager: Address,
    ad_token: BytesN<32>,
    order_token: BytesN<32>,
    portal: BytesN<32>,
    order_chain_id: u128,
    ad_id: String,
    agent: Agent,
}

/// AdManager + MerkleManager + a test token, the account as the ad's maker,
/// one ad funded under mock_all_auths.
fn escrow_fixture() -> Escrow {
    let env = Env::default();
    env.ledger().set_timestamp(T0);
    env.mock_all_auths();
    env.cost_estimate().budget().reset_unlimited();

    let admin = Address::generate(&env);
    let owner = env.register(MockAuthContract, ());
    let ad_manager = env.register(ad_manager::AdManagerContract, ());
    let merkle = env.register(merkle_manager::ProofBridgeMerkleManagerContract, ());
    let token = env.register(
        test_token::TokenContract,
        (
            admin.clone(),
            0_i128,
            7_u32,
            String::from_str(&env, "Test"),
            String::from_str(&env, "TST"),
        ),
    );

    let (account, client) = deploy(&env, &owner, &vec![&env, ad_manager.clone()]);

    let ad_token = address_to_bytes32(&env, &token);
    let order_token = b32(&env, 0xBB);
    let portal = b32(&env, 0xFF);
    let order_chain_id: u128 = 1;

    merkle_manager::ProofBridgeMerkleManagerContractClient::new(&env, &merkle).initialize(&admin);
    merkle_manager::ProofBridgeMerkleManagerContractClient::new(&env, &merkle)
        .set_manager(&ad_manager, &true);

    let am = ad_manager::AdManagerContractClient::new(&env, &ad_manager);
    am.initialize(
        &admin,
        &Address::generate(&env),
        &merkle,
        &Address::generate(&env),
        &2_000_000_002_u128,
    );
    am.set_chain(&order_chain_id, &portal, &true);
    am.set_token_route(&ad_token, &order_token, &order_chain_id);

    test_token::TokenContractClient::new(&env, &token).mint(&account, &10_000_000_i128);
    let ad_id = String::from_str(&env, "ad-1");
    am.create_ad(
        &account,
        &ad_id,
        &ad_token,
        &5_000_000_u128,
        &order_chain_id,
        &b32(&env, 0xCC),
    );

    let agent = Agent::new(7);
    let signer = address_to_bytes32(&env, &account);
    client.set_policy(
        &agent.id(&env),
        &vec![&env, lock_sym(&env)],
        &vec![&env, ad_token.clone(), order_token.clone()],
        &1_000_000_u128,
        &0_u64,
        &signer,
    );

    Escrow {
        env,
        owner,
        account,
        ad_manager,
        ad_token,
        order_token,
        portal,
        order_chain_id,
        ad_id,
        agent,
    }
}

fn escrow_params(e: &Escrow, amount: u128) -> OrderParams {
    OrderParams {
        order_chain_token: e.order_token.clone(),
        ad_chain_token: e.ad_token.clone(),
        amount,
        bridger: b32(&e.env, 0xDD),
        order_chain_id: e.order_chain_id,
        src_order_portal: e.portal.clone(),
        order_recipient: b32(&e.env, 0x11),
        ad_id: e.ad_id.clone(),
        ad_creator: address_to_bytes32(&e.env, &e.account),
        ad_recipient: b32(&e.env, 0xCC),
        salt: 42,
        order_decimals: 7,
        ad_decimals: 7,
    }
}

fn sc_val(env: &Env, v: Val) -> ScVal {
    ScVal::try_from_val(env, &v).unwrap()
}

fn sc_addr(a: &Address) -> ScAddress {
    a.try_into().unwrap()
}

fn invocation(
    contract: &Address,
    fn_name: &str,
    args: std::vec::Vec<ScVal>,
) -> SorobanAuthorizedInvocation {
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: sc_addr(contract),
            function_name: fn_name.try_into().unwrap(),
            args: args.try_into().unwrap(),
        }),
        sub_invocations: VecM::default(),
    }
}

/// sha256 of the HashIdPreimage::SorobanAuthorization XDR: what the host
/// hands `__check_auth` as `signature_payload`.
fn payload_hash(env: &Env, inv: &SorobanAuthorizedInvocation, nonce: i64, exp: u32) -> BytesN<32> {
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: xdr::Hash(env.ledger().network_id().to_array()),
        nonce,
        signature_expiration_ledger: exp,
        invocation: inv.clone(),
    });
    let bytes = preimage.to_xdr(Limits::none()).unwrap();
    env.crypto()
        .sha256(&Bytes::from_slice(env, &bytes))
        .to_bytes()
}

fn entry(
    address: &Address,
    inv: SorobanAuthorizedInvocation,
    nonce: i64,
    exp: u32,
    signature: ScVal,
) -> SorobanAuthorizationEntry {
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: sc_addr(address),
            nonce,
            signature_expiration_ledger: exp,
            signature,
        }),
        root_invocation: inv,
    }
}

fn liquidity(e: &Escrow) -> u128 {
    e.env.invoke_contract(
        &e.ad_manager,
        &Symbol::new(&e.env, "available_liquidity"),
        vec![&e.env, e.ad_id.clone().into_val(&e.env)],
    )
}

/// The real thing: `lock_for_order` -> `ad.maker.require_auth()` -> this
/// account's `__check_auth` with the agent's signature over the host-derived
/// payload. Over the cap it fails at auth with no state change.
#[test]
fn e2e_agent_lock_via_require_auth() {
    let e = escrow_fixture();
    assert_eq!(liquidity(&e), 5_000_000);
    let exp = e.env.ledger().sequence() + 100;

    // In policy.
    let p = escrow_params(&e, 400_000);
    let p_val: Val = p.into_val(&e.env);
    let inv = invocation(
        &e.ad_manager,
        "lock_for_order",
        std::vec![sc_val(&e.env, p_val)],
    );
    let payload = payload_hash(&e.env, &inv, 1, exp);
    let sig = sc_val(&e.env, e.agent.sign(&e.env, &payload).into_val(&e.env));
    e.env.set_auths(&[entry(&e.account, inv, 1, exp, sig)]);
    let _hash: BytesN<32> = e.env.invoke_contract(
        &e.ad_manager,
        &Symbol::new(&e.env, "lock_for_order"),
        vec![&e.env, p_val],
    );
    assert_eq!(liquidity(&e), 4_600_000);

    // Over the cap: the auth entry is well-formed and signed, the policy says no.
    let mut p = escrow_params(&e, 1_000_001);
    p.salt = 43;
    let p_val: Val = p.into_val(&e.env);
    let inv = invocation(
        &e.ad_manager,
        "lock_for_order",
        std::vec![sc_val(&e.env, p_val)],
    );
    let payload = payload_hash(&e.env, &inv, 2, exp);
    let sig = sc_val(&e.env, e.agent.sign(&e.env, &payload).into_val(&e.env));
    e.env.set_auths(&[entry(&e.account, inv, 2, exp, sig)]);
    let r = e.env.try_invoke_contract::<BytesN<32>, soroban_sdk::Error>(
        &e.ad_manager,
        &Symbol::new(&e.env, "lock_for_order"),
        vec![&e.env, p_val],
    );
    assert!(r.is_err());
    assert_eq!(liquidity(&e), 4_600_000);
}

/// Owner path end to end: the account authorizes `withdraw_from_ad` with
/// `AccountSig::Owner`, and the (contract) owner authorizes
/// `account.__check_auth(payload)` in a second entry.
#[test]
fn e2e_owner_withdraw_via_nested_require_auth() {
    let e = escrow_fixture();
    let exp = e.env.ledger().sequence() + 100;
    let to = Address::generate(&e.env);

    let inv = invocation(
        &e.ad_manager,
        "withdraw_from_ad",
        std::vec![
            sc_val(&e.env, e.ad_id.clone().into_val(&e.env)),
            sc_val(&e.env, 1_000_000_u128.into_val(&e.env)),
            sc_val(&e.env, to.clone().into_val(&e.env)),
        ],
    );
    let payload = payload_hash(&e.env, &inv, 7, exp);
    let owner_inv = invocation(
        &e.account,
        "__check_auth",
        std::vec![ScVal::Bytes(ScBytes(
            payload.to_array().to_vec().try_into().unwrap()
        ))],
    );
    e.env.set_auths(&[
        entry(
            &e.account,
            inv,
            7,
            exp,
            sc_val(&e.env, AccountSig::Owner.into_val(&e.env)),
        ),
        // MockAuthContract accepts any signature; Void keeps the entry minimal.
        entry(&e.owner, owner_inv, 8, exp, ScVal::Void),
    ]);
    let _: () = e.env.invoke_contract(
        &e.ad_manager,
        &Symbol::new(&e.env, "withdraw_from_ad"),
        vec![
            &e.env,
            e.ad_id.clone().into_val(&e.env),
            1_000_000_u128.into_val(&e.env),
            to.into_val(&e.env),
        ],
    );
    assert_eq!(liquidity(&e), 4_000_000);

    // Same call with only the account entry (no owner authorization) fails.
    let inv = invocation(
        &e.ad_manager,
        "withdraw_from_ad",
        std::vec![
            sc_val(&e.env, e.ad_id.clone().into_val(&e.env)),
            sc_val(&e.env, 1_000_000_u128.into_val(&e.env)),
            sc_val(&e.env, Address::generate(&e.env).into_val(&e.env)),
        ],
    );
    e.env.set_auths(&[entry(
        &e.account,
        inv,
        9,
        exp,
        sc_val(&e.env, AccountSig::Owner.into_val(&e.env)),
    )]);
    let r = e.env.try_invoke_contract::<(), soroban_sdk::Error>(
        &e.ad_manager,
        &Symbol::new(&e.env, "withdraw_from_ad"),
        vec![
            &e.env,
            e.ad_id.clone().into_val(&e.env),
            1_000_000_u128.into_val(&e.env),
            Address::generate(&e.env).into_val(&e.env),
        ],
    );
    assert!(r.is_err());
    assert_eq!(liquidity(&e), 4_000_000);
}
