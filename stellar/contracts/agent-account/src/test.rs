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
    auth::{
        ContractContext, CreateContractHostFnContext, CreateContractWithConstructorHostFnContext,
    },
    testutils::{Address as _, Events as _, Ledger as _, MockAuthContract},
    vec,
    xdr::{
        self, HashIdPreimage, HashIdPreimageSorobanAuthorization,
        HashIdPreimageSorobanAuthorizationWithAddress, InvokeContractArgs, Limits, ScAddress,
        ScBytes, ScSymbol, ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry,
        SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials, VecM, WriteXdr,
    },
    Address, Bytes, BytesN, ContractExecutable, ContractExecutableRef, Env, InvokeError, Map,
    String, Symbol, TryFromVal, Val, Vec,
};

/// Protocol 28 (testnet since 2026-08-27, mainnet vote 2026-09-16): the
/// fixtures pin it so CAP-85 executables and AddressV2 credentials are real.
const PROTOCOL: u32 = 28;

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
/// Volume limits wide enough that a test which is not about volume never trips them. Volume has
/// its own tests; everything else should keep testing what it was written to test.
fn wide(env: &Env, tokens: &Vec<BytesN<32>>) -> Vec<TokenLimit> {
    let mut v = Vec::new(env);
    for t in tokens.iter() {
        v.push_back(tl(&t, u128::MAX / 2, u128::MAX / 2, 1));
    }
    v
}

/// One row: a token, the size cap for it, and its refill rate.
fn tl(
    token: &BytesN<32>,
    max_per_order: u128,
    capacity: u128,
    refill_per_second: u128,
) -> TokenLimit {
    TokenLimit {
        token: token.clone(),
        max_per_order,
        rate: Limit {
            capacity,
            refill_per_second,
        },
    }
}

fn fixture() -> Fixture {
    let env = Env::default();
    env.ledger().set_timestamp(T0);
    env.mock_all_auths();
    env.ledger().set_protocol_version(PROTOCOL);

    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    let (account, client) = deploy(&env, &owner, &vec![&env, target.clone()]);

    let agent = Agent::new(7);
    let ad_token = b32(&env, 0xAA);
    let order_token = b32(&env, 0xBB);
    let signer = address_to_bytes32(&env, &account);
    let tokens = vec![&env, ad_token.clone(), order_token.clone()];
    // Ceilings first: `validate` refuses a policy naming a token the account has no limit for, so
    // that a broken ordering is an install-time answer rather than an agent that cannot work.
    for t in tokens.iter() {
        client.set_account_limit(
            &t,
            &Limit {
                capacity: u128::MAX / 2,
                refill_per_second: 1,
            },
        );
    }
    // Wide rate, real size cap: the fixture's cap tests are about `max_per_order`, so it has to be
    // a number a lock can actually exceed.
    let mut limits = Vec::new(&env);
    for t in tokens.iter() {
        limits.push_back(tl(&t, 1_000_000, u128::MAX / 2, 1));
    }
    client.set_policy(
        &agent.id(&env),
        &vec![&env, lock_for_order(&env)],
        &tokens,
        &0_u64,
        &signer,
        &None,
        &limits,
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
        salt: soroban_sdk::U256::from_u128(&f.env, 42),
        order_decimals: 7,
        ad_decimals: 7,
        deadline: 4_102_444_800,
        ad_settlement_signer: f.signer.clone(),
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
            fn_name: lock_for_order(env),
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
    assert_eq!(
        policy::limit_for(&p, &f.ad_token).unwrap().max_per_order,
        1_000_000
    );
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
            &vec![&f.env, lock_for_order(&f.env)],
            &vec![&f.env, f.ad_token.clone()],
            &0_u64,
            &f.signer,
            &None,
            &wide(&f.env, &vec![&f.env, f.ad_token.clone()])
        )
        .is_err());
    assert!(f.client.try_revoke_agent(&id).is_err());
    assert!(f
        .client
        .try_set_targets(&vec![&f.env, f.target.clone()])
        .is_err());
    // Unchanged.
    assert_eq!(
        policy::limit_for(&f.client.policy(&id).unwrap(), &f.ad_token)
            .unwrap()
            .max_per_order,
        1_000_000
    );
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
            &vec![&f.env, lock_for_order(&f.env), Symbol::new(&f.env, bad)],
            &vec![&f.env, f.ad_token.clone()],
            &0_u64,
            &f.signer,
            &None,
            &wide(&f.env, &vec![&f.env, f.ad_token.clone()]),
        );
        assert_eq!(r, Err(Ok(AccountError::BadPolicy)), "{bad}");
    }
    assert!(f.client.policy(&id).is_none());
}

#[test]
fn set_policy_validates_lengths_and_zero_values() {
    let f = fixture();
    let id = b32(&f.env, 0x03);
    let ok_actions = vec![&f.env, lock_for_order(&f.env)];
    let ok_tokens = vec![&f.env, f.ad_token.clone()];

    // empty actions / 5 actions
    let r = f.client.try_set_policy(
        &id,
        &Vec::new(&f.env),
        &ok_tokens,
        &0,
        &f.signer,
        &None,
        &wide(&f.env, &ok_tokens),
    );
    assert_eq!(r, Err(Ok(AccountError::BadPolicy)));
    let mut five = Vec::new(&f.env);
    for _ in 0..5 {
        five.push_back(lock_for_order(&f.env));
    }
    let r = f.client.try_set_policy(
        &id,
        &five,
        &ok_tokens,
        &0,
        &f.signer,
        &None,
        &wide(&f.env, &ok_tokens),
    );
    assert_eq!(r, Err(Ok(AccountError::BadPolicy)));

    // empty tokens / 17 tokens / zero token
    let r = f.client.try_set_policy(
        &id,
        &ok_actions,
        &Vec::new(&f.env),
        &0,
        &f.signer,
        &None,
        &Vec::new(&f.env),
    );
    assert_eq!(r, Err(Ok(AccountError::BadPolicy)));
    let mut seventeen = Vec::new(&f.env);
    for i in 1..=17u8 {
        seventeen.push_back(b32(&f.env, i));
    }
    let r = f.client.try_set_policy(
        &id,
        &ok_actions,
        &seventeen,
        &0,
        &f.signer,
        &None,
        &wide(&f.env, &seventeen),
    );
    assert_eq!(r, Err(Ok(AccountError::BadPolicy)));
    let r = f.client.try_set_policy(
        &id,
        &ok_actions,
        &vec![&f.env, b32(&f.env, 0)],
        &0,
        &f.signer,
        &None,
        &wide(&f.env, &vec![&f.env, b32(&f.env, 0)]),
    );
    assert_eq!(r, Err(Ok(AccountError::BadPolicy)));

    // zero signer / expiry in the past. The zero per-order cap moved to the per-token row and is
    // covered by `every_whitelisted_token_must_carry_a_limit`.
    let r = f.client.try_set_policy(
        &id,
        &ok_actions,
        &ok_tokens,
        &0,
        &b32(&f.env, 0),
        &None,
        &wide(&f.env, &ok_tokens),
    );
    assert_eq!(r, Err(Ok(AccountError::BadPolicy)));
    let r = f.client.try_set_policy(
        &id,
        &ok_actions,
        &ok_tokens,
        &T0,
        &f.signer,
        &None,
        &wide(&f.env, &ok_tokens),
    );
    assert_eq!(r, Err(Ok(AccountError::BadPolicy)));
    // foreign settlement signer (F5: until 2.3b only this account may be named)
    let r = f.client.try_set_policy(
        &id,
        &ok_actions,
        &ok_tokens,
        &0,
        &b32(&f.env, 0x77),
        &None,
        &wide(&f.env, &ok_tokens),
    );
    assert_eq!(r, Err(Ok(AccountError::BadPolicy)));
    // duplicate selector
    let dup = vec![&f.env, lock_for_order(&f.env), lock_for_order(&f.env)];
    let r = f.client.try_set_policy(
        &id,
        &dup,
        &ok_tokens,
        &0,
        &f.signer,
        &None,
        &wide(&f.env, &ok_tokens),
    );
    assert_eq!(r, Err(Ok(AccountError::BadPolicy)));
    // and the boundary that is fine
    f.client.set_policy(
        &id,
        &ok_actions,
        &ok_tokens,
        &(T0 + 1),
        &f.signer,
        &None,
        &wide(&f.env, &ok_tokens),
    );
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
        &vec![&f.env, lock_for_order(&f.env)],
        &vec![&f.env, f.ad_token.clone(), f.order_token.clone()],
        &(T0 + 100),
        &f.signer,
        &None,
        &wide(
            &f.env,
            &vec![&f.env, f.ad_token.clone(), f.order_token.clone()],
        ),
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
        &vec![&f.env, lock_for_order(&f.env)],
        &vec![&f.env, f.ad_token.clone()],
        &0,
        &f.signer,
        &None,
        &wide(&f.env, &vec![&f.env, f.ad_token.clone()]),
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

/// F4a: the decoder reads only the keys the policy needs, so a shape wider
/// than the 15-key order passes unchanged.
#[test]
fn wider_order_shape_decodes() {
    let f = fixture();
    let mut m = lock_map(&f);
    for k in ["extra_a", "extra_b"] {
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

/// CAP-85 (P28): an `ExternalRef` executable inside a create-contract context
/// is a clean `UnsupportedContext` on the agent path (never a trap) and is
/// invisible to the owner path, which does not inspect contexts. This is the
/// whole of the design's "tolerate the new executable type" requirement for
/// the built account: agents never create contracts, owners are sovereign.
#[test]
fn cap85_external_executable_is_a_clean_refusal_for_agents_and_invisible_to_the_owner() {
    let f = fixture();
    let external = ContractExecutable::ExternalRef(ContractExecutableRef {
        owner: Address::generate(&f.env),
        tag: String::from_str(&f.env, "cap85-external"),
    });
    let contexts = [
        Context::CreateContractHostFn(CreateContractHostFnContext {
            executable: external.clone(),
            salt: b32(&f.env, 0x11),
        }),
        Context::CreateContractWithCtorHostFn(CreateContractWithConstructorHostFnContext {
            executable: external,
            salt: b32(&f.env, 0x12),
            constructor_args: vec![&f.env],
        }),
    ];
    for ctx in contexts {
        expect_err(
            agent_check(&f, &vec![&f.env, ctx.clone()]),
            AccountError::UnsupportedContext,
        );
        // Owner path: mock_all_auths satisfies the nested owner auth; the
        // context is never decoded, so the new executable type cannot break it.
        check(&f, AccountSig::Owner, &vec![&f.env, ctx]).unwrap();
    }
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
            fn_name: lock_for_order(&f.env),
            args: vec![&f.env, good.into_val(&f.env)],
        }),
        Context::Contract(ContractContext {
            contract: f.target.clone(),
            fn_name: lock_for_order(&f.env),
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
        &vec![&f.env, lock_for_order(&f.env)],
        &vec![&f.env, f.ad_token.clone(), f.order_token.clone()],
        &0,
        &f.signer,
        &None,
        &wide(
            &f.env,
            &vec![&f.env, f.ad_token.clone(), f.order_token.clone()],
        ),
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
    env.ledger().set_protocol_version(PROTOCOL);
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
    // 2.3e: timing is fail-closed; the smallest legal clocks.
    am.set_route_timing(
        &order_chain_id,
        &ad_manager::RouteTiming {
            min_window: 0,
            buffer: 1_800,
            margin: 0,
            long_backstop: 86_400,
            claim_stagger: 0,
        },
    );

    test_token::TokenContractClient::new(&env, &token).mint(&account, &10_000_000_i128);

    // 2.3c: the ad declares its settlement signer (here the account itself, matching the lock
    // params below) and the escrow requires it registered — a mock registry marks it so.
    let signer = address_to_bytes32(&env, &account);
    let key_registry = env.register(MockKeyRegistry, ());
    MockKeyRegistryClient::new(&env, &key_registry).set(&signer, &true);
    am.set_key_registry(&key_registry);

    let ad_id = String::from_str(&env, "ad-1");
    am.create_ad(
        &account,
        &ad_id,
        &ad_token,
        &5_000_000_u128,
        &order_chain_id,
        &b32(&env, 0xCC),
        &signer,
    );

    let agent = Agent::new(7);
    let signer = address_to_bytes32(&env, &account);
    for t in [ad_token.clone(), order_token.clone()] {
        client.set_account_limit(
            &t,
            &Limit {
                capacity: u128::MAX / 2,
                refill_per_second: 1,
            },
        );
    }
    // Same as the unit fixture: wide rate, a per-order cap the escrow tests can exceed on purpose.
    let mut limits = Vec::new(&env);
    for t in [ad_token.clone(), order_token.clone()] {
        limits.push_back(tl(&t, 1_000_000, u128::MAX / 2, 1));
    }
    client.set_policy(
        &agent.id(&env),
        &vec![&env, lock_for_order(&env)],
        &vec![&env, ad_token.clone(), order_token.clone()],
        &0_u64,
        &signer,
        &None,
        &limits,
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
        salt: soroban_sdk::U256::from_u128(&e.env, 42),
        order_decimals: 7,
        ad_decimals: 7,
        deadline: 4_102_444_800,
        ad_settlement_signer: address_to_bytes32(&e.env, &e.account),
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

/// Which credential the auth entry carries. `Address` is the pre-P28 shape
/// (still accepted at protocol 28, retired after); `AddressV2` (CAP-71-02)
/// binds the signing address into the payload preimage.
#[derive(Clone, Copy)]
enum Creds {
    V1,
    V2,
}

/// sha256 of the HashIdPreimage the host hands `__check_auth` as
/// `signature_payload`: `SorobanAuthorization` for V1 credentials,
/// `SorobanAuthorizationWithAddress` for V2.
fn payload_hash(
    env: &Env,
    address: &Address,
    inv: &SorobanAuthorizedInvocation,
    nonce: i64,
    exp: u32,
    creds: Creds,
) -> BytesN<32> {
    let network_id = xdr::Hash(env.ledger().network_id().to_array());
    let preimage = match creds {
        Creds::V1 => HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id,
            nonce,
            signature_expiration_ledger: exp,
            invocation: inv.clone(),
        }),
        Creds::V2 => HashIdPreimage::SorobanAuthorizationWithAddress(
            HashIdPreimageSorobanAuthorizationWithAddress {
                network_id,
                nonce,
                signature_expiration_ledger: exp,
                address: sc_addr(address),
                invocation: inv.clone(),
            },
        ),
    };
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
    creds: Creds,
) -> SorobanAuthorizationEntry {
    let address_creds = SorobanAddressCredentials {
        address: sc_addr(address),
        nonce,
        signature_expiration_ledger: exp,
        signature,
    };
    SorobanAuthorizationEntry {
        credentials: match creds {
            Creds::V1 => SorobanCredentials::Address(address_creds),
            Creds::V2 => SorobanCredentials::AddressV2(address_creds),
        },
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
fn agent_lock_e2e(creds: Creds) {
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
    let payload = payload_hash(&e.env, &e.account, &inv, 1, exp, creds);
    let sig = sc_val(&e.env, e.agent.sign(&e.env, &payload).into_val(&e.env));
    e.env
        .set_auths(&[entry(&e.account, inv, 1, exp, sig, creds)]);
    let _hash: BytesN<32> = e.env.invoke_contract(
        &e.ad_manager,
        &Symbol::new(&e.env, "lock_for_order"),
        vec![&e.env, p_val],
    );
    assert_eq!(liquidity(&e), 4_600_000);

    // Over the cap: the auth entry is well-formed and signed, the policy says no.
    let mut p = escrow_params(&e, 1_000_001);
    p.salt = soroban_sdk::U256::from_u128(&e.env, 43);
    let p_val: Val = p.into_val(&e.env);
    let inv = invocation(
        &e.ad_manager,
        "lock_for_order",
        std::vec![sc_val(&e.env, p_val)],
    );
    let payload = payload_hash(&e.env, &e.account, &inv, 2, exp, creds);
    let sig = sc_val(&e.env, e.agent.sign(&e.env, &payload).into_val(&e.env));
    e.env
        .set_auths(&[entry(&e.account, inv, 2, exp, sig, creds)]);
    let r = e.env.try_invoke_contract::<BytesN<32>, soroban_sdk::Error>(
        &e.ad_manager,
        &Symbol::new(&e.env, "lock_for_order"),
        vec![&e.env, p_val],
    );
    // The policy's CapExceeded fails the account's __check_auth; the host
    // surfaces that as a context error on the escrow call, not a panic.
    assert_eq!(
        r,
        Err(Ok(soroban_sdk::Error::from_type_and_code(
            soroban_sdk::xdr::ScErrorType::Context,
            soroban_sdk::xdr::ScErrorCode::InvalidAction,
        )))
    );
    assert_eq!(liquidity(&e), 4_600_000);
}

/// Owner path end to end: the account authorizes `withdraw_from_ad` with
/// `AccountSig::Owner`, and the (contract) owner authorizes
/// `account.__check_auth(payload)` in a second entry.
fn owner_withdraw_e2e(creds: Creds) {
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
    let payload = payload_hash(&e.env, &e.account, &inv, 7, exp, creds);
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
            creds,
        ),
        // MockAuthContract accepts any signature; Void keeps the entry minimal.
        entry(&e.owner, owner_inv, 8, exp, ScVal::Void, creds),
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
        creds,
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

/// The real thing under both credential shapes. V1 stays while the host still
/// accepts it at protocol 28; V2 is what every client must send after.
#[test]
fn e2e_agent_lock_via_require_auth_address_v2_credentials() {
    agent_lock_e2e(Creds::V2);
}

#[test]
fn e2e_agent_lock_via_require_auth_legacy_v1_credentials() {
    agent_lock_e2e(Creds::V1);
}

#[test]
fn e2e_owner_withdraw_via_nested_require_auth_address_v2_credentials() {
    owner_withdraw_e2e(Creds::V2);
}

#[test]
fn e2e_owner_withdraw_via_nested_require_auth_legacy_v1_credentials() {
    owner_withdraw_e2e(Creds::V1);
}

/// A V2 signature over the V1 preimage (or vice versa) must not authorize:
/// the credential type selects the preimage the host verifies against.
#[test]
fn e2e_credential_type_and_preimage_must_match() {
    let e = escrow_fixture();
    let exp = e.env.ledger().sequence() + 100;
    let p = escrow_params(&e, 400_000);
    let p_val: Val = p.into_val(&e.env);
    let inv = invocation(
        &e.ad_manager,
        "lock_for_order",
        std::vec![sc_val(&e.env, p_val)],
    );
    // signed over the V1 preimage, submitted as AddressV2
    let payload = payload_hash(&e.env, &e.account, &inv, 1, exp, Creds::V1);
    let sig = sc_val(&e.env, e.agent.sign(&e.env, &payload).into_val(&e.env));
    e.env
        .set_auths(&[entry(&e.account, inv, 1, exp, sig, Creds::V2)]);
    let r = e.env.try_invoke_contract::<BytesN<32>, soroban_sdk::Error>(
        &e.ad_manager,
        &Symbol::new(&e.env, "lock_for_order"),
        vec![&e.env, p_val],
    );
    assert!(r.is_err());
    assert_eq!(liquidity(&e), 5_000_000);
}

/// Stands in for bls-key-registry.has_usable_slot for the escrow fixture (2.3c): an account is
/// registered iff a test marked it so.
#[soroban_sdk::contract]
pub struct MockKeyRegistry;

#[soroban_sdk::contractimpl]
impl MockKeyRegistry {
    pub fn set(env: Env, account: BytesN<32>, ok: bool) {
        env.storage()
            .instance()
            .set(&(soroban_sdk::symbol_short!("usable"), account), &ok);
    }

    pub fn has_usable_slot(env: Env, account: BytesN<32>) -> bool {
        env.storage()
            .instance()
            .get(&(soroban_sdk::symbol_short!("usable"), account))
            .unwrap_or(false)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 2.1d — volume buckets and ad scope
// ─────────────────────────────────────────────────────────────────────────

/// A policy whose only wide thing is the token list: one token, a real limit, and a scope the
/// caller picks. `cap`/`refill` are in ad-token units, the same units the escrow locks.
fn install_metered(
    f: &Fixture,
    cap: u128,
    refill: u128,
    scope: Option<Vec<String>>,
) -> Vec<TokenLimit> {
    let tokens = vec![&f.env, f.ad_token.clone(), f.order_token.clone()];
    // The size cap is the capacity here: these tests are about the rate, and a size cap below it
    // would silently do the refusing instead.
    let mut limits = Vec::new(&f.env);
    for t in tokens.iter() {
        limits.push_back(tl(&t, cap, cap, refill));
    }
    f.client.set_policy(
        &f.agent.id(&f.env),
        &vec![&f.env, lock_for_order(&f.env)],
        &tokens,
        &0_u64,
        &f.signer,
        &scope,
        &limits,
    );
    limits
}

fn lock_of(f: &Fixture, amount: u128, ad_id: &str) -> Vec<Context> {
    let mut p = params(f);
    p.amount = amount;
    p.ad_id = String::from_str(&f.env, ad_id);
    lock_ctx(&f.env, &f.target, vec![&f.env, p.into_val(&f.env)])
}

/// T-07, the boundary half. A fixed window passes this at 2×: spend the cap just before the
/// rollover and again just after. Continuous refill has no rollover to sit either side of, so one
/// second buys exactly one second of allowance and nothing else.
#[test]
fn t07_a_drained_bucket_refills_by_the_second_not_by_the_window() {
    let f = fixture();
    install_metered(&f, 1_000, 10, None);
    f.client.set_account_limit(
        &f.ad_token,
        &Limit {
            capacity: u128::MAX / 2,
            refill_per_second: 1,
        },
    );

    agent_check(&f, &lock_of(&f, 1_000, "ad-1")).unwrap();

    f.env.ledger().set_timestamp(T0 + 1);
    expect_err(
        agent_check(&f, &lock_of(&f, 1_000, "ad-1")),
        AccountError::VolumeExceeded,
    );
    expect_err(
        agent_check(&f, &lock_of(&f, 11, "ad-1")),
        AccountError::VolumeExceeded,
    );
    agent_check(&f, &lock_of(&f, 10, "ad-1")).expect("exactly one second of refill");
}

/// T-07, the aggregate half. Two agents, each with a full private bucket, drain one shared
/// account ceiling — so N agents stop multiplying the exposure.
#[test]
fn t07_two_agents_share_one_account_ceiling() {
    let f = fixture();
    let tokens = vec![&f.env, f.ad_token.clone(), f.order_token.clone()];
    let mut limits = Vec::new(&f.env);
    for t in tokens.iter() {
        limits.push_back(tl(&t, 1_000, 1_000, 1));
    }
    let second = Agent::new(9);
    for id in [f.agent.id(&f.env), second.id(&f.env)] {
        f.client.set_policy(
            &id,
            &vec![&f.env, lock_for_order(&f.env)],
            &tokens,
            &0_u64,
            &f.signer,
            &None,
            &limits,
        );
    }
    // The account allows one agent's worth in total, not one each.
    f.client.set_account_limit(
        &f.ad_token,
        &Limit {
            capacity: 1_000,
            refill_per_second: 1,
        },
    );

    agent_check(&f, &lock_of(&f, 1_000, "ad-1")).unwrap();

    // The second agent's own bucket is untouched and full; the account's is empty.
    let payload = b32(&f.env, 0x01);
    let sig = second.sign(&f.env, &payload);
    let r = f.env.try_invoke_contract_check_auth::<AccountError>(
        &f.account,
        &payload,
        sig.into_val(&f.env),
        &lock_of(&f, 1_000, "ad-1"),
    );
    expect_err(r, AccountError::VolumeExceeded);
}

/// The account ceiling has to exist, and its absence refuses at both ends.
///
/// At install, because a policy naming a token the account has no limit for would install cleanly
/// and then fail on its first lock — fail-closed, but the owner gets no answer until an agent
/// mysteriously cannot work. At use, because the row can still go away underneath a live policy:
/// its TTL is extended on every write, so an account idle past the window archives it. Absence
/// refuses there too; it never reads as an unlimited ceiling (2.3h).
#[test]
fn a_missing_account_ceiling_refuses_at_install_and_at_use() {
    let f = fixture();
    let unmetered = b32(&f.env, 0x5E);
    let tokens = vec![&f.env, unmetered.clone(), f.order_token.clone()];
    assert_eq!(
        f.client.try_set_policy(
            &f.agent.id(&f.env),
            &vec![&f.env, lock_for_order(&f.env)],
            &tokens,
            &0_u64,
            &f.signer,
            &None,
            &wide(&f.env, &tokens)
        ),
        Err(Ok(AccountError::NoVolumeLimit)),
        "the account has no ceiling for this token"
    );

    // Now the use-time half: a policy installed against a live ceiling, whose row then archives.
    install_metered(&f, 1_000, 1, None);
    agent_check(&f, &lock_of(&f, 1, "ad-1")).expect("works while the ceiling is there");
    f.env.as_contract(&f.account, || {
        f.env
            .storage()
            .persistent()
            .remove(&policy::DataKey::AccountVolume(f.ad_token.clone()));
    });
    expect_err(
        agent_check(&f, &lock_of(&f, 1, "ad-1")),
        AccountError::NoVolumeLimit,
    );
}

/// One auth entry carrying two locks must pay for both. The policy is read once and handed to
/// every context, so a per-context write would have the second overwrite the first and make it
/// free.
#[test]
fn two_locks_in_one_auth_entry_are_both_charged() {
    let f = fixture();
    install_metered(&f, 1_000, 1, None);
    f.client.set_account_limit(
        &f.ad_token,
        &Limit {
            capacity: u128::MAX / 2,
            refill_per_second: 1,
        },
    );

    let mut a = params(&f);
    a.amount = 600;
    let mut b = params(&f);
    b.amount = 600;
    b.salt = soroban_sdk::U256::from_u128(&f.env, 43);
    let both = vec![
        &f.env,
        Context::Contract(ContractContext {
            contract: f.target.clone(),
            fn_name: lock_for_order(&f.env),
            args: vec![&f.env, a.into_val(&f.env)],
        }),
        Context::Contract(ContractContext {
            contract: f.target.clone(),
            fn_name: lock_for_order(&f.env),
            args: vec![&f.env, b.into_val(&f.env)],
        }),
    ];
    expect_err(agent_check(&f, &both), AccountError::VolumeExceeded);
}

/// `None` scope is every ad this account owns — the 2.1c behaviour, pinned so it cannot regress
/// into an accidental restriction.
#[test]
fn an_unscoped_agent_serves_every_ad() {
    let f = fixture();
    install_metered(&f, u128::MAX / 2, 1, None);
    f.client.set_account_limit(
        &f.ad_token,
        &Limit {
            capacity: u128::MAX / 2,
            refill_per_second: 1,
        },
    );
    for ad in ["ad-1", "ad-2", "something-else"] {
        agent_check(&f, &lock_of(&f, 1, ad)).unwrap_or_else(|_| panic!("{ad}"));
    }
}

/// A scoped agent serves its ads and nothing else, and a refusal leaves its allowance intact.
///
/// The second half holds because a rejected `__check_auth` discards the frame, **not** because the
/// scope test runs before the debit — moving it after the debit leaves this test green. The
/// property is worth pinning anyway; the ordering it looks like it proves, it does not.
#[test]
fn a_scoped_agent_is_held_to_its_ads_and_its_allowance_survives_a_refusal() {
    let f = fixture();
    install_metered(
        &f,
        1_000,
        1,
        Some(vec![&f.env, String::from_str(&f.env, "ad-1")]),
    );
    f.client.set_account_limit(
        &f.ad_token,
        &Limit {
            capacity: 1_000,
            refill_per_second: 1,
        },
    );

    expect_err(
        agent_check(&f, &lock_of(&f, 400, "ad-2")),
        AccountError::AdNotAllowed,
    );
    // The whole capacity is still there: the refusal above spent nothing.
    agent_check(&f, &lock_of(&f, 1_000, "ad-1")).expect("the refused lock left the bucket full");
}

#[test]
fn ad_scope_is_validated_like_the_token_whitelist() {
    let f = fixture();
    let tokens = vec![&f.env, f.ad_token.clone(), f.order_token.clone()];
    let limits = wide(&f.env, &tokens);
    let id = f.agent.id(&f.env);
    let install = |scope: Option<Vec<String>>| {
        f.client.try_set_policy(
            &id,
            &vec![&f.env, lock_for_order(&f.env)],
            &tokens,
            &0_u64,
            &f.signer,
            &scope,
            &limits,
        )
    };
    let dup = String::from_str(&f.env, "ad-1");
    assert_eq!(
        install(Some(Vec::new(&f.env))),
        Err(Ok(AccountError::BadPolicy)),
        "an empty scope means invalid here, never 'all ads'"
    );
    assert_eq!(
        install(Some(vec![&f.env, dup.clone(), dup.clone()])),
        Err(Ok(AccountError::BadPolicy)),
        "duplicates"
    );
    assert_eq!(
        install(Some(vec![&f.env, String::from_str(&f.env, "")])),
        Err(Ok(AccountError::BadPolicy)),
        "an empty ad id"
    );
}

/// The whitelist says which tokens are permitted at all; `limits` says how much. A policy where
/// the two disagree is half-written, and is refused rather than defaulted.
#[test]
fn every_whitelisted_token_must_carry_a_limit() {
    let f = fixture();
    let tokens = vec![&f.env, f.ad_token.clone(), f.order_token.clone()];
    let mut only_one = Vec::new(&f.env);
    only_one.push_back(tl(&f.ad_token, 1, 1, 1));
    let r = f.client.try_set_policy(
        &f.agent.id(&f.env),
        &vec![&f.env, lock_for_order(&f.env)],
        &tokens,
        &0_u64,
        &f.signer,
        &None,
        &only_one,
    );
    assert_eq!(r, Err(Ok(AccountError::BadPolicy)));

    // ...and a zero on either side of a limit is refused too: a zero capacity blocks the agent
    // outright, a zero refill makes the bucket one-shot. Both read as a mis-set field.
    for (mpo, cap, refill) in [
        // zero capacity, zero refill, no size cap, and a size cap above the capacity — the last
        // one can never bind, so an owner who wrote it meant something the policy cannot do.
        (1_u128, 0_u128, 1_u128),
        (1, 1, 0),
        (0, 1, 1),
        (2, 1, 1),
    ] {
        let mut m = Vec::new(&f.env);
        for t in tokens.iter() {
            m.push_back(tl(&t, mpo, cap, refill));
        }
        assert_eq!(
            f.client.try_set_policy(
                &f.agent.id(&f.env),
                &vec![&f.env, lock_for_order(&f.env)],
                &tokens,
                &0_u64,
                &f.signer,
                &None,
                &m
            ),
            Err(Ok(AccountError::BadPolicy))
        );
        // The account row carries a rate and no size cap, so only the rate-shaped rows apply here.
        if cap == 0 || refill == 0 {
            assert_eq!(
                f.client.try_set_account_limit(
                    &f.ad_token,
                    &Limit {
                        capacity: cap,
                        refill_per_second: refill
                    }
                ),
                Err(Ok(AccountError::BadPolicy))
            );
        }
    }
}

/// Raising the refill rate must not re-price the idle interval at the new rate. The first version
/// of this test re-set the same rate at the same timestamp and so proved nothing: drain, wait,
/// raise the rate, and the bucket came back full — the cap-resets-on-demand the clamp is supposed
/// to prevent, reached through the rate instead of the level.
#[test]
fn raising_the_refill_rate_does_not_replay_the_idle_window() {
    let f = fixture();
    install_metered(&f, u128::MAX / 2, 1, None);
    f.client.set_account_limit(
        &f.ad_token,
        &Limit {
            capacity: 1_000,
            refill_per_second: 1,
        },
    );
    agent_check(&f, &lock_of(&f, 1_000, "ad-1")).unwrap();

    // 100 idle seconds are worth 100 units at the old rate. Raising the rate must not make them
    // worth 100_000.
    f.env.ledger().set_timestamp(T0 + 100);
    f.client.set_account_limit(
        &f.ad_token,
        &Limit {
            capacity: 1_000,
            refill_per_second: 1_000,
        },
    );
    expect_err(
        agent_check(&f, &lock_of(&f, 101, "ad-1")),
        AccountError::VolumeExceeded,
    );
    agent_check(&f, &lock_of(&f, 100, "ad-1")).expect("the 100 seconds it actually idled");
}

/// Lowering the account ceiling applies at once and never tops the bucket up.
#[test]
fn re_setting_the_account_limit_clamps_and_never_refills() {
    let f = fixture();
    install_metered(&f, u128::MAX / 2, 1, None);
    f.client.set_account_limit(
        &f.ad_token,
        &Limit {
            capacity: 1_000,
            refill_per_second: 1,
        },
    );
    agent_check(&f, &lock_of(&f, 900, "ad-1")).unwrap();

    // Same capacity again: the 100 left is still 100, not 1,000.
    f.client.set_account_limit(
        &f.ad_token,
        &Limit {
            capacity: 1_000,
            refill_per_second: 1,
        },
    );
    expect_err(
        agent_check(&f, &lock_of(&f, 101, "ad-1")),
        AccountError::VolumeExceeded,
    );
    agent_check(&f, &lock_of(&f, 100, "ad-1")).expect("the remaining 100");
}

/// G1: an account upgraded in place must not lose the agents it already had.
///
/// A 2.1c policy is an `ScMap` with six keys; reading it straight into the nine-key 2.1d struct
/// traps rather than returning `None`, and every entry point that touches an agent reads its policy
/// first — so before the lazy migration, upgrading bricked the id in every direction at once: it
/// could not act, be inspected, be revoked, or be replaced.
#[test]
fn a_2_1c_policy_survives_the_upgrade_useless_but_repairable() {
    let f = fixture();
    let old = Agent::new(11);
    let id = old.id(&f.env);

    // Write what 2.1c wrote, straight past the current `set_policy`.
    f.env.as_contract(&f.account, || {
        f.env.storage().persistent().set(
            &policy::DataKey::Policy(id.clone()),
            &policy::AgentPolicyV1 {
                allowed_actions: vec![&f.env, lock_for_order(&f.env)],
                token_whitelist: vec![&f.env, f.ad_token.clone(), f.order_token.clone()],
                max_per_order: 1_000_000,
                valid_until: 0,
                revoked: false,
                settlement_signer: f.signer.clone(),
            },
        );
    });

    // Readable, and the fields that existed came across.
    let migrated = f.client.policy(&id).expect("a v1 policy still reads");
    assert_eq!(migrated.settlement_signer, f.signer);
    assert!(migrated.ad_scope.is_none(), "unscoped, as it was");
    assert!(
        migrated.limits.is_empty(),
        "no limits: it predates them, and v1's single max_per_order has no per-token row to go in"
    );

    // Useless rather than dangerous: with no limit the agent cannot lock.
    let payload = b32(&f.env, 0x01);
    let sig = old.sign(&f.env, &payload);
    let r = f.env.try_invoke_contract_check_auth::<AccountError>(
        &f.account,
        &payload,
        sig.into_val(&f.env),
        &lock_of(&f, 1, "ad-1"),
    );
    expect_err(r, AccountError::NoVolumeLimit);

    // And repairable: the owner can meter it, and it works.
    let tokens = vec![&f.env, f.ad_token.clone(), f.order_token.clone()];
    f.client.set_policy(
        &id,
        &vec![&f.env, lock_for_order(&f.env)],
        &tokens,
        &0_u64,
        &f.signer,
        &None,
        &wide(&f.env, &tokens),
    );
    let sig = old.sign(&f.env, &payload);
    f.env
        .try_invoke_contract_check_auth::<AccountError>(
            &f.account,
            &payload,
            sig.into_val(&f.env),
            &lock_of(&f, 1, "ad-1"),
        )
        .expect("re-installed and metered");
}

/// The tombstone has to survive the upgrade too, or a revoked id could be re-installed by an owner
/// whose key was the reason it was revoked.
#[test]
fn a_revoked_2_1c_policy_is_still_revoked_after_the_upgrade() {
    let f = fixture();
    let id = Agent::new(12).id(&f.env);
    f.env.as_contract(&f.account, || {
        f.env.storage().persistent().set(
            &policy::DataKey::Policy(id.clone()),
            &policy::AgentPolicyV1 {
                allowed_actions: vec![&f.env, lock_for_order(&f.env)],
                token_whitelist: vec![&f.env, f.ad_token.clone()],
                max_per_order: 1,
                valid_until: 0,
                revoked: true,
                settlement_signer: f.signer.clone(),
            },
        );
    });
    assert!(f.client.is_revoked(&id));
    let tokens = vec![&f.env, f.ad_token.clone()];
    assert_eq!(
        f.client.try_set_policy(
            &id,
            &vec![&f.env, lock_for_order(&f.env)],
            &tokens,
            &0_u64,
            &f.signer,
            &None,
            &wide(&f.env, &tokens)
        ),
        Err(Ok(AccountError::AgentRevoked))
    );
}

/// G4: a repeated token would make the length-based containment check lie — `[A, A]` balances
/// against limits `{A, B}`, and `B` would carry a limit while never being whitelisted.
#[test]
fn a_duplicate_whitelisted_token_is_refused() {
    let f = fixture();
    let dup = vec![&f.env, f.ad_token.clone(), f.ad_token.clone()];
    let mut limits = Vec::new(&f.env);
    for t in [f.ad_token.clone(), f.order_token.clone()] {
        limits.push_back(tl(&t, 1, 1, 1));
    }
    assert_eq!(
        f.client.try_set_policy(
            &f.agent.id(&f.env),
            &vec![&f.env, lock_for_order(&f.env)],
            &dup,
            &0_u64,
            &f.signer,
            &None,
            &limits
        ),
        Err(Ok(AccountError::BadPolicy))
    );
}

/// G6: the per-order cap is per token, because one number cannot be right for two assets of
/// different value — 1,000,000 units is a few cents of XLM and a few hundred dollars of wETH.
/// Decimal scaling does not help: it converts units, and what differs here is worth.
#[test]
fn each_token_carries_its_own_per_order_cap() {
    let f = fixture();
    let tokens = vec![&f.env, f.ad_token.clone(), f.order_token.clone()];
    let mut limits = Vec::new(&f.env);
    limits.push_back(tl(&f.ad_token, 100, 10_000, 1));
    limits.push_back(tl(&f.order_token, 10_000, 10_000, 1));
    f.client.set_policy(
        &f.agent.id(&f.env),
        &vec![&f.env, lock_for_order(&f.env)],
        &tokens,
        &0_u64,
        &f.signer,
        &None,
        &limits,
    );

    // The cap applies to the ad token this lock names, not to whichever number was set first.
    agent_check(&f, &lock_of(&f, 100, "ad-1")).expect("at the ad token's own cap");
    expect_err(
        agent_check(&f, &lock_of(&f, 101, "ad-1")),
        AccountError::CapExceeded,
    );

    // The other token's far larger cap does not leak across: it is not this lock's ad token.
    let mut p = params(&f);
    p.amount = 101;
    p.salt = soroban_sdk::U256::from_u128(&f.env, 44);
    let ctxs = lock_ctx(&f.env, &f.target, vec![&f.env, p.into_val(&f.env)]);
    expect_err(agent_check(&f, &ctxs), AccountError::CapExceeded);
}

/// Rows carrying their own key mean `limits` and `token_whitelist` can disagree in three ways. Two
/// checks cover all three: the count, and a lookup for every whitelisted token. Each case below is
/// caught by one of them, and each is mutation-verified against the check that catches it.
#[test]
fn limit_rows_must_match_the_whitelist_exactly() {
    let f = fixture();
    let tokens = vec![&f.env, f.ad_token.clone(), f.order_token.clone()];
    let stranger = b32(&f.env, 0x9E);
    let install = |limits: Vec<TokenLimit>| {
        f.client.try_set_policy(
            &f.agent.id(&f.env),
            &vec![&f.env, lock_for_order(&f.env)],
            &tokens,
            &0_u64,
            &f.signer,
            &None,
            &limits,
        )
    };

    // Right length, wrong set — caught by the per-token lookup: the order token has no row.
    let mut wrong_set = Vec::new(&f.env);
    wrong_set.push_back(tl(&f.ad_token, 1, 1, 1));
    wrong_set.push_back(tl(&stranger, 1, 1, 1));
    assert_eq!(install(wrong_set), Err(Ok(AccountError::BadPolicy)));

    // Right length, duplicated row — same check, same reason: the order token has no row.
    let mut dup = Vec::new(&f.env);
    dup.push_back(tl(&f.ad_token, 1, 1, 1));
    dup.push_back(tl(&f.ad_token, 1, 1, 1));
    assert_eq!(install(dup), Err(Ok(AccountError::BadPolicy)));

    // Every whitelisted token has a row AND a stranger carries one too — the lookup is satisfied,
    // so only the count catches this. Without it a token off the whitelist holds a limit.
    let mut extra = wide(&f.env, &tokens);
    extra.push_back(tl(&stranger, 1, 1, 1));
    assert_eq!(install(extra), Err(Ok(AccountError::BadPolicy)));

    assert_eq!(install(wide(&f.env, &tokens)), Ok(Ok(())));
}
