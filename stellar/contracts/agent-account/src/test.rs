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
    // (2.6 D9: a settlement signer other than this account is the owner's to name; see
    // `d9_an_owner_named_settlement_signer_installs_and_settles`.)
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

/// T-05, and the name is the point.
///
/// Revocation stops the agent **acting**. It does not stop orders that are already locked and
/// co-signed from settling, because settlement authenticates against the BLS registry — a proof
/// plus an aggregate checked against `registry.keyOf(...)` — and never calls this account's
/// `__check_auth` or reads `policy.revoked` at all (risk 01 F1, CRITICAL).
///
/// So "instant kill verified mid-trade" is false as it is usually read, and a test called
/// `revoke_agent_kills_the_agent` would invite exactly that reading. What stops co-signed orders is
/// lever 2, `set_valid_until = now` on both registries — a different key (the settlement identity,
/// not the custody owner) and a different contract. The escrow side of that is
/// `test_t14_lock_after_key_retired_errors` in the integration suite; nothing here can assert it,
/// because nothing here is consulted.
#[test]
fn revoke_stops_new_locks_but_not_settlement_of_co_signed_orders() {
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

/// 2.6 D9: the owner names the settlement signer — the agent's derived secp256k1 identity M, an
/// EVM-shaped id — and a lock naming it passes; `ad_creator` must still be this account.
#[test]
fn d9_an_owner_named_settlement_signer_installs_and_settles() {
    let f = fixture();
    let mut m = [0u8; 32];
    m[12..].copy_from_slice(&[0x8f; 20]);
    let m = BytesN::from_array(&f.env, &m);
    let tokens = vec![&f.env, f.ad_token.clone(), f.order_token.clone()];
    f.client.set_policy(
        &f.agent.id(&f.env),
        &vec![&f.env, lock_for_order(&f.env)],
        &tokens,
        &0,
        &m,
        &None,
        &wide(&f.env, &tokens),
    );
    assert_eq!(
        f.client
            .policy(&f.agent.id(&f.env))
            .unwrap()
            .settlement_signer,
        m
    );

    let mut p = params(&f);
    p.ad_settlement_signer = m.clone();
    let lock = |p: &OrderParams| lock_ctx(&f.env, &f.target, vec![&f.env, p.into_val(&f.env)]);
    assert_eq!(agent_check(&f, &lock(&p)), Ok(()));
    // the lock still names this account as the ad's maker
    p.ad_creator = m.clone();
    expect_err(
        agent_check(&f, &lock(&p)),
        AccountError::SettlementSignerMismatch,
    );
    // and a lock naming the account itself no longer matches the policy
    let mut q = params(&f);
    q.ad_settlement_signer = f.signer.clone();
    expect_err(
        agent_check(&f, &lock(&q)),
        AccountError::SettlementSignerMismatch,
    );
}

/// 2.6 D9: on a guarded account, changing the settlement signer is a loosening write: refused
/// unannounced, accepted once the exact write is scheduled and matured.
#[test]
fn d9_changing_the_settlement_signer_waits_the_delay_on_a_guarded_account() {
    let f = fixture();
    let id = f.agent.id(&f.env);
    guard(&f, 0, 3_600, 86_400);
    let tokens = vec![&f.env, f.ad_token.clone(), f.order_token.clone()];
    let mut limits = Vec::new(&f.env);
    for t in tokens.iter() {
        limits.push_back(tl(&t, 1_000_000, u128::MAX / 2, 1));
    }
    let m = b32(&f.env, 0x8f);
    let set = || {
        f.client.try_set_policy(
            &id,
            &vec![&f.env, lock_for_order(&f.env)],
            &tokens,
            &0,
            &m,
            &None,
            &limits,
        )
    };
    assert_eq!(set(), Err(Ok(AccountError::NotScheduled)));
    let args = policy_args(&f.env, &id, &tokens, 0, &m, &None, &limits);
    f.client
        .schedule_account_extractive(&sym_of(&f.env, "set_policy"), &commit(&f.env, args));
    f.env.ledger().set_timestamp(T0 + 3_600);
    assert_eq!(set(), Ok(Ok(())));
    assert_eq!(f.client.policy(&id).unwrap().settlement_signer, m);
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

/// #422: the settlement halt and its resume are the custody key's, never the agent's.
#[test]
fn agent_cannot_halt_or_resume_settlement() {
    let f = fixture();
    for name in ["halt_settlement", "resume_settlement"] {
        let ctxs = vec![
            &f.env,
            Context::Contract(ContractContext {
                contract: f.target.clone(),
                fn_name: Symbol::new(&f.env, name),
                args: vec![&f.env],
            }),
        ];
        expect_err(agent_check(&f, &ctxs), AccountError::ActionNotAllowed);
    }
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
        // #453: inside the escrow's 7-day order window.
        deadline: T0 + 86_400,
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

// ─────────────────────────────────────────────────────────────────────────
// 2.1e — the owner's guardrails
// ─────────────────────────────────────────────────────────────────────────

const AD: &str = "ad-1";

fn ad(env: &Env) -> String {
    String::from_str(env, AD)
}

/// Arm with a bucket wide enough that a test which is not about the flow rate never trips it.
fn guard(f: &Fixture, threshold: u128, delay: u64, window: u64) {
    guard_rate(f, threshold, delay, window, u128::MAX / 2, 1);
}

fn guard_rate(
    f: &Fixture,
    threshold: u128,
    delay: u64,
    window: u64,
    capacity: u128,
    refill_per_second: u128,
) {
    f.client.set_guard_rail(
        &ad(&f.env),
        &Some(GuardRail {
            threshold,
            delay,
            window,
            rate: Limit {
                capacity,
                refill_per_second,
            },
            bucket: Bucket {
                level: 0,
                last_ts: 0,
            },
        }),
    );
}

/// `withdraw_from_ad(ad_id, amount, to)` as the escrow receives it.
fn withdraw_ctx(f: &Fixture, amount: u128, to: &Address) -> Vec<Context> {
    vec![
        &f.env,
        Context::Contract(ContractContext {
            contract: f.target.clone(),
            fn_name: Symbol::new(&f.env, "withdraw_from_ad"),
            args: vec![
                &f.env,
                ad(&f.env).into_val(&f.env),
                amount.into_val(&f.env),
                to.into_val(&f.env),
            ],
        }),
    ]
}

/// `close_ad(ad_id, to)` — no amount, by design.
fn close_ctx(f: &Fixture, to: &Address) -> Vec<Context> {
    vec![
        &f.env,
        Context::Contract(ContractContext {
            contract: f.target.clone(),
            fn_name: Symbol::new(&f.env, "close_ad"),
            args: vec![&f.env, ad(&f.env).into_val(&f.env), to.into_val(&f.env)],
        }),
    ]
}

fn owner_check(f: &Fixture, ctxs: &Vec<Context>) -> Result<(), Result<AccountError, InvokeError>> {
    check(f, AccountSig::Owner, ctxs)
}

/// An unguarded ad behaves exactly as it did before 2.1e — which is every ad that exists today.
#[test]
fn t52_an_unguarded_ad_is_untouched() {
    let f = fixture();
    let to = Address::generate(&f.env);
    owner_check(&f, &withdraw_ctx(&f, u128::MAX, &to)).expect("no guardrail, no delay");
    owner_check(&f, &close_ctx(&f, &to)).expect("same for close_ad");
}

/// The delay, end to end: refused unannounced, refused early, allowed once matured, and refused a
/// second time on the same schedule.
#[test]
fn t52_an_over_threshold_withdrawal_must_be_announced_and_waited_out() {
    let f = fixture();
    let to = Address::generate(&f.env);
    guard(&f, 100, 3_600, 86_400);

    // Under the threshold is instant — the guardrail has to be livable or it gets turned off.
    owner_check(&f, &withdraw_ctx(&f, 100, &to)).expect("at the threshold");

    expect_err(
        owner_check(&f, &withdraw_ctx(&f, 101, &to)),
        AccountError::NotScheduled,
    );

    f.client.schedule_extractive(
        &ad(&f.env),
        &Symbol::new(&f.env, "withdraw_from_ad"),
        &101,
        &to,
    );
    expect_err(
        owner_check(&f, &withdraw_ctx(&f, 101, &to)),
        AccountError::NotScheduled,
    );

    f.env.ledger().set_timestamp(T0 + 3_600);
    owner_check(&f, &withdraw_ctx(&f, 101, &to)).expect("matured");
    expect_err(
        owner_check(&f, &withdraw_ctx(&f, 101, &to)),
        AccountError::NotScheduled,
    );
}

/// A schedule is for one call, not a standing approval: the amount and the destination are both
/// compared exactly.
#[test]
fn t52_a_schedule_authorizes_exactly_what_it_named() {
    let f = fixture();
    let alice = Address::generate(&f.env);
    let mallory = Address::generate(&f.env);
    guard(&f, 0, 3_600, 86_400);

    f.client.schedule_extractive(
        &ad(&f.env),
        &Symbol::new(&f.env, "withdraw_from_ad"),
        &100,
        &alice,
    );
    f.env.ledger().set_timestamp(T0 + 3_600);

    expect_err(
        owner_check(&f, &withdraw_ctx(&f, 101, &alice)),
        AccountError::NotScheduled,
    );
    expect_err(
        owner_check(&f, &withdraw_ctx(&f, 100, &mallory)),
        AccountError::NotScheduled,
    );
    owner_check(&f, &withdraw_ctx(&f, 100, &alice)).expect("exactly what was announced");
}

/// A matured schedule is usable for a window, not forever. One left sitting is an authorization
/// waiting for whoever finds the key next.
#[test]
fn t52_a_schedule_expires() {
    let f = fixture();
    let to = Address::generate(&f.env);
    guard(&f, 0, 3_600, 600);
    f.client.schedule_extractive(
        &ad(&f.env),
        &Symbol::new(&f.env, "withdraw_from_ad"),
        &1,
        &to,
    );

    f.env.ledger().set_timestamp(T0 + 3_600 + 600);
    expect_err(
        owner_check(&f, &withdraw_ctx(&f, 1, &to)),
        AccountError::NotScheduled,
    );
}

/// `close_ad` carries no amount and empties the ad, and the account cannot read the balance without
/// re-entering the escrow that is calling it. So no threshold can gate it: on a guarded ad it is
/// always announced, whatever the balance and however high the threshold.
#[test]
fn t52_close_ad_is_extractive_whatever_the_threshold() {
    let f = fixture();
    let to = Address::generate(&f.env);
    guard(&f, u128::MAX, 3_600, 86_400);

    expect_err(
        owner_check(&f, &close_ctx(&f, &to)),
        AccountError::NotScheduled,
    );
    f.client
        .schedule_extractive(&ad(&f.env), &Symbol::new(&f.env, "close_ad"), &0, &to);
    f.env.ledger().set_timestamp(T0 + 3_600);
    owner_check(&f, &close_ctx(&f, &to)).expect("announced and matured");
}

/// The asymmetry, which is the whole point of the section: on the *same* guarded ad, the actions
/// that **reduce** what a stolen key can do still fire instantly. A delay on those would only ever
/// help whoever stole it.
#[test]
fn t52_protective_actions_are_never_delayed_on_a_guarded_ad() {
    let f = fixture();
    guard(&f, 0, 86_400, 86_400);

    // Lever 3: re-point the ad's settlement identity, through the escrow.
    let repoint = vec![
        &f.env,
        Context::Contract(ContractContext {
            contract: f.target.clone(),
            fn_name: Symbol::new(&f.env, "set_settlement_signer"),
            args: vec![
                &f.env,
                ad(&f.env).into_val(&f.env),
                f.signer.into_val(&f.env),
            ],
        }),
    ];
    owner_check(&f, &repoint).expect("re-pointing is protective");

    // Lever 1 is a call on the account itself, so it never reaches the context loop — but it must
    // still work with a guardrail armed.
    f.client.revoke_agent(&f.agent.id(&f.env));
    assert!(f.client.is_revoked(&f.agent.id(&f.env)));

    // And tightening is protective too: a lower threshold, a longer delay, a smaller bucket.
    guard_rate(&f, 0, 172_800, 3_600, 1, 1);
    assert_eq!(f.client.guard_rail(&ad(&f.env)).unwrap().delay, 172_800);
}

/// J1. Disarming is **not** protective, and an earlier version of this had it instant.
///
/// Design 02 §2.8's protective list is every action that reduces an attacker's power — which is
/// why delaying them "only helps an attacker". Relaxing a brake does the opposite, and the
/// arithmetic settles it: with a delay on both, a thief waits `delay` whichever route they take;
/// with disarm instant, they disarm and withdraw and wait nothing. The delay was not relocated, it
/// was removed.
#[test]
fn t52_loosening_and_disarming_go_through_the_delay() {
    let f = fixture();
    let to = Address::generate(&f.env);
    guard(&f, 0, 3_600, 86_400);
    let change = Symbol::new(&f.env, "set_guard_rail");

    // Disarm: refused outright.
    assert_eq!(
        f.client.try_set_guard_rail(&ad(&f.env), &None),
        Err(Ok(AccountError::NotScheduled))
    );
    // Loosening — a higher threshold — is the same thing by another route.
    assert_eq!(
        f.client.try_set_guard_rail(
            &ad(&f.env),
            &Some(GuardRail {
                threshold: u128::MAX,
                delay: 3_600,
                window: 86_400,
                rate: Limit {
                    capacity: u128::MAX / 2,
                    refill_per_second: 1
                },
                bucket: Bucket {
                    level: 0,
                    last_ts: 0
                },
            }),
        ),
        Err(Ok(AccountError::NotScheduled))
    );

    // Announced and waited out, it goes through — and the thief has paid the same delay they would
    // have paid to withdraw.
    f.client.schedule_extractive(&ad(&f.env), &change, &0, &to);
    f.env.ledger().set_timestamp(T0 + 3_600);
    f.client.set_guard_rail(&ad(&f.env), &None);
    assert!(f.client.guard_rail(&ad(&f.env)).is_none());
    assert!(f.client.guarded_ads().is_empty(), "off the roster too");
}

/// K1. The guard used to run only for contexts whose contract was a pinned target, and
/// `set_targets` is owner-only and instant — so pointing targets elsewhere removed the guard
/// without touching it. The selector and the ad are what matter now.
#[test]
fn t52_repointing_targets_does_not_remove_the_guard() {
    let f = fixture();
    let to = Address::generate(&f.env);
    guard(&f, 0, 3_600, 86_400);

    // Adding a target on a guarded account is itself scheduled (C-29); announce and wait it out.
    let elsewhere = Address::generate(&f.env);
    let targets = vec![&f.env, elsewhere.clone()];
    f.client.schedule_account_extractive(
        &Symbol::new(&f.env, "set_targets"),
        &commit(&f.env, vec![&f.env, targets.to_val()]),
    );
    f.env.ledger().set_timestamp(T0 + 3_600);
    f.client.set_targets(&targets);

    let ctx = vec![
        &f.env,
        Context::Contract(ContractContext {
            contract: f.target.clone(),
            fn_name: Symbol::new(&f.env, "withdraw_from_ad"),
            args: vec![
                &f.env,
                ad(&f.env).into_val(&f.env),
                1_u128.into_val(&f.env),
                to.into_val(&f.env),
            ],
        }),
    ];
    expect_err(owner_check(&f, &ctx), AccountError::NotScheduled);
}

/// K2. The settings entry is persistent and archives after ~180 days of no writes. An ad left that
/// long would otherwise silently lose its brake — absence reading as permission, the failure
/// contracts#25 fixed for the route and verifier rows. The roster lives in the instance, which
/// every entry point re-extends, so an armed ad whose row is gone refuses instead.
#[test]
fn t52_an_archived_guardrail_refuses_rather_than_reading_as_unguarded() {
    let f = fixture();
    let to = Address::generate(&f.env);
    guard(&f, u128::MAX, 3_600, 86_400);
    owner_check(&f, &withdraw_ctx(&f, 1, &to)).expect("guarded but under the threshold");

    f.env.as_contract(&f.account, || {
        f.env
            .storage()
            .persistent()
            .remove(&policy::DataKey::GuardRail(ad(&f.env)));
    });
    assert!(
        f.client.guarded_ads().contains(ad(&f.env)),
        "still on the roster"
    );
    expect_err(
        owner_check(&f, &withdraw_ctx(&f, 1, &to)),
        AccountError::GuardRailArchived,
    );
}

/// J2. A threshold bounds one call; nothing bounded N of them, and one auth entry can carry
/// several. Design 02 §2.8's residual is a *flow rate* — "the sub-threshold flow rate until
/// detected, not the balance" — so the sub-threshold path spends a refilling bucket.
#[test]
fn t52_sub_threshold_withdrawals_are_bounded_by_a_flow_rate() {
    let f = fixture();
    let to = Address::generate(&f.env);
    // Anything at or under 100 needs no announcement, but only 250 may leave per 250 seconds.
    guard_rate(&f, 100, 3_600, 86_400, 250, 1);

    owner_check(&f, &withdraw_ctx(&f, 100, &to)).unwrap();
    owner_check(&f, &withdraw_ctx(&f, 100, &to)).unwrap();
    expect_err(
        owner_check(&f, &withdraw_ctx(&f, 100, &to)),
        AccountError::VolumeExceeded,
    );
    owner_check(&f, &withdraw_ctx(&f, 50, &to)).expect("the last of the bucket");

    f.env.ledger().set_timestamp(T0 + 10);
    owner_check(&f, &withdraw_ctx(&f, 10, &to)).expect("ten seconds of refill");
    expect_err(
        owner_check(&f, &withdraw_ctx(&f, 1, &to)),
        AccountError::VolumeExceeded,
    );
}

/// K3. `lock_for_order` moves the ad's free balance into escrow. It is bounded for the agent by
/// `limits`; leaving it unbounded for the owner would be a hole in a feature whose subject is
/// bounding the owner, so on a guarded ad it spends the same bucket.
#[test]
fn t52_the_owner_path_bounds_lock_for_order_too() {
    let f = fixture();
    guard_rate(&f, u128::MAX, 3_600, 86_400, 600_000, 1);

    let ctxs = lock_ctx(&f.env, &f.target, vec![&f.env, params(&f).into_val(&f.env)]);
    owner_check(&f, &ctxs).expect("500_000 fits");
    expect_err(owner_check(&f, &ctxs), AccountError::VolumeExceeded);
}

/// K6. Settings the schedules were made under are gone when the guardrail changes, so the
/// schedules go with them — or a matured row outlives its settings and the next arming is bypassed
/// by an announcement nobody remembers.
#[test]
fn t52_changing_the_guardrail_clears_its_schedules() {
    let f = fixture();
    let to = Address::generate(&f.env);
    guard(&f, 0, 3_600, 86_400);
    let withdraw = Symbol::new(&f.env, "withdraw_from_ad");
    let change = Symbol::new(&f.env, "set_guard_rail");

    f.client
        .schedule_extractive(&ad(&f.env), &withdraw, &100, &to);
    f.client.schedule_extractive(&ad(&f.env), &change, &0, &to);
    f.env.ledger().set_timestamp(T0 + 3_600);

    // Disarm, then re-arm: the old matured withdrawal must not survive the round trip.
    f.client.set_guard_rail(&ad(&f.env), &None);
    guard(&f, 0, 3_600, 86_400);
    assert!(f.client.schedule(&ad(&f.env), &withdraw).is_none());
    expect_err(
        owner_check(&f, &withdraw_ctx(&f, 100, &to)),
        AccountError::NotScheduled,
    );
}

/// The lever an owner reaches for on seeing an `ExtractiveScheduled`/// The lever an owner reaches for on seeing an `ExtractiveScheduled` they did not cause.
#[test]
fn t52_a_schedule_can_be_cancelled_before_it_matures() {
    let f = fixture();
    let to = Address::generate(&f.env);
    guard(&f, 0, 3_600, 86_400);
    let action = Symbol::new(&f.env, "withdraw_from_ad");
    f.client.schedule_extractive(&ad(&f.env), &action, &5, &to);
    f.client.cancel_extractive(&ad(&f.env), &action);

    f.env.ledger().set_timestamp(T0 + 3_600);
    expect_err(
        owner_check(&f, &withdraw_ctx(&f, 5, &to)),
        AccountError::NotScheduled,
    );
}

#[test]
fn t52_guardrail_input_is_validated() {
    let f = fixture();
    for bad in [(0_u64, 1_u64), (1, 0)] {
        assert_eq!(
            f.client.try_set_guard_rail(
                &ad(&f.env),
                &Some(GuardRail {
                    threshold: 0,
                    delay: bad.0,
                    window: bad.1,
                    rate: Limit {
                        capacity: 1,
                        refill_per_second: 1,
                    },
                    bucket: Bucket {
                        level: 0,
                        last_ts: 0,
                    },
                }),
            ),
            Err(Ok(AccountError::BadGuardRail)),
            "a zero delay does nothing and a zero window can never be used",
        );
    }
    // Scheduling against an ad with no guardrail is refused, and with its own code: NotScheduled
    // means "no matured schedule" everywhere else, and overloading it made the two
    // indistinguishable to anyone reading the error.
    assert_eq!(
        f.client.try_schedule_extractive(
            &ad(&f.env),
            &Symbol::new(&f.env, "withdraw_from_ad"),
            &1,
            &Address::generate(&f.env),
        ),
        Err(Ok(AccountError::NoGuardRail))
    );
    // And only the two extractive selectors can be scheduled at all.
    guard(&f, 0, 1, 1);
    assert_eq!(
        f.client.try_schedule_extractive(
            &ad(&f.env),
            &Symbol::new(&f.env, "set_settlement_signer"),
            &1,
            &Address::generate(&f.env),
        ),
        Err(Ok(AccountError::ActionNotAllowed))
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Pre-soak batch C: D6 and the agent account gaps
// ─────────────────────────────────────────────────────────────────────────

/// Built by `stellar contract build --optimize` before the tests, as CI does.
const ACCOUNT_WASM: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/release/agent_account.wasm");
const AD_MANAGER_WASM: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/release/ad_manager.wasm");
const MERKLE_WASM: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/release/merkle_manager.wasm");

/// `sha256(XDR(ScVal::Vec(args)))`, computed through the XDR crate the way a client would, not
/// through the contract's own helper.
fn commit(env: &Env, args: Vec<Val>) -> BytesN<32> {
    let sc = ScVal::try_from_val(env, &args.to_val()).unwrap();
    let bytes = sc.to_xdr(Limits::none()).unwrap();
    env.crypto()
        .sha256(&Bytes::from_slice(env, &bytes))
        .to_bytes()
}

fn policy_args(
    env: &Env,
    id: &BytesN<32>,
    tokens: &Vec<BytesN<32>>,
    valid_until: u64,
    signer: &BytesN<32>,
    scope: &Option<Vec<String>>,
    limits: &Vec<TokenLimit>,
) -> Vec<Val> {
    vec![
        env,
        id.into_val(env),
        vec![env, lock_for_order(env)].into_val(env),
        tokens.into_val(env),
        valid_until.into_val(env),
        signer.into_val(env),
        scope.into_val(env),
        limits.into_val(env),
    ]
}

fn sym_of(env: &Env, s: &str) -> Symbol {
    Symbol::new(env, s)
}

/// C-5 (D6): on a guarded account, `upgrade` needs a matured `upgrade` schedule naming exactly
/// that wasm hash, and the schedule is single use.
#[test]
fn c5_upgrade_on_a_guarded_account_needs_a_matured_schedule_for_that_wasm() {
    let f = fixture();
    let hash = f.env.deployer().upload_contract_wasm(ACCOUNT_WASM);
    let other = b32(&f.env, 0x42);
    let up = sym_of(&f.env, "upgrade");
    guard(&f, 0, 3_600, 86_400);

    assert_eq!(
        f.client.try_upgrade(&hash),
        Err(Ok(AccountError::NotScheduled))
    );

    // A matured schedule for a different wasm does not authorize this one.
    f.client.schedule_account_extractive(&up, &other);
    f.env.ledger().set_timestamp(T0 + 3_600);
    assert_eq!(
        f.client.try_upgrade(&hash),
        Err(Ok(AccountError::NotScheduled))
    );

    // The right hash, announced but not matured.
    f.client.schedule_account_extractive(&up, &hash);
    let s = f.client.account_schedule(&up).unwrap();
    assert_eq!(s.commitment, hash);
    assert_eq!(s.ready_at, T0 + 3_600 + 3_600);
    f.env.ledger().set_timestamp(T0 + 3_600 + 3_599);
    assert_eq!(
        f.client.try_upgrade(&hash),
        Err(Ok(AccountError::NotScheduled))
    );

    // Expired is refused too.
    f.env.ledger().set_timestamp(T0 + 3_600 + 3_600 + 86_400);
    assert_eq!(
        f.client.try_upgrade(&hash),
        Err(Ok(AccountError::NotScheduled))
    );

    // Matured and in the window: it goes through, and the row is spent.
    f.client.schedule_account_extractive(&up, &hash);
    f.env
        .ledger()
        .set_timestamp(T0 + 3_600 + 3_600 + 86_400 + 3_600);
    f.client.upgrade(&hash);
    assert!(f.client.account_schedule(&up).is_none(), "single use");
    assert_eq!(f.client.owner(), f.owner, "storage survived the swap");
}

/// 49S-1: a change announced under a short delay must wait the LONGER delay the owner arms
/// afterwards — a stolen key's 1-day upgrade cannot outrun a 7-day guard raised in the meantime.
#[test]
fn s1_arming_a_longer_guard_restamps_a_pending_change() {
    let f = fixture();
    let hash = f.env.deployer().upload_contract_wasm(ACCOUNT_WASM);
    let up = sym_of(&f.env, "upgrade");
    guard(&f, 0, 3_600, 7 * 86_400);
    f.client.schedule_account_extractive(&up, &hash);
    assert_eq!(f.client.account_schedule(&up).unwrap().ready_at, T0 + 3_600);

    // The owner tightens the delay to seven days while the change is pending.
    guard(&f, 0, 7 * 86_400, 7 * 86_400);
    assert_eq!(
        f.client.account_schedule(&up).unwrap().ready_at,
        T0 + 7 * 86_400,
        "the pending row now waits the new delay"
    );
    f.env.ledger().set_timestamp(T0 + 3_600 + 1);
    assert_eq!(
        f.client.try_upgrade(&hash),
        Err(Ok(AccountError::NotScheduled)),
        "the old delay no longer opens it"
    );
    f.env.ledger().set_timestamp(T0 + 7 * 86_400 + 1);
    f.client.upgrade(&hash);
}

/// Arm another ad on the same account (threshold 0, a wide bucket).
fn guard_other(f: &Fixture, id: &str, delay: u64, window: u64) {
    f.client.set_guard_rail(
        &String::from_str(&f.env, id),
        &Some(GuardRail {
            threshold: 0,
            delay,
            window,
            rate: Limit {
                capacity: u128::MAX / 2,
                refill_per_second: 1,
            },
            bucket: Bucket {
                level: 0,
                last_ts: 0,
            },
        }),
    );
}

/// Pending rows of every kind: the ad's withdraw, its lock, and the account-wide upgrade.
fn schedule_one_of_each(f: &Fixture) -> (Symbol, BytesN<32>) {
    let hash = f.env.deployer().upload_contract_wasm(ACCOUNT_WASM);
    let up = sym_of(&f.env, "upgrade");
    f.client.schedule_account_extractive(&up, &hash);
    f.client.schedule_extractive(
        &ad(&f.env),
        &sym_of(&f.env, "withdraw_from_ad"),
        &1,
        &Address::generate(&f.env),
    );
    let args = vec![&f.env, Val::from_u32(1).to_val()];
    f.client
        .schedule_lock(&ad(&f.env), &500_000, &commit(&f.env, args));
    (up, hash)
}

/// (ready_at, expires_at) of the three rows `schedule_one_of_each` made.
fn clocks(f: &Fixture, up: &Symbol) -> [(u64, u64); 3] {
    let a = f.client.account_schedule(up).unwrap();
    let w = f
        .client
        .schedule(&ad(&f.env), &sym_of(&f.env, "withdraw_from_ad"))
        .unwrap();
    let l = f.client.lock_schedule(&ad(&f.env)).unwrap();
    [
        (a.ready_at, a.expires_at),
        (w.ready_at, w.expires_at),
        (l.ready_at, l.expires_at),
    ]
}

/// 49S-1 dead rows: a re-stamp moves `expires_at` with `ready_at`, so a 1 h / 1-day row tightened to
/// a 7-day delay opens at day 7 and is still usable inside its window.
#[test]
fn s1_a_restamped_row_keeps_its_window() {
    let f = fixture();
    guard(&f, 0, 3_600, 86_400);
    let (up, hash) = schedule_one_of_each(&f);
    guard(&f, 0, 7 * 86_400, 86_400);
    let want = (T0 + 7 * 86_400, T0 + 7 * 86_400 + 86_400);
    assert_eq!(clocks(&f, &up), [want; 3], "every row shifted whole");
    f.env.ledger().set_timestamp(T0 + 7 * 86_400 + 86_400 - 1);
    f.client.upgrade(&hash);
}

/// A threshold-only tightening raises no delay, so pending clocks stay where they were.
#[test]
fn s1_a_threshold_only_tightening_leaves_pending_clocks() {
    let f = fixture();
    guard(&f, 100, 3_600, 86_400);
    let (up, _) = schedule_one_of_each(&f);
    let before = clocks(&f, &up);
    f.env.ledger().set_timestamp(T0 + 1_800);
    guard(&f, 50, 3_600, 86_400);
    assert_eq!(clocks(&f, &up), before);
}

/// Account-wide rows follow the account's longest delay: arming a second ad with a shorter delay
/// leaves them alone, arming one with a longer delay re-stamps them (and not the first ad's rows).
#[test]
fn s1_account_rows_restamp_only_when_the_longest_delay_rises() {
    let f = fixture();
    guard(&f, 0, 7 * 86_400, 7 * 86_400);
    let (up, _) = schedule_one_of_each(&f);
    let before = clocks(&f, &up);
    let now = T0 + 7 * 86_400 - 10;
    f.env.ledger().set_timestamp(now);
    guard_other(&f, "ad-2", 3_600, 7 * 86_400);
    assert_eq!(clocks(&f, &up), before, "a shorter delay moves nothing");

    guard_other(&f, "ad-3", 14 * 86_400, 7 * 86_400);
    let after = clocks(&f, &up);
    let shift = now + 14 * 86_400 - before[0].0;
    assert_eq!(after[0], (before[0].0 + shift, before[0].1 + shift));
    assert_eq!(
        &after[1..],
        &before[1..],
        "the first ad's own rows keep its delay"
    );
}

/// 49S-4: disarming clears the pending lock schedule along with the others.
#[test]
fn s4_disarming_clears_the_lock_schedule() {
    let f = fixture();
    guard(&f, 0, 3_600, 86_400);
    let args = vec![&f.env, Val::from_u32(1).to_val()];
    f.client
        .schedule_lock(&ad(&f.env), &500_000, &commit(&f.env, args));
    let has = |f: &Fixture| {
        f.env.as_contract(&f.account, || {
            policy::get_lock_schedule(&f.env, &ad(&f.env)).is_some()
        })
    };
    assert!(has(&f), "scheduled");
    // Disarming is a loosening: announced, then waited out (T-52).
    let to = Address::generate(&f.env);
    f.client
        .schedule_extractive(&ad(&f.env), &Symbol::new(&f.env, "set_guard_rail"), &0, &to);
    f.env.ledger().set_timestamp(T0 + 3_600);
    f.client.set_guard_rail(&ad(&f.env), &None);
    assert!(!has(&f), "disarming cleared it");
}

/// C-5: an unguarded account upgrades as it always did, with no schedule.
#[test]
fn c5_an_unguarded_account_upgrades_instantly() {
    let f = fixture();
    let hash = f.env.deployer().upload_contract_wasm(ACCOUNT_WASM);
    f.client.upgrade(&hash);
    assert_eq!(f.client.owner(), f.owner);
}

/// D6: the account-wide delay is the longest across the roster and the window the shortest, so
/// guarding a second ad with a short delay cannot shorten the wait. Scheduling needs a roster.
#[test]
fn d6_account_schedules_take_the_strictest_guardrail() {
    let f = fixture();
    let up = sym_of(&f.env, "upgrade");
    assert_eq!(
        f.client
            .try_schedule_account_extractive(&up, &b32(&f.env, 1)),
        Err(Ok(AccountError::NoGuardRail))
    );
    assert_eq!(
        f.client
            .try_schedule_account_extractive(&sym_of(&f.env, "withdraw_from_ad"), &b32(&f.env, 1)),
        Err(Ok(AccountError::ActionNotAllowed))
    );
    guard(&f, 0, 86_400, 600);
    f.client.set_guard_rail(
        &String::from_str(&f.env, "ad-2"),
        &Some(GuardRail {
            threshold: 0,
            delay: 60,
            window: 86_400,
            rate: Limit {
                capacity: 1,
                refill_per_second: 1,
            },
            bucket: Bucket {
                level: 0,
                last_ts: 0,
            },
        }),
    );
    f.client.schedule_account_extractive(&up, &b32(&f.env, 1));
    let s = f.client.account_schedule(&up).unwrap();
    assert_eq!(s.ready_at, T0 + 86_400);
    assert_eq!(s.expires_at, T0 + 86_400 + 600);

    f.client.cancel_account_extractive(&up);
    assert!(f.client.account_schedule(&up).is_none());
    assert_eq!(
        f.client.try_cancel_account_extractive(&up),
        Err(Ok(AccountError::NotScheduled))
    );

    // Disarming a guardrail clears the account-wide rows timed against it.
    f.client.schedule_account_extractive(&up, &b32(&f.env, 1));
    f.client
        .schedule_extractive(&ad(&f.env), &sym_of(&f.env, "set_guard_rail"), &0, &f.owner);
    f.env.ledger().set_timestamp(T0 + 86_400);
    f.client.set_guard_rail(&ad(&f.env), &None);
    assert!(f.client.account_schedule(&up).is_none());
}

/// C-40: the swap lands after `upgrade` returns, so `upgrade` must not claim a version; the new
/// code's `migrate` writes the one it expects. Storage survives the swap.
#[test]
fn c40_upgrade_leaves_the_marker_and_migrate_moves_it() {
    let f = fixture();
    // An account written by an older code: marker 1.
    f.env.as_contract(&f.account, || {
        f.env
            .storage()
            .instance()
            .set(&policy::DataKey::SchemaVersion, &1_u32);
    });
    let hash = f.env.deployer().upload_contract_wasm(ACCOUNT_WASM);
    f.client.upgrade(&hash);
    assert_eq!(f.client.schema_version(), 1, "upgrade claims no version");

    assert_eq!(f.client.migrate(), SCHEMA_VERSION);
    assert_eq!(f.client.schema_version(), SCHEMA_VERSION);
    assert_eq!(f.client.owner(), f.owner);
    assert_eq!(f.client.targets(), vec![&f.env, f.target.clone()]);
    assert!(f.client.policy(&f.agent.id(&f.env)).is_some());

    // A marker from newer code is a downgrade this code cannot read.
    f.env.as_contract(&f.account, || {
        f.env
            .storage()
            .instance()
            .set(&policy::DataKey::SchemaVersion, &(SCHEMA_VERSION + 1));
    });
    assert_eq!(f.client.try_migrate(), Err(Ok(AccountError::SchemaTooNew)));
}

/// C-40, on the running code rather than the uploaded wasm: `migrate` moves an old marker forward
/// and refuses a newer one.
#[test]
fn c40_migrate_moves_an_old_marker_and_refuses_a_newer_one() {
    let f = fixture();
    let set = |v: u32| {
        f.env.as_contract(&f.account, || {
            f.env
                .storage()
                .instance()
                .set(&policy::DataKey::SchemaVersion, &v);
        })
    };
    set(1);
    assert_eq!(f.client.migrate(), SCHEMA_VERSION);
    assert_eq!(f.client.schema_version(), SCHEMA_VERSION);
    set(SCHEMA_VERSION + 1);
    assert_eq!(f.client.try_migrate(), Err(Ok(AccountError::SchemaTooNew)));
    assert_eq!(f.client.schema_version(), SCHEMA_VERSION + 1);
}

/// C-29: every loosening axis of `set_policy` is refused unannounced on a guarded account, and the
/// boundary sits exactly at "no wider than now": equal is instant, one more is scheduled.
#[test]
fn c29_loosening_set_policy_is_scheduled_on_a_guarded_account() {
    let f = fixture();
    let id = f.agent.id(&f.env);
    let extra = b32(&f.env, 0x77);
    f.client.set_account_limit(
        &extra,
        &Limit {
            capacity: u128::MAX / 2,
            refill_per_second: 1,
        },
    );
    let two = vec![&f.env, f.ad_token.clone(), f.order_token.clone()];
    let scope = Some(vec![&f.env, ad(&f.env)]);
    let base = |max: u128, cap: u128, refill: u128| {
        let mut v = Vec::new(&f.env);
        for t in two.iter() {
            v.push_back(tl(&t, max, cap, refill));
        }
        v
    };
    let until = T0 + 10_000;
    f.client.set_policy(
        &id,
        &vec![&f.env, lock_for_order(&f.env)],
        &two,
        &until,
        &f.signer,
        &scope,
        &base(1_000, 2_000, 10),
    );
    guard(&f, 0, 3_600, 86_400);

    let try_set = |tokens: &Vec<BytesN<32>>,
                   until: u64,
                   scope: &Option<Vec<String>>,
                   limits: &Vec<TokenLimit>| {
        f.client.try_set_policy(
            &id,
            &vec![&f.env, lock_for_order(&f.env)],
            tokens,
            &until,
            &f.signer,
            scope,
            limits,
        )
    };
    let three = vec![
        &f.env,
        f.ad_token.clone(),
        f.order_token.clone(),
        extra.clone(),
    ];
    let mut three_limits = base(1_000, 2_000, 10);
    three_limits.push_back(tl(&extra, 1, 1, 1));
    let loosening: [(
        &str,
        Vec<BytesN<32>>,
        u64,
        Option<Vec<String>>,
        Vec<TokenLimit>,
    ); 8] = [
        (
            "cap +1",
            two.clone(),
            until,
            scope.clone(),
            base(1_001, 2_000, 10),
        ),
        (
            "capacity +1",
            two.clone(),
            until,
            scope.clone(),
            base(1_000, 2_001, 10),
        ),
        (
            "refill +1",
            two.clone(),
            until,
            scope.clone(),
            base(1_000, 2_000, 11),
        ),
        (
            "a new token",
            three.clone(),
            until,
            scope.clone(),
            three_limits.clone(),
        ),
        (
            "expiry +1",
            two.clone(),
            until + 1,
            scope.clone(),
            base(1_000, 2_000, 10),
        ),
        (
            "expiry removed",
            two.clone(),
            0,
            scope.clone(),
            base(1_000, 2_000, 10),
        ),
        (
            "a wider scope",
            two.clone(),
            until,
            Some(vec![&f.env, ad(&f.env), String::from_str(&f.env, "ad-2")]),
            base(1_000, 2_000, 10),
        ),
        (
            "scope dropped",
            two.clone(),
            until,
            None,
            base(1_000, 2_000, 10),
        ),
    ];
    for (label, tokens, u, sc, limits) in loosening.iter() {
        assert_eq!(
            try_set(tokens, *u, sc, limits),
            Err(Ok(AccountError::NotScheduled)),
            "{label} is loosening"
        );
    }
    // A new agent key is loosening by definition.
    assert_eq!(
        f.client.try_set_policy(
            &Agent::new(99).id(&f.env),
            &vec![&f.env, lock_for_order(&f.env)],
            &two,
            &until,
            &f.signer,
            &scope,
            &base(1_000, 2_000, 10),
        ),
        Err(Ok(AccountError::NotScheduled))
    );

    // Equal on every axis, and each axis one step tighter, are instant.
    let one = vec![&f.env, f.ad_token.clone()];
    let mut one_limits = Vec::new(&f.env);
    one_limits.push_back(tl(&f.ad_token, 999, 1_999, 9));
    let tightening: [(
        &str,
        Vec<BytesN<32>>,
        u64,
        Option<Vec<String>>,
        Vec<TokenLimit>,
    ); 6] = [
        (
            "equal",
            two.clone(),
            until,
            scope.clone(),
            base(1_000, 2_000, 10),
        ),
        (
            "cap -1",
            two.clone(),
            until,
            scope.clone(),
            base(999, 2_000, 10),
        ),
        (
            "capacity -1",
            two.clone(),
            until,
            scope.clone(),
            base(999, 1_999, 10),
        ),
        (
            "refill -1",
            two.clone(),
            until,
            scope.clone(),
            base(999, 1_999, 9),
        ),
        (
            "expiry -1",
            two.clone(),
            until - 1,
            scope.clone(),
            base(999, 1_999, 9),
        ),
        (
            "a token dropped",
            one.clone(),
            until - 1,
            scope.clone(),
            one_limits.clone(),
        ),
    ];
    for (label, tokens, u, sc, limits) in tightening.iter() {
        assert_eq!(
            try_set(tokens, *u, sc, limits),
            Ok(Ok(())),
            "{label} is instant"
        );
    }

    // Announced and matured, a loosening write goes through, but only the exact one announced.
    let limits = base(5_000, 5_000, 50);
    let args = policy_args(&f.env, &id, &two, 0, &f.signer, &None, &limits);
    f.client
        .schedule_account_extractive(&sym_of(&f.env, "set_policy"), &commit(&f.env, args));
    f.env.ledger().set_timestamp(T0 + 3_600);
    assert_eq!(
        try_set(&two, 0, &None, &base(5_000, 5_000, 51)),
        Err(Ok(AccountError::NotScheduled)),
        "a different write than the one announced"
    );
    assert_eq!(try_set(&two, 0, &None, &limits), Ok(Ok(())));
    assert!(f
        .client
        .account_schedule(&sym_of(&f.env, "set_policy"))
        .is_none());
}

/// C-29: an unscoped, non-expiring policy admits any scope and any expiry as tightening.
#[test]
fn c29_narrowing_an_open_policy_is_instant() {
    let f = fixture();
    guard(&f, 0, 3_600, 86_400);
    let tokens = vec![&f.env, f.ad_token.clone(), f.order_token.clone()];
    let mut limits = Vec::new(&f.env);
    for t in tokens.iter() {
        limits.push_back(tl(&t, 1_000_000, u128::MAX / 2, 1));
    }
    f.client.set_policy(
        &f.agent.id(&f.env),
        &vec![&f.env, lock_for_order(&f.env)],
        &tokens,
        &(T0 + 5),
        &f.signer,
        &Some(vec![&f.env, ad(&f.env)]),
        &limits,
    );
    assert_eq!(
        f.client.policy(&f.agent.id(&f.env)).unwrap().valid_until,
        T0 + 5
    );
}

/// C-29: an instant tightening must not refill the agent's spent bucket. Re-installing used to
/// reset it, which made "tighten" a way to top the agent up.
#[test]
fn c29_a_tightening_write_keeps_the_spent_bucket() {
    let f = fixture();
    install_metered(&f, 1_000, 1, None);
    agent_check(&f, &lock_of(&f, 1_000, "ad-1")).expect("drain the bucket");
    guard(&f, 0, 3_600, 86_400);
    install_metered(&f, 1_000, 1, None);
    expect_err(
        agent_check(&f, &lock_of(&f, 1, "ad-1")),
        AccountError::VolumeExceeded,
    );
    f.env.ledger().set_timestamp(T0 + 5);
    agent_check(&f, &lock_of(&f, 5, "ad-1")).expect("five seconds of refill, no more");
}

/// C-29: `set_account_limit` loosening (a first limit, a higher capacity or refill) is scheduled on
/// a guarded account; equal or lower is instant.
#[test]
fn c29_loosening_an_account_limit_is_scheduled() {
    let f = fixture();
    let lim = |capacity: u128, refill_per_second: u128| Limit {
        capacity,
        refill_per_second,
    };
    f.client.set_account_limit(&f.ad_token, &lim(1_000, 10));
    guard(&f, 0, 3_600, 86_400);

    for (label, l) in [
        ("capacity +1", lim(1_001, 10)),
        ("refill +1", lim(1_000, 11)),
    ] {
        assert_eq!(
            f.client.try_set_account_limit(&f.ad_token, &l),
            Err(Ok(AccountError::NotScheduled)),
            "{label}"
        );
    }
    assert_eq!(
        f.client
            .try_set_account_limit(&b32(&f.env, 0x55), &lim(1, 1)),
        Err(Ok(AccountError::NotScheduled)),
        "a first limit for a token"
    );
    f.client.set_account_limit(&f.ad_token, &lim(1_000, 10));
    f.client.set_account_limit(&f.ad_token, &lim(999, 9));

    let raised = lim(5_000, 50);
    f.client.schedule_account_extractive(
        &sym_of(&f.env, "set_account_limit"),
        &commit(
            &f.env,
            vec![&f.env, f.ad_token.to_val(), raised.into_val(&f.env)],
        ),
    );
    f.env.ledger().set_timestamp(T0 + 3_600);
    f.client.set_account_limit(&f.ad_token, &raised);
    assert_eq!(
        f.client.try_set_account_limit(&f.ad_token, &lim(5_001, 50)),
        Err(Ok(AccountError::NotScheduled)),
        "single use"
    );
}

/// C-29: adding a target widens where an agent may call; removing one is instant.
#[test]
fn c29_adding_a_target_is_scheduled_removing_is_not() {
    let f = fixture();
    guard(&f, 0, 3_600, 86_400);
    let extra = Address::generate(&f.env);
    assert_eq!(
        f.client
            .try_set_targets(&vec![&f.env, f.target.clone(), extra.clone()]),
        Err(Ok(AccountError::NotScheduled))
    );
    f.client.set_targets(&vec![&f.env, f.target.clone()]);
}

/// C-33: on the roster with no row is archived, not unarmed. `set_guard_rail` used to read it as
/// "never armed" and disarm instantly while the owner path refused the same state.
#[test]
fn c33_set_guard_rail_refuses_an_archived_row() {
    let f = fixture();
    guard(&f, 0, 3_600, 86_400);
    f.env.as_contract(&f.account, || {
        f.env
            .storage()
            .persistent()
            .remove(&policy::DataKey::GuardRail(ad(&f.env)));
    });
    assert_eq!(
        f.client.try_set_guard_rail(&ad(&f.env), &None),
        Err(Ok(AccountError::GuardRailArchived))
    );
    assert_eq!(
        f.client.try_set_guard_rail(
            &ad(&f.env),
            &Some(GuardRail {
                threshold: u128::MAX,
                delay: 1,
                window: 1,
                rate: Limit {
                    capacity: 1,
                    refill_per_second: 1,
                },
                bucket: Bucket {
                    level: 0,
                    last_ts: 0,
                },
            }),
        ),
        Err(Ok(AccountError::GuardRailArchived))
    );
    assert_eq!(
        f.client.try_schedule_extractive(
            &ad(&f.env),
            &sym_of(&f.env, "withdraw_from_ad"),
            &1,
            &f.owner,
        ),
        Err(Ok(AccountError::GuardRailArchived))
    );
    assert_eq!(
        f.client
            .try_schedule_account_extractive(&sym_of(&f.env, "upgrade"), &b32(&f.env, 1)),
        Err(Ok(AccountError::GuardRailArchived))
    );
    assert!(f.client.guarded_ads().contains(ad(&f.env)));
}

/// C-32: the owner can lock above the threshold on a guarded ad by scheduling that exact order.
#[test]
fn c32_an_above_threshold_owner_lock_can_be_scheduled_for_one_order() {
    let f = fixture();
    guard(&f, 100, 3_600, 86_400);
    let order = params(&f);
    let args: Vec<Val> = vec![&f.env, order.clone().into_val(&f.env)];
    let ctxs = lock_ctx(&f.env, &f.target, args.clone());

    expect_err(owner_check(&f, &ctxs), AccountError::NotScheduled);
    // The per-ad scheduler still refuses the lock selector: it has no order to bind.
    assert_eq!(
        f.client
            .try_schedule_extractive(&ad(&f.env), &lock_for_order(&f.env), &500_000, &f.owner),
        Err(Ok(AccountError::ActionNotAllowed))
    );

    f.client
        .schedule_lock(&ad(&f.env), &500_000, &commit(&f.env, args.clone()));
    expect_err(owner_check(&f, &ctxs), AccountError::NotScheduled);
    f.env.ledger().set_timestamp(T0 + 3_600);

    // Same amount, a different order: refused.
    let mut other = params(&f);
    other.salt = soroban_sdk::U256::from_u128(&f.env, 43);
    let other_ctx = lock_ctx(&f.env, &f.target, vec![&f.env, other.into_val(&f.env)]);
    expect_err(owner_check(&f, &other_ctx), AccountError::NotScheduled);

    owner_check(&f, &ctxs).expect("the announced order");
    expect_err(owner_check(&f, &ctxs), AccountError::NotScheduled);

    // A wrong amount on the schedule is refused even with the right commitment.
    f.client
        .schedule_lock(&ad(&f.env), &499_999, &commit(&f.env, args.clone()));
    f.env.ledger().set_timestamp(T0 + 7_200);
    expect_err(owner_check(&f, &ctxs), AccountError::NotScheduled);

    // And a lock schedule can be cancelled.
    f.client
        .schedule_lock(&ad(&f.env), &500_000, &commit(&f.env, args));
    f.client
        .cancel_extractive(&ad(&f.env), &lock_for_order(&f.env));
    assert!(f.client.lock_schedule(&ad(&f.env)).is_none());
    f.env.ledger().set_timestamp(T0 + 10_800);
    expect_err(owner_check(&f, &ctxs), AccountError::NotScheduled);
}

/// The data of the last event this contract emitted.
fn last_event_data(env: &Env, contract: &Address) -> ScVal {
    let all = env.events().all().filter_by_contract(contract);
    let ev = all.events().last().unwrap().clone();
    match ev.body {
        xdr::ContractEventBody::V0(v0) => v0.data,
    }
}

fn sc<T: IntoVal<Env, Val>>(env: &Env, v: T) -> ScVal {
    ScVal::try_from_val(env, &v.into_val(env)).unwrap()
}

/// C-34: `PolicySet` carries the fingerprint and `AccountLimitSet` the numbers.
#[test]
fn c34_policy_and_limit_events_say_what_changed() {
    let f = fixture();
    let id = f.agent.id(&f.env);
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
    let data = last_event_data(&f.env, &f.account);
    let topics = event_topics(&f.env, &f.account, true);
    let fp = f.client.policy_fingerprint(&id);
    assert_eq!(topics, std::vec![sym("pol_set"), bytes32(&id)]);
    assert_eq!(
        data,
        ScVal::Vec(Some(
            std::vec![
                sc(&f.env, f.signer.clone()),
                sc(&f.env, 0_u64),
                sc(&f.env, fp)
            ]
            .try_into()
            .unwrap()
        ))
    );

    f.client.set_account_limit(
        &f.ad_token,
        &Limit {
            capacity: 1_234,
            refill_per_second: 56,
        },
    );
    assert_eq!(
        event_topics(&f.env, &f.account, true),
        std::vec![sym("acct_lim"), bytes32(&f.ad_token)]
    );
    assert_eq!(
        last_event_data(&f.env, &f.account),
        ScVal::Vec(Some(
            std::vec![sc(&f.env, 1_234_u128), sc(&f.env, 56_u128)]
                .try_into()
                .unwrap()
        ))
    );
}

/// The contract's exported functions, read from the wasm's `contractspecv0` section.
fn exported_fns() -> std::collections::BTreeSet<std::string::String> {
    use soroban_sdk::xdr::{Limited, ReadXdr, ScSpecEntry};
    let w = ACCOUNT_WASM;
    let leb = |i: &mut usize| -> usize {
        let (mut v, mut shift) = (0usize, 0);
        loop {
            let b = w[*i];
            *i += 1;
            v |= ((b & 0x7f) as usize) << shift;
            if b & 0x80 == 0 {
                return v;
            }
            shift += 7;
        }
    };
    let mut i = 8;
    let mut out = std::collections::BTreeSet::new();
    while i < w.len() {
        let id = w[i];
        i += 1;
        let len = leb(&mut i);
        let end = i + len;
        if id == 0 {
            let mut j = i;
            let nlen = leb(&mut j);
            if &w[j..j + nlen] == b"contractspecv0" {
                let mut r = Limited::new(std::io::Cursor::new(&w[j + nlen..end]), Limits::none());
                for e in ScSpecEntry::read_xdr_iter(&mut r) {
                    if let ScSpecEntry::FunctionV0(f) = e.unwrap() {
                        out.insert(f.name.to_utf8_string().unwrap());
                    }
                }
            }
        }
        i = end;
    }
    out
}

/// C-9: every owner-only entry point refuses a caller that is not the owner, with the host's auth
/// error and before touching state. The list is checked against the wasm's exported functions, so
/// a new entry point cannot land without a row here or on the view list.
#[test]
fn c9_every_owner_only_entry_point_refuses_a_non_owner() {
    let f = fixture();
    guard(&f, 0, 3_600, 86_400);
    let e = &f.env;
    let id = f.agent.id(e);
    let tokens = vec![e, f.ad_token.clone(), f.order_token.clone()];
    let g = GuardRail {
        threshold: 0,
        delay: 3_600,
        window: 86_400,
        rate: Limit {
            capacity: 1,
            refill_per_second: 1,
        },
        bucket: Bucket {
            level: 0,
            last_ts: 0,
        },
    };
    let owner_only: std::vec::Vec<(&str, Vec<Val>)> = std::vec![
        ("set_targets", vec![e, vec![e, f.target.clone()].to_val()]),
        (
            "set_policy",
            policy_args(e, &id, &tokens, 0, &f.signer, &None, &wide(e, &tokens))
        ),
        (
            "set_account_limit",
            vec![
                e,
                f.ad_token.to_val(),
                Limit {
                    capacity: 1,
                    refill_per_second: 1
                }
                .into_val(e)
            ]
        ),
        (
            "set_guard_rail",
            vec![e, ad(e).to_val(), Some(g).into_val(e)]
        ),
        (
            "schedule_extractive",
            vec![
                e,
                ad(e).to_val(),
                sym_of(e, "withdraw_from_ad").to_val(),
                1_u128.into_val(e),
                f.owner.to_val()
            ]
        ),
        (
            "schedule_lock",
            vec![e, ad(e).to_val(), 1_u128.into_val(e), b32(e, 1).to_val()]
        ),
        (
            "cancel_extractive",
            vec![e, ad(e).to_val(), sym_of(e, "withdraw_from_ad").to_val()]
        ),
        (
            "schedule_account_extractive",
            vec![e, sym_of(e, "upgrade").to_val(), b32(e, 1).to_val()]
        ),
        (
            "cancel_account_extractive",
            vec![e, sym_of(e, "upgrade").to_val()]
        ),
        ("revoke_agent", vec![e, id.to_val()]),
        ("upgrade", vec![e, b32(e, 0x42).to_val()]),
        ("migrate", vec![e]),
    ];
    let views = [
        "__constructor",
        "__check_auth",
        "guard_rail",
        "guarded_ads",
        "schedule",
        "lock_schedule",
        "account_schedule",
        "policy_fingerprint",
        "owner",
        "targets",
        "policy",
        "is_revoked",
        "schema_version",
    ];
    let mut listed: std::collections::BTreeSet<std::string::String> = views
        .iter()
        .map(|s| std::string::String::from(*s))
        .collect();
    for (name, _) in owner_only.iter() {
        listed.insert(std::string::String::from(*name));
    }
    assert_eq!(
        exported_fns(),
        listed,
        "every export is on one of the two lists"
    );

    // What the host returns when `require_auth` finds no authorization in a called contract.
    let auth_error: Result<(), Result<soroban_sdk::Error, InvokeError>> =
        Err(Ok(soroban_sdk::Error::from_type_and_code(
            xdr::ScErrorType::Context,
            xdr::ScErrorCode::InvalidAction,
        )));
    let before = f.client.policy(&id).unwrap();
    // A stranger signs everything; the owner signs nothing.
    let stranger = Address::generate(e);
    for (name, args) in owner_only.iter() {
        let fn_name = sym_of(e, name);
        e.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &stranger,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &f.account,
                fn_name: name,
                args: args.clone(),
                sub_invokes: &[],
            },
        }]);
        let r = e
            .try_invoke_contract::<Val, soroban_sdk::Error>(&f.account, &fn_name, args.clone())
            .map(|_| ());
        assert_eq!(r, auth_error, "{name} must refuse a non-owner");
    }
    // Nothing moved.
    assert_eq!(f.client.policy(&id).unwrap().limits, before.limits);
    assert!(f.client.guard_rail(&ad(e)).is_some());
    assert_eq!(f.client.targets(), vec![e, f.target.clone()]);

    // Positive control: with the owner signing, none of them fails on auth.
    e.mock_all_auths();
    for (name, args) in owner_only.iter() {
        if *name == "upgrade" {
            continue; // a made-up hash traps in the host; covered by the C-5 tests.
        }
        let r = e
            .try_invoke_contract::<Val, soroban_sdk::Error>(
                &f.account,
                &sym_of(e, name),
                args.clone(),
            )
            .map(|_| ());
        assert_ne!(r, auth_error, "{name} passed auth for the owner");
    }
}

/// C-6: an agent lock at the policy's maximal shape, metered against the network's per-transaction
/// limits. Everything the lock touches is wasm (account, AdManager, MerkleManager) or a built-in
/// (the SAC token), so VM instantiation and storage reads are in the figure. Only the key registry
/// is a native mock.
///
/// Limits: `InvocationResourceLimits::mainnet()` in soroban-sdk 28 (a 2026-07-10 snapshot of
/// `stellar network settings --network mainnet`): 400M instructions, 41,943,040 bytes of memory,
/// 200 disk reads, 200 writes, 400 footprint entries, 132,096 write bytes, 16,384 event bytes.
///
/// Measured 2026-09-28 (SDK 28.0.0-rc.1, optimized wasm): 14.0M instructions (3.5% of the limit),
/// 3.23MB memory (7.7%), 0 disk reads, 21 in-memory reads, 9 writes, 7,028 write bytes.
#[test]
fn test_agent_lock_metering() {
    let env = Env::default();
    env.ledger().set_timestamp(T0);
    env.ledger().set_protocol_version(PROTOCOL);
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let owner = env.register(MockAuthContract, ());
    let ad_manager = env.register(AD_MANAGER_WASM, ());
    let merkle = env.register(MERKLE_WASM, ());
    let sac = env.register_stellar_asset_contract_v2(admin.clone());
    let token = sac.address();
    let account = env.register(
        ACCOUNT_WASM,
        (owner.clone(), vec![&env, ad_manager.clone()]),
    );
    let client = AgentAccountClient::new(&env, &account);

    let ad_token = address_to_bytes32(&env, &token);
    let order_token = b32(&env, 0xBB);
    let portal = b32(&env, 0xFF);
    let order_chain_id: u128 = 1;
    let mm = merkle_manager::ProofBridgeMerkleManagerContractClient::new(&env, &merkle);
    mm.initialize(&admin);
    mm.set_manager(&ad_manager, &true);
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
    soroban_sdk::token::StellarAssetClient::new(&env, &token).mint(&account, &10_000_000_i128);
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

    // Maximal policy: 16 tokens with their limits, 16 ads in scope, 16 guarded ads.
    // The lock's two tokens and its ad go last, so every linear scan runs its full length.
    let mut tokens = Vec::new(&env);
    for i in 0..(MAX_WHITELIST_TOKENS - 2) {
        tokens.push_back(b32(&env, 0x10 + i as u8));
    }
    tokens.push_back(order_token.clone());
    tokens.push_back(ad_token.clone());
    let mut limits = Vec::new(&env);
    for t in tokens.iter() {
        client.set_account_limit(
            &t,
            &Limit {
                capacity: u128::MAX / 2,
                refill_per_second: 1,
            },
        );
        limits.push_back(tl(&t, 1_000_000, u128::MAX / 2, 1));
    }
    let mut scope = Vec::new(&env);
    for i in 0..MAX_AD_SCOPE {
        let id = if i == MAX_AD_SCOPE - 1 {
            ad_id.clone()
        } else {
            String::from_str(&env, &std::format!("ad-scope-{i:02}"))
        };
        scope.push_back(id);
    }
    let agent = Agent::new(7);
    client.set_policy(
        &agent.id(&env),
        &vec![&env, lock_for_order(&env)],
        &tokens,
        &0_u64,
        &signer,
        &Some(scope),
        &limits,
    );
    for i in 0..policy::MAX_GUARDED_ADS {
        let g = if i == policy::MAX_GUARDED_ADS - 1 {
            ad_id.clone()
        } else {
            String::from_str(&env, &std::format!("guarded-{i:02}"))
        };
        client.set_guard_rail(
            &g,
            &Some(GuardRail {
                threshold: 1,
                delay: 3_600,
                window: 86_400,
                rate: Limit {
                    capacity: 1,
                    refill_per_second: 1,
                },
                bucket: Bucket {
                    level: 0,
                    last_ts: 0,
                },
            }),
        );
    }
    assert_eq!(client.guarded_ads().len(), policy::MAX_GUARDED_ADS);

    // The real agent path: a signed auth entry, the escrow's require_auth, the wasm __check_auth.
    let e = Escrow {
        env: env.clone(),
        owner,
        account: account.clone(),
        ad_manager: ad_manager.clone(),
        ad_token,
        order_token,
        portal,
        order_chain_id,
        ad_id,
        agent,
    };
    let exp = env.ledger().sequence() + 100;
    let p_val: Val = escrow_params(&e, 400_000).into_val(&env);
    let inv = invocation(
        &ad_manager,
        "lock_for_order",
        std::vec![sc_val(&env, p_val)],
    );
    let payload = payload_hash(&env, &account, &inv, 1, exp, Creds::V2);
    let sig = sc_val(&env, e.agent.sign(&env, &payload).into_val(&env));
    env.set_auths(&[entry(&account, inv, 1, exp, sig, Creds::V2)]);
    env.cost_estimate().budget().reset_default();
    let _: BytesN<32> = env.invoke_contract(
        &ad_manager,
        &Symbol::new(&env, "lock_for_order"),
        vec![&env, p_val],
    );
    let r = env.cost_estimate().resources();
    std::println!(
        "agent lock_for_order (maximal policy, 16 guarded ads): cpu {} insns, mem {} bytes, \
         disk reads {}, memory reads {}, writes {}, write bytes {}, disk read bytes {}, event bytes {}",
        r.instructions,
        r.mem_bytes,
        r.disk_read_entries,
        r.memory_read_entries,
        r.write_entries,
        r.write_bytes,
        r.disk_read_bytes,
        r.contract_events_size_bytes,
    );
    assert_eq!(liquidity(&e), 4_600_000, "the lock landed");

    // The SDK does not re-export `InvocationResourceLimits`; these are its `mainnet()` values. The
    // test env also enforces them on every invocation, so an overrun panics before this point.
    assert!(r.instructions <= 400_000_000, "CPU over the tx limit");
    assert!(r.mem_bytes <= 41_943_040, "memory over the tx limit");
    assert!(r.disk_read_entries <= 200);
    assert!(r.write_entries <= 200);
    assert!(
        r.disk_read_entries + r.memory_read_entries + r.write_entries <= 400,
        "footprint over the tx limit"
    );
    assert!(r.write_bytes <= 132_096);
    assert!(r.disk_read_bytes <= 200_000);
    assert!(r.contract_events_size_bytes <= 16_384);
}
