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
/// ad units, the ad token in `ad_tokens`, the order token in `order_tokens`, no expiry).
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
    // A stand-in escrow, so the owner's `call` (plan 46) reaches a real contract.
    let target = env.register(StubEscrow, ());
    let (account, client) = deploy(&env, &owner, &vec![&env, target.clone()]);

    let agent = Agent::new(7);
    let ad_token = b32(&env, 0xAA);
    let order_token = b32(&env, 0xBB);
    let signer = address_to_bytes32(&env, &account);
    // Ceilings first: `validate` refuses an ad token the account has no limit for, so that a broken
    // ordering is an install-time answer rather than an agent that cannot work. The order token
    // needs none (`an_order_token_needs_no_ceiling_but_an_ad_token_does`); it gets one here so the
    // suites that list it as an ad token too can install.
    for t in [ad_token.clone(), order_token.clone()] {
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
    client.set_policy(
        &agent.id(&env),
        &lock_for_order(&env),
        &vec![&env, tl(&ad_token, 1_000_000, u128::MAX / 2, 1)],
        &vec![&env, order_token.clone()],
        &0_u64,
        &signer,
        &None,
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
        lp_fee_bps: 0,
        protocol_fee_bps: 0,
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
            &lock_for_order(&f.env),
            &wide(&f.env, &vec![&f.env, f.ad_token.clone()]),
            &vec![&f.env, f.ad_token.clone()],
            &0_u64,
            &f.signer,
            &None,
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
            &Symbol::new(&f.env, bad),
            &wide(&f.env, &vec![&f.env, f.ad_token.clone()]),
            &vec![&f.env, f.order_token.clone()],
            &0_u64,
            &f.signer,
            &None,
        );
        assert_eq!(r, Err(Ok(AccountError::BadPolicy)), "{bad}");
    }
    assert!(f.client.policy(&id).is_none());
}

#[test]
fn set_policy_validates_lengths_and_zero_values() {
    let f = fixture();
    let id = b32(&f.env, 0x03);
    let lock = lock_for_order(&f.env);
    let ad = vec![&f.env, f.ad_token.clone()];
    let ord = vec![&f.env, f.order_token.clone()];
    let try_set = |ad_tokens: &Vec<TokenLimit>, order_tokens: &Vec<BytesN<32>>| {
        f.client
            .try_set_policy(&id, &lock, ad_tokens, order_tokens, &0, &f.signer, &None)
    };
    let mut seventeen = Vec::new(&f.env);
    for i in 1..=17u8 {
        seventeen.push_back(b32(&f.env, i));
    }
    let zero = vec![&f.env, b32(&f.env, 0)];
    let twice = vec![&f.env, f.order_token.clone(), f.order_token.clone()];

    // ad tokens: empty / 17 / zero token / repeated
    assert_eq!(
        try_set(&Vec::new(&f.env), &ord),
        Err(Ok(AccountError::BadPolicy))
    );
    assert_eq!(
        try_set(&wide(&f.env, &seventeen), &ord),
        Err(Ok(AccountError::BadPolicy))
    );
    assert_eq!(
        try_set(&wide(&f.env, &zero), &ord),
        Err(Ok(AccountError::BadPolicy))
    );
    let ad_twice = vec![&f.env, f.ad_token.clone(), f.ad_token.clone()];
    assert_eq!(
        try_set(&wide(&f.env, &ad_twice), &ord),
        Err(Ok(AccountError::BadPolicy))
    );

    // order tokens: empty / 17 / zero token / repeated
    assert_eq!(
        try_set(&wide(&f.env, &ad), &Vec::new(&f.env)),
        Err(Ok(AccountError::BadPolicy))
    );
    assert_eq!(
        try_set(&wide(&f.env, &ad), &seventeen),
        Err(Ok(AccountError::BadPolicy))
    );
    assert_eq!(
        try_set(&wide(&f.env, &ad), &zero),
        Err(Ok(AccountError::BadPolicy))
    );
    assert_eq!(
        try_set(&wide(&f.env, &ad), &twice),
        Err(Ok(AccountError::BadPolicy))
    );

    // sixteen order tokens is the bound, and needs no ceiling for any of them
    let mut sixteen = Vec::new(&f.env);
    for i in 1..=16u8 {
        sixteen.push_back(b32(&f.env, i));
    }
    assert_eq!(try_set(&wide(&f.env, &ad), &sixteen), Ok(Ok(())));

    // zero signer / expiry in the past. The zero per-order cap is per row and is covered by
    // `every_ad_token_row_is_a_well_formed_limit`.
    let r = f.client.try_set_policy(
        &id,
        &lock,
        &wide(&f.env, &ad),
        &ord,
        &0,
        &b32(&f.env, 0),
        &None,
    );
    assert_eq!(r, Err(Ok(AccountError::BadPolicy)));
    let r = f
        .client
        .try_set_policy(&id, &lock, &wide(&f.env, &ad), &ord, &T0, &f.signer, &None);
    assert_eq!(r, Err(Ok(AccountError::BadPolicy)));
    // (2.6 D9: a settlement signer other than this account is the owner's to name; see
    // `d9_an_owner_named_settlement_signer_installs_and_settles`.)
    // and the boundary that is fine
    f.client.set_policy(
        &id,
        &lock,
        &wide(&f.env, &ad),
        &ord,
        &(T0 + 1),
        &f.signer,
        &None,
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
    let ctxs = lock_ctx(
        &f.env,
        &f.target,
        vec![&f.env, p.into_val(&f.env), 0u32.into_val(&f.env)],
    );
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
            &lock_ctx(
                &f.env,
                &f.target,
                vec![&f.env, p.into_val(&f.env), 0u32.into_val(&f.env)],
            ),
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
        &lock_ctx(
            &f.env,
            &f.target,
            vec![&f.env, p.into_val(&f.env), 0u32.into_val(&f.env)],
        ),
    )
    .unwrap();
    let mut p = params(&f);
    p.amount = 100_000_100;
    p.order_decimals = 9;
    expect_err(
        agent_check(
            &f,
            &lock_ctx(
                &f.env,
                &f.target,
                vec![&f.env, p.into_val(&f.env), 0u32.into_val(&f.env)],
            ),
        ),
        AccountError::CapExceeded,
    );

    // Exactly the cap passes.
    let mut p = params(&f);
    p.amount = 1_000_000;
    agent_check(
        &f,
        &lock_ctx(
            &f.env,
            &f.target,
            vec![&f.env, p.into_val(&f.env), 0u32.into_val(&f.env)],
        ),
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
            &lock_ctx(
                &f.env,
                &f.target,
                vec![&f.env, p.into_val(&f.env), 0u32.into_val(&f.env)],
            ),
        ),
        AccountError::TokenNotAllowed,
    );
    let mut p = params(&f);
    p.order_chain_token = b32(&f.env, 0x99);
    expect_err(
        agent_check(
            &f,
            &lock_ctx(
                &f.env,
                &f.target,
                vec![&f.env, p.into_val(&f.env), 0u32.into_val(&f.env)],
            ),
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
        &lock_for_order(&f.env),
        &wide(
            &f.env,
            &vec![&f.env, f.ad_token.clone(), f.order_token.clone()],
        ),
        &vec![&f.env, f.ad_token.clone(), f.order_token.clone()],
        &(T0 + 100),
        &f.signer,
        &None,
    );
    let ctxs = lock_ctx(
        &f.env,
        &f.target,
        vec![&f.env, params(&f).into_val(&f.env), 0u32.into_val(&f.env)],
    );

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
    let ctxs = lock_ctx(
        &f.env,
        &f.target,
        vec![&f.env, params(&f).into_val(&f.env), 0u32.into_val(&f.env)],
    );
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
        &lock_for_order(&f.env),
        &wide(&f.env, &vec![&f.env, f.ad_token.clone()]),
        &vec![&f.env, f.ad_token.clone()],
        &0,
        &f.signer,
        &None,
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
        &lock_for_order(&f.env),
        &wide(&f.env, &tokens),
        &tokens,
        &0,
        &m,
        &None,
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
    let lock = |p: &OrderParams| {
        lock_ctx(
            &f.env,
            &f.target,
            vec![&f.env, p.into_val(&f.env), 0u32.into_val(&f.env)],
        )
    };
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
            &lock_for_order(&f.env),
            &limits,
            &tokens,
            &0,
            &m,
            &None,
        )
    };
    assert_eq!(set(), Err(Ok(AccountError::NotScheduled)));
    let args = policy_args(&f.env, &id, &tokens, 0, &m, &None, &limits);
    f.client
        .schedule(&Scope::Account, &sym_of(&f.env, "set_policy"), &args);
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
            &lock_ctx(
                &f.env,
                &f.target,
                vec![&f.env, p.into_val(&f.env), 0u32.into_val(&f.env)],
            ),
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
            &lock_ctx(
                &f.env,
                &other,
                vec![&f.env, params(&f).into_val(&f.env), 0u32.into_val(&f.env)],
            ),
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

/// The argument decoder types the lock's shape on its own (plan 12 D13): one argument, three, or a
/// slot that is not a `u32` are refused before the policy reads anything.
#[test]
fn lock_args_decoder_requires_params_and_a_u32_slot() {
    let f = fixture();
    let p = params(&f);
    let action = lock_for_order(&f.env);
    let one: Vec<Val> = vec![&f.env, p.clone().into_val(&f.env)];
    assert!(matches!(
        crate::args::decode_ad_call(&f.env, &action, &one),
        Err(AccountError::BadArgs)
    ));
    let three: Vec<Val> = vec![
        &f.env,
        p.clone().into_val(&f.env),
        1u32.into_val(&f.env),
        2u32.into_val(&f.env),
    ];
    assert!(matches!(
        crate::args::decode_ad_call(&f.env, &action, &three),
        Err(AccountError::BadArgs)
    ));
    let not_u32: Vec<Val> = vec![
        &f.env,
        p.clone().into_val(&f.env),
        p.clone().into_val(&f.env),
    ];
    assert!(matches!(
        crate::args::decode_ad_call(&f.env, &action, &not_u32),
        Err(AccountError::BadArgs)
    ));
    let two: Vec<Val> = vec![&f.env, p.clone().into_val(&f.env), 1u32.into_val(&f.env)];
    assert!(crate::args::decode_ad_call(&f.env, &action, &two).is_ok());
}

#[test]
fn bad_args_fail_closed() {
    let f = fixture();
    // no args
    expect_err(
        agent_check(&f, &lock_ctx(&f.env, &f.target, vec![&f.env])),
        AccountError::BadArgs,
    );
    // plan 12 D13: the old one-argument shape, and three arguments
    let p = params(&f);
    let old_shape: Vec<Val> = vec![&f.env, p.clone().into_val(&f.env)];
    expect_err(
        agent_check(&f, &lock_ctx(&f.env, &f.target, old_shape)),
        AccountError::BadArgs,
    );
    expect_err(
        agent_check(
            &f,
            &lock_ctx(
                &f.env,
                &f.target,
                vec![
                    &f.env,
                    p.clone().into_val(&f.env),
                    1u32.into_val(&f.env),
                    2u32.into_val(&f.env),
                ],
            ),
        ),
        AccountError::BadArgs,
    );
    // the slot not a u32
    expect_err(
        agent_check(
            &f,
            &lock_ctx(
                &f.env,
                &f.target,
                vec![
                    &f.env,
                    p.clone().into_val(&f.env),
                    p.clone().into_val(&f.env),
                ],
            ),
        ),
        AccountError::BadArgs,
    );
    // wrong type
    expect_err(
        agent_check(
            &f,
            &lock_ctx(
                &f.env,
                &f.target,
                vec![&f.env, 7u32.into_val(&f.env), 0u32.into_val(&f.env)],
            ),
        ),
        AccountError::BadArgs,
    );
    // decimals out of range
    let mut p = params(&f);
    p.ad_decimals = 31;
    expect_err(
        agent_check(
            &f,
            &lock_ctx(
                &f.env,
                &f.target,
                vec![&f.env, p.into_val(&f.env), 0u32.into_val(&f.env)],
            ),
        ),
        AccountError::BadArgs,
    );
    // a required key missing
    let mut m = lock_map(&f);
    m.remove(Symbol::new(&f.env, "amount"));
    expect_err(
        agent_check(
            &f,
            &lock_ctx(
                &f.env,
                &f.target,
                vec![&f.env, m.into_val(&f.env), 0u32.into_val(&f.env)],
            ),
        ),
        AccountError::BadArgs,
    );
    // a required key of the wrong type
    let mut m = lock_map(&f);
    m.set(Symbol::new(&f.env, "amount"), 7u32.into_val(&f.env));
    expect_err(
        agent_check(
            &f,
            &lock_ctx(
                &f.env,
                &f.target,
                vec![&f.env, m.into_val(&f.env), 0u32.into_val(&f.env)],
            ),
        ),
        AccountError::BadArgs,
    );
}

/// F4a: the decoder reads only the keys the policy needs, so a shape wider
/// than the order (#586 grew it to 17 keys) passes unchanged.
#[test]
fn wider_order_shape_decodes() {
    let f = fixture();
    let mut m = lock_map(&f);
    let base = m.len();
    for k in ["extra_a", "extra_b"] {
        m.set(Symbol::new(&f.env, k), b32(&f.env, 0x33).into_val(&f.env));
    }
    assert_eq!(m.len(), base + 2);
    agent_check(
        &f,
        &lock_ctx(
            &f.env,
            &f.target,
            vec![&f.env, m.into_val(&f.env), 0u32.into_val(&f.env)],
        ),
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
        // Plan 46: there is no owner signature path to break; it is refused whatever the context.
        expect_err(
            check(&f, AccountSig::Owner, &vec![&f.env, ctx]),
            AccountError::OwnerPathRetired,
        );
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
            args: vec![&f.env, good.into_val(&f.env), 0u32.into_val(&f.env)],
        }),
        Context::Contract(ContractContext {
            contract: f.target.clone(),
            fn_name: lock_for_order(&f.env),
            args: vec![&f.env, bad.into_val(&f.env), 0u32.into_val(&f.env)],
        }),
    ];
    expect_err(agent_check(&f, &ctxs), AccountError::CapExceeded);
}

#[test]
fn unknown_agent_and_bad_signature_rejected() {
    let f = fixture();
    let ctxs = lock_ctx(
        &f.env,
        &f.target,
        vec![&f.env, params(&f).into_val(&f.env), 0u32.into_val(&f.env)],
    );
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
        &lock_for_order(&f.env),
        &wide(
            &f.env,
            &vec![&f.env, f.ad_token.clone(), f.order_token.clone()],
        ),
        &vec![&f.env, f.ad_token.clone(), f.order_token.clone()],
        &0,
        &f.signer,
        &None,
    );
    let ctxs = lock_ctx(
        &f.env,
        &f.target,
        vec![&f.env, params(&f).into_val(&f.env), 0u32.into_val(&f.env)],
    );
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

/// Plan 46: the owner acts through the account's own functions; signing as the account is refused,
/// even with the owner's authorization, whatever it carries.
#[test]
fn the_owner_signature_path_is_retired() {
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
    // mock_all_auths would satisfy the owner's nested authorization; refused anyway.
    expect_err(
        check(&f, AccountSig::Owner, &ctxs),
        AccountError::OwnerPathRetired,
    );
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
    am.set_chain(&order_chain_id, &portal);
    am.set_token_route(&ad_token, &order_token, &order_chain_id);
    // 2.3e: timing is fail-closed; the smallest legal clocks.
    am.set_route_timing(
        &order_chain_id,
        &ad_manager::RouteTiming {
            min_window: 0,
            buffer: 1_800,
            margin: 0,
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
        &lock_for_order(&env),
        &limits,
        &vec![&env, ad_token.clone(), order_token.clone()],
        &0_u64,
        &signer,
        &None,
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
        lp_fee_bps: 0,
        protocol_fee_bps: 0,
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
        std::vec![sc_val(&e.env, p_val), sc_val(&e.env, 0u32.into_val(&e.env))],
    );
    let payload = payload_hash(&e.env, &e.account, &inv, 1, exp, creds);
    let sig = sc_val(&e.env, e.agent.sign(&e.env, &payload).into_val(&e.env));
    e.env
        .set_auths(&[entry(&e.account, inv, 1, exp, sig, creds)]);
    let _hash: BytesN<32> = e.env.invoke_contract(
        &e.ad_manager,
        &Symbol::new(&e.env, "lock_for_order"),
        vec![&e.env, p_val, 0u32.into_val(&e.env)],
    );
    assert_eq!(liquidity(&e), 4_600_000);

    // Over the cap: the auth entry is well-formed and signed, the policy says no.
    let mut p = escrow_params(&e, 1_000_001);
    p.salt = soroban_sdk::U256::from_u128(&e.env, 43);
    let p_val: Val = p.into_val(&e.env);
    let inv = invocation(
        &e.ad_manager,
        "lock_for_order",
        std::vec![sc_val(&e.env, p_val), sc_val(&e.env, 0u32.into_val(&e.env))],
    );
    let payload = payload_hash(&e.env, &e.account, &inv, 2, exp, creds);
    let sig = sc_val(&e.env, e.agent.sign(&e.env, &payload).into_val(&e.env));
    e.env
        .set_auths(&[entry(&e.account, inv, 2, exp, sig, creds)]);
    let r = e.env.try_invoke_contract::<BytesN<32>, soroban_sdk::Error>(
        &e.ad_manager,
        &Symbol::new(&e.env, "lock_for_order"),
        vec![&e.env, p_val, 0u32.into_val(&e.env)],
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

/// The owner's withdraw end to end (plan 46): the owner authorizes the account's own `call`, which
/// calls the escrow as the account (the direct invoker, so the escrow's `maker.require_auth` passes).
/// Without the owner's authorization it fails, and so does the retired "sign as the account" route.
fn owner_withdraw_e2e(creds: Creds) {
    let e = escrow_fixture();
    let exp = e.env.ledger().sequence() + 100;
    let to = Address::generate(&e.env);
    let client = AgentAccountClient::new(&e.env, &e.account);
    let withdraw = Symbol::new(&e.env, "withdraw_from_ad");
    let args: Vec<Val> = vec![
        &e.env,
        e.ad_id.clone().into_val(&e.env),
        1_000_000_u128.into_val(&e.env),
        to.clone().into_val(&e.env),
    ];
    let none: Option<(Address, u128)> = None;
    let approvals: Vec<InvokerContractAuthEntry> = Vec::new(&e.env);
    let owner_inv = invocation(
        &e.account,
        "call",
        std::vec![
            sc_val(&e.env, e.ad_manager.to_val()),
            sc_val(&e.env, withdraw.to_val()),
            sc_val(&e.env, args.to_val()),
            sc_val(&e.env, none.into_val(&e.env)),
            sc_val(&e.env, approvals.to_val()),
        ],
    );
    e.env
        .set_auths(&[entry(&e.owner, owner_inv, 7, exp, ScVal::Void, creds)]);
    client.call(&e.ad_manager, &withdraw, &args, &none, &approvals);
    assert_eq!(liquidity(&e), 4_000_000);

    // No owner authorization: refused, nothing moves.
    e.env.set_auths(&[]);
    assert!(client
        .try_call(&e.ad_manager, &withdraw, &args, &none, &approvals)
        .is_err());

    // The retired route: the account's `Owner` entry plus the owner's nested entry.
    let inv = invocation(
        &e.ad_manager,
        "withdraw_from_ad",
        std::vec![
            sc_val(&e.env, e.ad_id.clone().into_val(&e.env)),
            sc_val(&e.env, 1_000_000_u128.into_val(&e.env)),
            sc_val(&e.env, to.clone().into_val(&e.env)),
        ],
    );
    let payload = payload_hash(&e.env, &e.account, &inv, 8, exp, creds);
    let nested = invocation(
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
            8,
            exp,
            sc_val(&e.env, AccountSig::Owner.into_val(&e.env)),
            creds,
        ),
        entry(&e.owner, nested, 9, exp, ScVal::Void, creds),
    ]);
    let r = e.env.try_invoke_contract::<(), soroban_sdk::Error>(
        &e.ad_manager,
        &withdraw,
        vec![
            &e.env,
            e.ad_id.clone().into_val(&e.env),
            1_000_000_u128.into_val(&e.env),
            to.into_val(&e.env),
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
        std::vec![sc_val(&e.env, p_val), sc_val(&e.env, 0u32.into_val(&e.env))],
    );
    // signed over the V1 preimage, submitted as AddressV2
    let payload = payload_hash(&e.env, &e.account, &inv, 1, exp, Creds::V1);
    let sig = sc_val(&e.env, e.agent.sign(&e.env, &payload).into_val(&e.env));
    e.env
        .set_auths(&[entry(&e.account, inv, 1, exp, sig, Creds::V2)]);
    let r = e.env.try_invoke_contract::<BytesN<32>, soroban_sdk::Error>(
        &e.ad_manager,
        &Symbol::new(&e.env, "lock_for_order"),
        vec![&e.env, p_val, 0u32.into_val(&e.env)],
    );
    assert!(r.is_err());
    assert_eq!(liquidity(&e), 5_000_000);
}

/// Stands in for the escrow in the unit fixture: the owner's `call` needs a contract to reach, and
/// these tests are about the account's guard rail, not the escrow.
#[soroban_sdk::contract]
pub struct StubEscrow;

#[soroban_sdk::contractimpl]
impl StubEscrow {
    pub fn withdraw_from_ad(_env: Env, _ad_id: String, _amount: u128, _to: Address) {}
    pub fn close_ad(_env: Env, _ad_id: String, _to: Address) {}
    pub fn lock_for_order(_env: Env, _params: Map<Symbol, Val>, _slot: u32) {}
    pub fn set_settlement_signer(_env: Env, _ad_id: String, _signer: BytesN<32>) {}
    pub fn halt_settlement(_env: Env, _maker: Address) {}
    pub fn resume_settlement(_env: Env, _maker: Address) {}
    /// Takes nothing: an escrow that doesn't pull what the account paid in.
    pub fn fund_ad(_env: Env, _ad_id: String, _amount: u128) {}
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

    /// Plan 12 C: every slot of a usable account answers; the pin is not what these tests check.
    pub fn commitment_at(env: Env, account: BytesN<32>, _slot_id: u32) -> BytesN<32> {
        if !Self::has_usable_slot(env, account.clone()) {
            panic!("no usable slot");
        }
        account
    }

    pub fn expired_at(_env: Env, _account: BytesN<32>, _slot_id: u32) -> u64 {
        0
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
        &lock_for_order(&f.env),
        &limits,
        &tokens,
        &0_u64,
        &f.signer,
        &scope,
    );
    limits
}

fn lock_of(f: &Fixture, amount: u128, ad_id: &str) -> Vec<Context> {
    let mut p = params(f);
    p.amount = amount;
    p.ad_id = String::from_str(&f.env, ad_id);
    lock_ctx(
        &f.env,
        &f.target,
        vec![&f.env, p.into_val(&f.env), 0u32.into_val(&f.env)],
    )
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
            &lock_for_order(&f.env),
            &limits,
            &tokens,
            &0_u64,
            &f.signer,
            &None,
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
            &lock_for_order(&f.env),
            &wide(&f.env, &tokens),
            &tokens,
            &0_u64,
            &f.signer,
            &None,
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
            args: vec![&f.env, a.into_val(&f.env), 0u32.into_val(&f.env)],
        }),
        Context::Contract(ContractContext {
            contract: f.target.clone(),
            fn_name: lock_for_order(&f.env),
            args: vec![&f.env, b.into_val(&f.env), 0u32.into_val(&f.env)],
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
fn ad_scope_is_validated_like_the_token_lists() {
    let f = fixture();
    let tokens = vec![&f.env, f.ad_token.clone(), f.order_token.clone()];
    let limits = wide(&f.env, &tokens);
    let id = f.agent.id(&f.env);
    let install = |scope: Option<Vec<String>>| {
        f.client.try_set_policy(
            &id,
            &lock_for_order(&f.env),
            &limits,
            &tokens,
            &0_u64,
            &f.signer,
            &scope,
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
    // The bound the EVM codec shares: 512 bytes installs, 513 does not. Without it this chain
    // would hold a policy the other refuses, and the largest policy's event would not fit.
    let long = |n: usize| String::from_str(&f.env, &"x".repeat(n));
    assert_eq!(
        install(Some(vec![&f.env, long(513)])),
        Err(Ok(AccountError::BadPolicy)),
        "an ad id over 512 bytes"
    );
    assert_eq!(install(Some(vec![&f.env, long(512)])), Ok(Ok(())));
}

/// Every ad-token row is a well-formed limit: a zero on either side of the rate, no size cap, or a
/// size cap above the capacity is refused rather than defaulted.
#[test]
fn every_ad_token_row_is_a_well_formed_limit() {
    let f = fixture();
    let ord = vec![&f.env, f.order_token.clone()];
    // A zero capacity blocks the agent outright, a zero refill makes the bucket one-shot. Both
    // read as a mis-set field.
    for (mpo, cap, refill) in [
        // zero capacity, zero refill, no size cap, and a size cap above the capacity — the last
        // one can never bind, so an owner who wrote it meant something the policy cannot do.
        (1_u128, 0_u128, 1_u128),
        (1, 1, 0),
        (0, 1, 1),
        (2, 1, 1),
    ] {
        let m = vec![&f.env, tl(&f.ad_token, mpo, cap, refill)];
        assert_eq!(
            f.client.try_set_policy(
                &f.agent.id(&f.env),
                &lock_for_order(&f.env),
                &m,
                &ord,
                &0_u64,
                &f.signer,
                &None,
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

/// A repeated token in either list is refused: `ad_tokens` would carry two rows for one token,
/// and `order_tokens` would be a list that does not say what the owner thinks it says.
#[test]
fn a_duplicate_token_in_either_list_is_refused() {
    let f = fixture();
    let try_set = |ad: Vec<TokenLimit>, ord: Vec<BytesN<32>>| {
        f.client.try_set_policy(
            &f.agent.id(&f.env),
            &lock_for_order(&f.env),
            &ad,
            &ord,
            &0_u64,
            &f.signer,
            &None,
        )
    };
    let row = tl(&f.ad_token, 1, 1, 1);
    let ord = vec![&f.env, f.order_token.clone()];
    assert_eq!(
        try_set(vec![&f.env, row.clone(), row.clone()], ord.clone()),
        Err(Ok(AccountError::BadPolicy))
    );
    assert_eq!(
        try_set(
            vec![&f.env, row.clone()],
            vec![&f.env, f.order_token.clone(), f.order_token.clone()]
        ),
        Err(Ok(AccountError::BadPolicy))
    );
    assert_eq!(try_set(vec![&f.env, row], ord), Ok(Ok(())));
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
        &lock_for_order(&f.env),
        &limits,
        &tokens,
        &0_u64,
        &f.signer,
        &None,
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
    let ctxs = lock_ctx(
        &f.env,
        &f.target,
        vec![&f.env, p.into_val(&f.env), 0u32.into_val(&f.env)],
    );
    expect_err(agent_check(&f, &ctxs), AccountError::CapExceeded);
}

/// An order token is only checked for membership, so it needs no account ceiling; an ad token is
/// spent from this account, so it does.
#[test]
fn an_order_token_needs_no_ceiling_but_an_ad_token_does() {
    let f = fixture();
    let fresh = b32(&f.env, 0x6A);
    let install = |ad: &BytesN<32>, ord: &BytesN<32>| {
        f.client.try_set_policy(
            &f.agent.id(&f.env),
            &lock_for_order(&f.env),
            &wide(&f.env, &vec![&f.env, ad.clone()]),
            &vec![&f.env, ord.clone()],
            &0_u64,
            &f.signer,
            &None,
        )
    };
    assert_eq!(install(&f.ad_token, &fresh), Ok(Ok(())));
    assert_eq!(
        install(&fresh, &f.order_token),
        Err(Ok(AccountError::NoVolumeLimit))
    );
}

fn lock_with(f: &Fixture, ad_token: &BytesN<32>, order_token: &BytesN<32>) -> Vec<Context> {
    let mut p = params(f);
    p.ad_chain_token = ad_token.clone();
    p.order_chain_token = order_token.clone();
    lock_ctx(
        &f.env,
        &f.target,
        vec![&f.env, p.into_val(&f.env), 0u32.into_val(&f.env)],
    )
}

/// The fixture lists the ad token only as an ad token and the order token only as an order token.
/// Each in the other's place is a miss, and so is a token in neither list.
#[test]
fn a_token_in_the_wrong_list_or_in_neither_is_refused() {
    let f = fixture();
    let stranger = b32(&f.env, 0x99);
    agent_check(&f, &lock_with(&f, &f.ad_token, &f.order_token)).expect("the listed pair");
    for (ad, ord, why) in [
        (&f.ad_token, &stranger, "order token in neither list"),
        (
            &f.ad_token,
            &f.ad_token,
            "order token listed only as an ad token",
        ),
        (
            &f.order_token,
            &f.order_token,
            "ad token listed only as an order token",
        ),
        (&f.order_token, &f.ad_token, "both swapped"),
    ] {
        assert_eq!(
            agent_check(&f, &lock_with(&f, ad, ord)),
            Err(Ok(AccountError::TokenNotAllowed)),
            "{why}"
        );
    }
}

/// A token may sit in both lists, and then serves either side.
#[test]
fn a_token_in_both_lists_serves_both_sides() {
    let f = fixture();
    let both = vec![&f.env, f.ad_token.clone(), f.order_token.clone()];
    f.client.set_policy(
        &f.agent.id(&f.env),
        &lock_for_order(&f.env),
        &wide(&f.env, &both),
        &both,
        &0_u64,
        &f.signer,
        &None,
    );
    agent_check(&f, &lock_with(&f, &f.ad_token, &f.order_token)).unwrap();
    let mut p = params(&f);
    p.ad_chain_token = f.order_token.clone();
    p.order_chain_token = f.ad_token.clone();
    p.salt = soroban_sdk::U256::from_u128(&f.env, 43);
    agent_check(
        &f,
        &lock_ctx(
            &f.env,
            &f.target,
            vec![&f.env, p.into_val(&f.env), 0u32.into_val(&f.env)],
        ),
    )
    .unwrap();
}

/// A call whose function is not the policy's one action is refused before its args are read.
#[test]
fn a_function_other_than_the_policys_action_is_refused() {
    let f = fixture();
    let ctxs = vec![
        &f.env,
        Context::Contract(ContractContext {
            contract: f.target.clone(),
            fn_name: Symbol::new(&f.env, "withdraw_from_ad"),
            args: vec![&f.env, params(&f).into_val(&f.env)],
        }),
    ];
    expect_err(agent_check(&f, &ctxs), AccountError::ActionNotAllowed);
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

/// The test ad's schedule scope.
fn ad_scope(env: &Env) -> Scope {
    Scope::Ad(ad(env))
}

/// `withdraw_from_ad(ad_id, amount, to)`'s argument list, in call order.
fn withdraw_args(env: &Env, amount: u128, to: &Address) -> Vec<Val> {
    vec![
        env,
        ad(env).into_val(env),
        amount.into_val(env),
        to.into_val(env),
    ]
}

/// `close_ad(ad_id, to)`'s argument list — no amount, by design.
fn close_args(env: &Env, to: &Address) -> Vec<Val> {
    vec![env, ad(env).into_val(env), to.into_val(env)]
}

/// `set_guard_rail(ad_id, guard_rail)`'s argument list; `None` is a disarm.
fn guard_args(env: &Env, g: &Option<GuardRail>) -> Vec<Val> {
    vec![env, ad(env).into_val(env), g.into_val(env)]
}

fn schedule_withdraw(f: &Fixture, amount: u128, to: &Address) {
    f.client.schedule(
        &ad_scope(&f.env),
        &Symbol::new(&f.env, "withdraw_from_ad"),
        &withdraw_args(&f.env, amount, to),
    );
}

fn schedule_close(f: &Fixture, to: &Address) {
    f.client.schedule(
        &ad_scope(&f.env),
        &Symbol::new(&f.env, "close_ad"),
        &close_args(&f.env, to),
    );
}

fn schedule_guard(f: &Fixture, g: &Option<GuardRail>) {
    f.client.schedule(
        &ad_scope(&f.env),
        &Symbol::new(&f.env, "set_guard_rail"),
        &guard_args(&f.env, g),
    );
}

/// `withdraw_from_ad(ad_id, amount, to)` as the escrow receives it.
fn withdraw_ctx(f: &Fixture, amount: u128, to: &Address) -> Vec<Context> {
    vec![
        &f.env,
        Context::Contract(ContractContext {
            contract: f.target.clone(),
            fn_name: Symbol::new(&f.env, "withdraw_from_ad"),
            args: withdraw_args(&f.env, amount, to),
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
            args: close_args(&f.env, to),
        }),
    ]
}

/// The guard rail as the owner meets it since plan 46: each escrow call through the account's own
/// `call`, which runs the check before it calls the (stub) escrow.
fn owner_check(f: &Fixture, ctxs: &Vec<Context>) -> Result<(), Result<AccountError, InvokeError>> {
    for ctx in ctxs.iter() {
        let Context::Contract(c) = ctx else { continue };
        f.client
            .try_call(&c.contract, &c.fn_name, &c.args, &None, &Vec::new(&f.env))
            .map(|_| ())?;
    }
    Ok(())
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

    schedule_withdraw(&f, 101, &to);
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

    schedule_withdraw(&f, 100, &alice);
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
    guard(&f, 0, 3_600, 3_600);
    schedule_withdraw(&f, 1, &to);

    f.env.ledger().set_timestamp(T0 + 3_600 + 3_600);
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
    schedule_close(&f, &to);
    f.env.ledger().set_timestamp(T0 + 3_600);
    expect_err(
        owner_check(&f, &close_ctx(&f, &Address::generate(&f.env))),
        AccountError::NotScheduled,
    );
    owner_check(&f, &close_ctx(&f, &to)).expect("announced and matured");
    expect_err(
        owner_check(&f, &close_ctx(&f, &to)),
        AccountError::NotScheduled,
    );
}

/// The asymmetry, which is the whole point of the section: on the *same* guarded ad, the actions
/// that **reduce** what a stolen key can do still fire instantly. A delay on those would only ever
/// help whoever stole it.
#[test]
fn t52_protective_actions_are_never_delayed_on_a_guarded_ad() {
    let f = fixture();
    guard(&f, 0, 86_400, 86_400);

    // Halting settlement, through the escrow: the incident response. (Re-pointing the settlement
    // identity and resuming were here too; since R2 they wait out the delay.)
    let halt = vec![
        &f.env,
        Context::Contract(ContractContext {
            contract: f.target.clone(),
            fn_name: Symbol::new(&f.env, "halt_settlement"),
            args: vec![&f.env, f.account.to_val()],
        }),
    ];
    owner_check(&f, &halt).expect("halting is protective");

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
    guard(&f, 0, 3_600, 86_400);

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
    schedule_guard(&f, &None);
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
    f.client.schedule(
        &Scope::Account,
        &Symbol::new(&f.env, "set_targets"),
        &vec![&f.env, targets.to_val()],
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
    // Since plan 46 the owner reaches escrows only through `call`, which takes pinned targets only:
    // the escrow the account was pointed away from can't be called as the account at all.
    expect_err(owner_check(&f, &ctx), AccountError::TargetNotAllowed);
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

    let ctxs = lock_ctx(
        &f.env,
        &f.target,
        vec![&f.env, params(&f).into_val(&f.env), 0u32.into_val(&f.env)],
    );
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

    schedule_withdraw(&f, 100, &to);
    schedule_guard(&f, &None);
    f.env.ledger().set_timestamp(T0 + 3_600);

    // Disarm, then re-arm: the old matured withdrawal must not survive the round trip.
    f.client.set_guard_rail(&ad(&f.env), &None);
    guard(&f, 0, 3_600, 86_400);
    assert!(f.client.scheduled(&ad_scope(&f.env), &withdraw).is_none());
    expect_err(
        owner_check(&f, &withdraw_ctx(&f, 100, &to)),
        AccountError::NotScheduled,
    );
}

/// The lever an owner reaches for on seeing a `Scheduled` event they did not cause.
#[test]
fn t52_a_schedule_can_be_cancelled_before_it_matures() {
    let f = fixture();
    let to = Address::generate(&f.env);
    guard(&f, 0, 3_600, 86_400);
    let action = Symbol::new(&f.env, "withdraw_from_ad");
    schedule_withdraw(&f, 5, &to);
    f.client.cancel(&ad_scope(&f.env), &action);
    assert_eq!(
        f.client.try_cancel(&ad_scope(&f.env), &action),
        Err(Ok(AccountError::NotScheduled)),
        "nothing left to cancel"
    );

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
        f.client.try_schedule(
            &ad_scope(&f.env),
            &Symbol::new(&f.env, "withdraw_from_ad"),
            &withdraw_args(&f.env, 1, &Address::generate(&f.env)),
        ),
        Err(Ok(AccountError::NoGuardRail))
    );
    // And only the ad's extractive selectors can be scheduled on an ad: not a protective call,
    // and not an account-wide one.
    guard(&f, 0, 1, 3_600);
    for name in ["halt_settlement", "upgrade", "set_policy"] {
        assert_eq!(
            f.client
                .try_schedule(&ad_scope(&f.env), &Symbol::new(&f.env, name), &vec![&f.env],),
            Err(Ok(AccountError::ActionNotAllowed)),
            "{name}"
        );
    }
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
    order_tokens: &Vec<BytesN<32>>,
    valid_until: u64,
    signer: &BytesN<32>,
    scope: &Option<Vec<String>>,
    ad_tokens: &Vec<TokenLimit>,
) -> Vec<Val> {
    vec![
        env,
        id.into_val(env),
        lock_for_order(env).into_val(env),
        ad_tokens.into_val(env),
        order_tokens.into_val(env),
        valid_until.into_val(env),
        signer.into_val(env),
        scope.into_val(env),
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
    f.client
        .schedule(&Scope::Account, &up, &vec![&f.env, other.to_val()]);
    f.env.ledger().set_timestamp(T0 + 3_600);
    assert_eq!(
        f.client.try_upgrade(&hash),
        Err(Ok(AccountError::NotScheduled))
    );

    // The right hash, announced but not matured.
    f.client
        .schedule(&Scope::Account, &up, &vec![&f.env, hash.to_val()]);
    let s = f.client.scheduled(&Scope::Account, &up).unwrap();
    assert_eq!(s.commitment, commit(&f.env, vec![&f.env, hash.to_val()]));
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
    f.client
        .schedule(&Scope::Account, &up, &vec![&f.env, hash.to_val()]);
    f.env
        .ledger()
        .set_timestamp(T0 + 3_600 + 3_600 + 86_400 + 3_600);
    f.client.upgrade(&hash);
    assert!(
        f.client.scheduled(&Scope::Account, &up).is_none(),
        "single use"
    );
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
    f.client
        .schedule(&Scope::Account, &up, &vec![&f.env, hash.to_val()]);
    assert_eq!(
        f.client.scheduled(&Scope::Account, &up).unwrap().ready_at,
        T0 + 3_600
    );

    // The owner tightens the delay to seven days while the change is pending.
    guard(&f, 0, 7 * 86_400, 7 * 86_400);
    assert_eq!(
        f.client.scheduled(&Scope::Account, &up).unwrap().ready_at,
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

/// Pending rows of every kind: the ad's withdraw, its lock, its guardrail change, and the
/// account-wide upgrade.
fn schedule_one_of_each(f: &Fixture) -> (Symbol, BytesN<32>) {
    let hash = f.env.deployer().upload_contract_wasm(ACCOUNT_WASM);
    let up = sym_of(&f.env, "upgrade");
    f.client
        .schedule(&Scope::Account, &up, &vec![&f.env, hash.to_val()]);
    schedule_withdraw(f, 1, &Address::generate(&f.env));
    f.client.schedule(
        &ad_scope(&f.env),
        &lock_for_order(&f.env),
        &vec![&f.env, params(f).into_val(&f.env), 0u32.into_val(&f.env)],
    );
    schedule_guard(f, &None);
    (up, hash)
}

/// (ready_at, expires_at) of the four rows `schedule_one_of_each` made: account first.
fn clocks(f: &Fixture, up: &Symbol) -> [(u64, u64); 4] {
    let a = f.client.scheduled(&Scope::Account, up).unwrap();
    let row = |name: &str| {
        let s = f
            .client
            .scheduled(&ad_scope(&f.env), &sym_of(&f.env, name))
            .unwrap();
        (s.ready_at, s.expires_at)
    };
    [
        (a.ready_at, a.expires_at),
        row("withdraw_from_ad"),
        row("lock_for_order"),
        row("set_guard_rail"),
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
    assert_eq!(clocks(&f, &up), [want; 4], "every row shifted whole");
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

/// 49S-4: disarming clears every pending row of the ad and of the account, the lock included.
#[test]
fn s4_disarming_clears_every_schedule() {
    let f = fixture();
    guard(&f, 0, 3_600, 86_400);
    let (up, _) = schedule_one_of_each(&f);
    let tokens = vec![&f.env, f.ad_token.clone()];
    let account_rows: [(&str, Vec<Val>); 3] = [
        (
            "set_policy",
            policy_args(
                &f.env,
                &f.agent.id(&f.env),
                &tokens,
                0,
                &f.signer,
                &None,
                &wide(&f.env, &tokens),
            ),
        ),
        (
            "set_account_limit",
            vec![
                &f.env,
                f.ad_token.to_val(),
                Limit {
                    capacity: 1,
                    refill_per_second: 1,
                }
                .into_val(&f.env),
            ],
        ),
        (
            "set_targets",
            vec![&f.env, vec![&f.env, f.target.clone()].to_val()],
        ),
    ];
    for (name, args) in account_rows.iter() {
        f.client
            .schedule(&Scope::Account, &sym_of(&f.env, name), args);
    }
    // Close is the one ad action `schedule_one_of_each` leaves out.
    schedule_close(&f, &f.owner);
    let pending = |f: &Fixture| {
        let mut n = 0;
        f.env.as_contract(&f.account, || {
            for scope in [ad_scope(&f.env), Scope::Account] {
                for a in policy::actions_for(&f.env, &scope) {
                    if policy::get_schedule(&f.env, &scope, &a).is_some() {
                        n += 1;
                    }
                }
            }
        });
        n
    };
    assert_eq!(pending(&f), 8, "one row per action, both scopes");
    // Disarming is a loosening: announced (`schedule_one_of_each` did), then waited out (T-52).
    f.env.ledger().set_timestamp(T0 + 3_600);
    f.client.set_guard_rail(&ad(&f.env), &None);
    assert_eq!(pending(&f), 0, "disarming cleared them all");
    assert!(f.client.scheduled(&Scope::Account, &up).is_none());
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
    let one = vec![&f.env, b32(&f.env, 1).to_val()];
    assert_eq!(
        f.client.try_schedule(&Scope::Account, &up, &one),
        Err(Ok(AccountError::NoGuardRail))
    );
    for name in [
        "withdraw_from_ad",
        "close_ad",
        "lock_for_order",
        "set_guard_rail",
    ] {
        assert_eq!(
            f.client
                .try_schedule(&Scope::Account, &sym_of(&f.env, name), &one),
            Err(Ok(AccountError::ActionNotAllowed)),
            "{name} is per ad"
        );
    }
    guard(&f, 0, 86_400, 3_600);
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
    f.client.schedule(&Scope::Account, &up, &one);
    let s = f.client.scheduled(&Scope::Account, &up).unwrap();
    assert_eq!(s.ready_at, T0 + 86_400);
    assert_eq!(s.expires_at, T0 + 86_400 + 3_600);

    f.client.cancel(&Scope::Account, &up);
    assert!(f.client.scheduled(&Scope::Account, &up).is_none());
    assert_eq!(
        f.client.try_cancel(&Scope::Account, &up),
        Err(Ok(AccountError::NotScheduled))
    );

    // Disarming a guardrail clears the account-wide rows timed against it.
    f.client.schedule(&Scope::Account, &up, &one);
    schedule_guard(&f, &None);
    f.env.ledger().set_timestamp(T0 + 86_400);
    f.client.set_guard_rail(&ad(&f.env), &None);
    assert!(f.client.scheduled(&Scope::Account, &up).is_none());
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
        &lock_for_order(&f.env),
        &base(1_000, 2_000, 10),
        &two,
        &until,
        &f.signer,
        &scope,
    );
    guard(&f, 0, 3_600, 86_400);

    let try_set = |tokens: &Vec<BytesN<32>>,
                   until: u64,
                   scope: &Option<Vec<String>>,
                   limits: &Vec<TokenLimit>| {
        f.client.try_set_policy(
            &id,
            &lock_for_order(&f.env),
            limits,
            tokens,
            &until,
            &f.signer,
            scope,
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
    ); 9] = [
        (
            "a new order token",
            three.clone(),
            until,
            scope.clone(),
            base(1_000, 2_000, 10),
        ),
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
            "a new ad token",
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
            &lock_for_order(&f.env),
            &base(1_000, 2_000, 10),
            &two,
            &until,
            &f.signer,
            &scope,
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
    ); 7] = [
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
            "an order token dropped",
            one.clone(),
            until - 1,
            scope.clone(),
            base(999, 1_999, 9),
        ),
        (
            "an ad token dropped",
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
        .schedule(&Scope::Account, &sym_of(&f.env, "set_policy"), &args);
    f.env.ledger().set_timestamp(T0 + 3_600);
    assert_eq!(
        try_set(&two, 0, &None, &base(5_000, 5_000, 51)),
        Err(Ok(AccountError::NotScheduled)),
        "a different write than the one announced"
    );
    assert_eq!(try_set(&two, 0, &None, &limits), Ok(Ok(())));
    assert!(f
        .client
        .scheduled(&Scope::Account, &sym_of(&f.env, "set_policy"))
        .is_none());
}

/// A changed action is loosening. `validate` admits only `lock_for_order` today, so `set_policy`
/// refuses any other action before this check runs; the rule is held here for the day a second
/// action exists.
#[test]
fn a_changed_action_is_loosening() {
    let f = fixture();
    let cur = f.client.policy(&f.agent.id(&f.env)).unwrap();
    let mut next = cur.clone();
    assert!(
        policy::is_policy_tightening(&cur, &next),
        "equal is tightening"
    );
    next.allowed_action = Symbol::new(&f.env, "withdraw_from_ad");
    assert!(!policy::is_policy_tightening(&cur, &next));
}

/// C-29: an unscoped, non-expiring policy admits any scope and any expiry as tightening.
#[test]
fn c29_narrowing_an_open_policy_is_instant() {
    let f = fixture();
    guard(&f, 0, 3_600, 86_400);
    // the fixture's own lists and limits
    f.client.set_policy(
        &f.agent.id(&f.env),
        &lock_for_order(&f.env),
        &vec![&f.env, tl(&f.ad_token, 1_000_000, u128::MAX / 2, 1)],
        &vec![&f.env, f.order_token.clone()],
        &(T0 + 5),
        &f.signer,
        &Some(vec![&f.env, ad(&f.env)]),
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
    f.client.schedule(
        &Scope::Account,
        &sym_of(&f.env, "set_account_limit"),
        &vec![&f.env, f.ad_token.to_val(), raised.into_val(&f.env)],
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
                window: 3_600,
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
        f.client.try_schedule(
            &ad_scope(&f.env),
            &sym_of(&f.env, "withdraw_from_ad"),
            &withdraw_args(&f.env, 1, &f.owner),
        ),
        Err(Ok(AccountError::GuardRailArchived))
    );
    assert_eq!(
        f.client.try_schedule(
            &Scope::Account,
            &sym_of(&f.env, "upgrade"),
            &vec![&f.env, b32(&f.env, 1).to_val()]
        ),
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
    let args: Vec<Val> = vec![
        &f.env,
        order.clone().into_val(&f.env),
        0u32.into_val(&f.env),
    ];
    let ctxs = lock_ctx(&f.env, &f.target, args.clone());

    expect_err(owner_check(&f, &ctxs), AccountError::NotScheduled);

    let lock = lock_for_order(&f.env);
    f.client.schedule(&ad_scope(&f.env), &lock, &args);
    expect_err(owner_check(&f, &ctxs), AccountError::NotScheduled);
    f.env.ledger().set_timestamp(T0 + 3_600);

    // Same amount, a different order: refused.
    let mut other = params(&f);
    other.salt = soroban_sdk::U256::from_u128(&f.env, 43);
    let other_ctx = lock_ctx(
        &f.env,
        &f.target,
        vec![&f.env, other.into_val(&f.env), 0u32.into_val(&f.env)],
    );
    expect_err(owner_check(&f, &other_ctx), AccountError::NotScheduled);

    owner_check(&f, &ctxs).expect("the announced order");
    expect_err(owner_check(&f, &ctxs), AccountError::NotScheduled);

    // Expired is refused.
    f.client.schedule(&ad_scope(&f.env), &lock, &args);
    f.env.ledger().set_timestamp(T0 + 3_600 + 3_600 + 86_400);
    expect_err(owner_check(&f, &ctxs), AccountError::NotScheduled);

    // And a lock schedule can be cancelled.
    f.client.schedule(&ad_scope(&f.env), &lock, &args);
    f.client.cancel(&ad_scope(&f.env), &lock);
    assert!(f.client.scheduled(&ad_scope(&f.env), &lock).is_none());
    f.env
        .ledger()
        .set_timestamp(T0 + 3_600 + 3_600 + 86_400 + 3_600);
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

/// C-34: `PolicySet` carries every installed field and `AccountLimitSet` the numbers.
#[test]
fn c34_policy_and_limit_events_say_what_changed() {
    let f = fixture();
    let id = f.agent.id(&f.env);
    let ad_tokens = wide(&f.env, &vec![&f.env, f.ad_token.clone()]);
    let order_tokens = vec![&f.env, f.order_token.clone(), f.ad_token.clone()];
    let scope = Some(vec![
        &f.env,
        String::from_str(&f.env, "ad-zulu"),
        ad(&f.env),
    ]);
    f.client.set_policy(
        &id,
        &lock_for_order(&f.env),
        &ad_tokens,
        &order_tokens,
        &(T0 + 50),
        &f.signer,
        &scope,
    );
    let data = last_event_data(&f.env, &f.account);
    let topics = event_topics(&f.env, &f.account, true);
    assert_eq!(topics, std::vec![sym("pol_set"), bytes32(&id)]);
    assert_eq!(
        data,
        ScVal::Vec(Some(
            std::vec![
                sc(&f.env, lock_for_order(&f.env)),
                sc(&f.env, ad_tokens),
                sc(&f.env, order_tokens),
                sc(&f.env, scope),
                sc(&f.env, T0 + 50),
                sc(&f.env, f.signer.clone()),
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
            "schedule",
            vec![
                e,
                ad_scope(e).into_val(e),
                sym_of(e, "withdraw_from_ad").to_val(),
                withdraw_args(e, 1, &f.owner).to_val()
            ]
        ),
        (
            "cancel",
            vec![
                e,
                ad_scope(e).into_val(e),
                sym_of(e, "withdraw_from_ad").to_val()
            ]
        ),
        ("revoke_agent", vec![e, id.to_val()]),
        ("upgrade", vec![e, b32(e, 0x42).to_val()]),
        ("migrate", vec![e]),
        // Plan 46: the owner's ad actions.
        (
            "create_ad",
            vec![
                e,
                f.target.to_val(),
                proofbridge_core::token::bytes32_to_token_address(e, &f.ad_token)
                    .unwrap()
                    .to_val(),
                ad(e).to_val(),
                f.ad_token.to_val(),
                1_u128.into_val(e),
                1_u128.into_val(e),
                b32(e, 0xCC).to_val(),
                f.signer.to_val()
            ]
        ),
        (
            "fund_ad",
            vec![
                e,
                f.target.to_val(),
                proofbridge_core::token::bytes32_to_token_address(e, &f.ad_token)
                    .unwrap()
                    .to_val(),
                ad(e).to_val(),
                1_u128.into_val(e)
            ]
        ),
        (
            "call",
            vec![
                e,
                f.target.to_val(),
                sym_of(e, "close_ad").to_val(),
                close_args(e, &f.owner).to_val(),
                Option::<(Address, u128)>::None.into_val(e),
                Vec::<InvokerContractAuthEntry>::new(e).to_val()
            ]
        ),
        (
            "sweep",
            vec![
                e,
                proofbridge_core::token::bytes32_to_token_address(e, &f.ad_token)
                    .unwrap()
                    .to_val(),
                f.owner.to_val(),
                1_u128.into_val(e)
            ]
        ),
    ];
    let views = [
        "__constructor",
        "__check_auth",
        "guard_rail",
        "guarded_ads",
        "scheduled",
        "owner",
        "targets",
        "policy",
        "is_revoked",
        "account_volume",
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
    assert_eq!(f.client.policy(&id).unwrap().ad_tokens, before.ad_tokens);
    assert!(f.client.guard_rail(&ad(e)).is_some());
    assert_eq!(f.client.targets(), vec![e, f.target.clone()]);

    // Positive control: with the owner signing, none of them fails on auth.
    e.mock_all_auths();
    for (name, args) in owner_only.iter() {
        if *name == "upgrade" {
            continue; // a made-up hash traps in the host; covered by the C-5 tests.
        }
        if ["create_ad", "fund_ad", "sweep"].contains(name) {
            continue; // the fixture's token is not a contract; covered by the p46 tests' real tokens.
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
    am.set_chain(&order_chain_id, &portal);
    am.set_token_route(&ad_token, &order_token, &order_chain_id);
    am.set_route_timing(
        &order_chain_id,
        &ad_manager::RouteTiming {
            min_window: 0,
            buffer: 1_800,
            margin: 0,
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
        &lock_for_order(&env),
        &limits,
        &tokens,
        &0_u64,
        &signer,
        &Some(scope),
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
        std::vec![sc_val(&env, p_val), sc_val(&env, 0u32.into_val(&env))],
    );
    let payload = payload_hash(&env, &account, &inv, 1, exp, Creds::V2);
    let sig = sc_val(&env, e.agent.sign(&env, &payload).into_val(&env));
    env.set_auths(&[entry(&account, inv, 1, exp, sig, Creds::V2)]);
    env.cost_estimate().budget().reset_default();
    let _: BytesN<32> = env.invoke_contract(
        &ad_manager,
        &Symbol::new(&env, "lock_for_order"),
        vec![&env, p_val, 0u32.into_val(&env)],
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

// ─────────────────────────────────────────────────────────────────────────
// One schedule shape: every delayed call bound to its exact arguments
// ─────────────────────────────────────────────────────────────────────────

/// A guardrail with the test defaults (delay 3_600, window 86_400) and the given threshold and
/// bucket capacity.
fn rail(threshold: u128, capacity: u128) -> GuardRail {
    GuardRail {
        threshold,
        delay: 3_600,
        window: 86_400,
        rate: Limit {
            capacity,
            refill_per_second: 1,
        },
        bucket: Bucket {
            level: 0,
            last_ts: 0,
        },
    }
}

/// The guardrail gap: a matured schedule for one loosening used to authorize any loosening, up to
/// disarming. Now it authorizes exactly the announced values, once.
#[test]
fn a_guardrail_loosening_spends_only_the_announced_values() {
    let f = fixture();
    f.client
        .set_guard_rail(&ad(&f.env), &Some(rail(100, 1_000)));
    let a = Some(rail(200, 1_000));
    schedule_guard(&f, &a);
    f.env.ledger().set_timestamp(T0 + 3_600);

    // A looser B, a different but equally loose B (capacity instead of threshold), and a disarm.
    for (label, other) in [
        ("a looser threshold", Some(rail(300, 1_000))),
        (
            "an equally loose change on another axis",
            Some(rail(100, 2_000)),
        ),
        ("a disarm", None),
    ] {
        assert_eq!(
            f.client.try_set_guard_rail(&ad(&f.env), &other),
            Err(Ok(AccountError::NotScheduled)),
            "{label} is not what was announced"
        );
    }
    f.client.set_guard_rail(&ad(&f.env), &a);
    assert_eq!(f.client.guard_rail(&ad(&f.env)).unwrap().threshold, 200);

    // Single use: the same loosening again (back down, then up) finds no row.
    f.client
        .set_guard_rail(&ad(&f.env), &Some(rail(100, 1_000)));
    assert_eq!(
        f.client.try_set_guard_rail(&ad(&f.env), &a),
        Err(Ok(AccountError::NotScheduled)),
        "spent"
    );
}

/// A disarm needs a schedule committed to `None`, and that schedule authorizes nothing else.
#[test]
fn a_disarm_needs_a_schedule_committed_to_none() {
    let f = fixture();
    f.client
        .set_guard_rail(&ad(&f.env), &Some(rail(100, 1_000)));
    schedule_guard(&f, &None);
    f.env.ledger().set_timestamp(T0 + 3_600);
    assert_eq!(
        f.client
            .try_set_guard_rail(&ad(&f.env), &Some(rail(200, 1_000))),
        Err(Ok(AccountError::NotScheduled)),
        "a disarm schedule is not a loosening schedule"
    );
    f.client.set_guard_rail(&ad(&f.env), &None);
    assert!(f.client.guard_rail(&ad(&f.env)).is_none());
}

/// The window rule for a guardrail change: refused before `ready_at`, refused at `expires_at`.
#[test]
fn a_guardrail_schedule_is_refused_early_and_expired() {
    let f = fixture();
    f.client
        .set_guard_rail(&ad(&f.env), &Some(rail(100, 1_000)));
    schedule_guard(&f, &None);
    f.env.ledger().set_timestamp(T0 + 3_599);
    assert_eq!(
        f.client.try_set_guard_rail(&ad(&f.env), &None),
        Err(Ok(AccountError::NotScheduled)),
        "early"
    );
    f.env.ledger().set_timestamp(T0 + 3_600 + 86_400);
    assert_eq!(
        f.client.try_set_guard_rail(&ad(&f.env), &None),
        Err(Ok(AccountError::NotScheduled)),
        "expired"
    );
}

/// Cancel stands a guardrail change down; a raised delay re-stamps it.
#[test]
fn a_guardrail_schedule_is_cancelled_and_restamped() {
    let f = fixture();
    let change = sym_of(&f.env, "set_guard_rail");
    f.client
        .set_guard_rail(&ad(&f.env), &Some(rail(100, 1_000)));
    schedule_guard(&f, &None);
    f.client.cancel(&ad_scope(&f.env), &change);
    f.env.ledger().set_timestamp(T0 + 3_600);
    assert_eq!(
        f.client.try_set_guard_rail(&ad(&f.env), &None),
        Err(Ok(AccountError::NotScheduled)),
        "cancelled"
    );

    schedule_guard(&f, &None);
    let before = f.client.scheduled(&ad_scope(&f.env), &change).unwrap();
    assert_eq!(before.ready_at, T0 + 7_200);
    // Tightening to a longer delay is instant, and the pending disarm waits the new delay.
    let mut longer = rail(100, 1_000);
    longer.delay = 86_400;
    f.client.set_guard_rail(&ad(&f.env), &Some(longer));
    let after = f.client.scheduled(&ad_scope(&f.env), &change).unwrap();
    assert_eq!(after.ready_at, T0 + 3_600 + 86_400);
    assert_eq!(
        after.expires_at - after.ready_at,
        before.expires_at - before.ready_at
    );
}

/// Arming and tightening stay instant: no row exists and none is needed.
#[test]
fn arming_and_tightening_need_no_schedule() {
    let f = fixture();
    let change = sym_of(&f.env, "set_guard_rail");
    f.client
        .set_guard_rail(&ad(&f.env), &Some(rail(100, 1_000)));
    f.client.set_guard_rail(&ad(&f.env), &Some(rail(50, 500)));
    assert!(f.client.scheduled(&ad_scope(&f.env), &change).is_none());
    assert_eq!(f.client.guard_rail(&ad(&f.env)).unwrap().threshold, 50);
}

/// Adding a target is bound to the exact target list.
#[test]
fn a_target_change_spends_only_the_announced_list() {
    let f = fixture();
    guard(&f, 0, 3_600, 86_400);
    let a = vec![&f.env, f.target.clone(), Address::generate(&f.env)];
    let b = vec![&f.env, f.target.clone(), Address::generate(&f.env)];
    f.client.schedule(
        &Scope::Account,
        &sym_of(&f.env, "set_targets"),
        &vec![&f.env, a.to_val()],
    );
    f.env.ledger().set_timestamp(T0 + 3_600);
    assert_eq!(
        f.client.try_set_targets(&b),
        Err(Ok(AccountError::NotScheduled))
    );
    f.client.set_targets(&a);
    assert_eq!(f.client.targets(), a);
}

/// A raised account limit is bound to the exact token and numbers.
#[test]
fn an_account_limit_change_spends_only_the_announced_values() {
    let f = fixture();
    guard(&f, 0, 3_600, 86_400);
    let raised = Limit {
        capacity: u128::MAX / 2 + 1,
        refill_per_second: 2,
    };
    f.client.schedule(
        &Scope::Account,
        &sym_of(&f.env, "set_account_limit"),
        &vec![&f.env, f.ad_token.to_val(), raised.into_val(&f.env)],
    );
    f.env.ledger().set_timestamp(T0 + 3_600);
    assert_eq!(
        f.client.try_set_account_limit(&f.order_token, &raised),
        Err(Ok(AccountError::NotScheduled)),
        "another token"
    );
    assert_eq!(
        f.client.try_set_account_limit(
            &f.ad_token,
            &Limit {
                capacity: raised.capacity,
                refill_per_second: 3
            }
        ),
        Err(Ok(AccountError::NotScheduled)),
        "other numbers"
    );
    f.client.set_account_limit(&f.ad_token, &raised);
}

/// `Scheduled` carries the scope, the action and the call's arguments in clear, beside the
/// commitment and the window; `Cancelled` the scope and action.
#[test]
fn the_schedule_events_carry_the_arguments_in_clear() {
    let f = fixture();
    let to = Address::generate(&f.env);
    guard(&f, 0, 3_600, 86_400);
    let withdraw = sym_of(&f.env, "withdraw_from_ad");
    let args = withdraw_args(&f.env, 500, &to);
    schedule_withdraw(&f, 500, &to);
    assert_eq!(
        event_topics(&f.env, &f.account, true),
        std::vec![
            sym("scheduled"),
            sc(&f.env, ad_scope(&f.env)),
            sym("withdraw_from_ad")
        ]
    );
    assert_eq!(
        last_event_data(&f.env, &f.account),
        ScVal::Vec(Some(
            std::vec![
                sc(&f.env, args.clone()),
                sc(&f.env, commit(&f.env, args)),
                sc(&f.env, T0 + 3_600),
                sc(&f.env, T0 + 3_600 + 86_400),
            ]
            .try_into()
            .unwrap()
        ))
    );

    f.client.cancel(&ad_scope(&f.env), &withdraw);
    assert_eq!(
        event_topics(&f.env, &f.account, true),
        std::vec![
            sym("cancelled"),
            sc(&f.env, ad_scope(&f.env)),
            sym("withdraw_from_ad")
        ]
    );
}

/// The commitment for fixed arguments, pinned so the TypeScript helpers in
/// `packages/agent-core/src/chain/agent-schedule.ts` can assert the same bytes.
#[test]
fn schedule_commitment_vectors() {
    let env = Env::default();
    let hex = |b: BytesN<32>| -> std::string::String {
        b.to_array()
            .iter()
            .map(|x| std::format!("{x:02x}"))
            .collect()
    };
    let ad = String::from_str(&env, "ad-1");
    let to = Address::from_str(
        &env,
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    );
    let upgrade = vec![&env, b32(&env, 0x42).to_val()];
    let withdraw = vec![&env, ad.to_val(), 500_000_u128.into_val(&env), to.to_val()];
    let disarm = vec![&env, ad.to_val(), Option::<GuardRail>::None.into_val(&env)];
    let loosen = vec![&env, ad.to_val(), Some(rail(200, 1_000)).into_val(&env)];
    let got = [
        hex(policy::args_commitment(&env, &upgrade)),
        hex(policy::args_commitment(&env, &withdraw)),
        hex(policy::args_commitment(&env, &disarm)),
        hex(policy::args_commitment(&env, &loosen)),
    ];
    assert_eq!(
        got,
        [
            "521dd51a8b326f9868f541bbcd7a3903e7cd2ff1760627d3b352a1afdf39f0e3",
            "17bde03e09abf32beb787a80d64326e9d50d0173d427fa5d6d442f9430f21fe5",
            "2d047a26baf1b80d141b7bedc641553c8439fcd002b11f2779722d165c9af7bf",
            "8f5cb79b26191bcf82ab1fd0a9117a100b1cef59b82171d821bc9cbec43382bb",
        ]
    );
}

/// The largest `set_policy` an owner can install: 16 tokens with limits and 16 ad-scope ids of
/// `MAX_AD_ID_BYTES` (512) bytes. Its `Scheduled` event must fit the network's 16,384-byte
/// per-transaction contract-event limit, or a guarded account could never schedule it.
fn maximal_policy_args(f: &Fixture) -> Vec<Val> {
    let mut tokens = Vec::new(&f.env);
    let mut limits = Vec::new(&f.env);
    for i in 0..policy::MAX_WHITELIST_TOKENS {
        let t = b32(&f.env, 0x10 + i as u8);
        tokens.push_back(t.clone());
        limits.push_back(tl(&t, 1_000, 1_000, 1));
    }
    let mut scope = Vec::new(&f.env);
    for i in 0..policy::MAX_AD_SCOPE {
        let id = std::format!("{i:02}{}", "x".repeat(policy::MAX_AD_ID_BYTES as usize - 2));
        scope.push_back(String::from_str(&f.env, &id));
    }
    policy_args(
        &f.env,
        &Agent::new(42).id(&f.env),
        &tokens,
        0,
        &f.signer,
        &Some(scope),
        &limits,
    )
}

#[test]
fn a_maximal_set_policy_schedule_fits_the_event_limit() {
    let f = fixture();
    guard(&f, 0, 3_600, 86_400);
    let args = maximal_policy_args(&f);
    let full = ScVal::try_from_val(&f.env, &args.to_val())
        .unwrap()
        .to_xdr(Limits::none())
        .unwrap()
        .len();
    f.env.cost_estimate().budget().reset_default();
    f.client
        .schedule(&Scope::Account, &sym_of(&f.env, "set_policy"), &args);
    let r = f.env.cost_estimate().resources();
    std::println!(
        "maximal set_policy: args XDR {full} bytes; Scheduled event {} bytes (limit 16384)",
        r.contract_events_size_bytes
    );
    assert!(r.contract_events_size_bytes <= 16_384);
    assert_eq!(
        last_event_data(&f.env, &f.account),
        ScVal::Vec(Some(
            std::vec![
                sc(&f.env, Vec::<Val>::new(&f.env)),
                sc(&f.env, commit(&f.env, args)),
                sc(&f.env, T0 + 3_600),
                sc(&f.env, T0 + 3_600 + 86_400),
            ]
            .try_into()
            .unwrap()
        )),
        "set_policy's event carries the commitment, not the args"
    );
}

/// The next-largest event: an owner lock carries the whole order. A guarded ad's id is bounded by
/// the 250-byte ledger-key limit: `Schedule(Ad(id), "set_settlement_signer")` is the longest key
/// since R2 (136 bytes plus the id, XDR-padded to 4), so 112 bytes is the longest id that can be
/// armed at all, and a longer one fails closed. (Ad ids are 36-byte UUIDs.)
#[test]
fn a_lock_schedule_on_the_longest_schedulable_ad_id_fits_the_event_limit() {
    let f = fixture();
    let long = "y".repeat(112);
    let ad_id = String::from_str(&f.env, &long);
    f.client.set_guard_rail(&ad_id, &Some(rail(0, 1_000)));
    let mut order = params(&f);
    order.ad_id = ad_id.clone();
    f.env.cost_estimate().budget().reset_default();
    f.client.schedule(
        &Scope::Ad(ad_id),
        &lock_for_order(&f.env),
        &vec![&f.env, order.into_val(&f.env), 0u32.into_val(&f.env)],
    );
    let r = f.env.cost_estimate().resources();
    std::println!(
        "lock on a 112-byte ad id: Scheduled event {} bytes (limit 16384)",
        r.contract_events_size_bytes
    );
    assert!(r.contract_events_size_bytes <= 16_384);
}

/// The guardrail commitment ignores the bucket: the owner schedules from one read, a
/// sub-threshold withdrawal moves the bucket, and the spend built from a fresh read still matches.
#[test]
fn a_guardrail_schedule_survives_a_moved_bucket() {
    let f = fixture();
    let to = Address::generate(&f.env);
    f.client
        .set_guard_rail(&ad(&f.env), &Some(rail(100, 1_000)));
    let looser = |g: GuardRail| GuardRail {
        threshold: 200,
        ..g
    };
    let first = f.client.guard_rail(&ad(&f.env)).unwrap();
    schedule_guard(&f, &Some(looser(first.clone())));
    f.env.ledger().set_timestamp(T0 + 600);
    owner_check(&f, &withdraw_ctx(&f, 50, &to)).expect("under the threshold");
    f.env.ledger().set_timestamp(T0 + 3_600);
    let fresh = f.client.guard_rail(&ad(&f.env)).unwrap();
    assert_ne!(
        (fresh.bucket.level, fresh.bucket.last_ts),
        (first.bucket.level, first.bucket.last_ts),
        "the bucket moved"
    );
    f.client.set_guard_rail(&ad(&f.env), &Some(looser(fresh)));
    assert_eq!(f.client.guard_rail(&ad(&f.env)).unwrap().threshold, 200);
}

/// Single use, on paths that do not clear the ad's rows: the same withdraw, close, lock and upgrade
/// spent twice. (A guardrail loosening also clears every row of the ad, so it cannot show this.)
#[test]
fn every_spend_is_single_use() {
    let f = fixture();
    let to = Address::generate(&f.env);
    guard(&f, 0, 3_600, 86_400);
    let order_args: Vec<Val> = vec![&f.env, params(&f).into_val(&f.env), 0u32.into_val(&f.env)];
    let lock = lock_ctx(&f.env, &f.target, order_args.clone());
    let hash = f.env.deployer().upload_contract_wasm(ACCOUNT_WASM);
    schedule_withdraw(&f, 7, &to);
    schedule_close(&f, &to);
    f.client
        .schedule(&ad_scope(&f.env), &lock_for_order(&f.env), &order_args);
    f.client.schedule(
        &Scope::Account,
        &sym_of(&f.env, "upgrade"),
        &vec![&f.env, hash.to_val()],
    );
    f.env.ledger().set_timestamp(T0 + 3_600);

    for (label, ctxs) in [
        ("withdraw", withdraw_ctx(&f, 7, &to)),
        ("close", close_ctx(&f, &to)),
        ("lock", lock),
    ] {
        owner_check(&f, &ctxs).unwrap_or_else(|e| panic!("{label}: {e:?}"));
        expect_err(owner_check(&f, &ctxs), AccountError::NotScheduled);
    }
    // `upgrade` swaps the code, but the uploaded wasm is this one, so the second call runs the
    // same rule.
    f.client.upgrade(&hash);
    assert_eq!(
        f.client.try_upgrade(&hash),
        Err(Ok(AccountError::NotScheduled))
    );
}

/// `schedule` reads its args in the call's own shape and, on an ad, refuses args that name another
/// ad: an unspendable schedule would still publish an event a watcher reads as a pending call.
#[test]
fn schedule_checks_each_actions_args() {
    let f = fixture();
    guard(&f, 0, 3_600, 86_400);
    let e = &f.env;
    let other = String::from_str(e, "ad-2");
    let to = Address::generate(e);
    let try_ad = |action: &str, args: Vec<Val>| {
        f.client
            .try_schedule(&ad_scope(e), &sym_of(e, action), &args)
    };
    let try_acct = |action: &str, args: Vec<Val>| {
        f.client
            .try_schedule(&Scope::Account, &sym_of(e, action), &args)
    };
    let mut other_order = params(&f);
    other_order.ad_id = other.clone();

    // Another ad, right shape.
    for (action, args) in [
        (
            "withdraw_from_ad",
            vec![e, other.to_val(), 1_u128.into_val(e), to.to_val()],
        ),
        ("close_ad", vec![e, other.to_val(), to.to_val()]),
        (
            "lock_for_order",
            vec![e, other_order.into_val(e), 0u32.into_val(e)],
        ),
        (
            "set_guard_rail",
            vec![e, other.to_val(), Option::<GuardRail>::None.into_val(e)],
        ),
    ] {
        assert_eq!(
            try_ad(action, args),
            Err(Ok(AccountError::ScopeMismatch)),
            "{action} naming ad-2 under ad-1"
        );
    }

    // The right ad, wrong shape.
    let bad_ad: [(&str, Vec<Val>); 6] = [
        (
            "withdraw_from_ad",
            vec![e, ad(e).to_val(), 1_u128.into_val(e)],
        ),
        (
            "withdraw_from_ad",
            vec![e, ad(e).to_val(), 1_u128.into_val(e), 5_u32.into_val(e)],
        ),
        ("close_ad", vec![e, ad(e).to_val(), 1_u128.into_val(e)]),
        ("lock_for_order", vec![e, ad(e).to_val()]),
        ("set_guard_rail", vec![e, ad(e).to_val(), 5_u32.into_val(e)]),
        ("set_guard_rail", vec![e, ad(e).to_val()]),
    ];
    for (action, args) in bad_ad.iter() {
        assert_eq!(
            try_ad(action, args.clone()),
            Err(Ok(AccountError::BadArgs)),
            "{action} {args:?}"
        );
    }

    let tokens = vec![e, f.ad_token.clone()];
    let mut short_policy = policy_args(
        e,
        &f.agent.id(e),
        &tokens,
        0,
        &f.signer,
        &None,
        &wide(e, &tokens),
    );
    short_policy.pop_back();
    let mut bad_tokens = policy_args(
        e,
        &f.agent.id(e),
        &tokens,
        0,
        &f.signer,
        &None,
        &wide(e, &tokens),
    );
    bad_tokens.set(2, vec![e, 5_u32].to_val());
    let bad_acct: [(&str, Vec<Val>); 6] = [
        ("upgrade", vec![e, 5_u32.into_val(e)]),
        ("set_targets", vec![e, vec![e, 5_u32].to_val()]),
        ("set_account_limit", vec![e, f.ad_token.to_val()]),
        (
            "set_account_limit",
            vec![e, f.ad_token.to_val(), 5_u32.into_val(e)],
        ),
        ("set_policy", short_policy),
        ("set_policy", bad_tokens),
    ];
    for (action, args) in bad_acct.iter() {
        assert_eq!(
            try_acct(action, args.clone()),
            Err(Ok(AccountError::BadArgs)),
            "{action} {args:?}"
        );
    }
    assert!(
        f.env
            .events()
            .all()
            .filter_by_contract(&f.account)
            .events()
            .iter()
            .all(|ev| {
                match &ev.body {
                    xdr::ContractEventBody::V0(v0) => v0.topics.first() != Some(&sym("scheduled")),
                }
            }),
        "no refused schedule published an event"
    );
}

/// The owner path reads an escrow call in its full shape: a sub-threshold withdrawal whose
/// destination does not decode is refused, even on an unguarded ad.
#[test]
fn the_owner_path_refuses_an_undecodable_destination() {
    let f = fixture();
    let bad = |fn_name: &str, args: Vec<Val>| {
        vec![
            &f.env,
            Context::Contract(ContractContext {
                contract: f.target.clone(),
                fn_name: Symbol::new(&f.env, fn_name),
                args,
            }),
        ]
    };
    let e = &f.env;
    expect_err(
        owner_check(
            &f,
            &bad(
                "withdraw_from_ad",
                vec![e, ad(e).to_val(), 1_u128.into_val(e), 5_u32.into_val(e)],
            ),
        ),
        AccountError::BadArgs,
    );
    expect_err(
        owner_check(
            &f,
            &bad("close_ad", vec![e, ad(e).to_val(), 5_u32.into_val(e)]),
        ),
        AccountError::BadArgs,
    );
}

/// `PolicySet` carries the whole policy, so its size grows with the lists. The largest policy that
/// installs — sixteen ad tokens at the widest limits, sixteen order tokens and sixteen ad ids at
/// the 512-byte bound — fits the network's 16,384-byte per-transaction event limit. (At a
/// 1,024-byte bound it measured 20,904 bytes and the host refused the install.)
#[test]
fn a_policy_set_event_with_full_lists_and_512_byte_ad_ids_fits_the_event_limit() {
    let f = fixture();
    let mut order_tokens = Vec::new(&f.env);
    let mut ad_tokens = Vec::new(&f.env);
    for i in 0..policy::MAX_WHITELIST_TOKENS {
        let t = b32(&f.env, 0x10 + i as u8);
        f.client.set_account_limit(
            &t,
            &Limit {
                capacity: 1_000,
                refill_per_second: 1,
            },
        );
        order_tokens.push_back(t.clone());
        ad_tokens.push_back(tl(&t, u128::MAX, u128::MAX, u128::MAX));
    }
    let mut scope = Vec::new(&f.env);
    for i in 0..policy::MAX_AD_SCOPE {
        let id = std::format!("{i:02}{}", "x".repeat(510));
        scope.push_back(String::from_str(&f.env, &id));
    }
    f.env.cost_estimate().budget().reset_default();
    f.client.set_policy(
        &Agent::new(42).id(&f.env),
        &lock_for_order(&f.env),
        &ad_tokens,
        &order_tokens,
        &0,
        &f.signer,
        &Some(scope),
    );
    let bytes = f.env.cost_estimate().resources().contract_events_size_bytes;
    std::println!("PolicySet with full lists and 512-byte ad ids: {bytes} bytes (limit 16384)");
    assert!(bytes <= 16_384);
}

/// The cross-chain vector: this account's `PolicySet` carries exactly `policySet`'s fields. The
/// other two halves are `order-params` (those fields fingerprint to `fingerprint`) and the EVM
/// module (it stores `fingerprint` for `encoded`), so a field left out of the event breaks the
/// chain from Soroban to the EVM's stored value.
#[test]
fn policy_set_carries_the_cross_chain_vector_fields() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../test-vectors/agent-policy-cross-chain.json"
    ))
    .unwrap();
    let hex32 = |env: &Env, s: &str| {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 + 2 * i..4 + 2 * i], 16).unwrap();
        }
        BytesN::from_array(env, &out)
    };
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 2);
    for c in cases {
        let f = fixture();
        let e = &f.env;
        let p = &c["policySet"];
        let u = |x: &serde_json::Value| x.as_str().unwrap().parse::<u128>().unwrap();
        let mut ad_tokens = Vec::new(e);
        for r in p["adTokens"].as_array().unwrap() {
            let token = hex32(e, r["token"].as_str().unwrap());
            f.client.set_account_limit(
                &token,
                &Limit {
                    capacity: 1,
                    refill_per_second: 1,
                },
            );
            ad_tokens.push_back(tl(
                &token,
                u(&r["maxPerOrder"]),
                u(&r["capacity"]),
                u(&r["refillPerSecond"]),
            ));
        }
        let mut order_tokens = Vec::new(e);
        for t in p["orderTokens"].as_array().unwrap() {
            order_tokens.push_back(hex32(e, t.as_str().unwrap()));
        }
        let scope: Option<Vec<String>> = p["adScope"].as_array().map(|ads| {
            let mut out = Vec::new(e);
            for a in ads {
                out.push_back(String::from_str(e, a.as_str().unwrap()));
            }
            out
        });
        let action = Symbol::new(e, p["action"].as_str().unwrap());
        let until: u64 = p["validUntil"].as_str().unwrap().parse().unwrap();
        let signer = hex32(e, p["settlementSigner"].as_str().unwrap());
        f.client.set_policy(
            &f.agent.id(e),
            &action,
            &ad_tokens,
            &order_tokens,
            &until,
            &signer,
            &scope,
        );
        assert_eq!(
            last_event_data(e, &f.account),
            ScVal::Vec(Some(
                std::vec![
                    sc(e, action),
                    sc(e, ad_tokens),
                    sc(e, order_tokens),
                    sc(e, scope),
                    sc(e, until),
                    sc(e, signer),
                ]
                .try_into()
                .unwrap()
            )),
            "{}",
            c["name"]
        );
    }
}

// ---------------------------------------------------------------------------
// plan 46: the owner's ad actions — funds pass through, never rest
// ---------------------------------------------------------------------------

/// The account's error from a `try_call`, if that is how it failed.
fn call_err<T, C>(
    r: Result<Result<T, C>, Result<AccountError, InvokeError>>,
) -> Option<AccountError> {
    match r {
        Err(Ok(e)) => Some(e),
        _ => None,
    }
}

/// The fixture's token contract and a client for it.
fn token_of(e: &Escrow) -> (Address, test_token::TokenContractClient<'static>) {
    let t = proofbridge_core::token::bytes32_to_token_address(&e.env, &e.ad_token).unwrap();
    (t.clone(), test_token::TokenContractClient::new(&e.env, &t))
}

/// An invocation with nested ones (the owner's call, then the token pull it spawns).
fn invocation_with(
    contract: &Address,
    fn_name: &str,
    args: std::vec::Vec<ScVal>,
    subs: std::vec::Vec<SorobanAuthorizedInvocation>,
) -> SorobanAuthorizedInvocation {
    let mut inv = invocation(contract, fn_name, args);
    inv.sub_invocations = subs.try_into().unwrap();
    inv
}

fn transfer_inv(
    e: &Escrow,
    token: &Address,
    from: &Address,
    to: &Address,
    amount: i128,
) -> SorobanAuthorizedInvocation {
    invocation(
        token,
        "transfer",
        std::vec![
            sc_val(&e.env, from.to_val()),
            sc_val(&e.env, to.to_val()),
            sc_val(&e.env, amount.into_val(&e.env)),
        ],
    )
}

fn liquidity_of(e: &Escrow, ad_id: &String) -> u128 {
    e.env.invoke_contract(
        &e.ad_manager,
        &Symbol::new(&e.env, "available_liquidity"),
        vec![&e.env, ad_id.clone().into_val(&e.env)],
    )
}

fn create_args(e: &Escrow, ad_id: &String, amount: u128) -> Vec<Val> {
    vec![
        &e.env,
        e.account.to_val(),
        ad_id.to_val(),
        e.ad_token.to_val(),
        amount.into_val(&e.env),
        e.order_chain_id.into_val(&e.env),
        b32(&e.env, 0xCC).to_val(),
        address_to_bytes32(&e.env, &e.account).to_val(),
    ]
}

/// D2: `create_ad` takes the deposit from the owner's wallet and hands it to the escrow in the same
/// call. The ad is the account's; the account's own balance doesn't move.
#[test]
fn p46_create_ad_passes_the_owners_funds_straight_to_the_escrow() {
    let e = escrow_fixture();
    let (token, tc) = token_of(&e);
    tc.mint(&e.owner, &2_000_000_i128);
    let account_before = tc.balance(&e.account);
    let client = AgentAccountClient::new(&e.env, &e.account);
    let ad2 = String::from_str(&e.env, "ad-2");
    let exp = e.env.ledger().sequence() + 100;

    let owner_inv = invocation_with(
        &e.account,
        "create_ad",
        std::vec![
            sc_val(&e.env, e.ad_manager.to_val()),
            sc_val(&e.env, token.to_val()),
            sc_val(&e.env, ad2.to_val()),
            sc_val(&e.env, e.ad_token.to_val()),
            sc_val(&e.env, 2_000_000_u128.into_val(&e.env)),
            sc_val(&e.env, e.order_chain_id.into_val(&e.env)),
            sc_val(&e.env, b32(&e.env, 0xCC).to_val()),
            sc_val(&e.env, address_to_bytes32(&e.env, &e.account).to_val()),
        ],
        std::vec![transfer_inv(&e, &token, &e.owner, &e.account, 2_000_000)],
    );
    e.env
        .set_auths(&[entry(&e.owner, owner_inv, 11, exp, ScVal::Void, Creds::V2)]);
    client.create_ad(
        &e.ad_manager,
        &token,
        &ad2,
        &e.ad_token,
        &2_000_000_u128,
        &e.order_chain_id,
        &b32(&e.env, 0xCC),
        &address_to_bytes32(&e.env, &e.account),
    );
    assert_eq!(liquidity_of(&e, &ad2), 2_000_000);
    assert_eq!(tc.balance(&e.owner), 0, "the deposit came from the wallet");
    assert_eq!(
        tc.balance(&e.account),
        account_before,
        "and never stayed in the account"
    );

    // Without the owner's authorization: refused.
    e.env.set_auths(&[]);
    let ad3 = String::from_str(&e.env, "ad-3");
    assert!(client
        .try_create_ad(
            &e.ad_manager,
            &token,
            &ad3,
            &e.ad_token,
            &1_u128,
            &e.order_chain_id,
            &b32(&e.env, 0xCC),
            &address_to_bytes32(&e.env, &e.account),
        )
        .is_err());
}

/// D3, the reason the pre-approval exists: the escrow pulls the deposit from the account, a call the
/// account doesn't make itself. With real authorization (no mocks: they would cover the account too),
/// the same `create_ad` through `call` is refused by the host without the approval, and passes with
/// exactly that transfer approved.
#[test]
fn p46_the_escrows_pull_needs_the_accounts_pre_approval_and_nothing_more() {
    let e = escrow_fixture();
    let (token, tc) = token_of(&e);
    tc.mint(&e.owner, &2_000_000_i128);
    let client = AgentAccountClient::new(&e.env, &e.account);
    let ad2 = String::from_str(&e.env, "ad-2");
    let create = Symbol::new(&e.env, "create_ad");
    let pay = Some((token.clone(), 1_000_000_u128));
    let exp = e.env.ledger().sequence() + 100;
    let owner_auth = |nonce: i64, approvals: &Vec<InvokerContractAuthEntry>| {
        let inv = invocation_with(
            &e.account,
            "call",
            std::vec![
                sc_val(&e.env, e.ad_manager.to_val()),
                sc_val(&e.env, create.to_val()),
                sc_val(&e.env, create_args(&e, &ad2, 1_000_000).to_val()),
                sc_val(&e.env, pay.clone().into_val(&e.env)),
                sc_val(&e.env, approvals.to_val()),
            ],
            std::vec![transfer_inv(&e, &token, &e.owner, &e.account, 1_000_000)],
        );
        entry(&e.owner, inv, nonce, exp, ScVal::Void, Creds::V2)
    };

    let none: Vec<InvokerContractAuthEntry> = Vec::new(&e.env);
    e.env.set_auths(&[owner_auth(21, &none)]);
    assert!(client
        .try_call(
            &e.ad_manager,
            &create,
            &create_args(&e, &ad2, 1_000_000),
            &pay,
            &none
        )
        .is_err());
    assert_eq!(liquidity_of(&e, &ad2), 0);
    assert_eq!(tc.balance(&e.owner), 2_000_000, "nothing moved");

    let approval = vec![
        &e.env,
        InvokerContractAuthEntry::Contract(soroban_sdk::auth::SubContractInvocation {
            context: ContractContext {
                contract: token.clone(),
                fn_name: Symbol::new(&e.env, "transfer"),
                args: vec![
                    &e.env,
                    e.account.to_val(),
                    e.ad_manager.to_val(),
                    1_000_000_i128.into_val(&e.env),
                ],
            },
            sub_invocations: Vec::new(&e.env),
        }),
    ];
    e.env.set_auths(&[owner_auth(22, &approval)]);
    client.call(
        &e.ad_manager,
        &create,
        &create_args(&e, &ad2, 1_000_000),
        &pay,
        &approval,
    );
    assert_eq!(liquidity_of(&e, &ad2), 1_000_000);
    assert_eq!(tc.balance(&e.owner), 1_000_000);
}

/// `fund_ad` the same way: the top-up goes wallet → escrow, the account's balance unchanged.
#[test]
fn p46_fund_ad_passes_the_top_up_through() {
    let e = escrow_fixture();
    let (token, tc) = token_of(&e);
    tc.mint(&e.owner, &300_000_i128);
    let account_before = tc.balance(&e.account);
    let client = AgentAccountClient::new(&e.env, &e.account);
    e.env.mock_all_auths_allowing_non_root_auth();
    client.fund_ad(&e.ad_manager, &token, &e.ad_id, &300_000_u128);
    assert_eq!(liquidity(&e), 5_300_000);
    assert_eq!(tc.balance(&e.owner), 0);
    assert_eq!(tc.balance(&e.account), account_before);
}

/// The account forwards only what the call paid in: paying in more than the escrow takes leaves funds
/// behind, and the whole call is refused (`FundsLeft`), the payment included.
#[test]
fn p46_a_call_that_leaves_funds_in_the_account_is_refused() {
    let e = escrow_fixture();
    let (token, tc) = token_of(&e);
    tc.mint(&e.owner, &500_001_i128);
    let client = AgentAccountClient::new(&e.env, &e.account);
    e.env.mock_all_auths_allowing_non_root_auth();
    let approval = vec![
        &e.env,
        InvokerContractAuthEntry::Contract(soroban_sdk::auth::SubContractInvocation {
            context: ContractContext {
                contract: token.clone(),
                fn_name: Symbol::new(&e.env, "transfer"),
                args: vec![
                    &e.env,
                    e.account.to_val(),
                    e.ad_manager.to_val(),
                    500_000_i128.into_val(&e.env),
                ],
            },
            sub_invocations: Vec::new(&e.env),
        }),
    ];
    let r = client.try_call(
        &e.ad_manager,
        &Symbol::new(&e.env, "fund_ad"),
        &vec![&e.env, e.ad_id.to_val(), 500_000_u128.into_val(&e.env)],
        &Some((token.clone(), 500_001_u128)),
        &approval,
    );
    assert_eq!(call_err(r), Some(AccountError::FundsLeft));
    assert_eq!(
        tc.balance(&e.owner),
        500_001,
        "the payment reverted with the call"
    );
    assert_eq!(liquidity(&e), 5_000_000);
}

/// An approval is a token transfer from this account, or an `open_dispute` over such transfers.
/// An `approve` (an allowance outlives the call) or a transfer from someone else is refused.
#[test]
fn p46_only_transfers_from_the_account_can_be_approved() {
    let e = escrow_fixture();
    let (token, _) = token_of(&e);
    let client = AgentAccountClient::new(&e.env, &e.account);
    e.env.mock_all_auths_allowing_non_root_auth();
    let one = |fn_name: &str, from: &Address, subs: Vec<InvokerContractAuthEntry>| {
        vec![
            &e.env,
            InvokerContractAuthEntry::Contract(soroban_sdk::auth::SubContractInvocation {
                context: ContractContext {
                    contract: token.clone(),
                    fn_name: Symbol::new(&e.env, fn_name),
                    args: vec![
                        &e.env,
                        from.to_val(),
                        e.ad_manager.to_val(),
                        1_i128.into_val(&e.env),
                    ],
                },
                sub_invocations: subs,
            }),
        ]
    };
    let empty = Vec::new(&e.env);
    let fund = Symbol::new(&e.env, "fund_ad");
    let fund_args = vec![&e.env, e.ad_id.to_val(), 1_u128.into_val(&e.env)];
    for approvals in [
        one("approve", &e.account, empty.clone()),
        one("transfer", &e.owner, empty.clone()),
        one(
            "transfer",
            &e.account,
            one("transfer", &e.account, empty.clone()),
        ),
        one("burn", &e.account, empty.clone()),
    ] {
        assert_eq!(
            call_err(client.try_call(&e.ad_manager, &fund, &fund_args, &None, &approvals)),
            Some(AccountError::BadApproval)
        );
    }
}

/// The owner's escrow calls reach pinned targets only, so no other contract (a token above all) can
/// be called as the account.
#[test]
fn p46_call_reaches_pinned_targets_only() {
    let e = escrow_fixture();
    let (token, _) = token_of(&e);
    let client = AgentAccountClient::new(&e.env, &e.account);
    e.env.mock_all_auths_allowing_non_root_auth();
    let r = client.try_call(
        &token,
        &Symbol::new(&e.env, "transfer"),
        &vec![
            &e.env,
            e.account.to_val(),
            e.owner.to_val(),
            1_i128.into_val(&e.env),
        ],
        &None,
        &Vec::new(&e.env),
    );
    assert_eq!(call_err(r), Some(AccountError::TargetNotAllowed));
    let ad2 = String::from_str(&e.env, "ad-2");
    assert_eq!(
        client.try_create_ad(
            &Address::generate(&e.env),
            &token,
            &ad2,
            &e.ad_token,
            &1_u128,
            &e.order_chain_id,
            &b32(&e.env, 0xCC),
            &address_to_bytes32(&e.env, &e.account),
        ),
        Err(Ok(AccountError::TargetNotAllowed))
    );
    // A token that isn't the ad's is refused before anything moves.
    assert_eq!(
        client.try_create_ad(
            &e.ad_manager,
            &Address::generate(&e.env),
            &ad2,
            &e.ad_token,
            &1_u128,
            &e.order_chain_id,
            &b32(&e.env, 0xCC),
            &address_to_bytes32(&e.env, &e.account),
        ),
        Err(Ok(AccountError::BadArgs))
    );
}

/// `sweep` is the one way out for funds at rest. Instant on an unguarded account; while any ad is
/// guarded it needs a matured schedule for exactly that call.
#[test]
fn p46_sweep_empties_funds_at_rest_and_waits_on_a_guarded_account() {
    let e = escrow_fixture();
    let (token, tc) = token_of(&e);
    let client = AgentAccountClient::new(&e.env, &e.account);
    e.env.mock_all_auths_allowing_non_root_auth();
    let held = tc.balance(&e.account);
    client.sweep(&token, &e.owner, &1_000_u128);
    assert_eq!(tc.balance(&e.account), held - 1_000);

    client.set_guard_rail(
        &e.ad_id,
        &Some(GuardRail {
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
        }),
    );
    assert_eq!(
        client.try_sweep(&token, &e.owner, &1_000_u128),
        Err(Ok(AccountError::NotScheduled))
    );
    client.schedule(
        &Scope::Account,
        &Symbol::new(&e.env, "sweep"),
        &vec![
            &e.env,
            token.to_val(),
            e.owner.to_val(),
            1_000_u128.into_val(&e.env),
        ],
    );
    e.env.ledger().set_timestamp(T0 + 3_600);
    client.sweep(&token, &e.owner, &1_000_u128);
    assert_eq!(tc.balance(&e.account), held - 2_000);
}

/// The pass-through's own check: if the escrow doesn't take what the owner paid in, the funds would
/// stay in the account, so the call is refused and the payment reverts with it.
#[test]
fn p46_funds_the_escrow_does_not_take_never_stay_in_the_account() {
    let f = fixture();
    let admin = Address::generate(&f.env);
    let token = f.env.register(
        test_token::TokenContract,
        (
            admin,
            0_i128,
            7_u32,
            String::from_str(&f.env, "Test"),
            String::from_str(&f.env, "TST"),
        ),
    );
    let tc = test_token::TokenContractClient::new(&f.env, &token);
    tc.mint(&f.owner, &1_000_i128);
    let r = f.client.try_fund_ad(
        &f.target,
        &token,
        &String::from_str(&f.env, "ad-1"),
        &1_000_u128,
    );
    assert_eq!(r, Err(Ok(AccountError::FundsLeft)));
    assert_eq!(tc.balance(&f.owner), 1_000);
    assert_eq!(tc.balance(&f.account), 0);
}

/// Plan 46 D11, one bound on both chains: an all-zero agent id and an expiry past the EVM module's
/// 48 bits are refused at install; the account-wide volume is readable.
#[test]
fn p46_parity_install_bounds_and_the_volume_view() {
    let f = fixture();
    let install = |agent_id: &BytesN<32>, valid_until: u64| {
        f.client.try_set_policy(
            agent_id,
            &lock_for_order(&f.env),
            &vec![&f.env, tl(&f.ad_token, 1, 1, 1)],
            &vec![&f.env, f.order_token.clone()],
            &valid_until,
            &f.signer,
            &None,
        )
    };
    assert_eq!(
        install(&b32(&f.env, 0), 0),
        Err(Ok(AccountError::BadPolicy))
    );
    let other = Agent::new(9).id(&f.env);
    assert_eq!(
        install(&other, MAX_VALID_UNTIL + 1),
        Err(Ok(AccountError::BadPolicy))
    );
    assert!(install(&other, MAX_VALID_UNTIL).is_ok());
    let v = f
        .client
        .account_volume(&f.ad_token)
        .expect("set by the fixture");
    assert_eq!(v.limit.capacity, u128::MAX / 2);
    assert!(f.client.account_volume(&b32(&f.env, 0x99)).is_none());
}

/// Plan 46 D11: a lock with an undecodable field is `BadArgs` even when its settlement signer is also
/// wrong. Every field is decoded before any reach check, the EVM module's order. (The shared fixture
/// can't express a missing field on both chains, so each chain pins this itself.)
#[test]
fn p46_a_malformed_lock_is_bad_args_before_any_reach_check() {
    let f = fixture();
    let mut m = lock_map(&f);
    m.set(
        Symbol::new(&f.env, "ad_settlement_signer"),
        b32(&f.env, 0x77).to_val(),
    );
    m.remove(Symbol::new(&f.env, "amount"));
    expect_err(
        agent_check(
            &f,
            &lock_ctx(&f.env, &f.target, vec![&f.env, m.to_val(), 0_u32.into()]),
        ),
        AccountError::BadArgs,
    );
}

// ---------------------------------------------------------------------------
// plan 46 review pass 1: the maker account's side of a dispute, against the real dispute manager
// ---------------------------------------------------------------------------

/// The escrow fixture with the real dispute manager wired in, an order locked on the account's ad,
/// and the bridger's dispute filed against it. Returns (dispute manager, the order's params, its
/// hash).
fn disputed_order(e: &Escrow) -> (Address, OrderParams, BytesN<32>) {
    let admin = Address::generate(&e.env);
    let dm = e.env.register(dispute_manager::DisputeManagerContract, ());
    let dmc = dispute_manager::DisputeManagerContractClient::new(&e.env, &dm);
    let (token, tc) = token_of(e);
    dmc.initialize(&admin, &token);
    dmc.set_escrow(&e.ad_manager, &true);
    dmc.set_arbiter(&Address::generate(&e.env));
    dmc.set_protocol_fee_pool(&Address::generate(&e.env));
    dmc.set_dispute_params(
        &e.order_chain_id,
        &proofbridge_core::types::DisputeParams {
            challenge_period: 3_600,
            bond_floor: 1_000,
        },
    );
    let am = ad_manager::AdManagerContractClient::new(&e.env, &e.ad_manager);
    am.set_dispute_manager(&dm);

    let p = escrow_params(e, 400_000);
    let order_hash: BytesN<32> = e.env.invoke_contract(
        &e.ad_manager,
        &Symbol::new(&e.env, "lock_for_order"),
        vec![&e.env, p.clone().into_val(&e.env), 0u32.into_val(&e.env)],
    );
    let bridger =
        proofbridge_core::token::bytes32_to_account_address(&e.env, &p.order_recipient).unwrap();
    tc.mint(&bridger, &1_000_000_i128);
    // the bridger authorizes the module's nested pull of its bond
    e.env.mock_all_auths_allowing_non_root_auth();
    am.dispute(&p, &bridger, &b32(&e.env, 0xE1));
    (dm, p, order_hash)
}

/// 80-1: the maker account answers a dispute through `call`. The dispute manager asks the responder
/// itself to authorize (`record_response`), which the account isn't the direct caller of, so the
/// account pre-approves exactly that call: rooted, nothing nested, this account as the responder,
/// for the escrow being called. With real authorization, end to end.
#[test]
fn p46_a_maker_account_answers_a_dispute_through_call() {
    let e = escrow_fixture();
    let (dm, p, order_hash) = disputed_order(&e);
    let client = AgentAccountClient::new(&e.env, &e.account);
    let respond = Symbol::new(&e.env, "respond_to_dispute");
    let evidence = b32(&e.env, 0xE2);
    let args = vec![
        &e.env,
        p.clone().into_val(&e.env),
        e.account.to_val(),
        evidence.to_val(),
    ];
    let approval_for = |escrow: &Address, responder: &Address| {
        vec![
            &e.env,
            InvokerContractAuthEntry::Contract(soroban_sdk::auth::SubContractInvocation {
                context: ContractContext {
                    contract: dm.clone(),
                    fn_name: Symbol::new(&e.env, "record_response"),
                    args: vec![
                        &e.env,
                        escrow.to_val(),
                        order_hash.to_val(),
                        responder.to_val(),
                        evidence.to_val(),
                    ],
                },
                sub_invocations: Vec::new(&e.env),
            }),
        ]
    };
    let exp = e.env.ledger().sequence() + 100;
    let owner_auth = |nonce: i64, approvals: &Vec<InvokerContractAuthEntry>| {
        let inv = invocation(
            &e.account,
            "call",
            std::vec![
                sc_val(&e.env, e.ad_manager.to_val()),
                sc_val(&e.env, respond.to_val()),
                sc_val(&e.env, args.to_val()),
                sc_val(&e.env, Option::<(Address, u128)>::None.into_val(&e.env)),
                sc_val(&e.env, approvals.to_val()),
            ],
        );
        entry(&e.owner, inv, nonce, exp, ScVal::Void, Creds::V2)
    };

    // No approval: the host refuses the responder's nested authorization.
    let none: Vec<InvokerContractAuthEntry> = Vec::new(&e.env);
    e.env.set_auths(&[owner_auth(31, &none)]);
    assert!(client
        .try_call(&e.ad_manager, &respond, &args, &None, &none)
        .is_err());

    // An approval naming someone else as the responder, or another escrow, is the account's to
    // refuse.
    // ...or one carrying a nested call (a transfer from the account riding on the answer).
    let (token, _) = token_of(&e);
    let mut with_child = approval_for(&e.ad_manager, &e.account);
    if let InvokerContractAuthEntry::Contract(mut inv) = with_child.get(0).unwrap() {
        inv.sub_invocations = vec![
            &e.env,
            InvokerContractAuthEntry::Contract(soroban_sdk::auth::SubContractInvocation {
                context: ContractContext {
                    contract: token.clone(),
                    fn_name: Symbol::new(&e.env, "transfer"),
                    args: vec![
                        &e.env,
                        e.account.to_val(),
                        dm.to_val(),
                        1_i128.into_val(&e.env),
                    ],
                },
                sub_invocations: Vec::new(&e.env),
            }),
        ];
        with_child.set(0, InvokerContractAuthEntry::Contract(inv));
    }
    for (nonce, wrong) in [
        (32, approval_for(&e.ad_manager, &e.owner)),
        (34, approval_for(&Address::generate(&e.env), &e.account)),
        (35, with_child),
    ] {
        e.env.set_auths(&[owner_auth(nonce, &wrong)]);
        assert_eq!(
            call_err(client.try_call(&e.ad_manager, &respond, &args, &None, &wrong)),
            Some(AccountError::BadApproval)
        );
    }

    let right = approval_for(&e.ad_manager, &e.account);
    e.env.set_auths(&[owner_auth(33, &right)]);
    client.call(&e.ad_manager, &respond, &args, &None, &right);
    let d = dispute_manager::DisputeManagerContractClient::new(&e.env, &dm)
        .get_dispute(&order_hash)
        .expect("the dispute is open");
    assert_eq!(
        d.responder_evidence, evidence,
        "the maker's answer is recorded"
    );
}

fn sweep_args(f: &Fixture) -> Vec<Val> {
    vec![
        &f.env,
        Address::generate(&f.env).to_val(),
        f.owner.to_val(),
        1_000_u128.into_val(&f.env),
    ]
}

/// 80-2, 49S-1 for funds at rest: a pending sweep waits a raised delay like every other account-wide
/// change, or a stolen key's 1-hour sweep lands after the owner arms a 7-day guard.
#[test]
fn p46_a_pending_sweep_waits_a_raised_delay() {
    let f = fixture();
    let sweep = sym_of(&f.env, "sweep");
    guard(&f, 0, 3_600, 7 * 86_400);
    f.client.schedule(&Scope::Account, &sweep, &sweep_args(&f));
    assert_eq!(
        f.client
            .scheduled(&Scope::Account, &sweep)
            .unwrap()
            .ready_at,
        T0 + 3_600
    );
    guard(&f, 0, 7 * 86_400, 7 * 86_400);
    assert_eq!(
        f.client
            .scheduled(&Scope::Account, &sweep)
            .unwrap()
            .ready_at,
        T0 + 7 * 86_400,
        "the pending sweep waits the new delay"
    );
}

/// 80-2: disarming clears a pending sweep with every other schedule, so a re-armed account can't be
/// emptied by a row made under settings that are gone.
#[test]
fn p46_disarming_clears_a_pending_sweep() {
    let f = fixture();
    let sweep = sym_of(&f.env, "sweep");
    guard(&f, 0, 3_600, 86_400);
    f.client.schedule(&Scope::Account, &sweep, &sweep_args(&f));
    schedule_guard(&f, &None);
    f.env.ledger().set_timestamp(T0 + 3_600);
    f.client.set_guard_rail(&ad(&f.env), &None);
    assert!(f.client.scheduled(&Scope::Account, &sweep).is_none());
}

/// An `open_dispute` approval as the escrow would make it: filed by this account against the escrow
/// being called, with `subs` nested under it.
fn open_dispute_approval(
    e: &Escrow,
    subs: Vec<InvokerContractAuthEntry>,
) -> InvokerContractAuthEntry {
    InvokerContractAuthEntry::Contract(soroban_sdk::auth::SubContractInvocation {
        context: ContractContext {
            contract: Address::generate(&e.env),
            fn_name: Symbol::new(&e.env, "open_dispute"),
            args: vec![
                &e.env,
                e.ad_manager.to_val(),
                b32(&e.env, 0x01).to_val(),
                e.order_chain_id.into_val(&e.env),
                e.account.to_val(),
            ],
        },
        sub_invocations: subs,
    })
}

fn token_call(
    e: &Escrow,
    token: &Address,
    fn_name: &str,
    from: &Address,
    amount: i128,
) -> InvokerContractAuthEntry {
    InvokerContractAuthEntry::Contract(soroban_sdk::auth::SubContractInvocation {
        context: ContractContext {
            contract: token.clone(),
            fn_name: Symbol::new(&e.env, fn_name),
            args: vec![
                &e.env,
                from.to_val(),
                e.ad_manager.to_val(),
                amount.into_val(&e.env),
            ],
        },
        sub_invocations: Vec::new(&e.env),
    })
}

/// 80-4: `open_dispute` is accepted only at the root, and only over transfers from this account. A
/// nested one, or one carrying an `approve` or someone else's transfer, is refused.
#[test]
fn p46_an_open_dispute_approval_is_rooted_and_carries_only_the_accounts_transfers() {
    let e = escrow_fixture();
    let (token, _) = token_of(&e);
    let client = AgentAccountClient::new(&e.env, &e.account);
    e.env.mock_all_auths_allowing_non_root_auth();
    let fund = Symbol::new(&e.env, "fund_ad");
    let fund_args = vec![&e.env, e.ad_id.to_val(), 1_u128.into_val(&e.env)];
    let nested = vec![
        &e.env,
        open_dispute_approval(
            &e,
            vec![&e.env, open_dispute_approval(&e, Vec::new(&e.env))],
        ),
    ];
    let with_approve = vec![
        &e.env,
        open_dispute_approval(
            &e,
            vec![&e.env, token_call(&e, &token, "approve", &e.account, 1)],
        ),
    ];
    let others_transfer = vec![
        &e.env,
        open_dispute_approval(
            &e,
            vec![&e.env, token_call(&e, &token, "transfer", &e.owner, 1)],
        ),
    ];
    for approvals in [nested, with_approve, others_transfer] {
        assert_eq!(
            call_err(client.try_call(&e.ad_manager, &fund, &fund_args, &None, &approvals)),
            Some(AccountError::BadApproval)
        );
    }
}

/// 80-4: the balance check runs both ways. An approval that lets the escrow pull funds already at
/// rest in the account (no payment in) leaves its balance lower, and is refused.
#[test]
fn p46_an_approval_cannot_spend_funds_at_rest() {
    let e = escrow_fixture();
    let (token, tc) = token_of(&e);
    let client = AgentAccountClient::new(&e.env, &e.account);
    e.env.mock_all_auths_allowing_non_root_auth();
    let held = tc.balance(&e.account);
    assert!(held >= 1_000, "the fixture leaves funds at rest");
    let r = client.try_call(
        &e.ad_manager,
        &Symbol::new(&e.env, "fund_ad"),
        &vec![&e.env, e.ad_id.to_val(), 1_000_u128.into_val(&e.env)],
        &None,
        &vec![
            &e.env,
            token_call(&e, &token, "transfer", &e.account, 1_000),
        ],
    );
    assert_eq!(call_err(r), Some(AccountError::FundsLeft));
    assert_eq!(tc.balance(&e.account), held);
    assert_eq!(liquidity(&e), 5_000_000);
}

/// 80-4: `fund_ad` reaches a pinned escrow only.
#[test]
fn p46_fund_ad_reaches_pinned_targets_only() {
    let e = escrow_fixture();
    let (token, _) = token_of(&e);
    let client = AgentAccountClient::new(&e.env, &e.account);
    e.env.mock_all_auths_allowing_non_root_auth();
    assert_eq!(
        client.try_fund_ad(&Address::generate(&e.env), &token, &e.ad_id, &1_u128),
        Err(Ok(AccountError::TargetNotAllowed))
    );
}

fn arm(e: &Escrow, client: &AgentAccountClient) {
    client.set_guard_rail(
        &e.ad_id,
        &Some(GuardRail {
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
        }),
    );
}

/// 80-3: no token is reached as the account through `call`, whatever the targets say. With a token
/// pinned (a misconfiguration the target list allows), its transfer, approve and burn functions are
/// refused, so funds at rest still leave only through `sweep`.
#[test]
fn p46_call_never_reaches_a_token_function_even_on_a_pinned_token() {
    let e = escrow_fixture();
    let (token, tc) = token_of(&e);
    let client = AgentAccountClient::new(&e.env, &e.account);
    e.env.mock_all_auths_allowing_non_root_auth();
    client.set_targets(&vec![&e.env, e.ad_manager.clone(), token.clone()]);
    let held = tc.balance(&e.account);
    let thief = Address::generate(&e.env);
    for (name, args) in [
        (
            "transfer",
            vec![
                &e.env,
                e.account.to_val(),
                thief.to_val(),
                1_i128.into_val(&e.env),
            ],
        ),
        (
            "transfer_from",
            vec![
                &e.env,
                e.account.to_val(),
                e.account.to_val(),
                thief.to_val(),
                1_i128.into_val(&e.env),
            ],
        ),
        (
            "approve",
            vec![
                &e.env,
                e.account.to_val(),
                thief.to_val(),
                1_i128.into_val(&e.env),
                1_000_u32.into_val(&e.env),
            ],
        ),
        (
            "burn",
            vec![&e.env, e.account.to_val(), 1_i128.into_val(&e.env)],
        ),
        (
            "burn_from",
            vec![
                &e.env,
                e.account.to_val(),
                e.account.to_val(),
                1_i128.into_val(&e.env),
            ],
        ),
    ] {
        let r = client.try_call(
            &token,
            &Symbol::new(&e.env, name),
            &args,
            &None,
            &Vec::new(&e.env),
        );
        assert_eq!(
            call_err(r),
            Some(AccountError::FunctionNotAllowed),
            "{name}"
        );
    }
    assert_eq!(tc.balance(&e.account), held);
}

/// R3 (plan 46 review pass 1): while any ad is guarded, `call` reaches only the escrow functions the
/// account knows. A protective one passes at once; anything not on the list is refused, so a stolen
/// key can't reach a function nobody classified.
#[test]
fn p46_a_guarded_account_calls_only_known_escrow_functions() {
    let e = escrow_fixture();
    let client = AgentAccountClient::new(&e.env, &e.account);
    e.env.mock_all_auths_allowing_non_root_auth();
    let unknown = Symbol::new(&e.env, "set_fee_bps");
    let unknown_args = vec![&e.env, 1_u32.into_val(&e.env), 1_u32.into_val(&e.env)];
    let none = Vec::new(&e.env);
    // Unguarded: the account doesn't judge it (the escrow refuses it, as it isn't the admin).
    assert_ne!(
        call_err(client.try_call(&e.ad_manager, &unknown, &unknown_args, &None, &none)),
        Some(AccountError::FunctionNotAllowed)
    );
    arm(&e, &client);
    assert_eq!(
        call_err(client.try_call(&e.ad_manager, &unknown, &unknown_args, &None, &none)),
        Some(AccountError::FunctionNotAllowed)
    );
    // Halting is the incident response: never delayed, never refused.
    client.call(
        &e.ad_manager,
        &Symbol::new(&e.env, "halt_settlement"),
        &vec![&e.env, e.account.to_val()],
        &None,
        &none,
    );
    let halt = ad_manager::AdManagerContractClient::new(&e.env, &e.ad_manager)
        .halt_of(&e.account)
        .unwrap();
    assert!(halt.halted);
}

/// R2 (plan 46 review pass 1): on a guarded ad, re-pointing its settlement signer and resuming
/// settlement wait out the delay. Either is a drain path for a stolen key (a signer it holds, or
/// settlement turned back on after the owner halted), so neither may skip the guard. Halting stays
/// instant.
#[test]
fn p46_resuming_and_repointing_the_signer_wait_out_the_delay() {
    let f = fixture();
    guard(&f, 0, 3_600, 86_400);
    let none = Vec::new(&f.env);
    let repoint = Symbol::new(&f.env, "set_settlement_signer");
    let repoint_args = vec![&f.env, ad(&f.env).to_val(), b32(&f.env, 0x4f).to_val()];
    let resume = Symbol::new(&f.env, "resume_settlement");
    let resume_args = vec![&f.env, f.account.to_val()];
    let run = |name: &Symbol, args: &Vec<Val>| {
        f.client
            .try_call(&f.target, name, args, &None, &none)
            .map(|_| ())
    };
    assert_eq!(
        run(&repoint, &repoint_args),
        Err(Ok(AccountError::NotScheduled))
    );
    assert_eq!(
        run(&resume, &resume_args),
        Err(Ok(AccountError::NotScheduled))
    );
    f.client.call(
        &f.target,
        &Symbol::new(&f.env, "halt_settlement"),
        &vec![&f.env, f.account.to_val()],
        &None,
        &none,
    );

    f.client
        .schedule(&ad_scope(&f.env), &repoint, &repoint_args);
    f.client.schedule(&Scope::Account, &resume, &resume_args);
    assert_eq!(
        run(&repoint, &repoint_args),
        Err(Ok(AccountError::NotScheduled)),
        "not matured"
    );
    f.env.ledger().set_timestamp(T0 + 3_600);
    // A schedule names the exact call: another signer isn't covered.
    let other = vec![&f.env, ad(&f.env).to_val(), b32(&f.env, 0x50).to_val()];
    assert_eq!(run(&repoint, &other), Err(Ok(AccountError::NotScheduled)));
    assert_eq!(run(&repoint, &repoint_args), Ok(()));
    assert_eq!(run(&resume, &resume_args), Ok(()));
    assert_eq!(
        run(&resume, &resume_args),
        Err(Ok(AccountError::NotScheduled)),
        "single use"
    );
}

/// R1 (plan 46 review pass 1): tightening is instant, so it is bounded. A delay over 30 days or a
/// window under an hour would freeze the ad (removing the rail waits out the current delay), and
/// is refused, whether arming or tightening. The bounds themselves are accepted.
#[test]
fn p46_a_guard_rail_cannot_freeze_the_ad() {
    let f = fixture();
    let day = 86_400;
    let set = |delay: u64, window: u64| {
        f.client.try_set_guard_rail(
            &ad(&f.env),
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
        )
    };
    assert_eq!(
        set(30 * day + 1, day),
        Err(Ok(AccountError::GuardRailOutOfBounds))
    );
    assert_eq!(
        set(3_600, 3_599),
        Err(Ok(AccountError::GuardRailOutOfBounds))
    );
    assert!(set(3_600, 3_600).is_ok(), "the shortest window");
    // Tightening from there: a longer delay is instant, up to the bound and not past it.
    assert!(set(30 * day, 3_600).is_ok(), "the longest delay");
    assert_eq!(
        set(1_000 * 365 * day, 3_600),
        Err(Ok(AccountError::GuardRailOutOfBounds))
    );
    assert_eq!(f.client.guard_rail(&ad(&f.env)).unwrap().delay, 30 * day);
    // A change that could never be made can't be announced either.
    let frozen = Some(GuardRail {
        threshold: 0,
        delay: 3_600,
        window: 1,
        rate: Limit {
            capacity: 1,
            refill_per_second: 1,
        },
        bucket: Bucket {
            level: 0,
            last_ts: 0,
        },
    });
    assert_eq!(
        f.client.try_schedule(
            &ad_scope(&f.env),
            &sym_of(&f.env, "set_guard_rail"),
            &guard_args(&f.env, &frozen),
        ),
        Err(Ok(AccountError::GuardRailOutOfBounds))
    );
}
