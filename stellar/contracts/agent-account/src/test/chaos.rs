//! Chaos pack (CHAOS.md), Soroban: an agent's key misbehaves, or is lost, around a trade it locked.
//! The real AgentAccount, AdManager, MerkleManager and DisputeManager in one Env; the agent signs real
//! auth entries (`__check_auth`). The root and the proof are mocked, as on the EVM half.

use super::*;
use ad_manager::{AdManagerContractClient, AdManagerError as AdErr, DisputeOutcome, Status};
use core::cell::Cell;
use dispute_manager::{DisputeManagerContractClient, Error as DmErr};

const AMOUNT: u128 = 100_000;
const MAX_PER_ORDER: u128 = 1_000_000;
const CAPACITY: u128 = 3_100_000;
const AD_FUNDS: u128 = 5_000_000;
const OTHER_FUNDS: u128 = 1_000_000;
const BOND: u128 = 1_000;
const AD: &str = "ad-1";
const OTHER_AD: &str = "ad-2";

/// Accepts any proof: the ZK verifier is not what these tests are about.
#[soroban_sdk::contract]
pub struct ChaosProofVerifier;

#[soroban_sdk::contractimpl]
impl ChaosProofVerifier {
    pub fn verify_proof(_env: Env, _public_inputs: Bytes, _proof_bytes: Bytes) {}
}

/// Accepts a root only for the envelope's pinned slot (bytes 96..100) it was told to expect.
#[soroban_sdk::contract]
pub struct ChaosRootVerifier;

#[soroban_sdk::contractimpl]
impl ChaosRootVerifier {
    pub fn expect(env: Env, pin: u32) {
        env.storage()
            .instance()
            .set(&soroban_sdk::symbol_short!("pin"), &pin);
    }

    pub fn is_root_valid(env: Env, _chain: u128, _root: BytesN<32>, metadata: Bytes) -> bool {
        let expected: u32 = env
            .storage()
            .instance()
            .get(&soroban_sdk::symbol_short!("pin"))
            .unwrap_or(0);
        if metadata.len() < 100 {
            return false;
        }
        let mut be = [0u8; 4];
        metadata.slice(96..100).copy_into_slice(&mut be);
        u32::from_be_bytes(be) == expected
    }
}

/// A key registry whose signer holds `slots` live co-signing slots; `add_slot` rotates one in.
#[soroban_sdk::contract]
pub struct ChaosKeyRegistry;

#[soroban_sdk::contractimpl]
impl ChaosKeyRegistry {
    pub fn add_slot(env: Env) {
        let n = Self::slots(env.clone());
        env.storage()
            .instance()
            .set(&soroban_sdk::symbol_short!("slots"), &(n + 1));
    }

    pub fn slots(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&soroban_sdk::symbol_short!("slots"))
            .unwrap_or(1)
    }

    pub fn has_usable_slot(_env: Env, _account: BytesN<32>) -> bool {
        true
    }

    pub fn commitment_at(env: Env, account: BytesN<32>, slot_id: u32) -> BytesN<32> {
        if slot_id >= Self::slots(env) {
            panic!("no such slot");
        }
        account
    }

    pub fn expired_at(_env: Env, _account: BytesN<32>, _slot_id: u32) -> u64 {
        0
    }
}

struct Chaos {
    env: Env,
    owner: Address,
    account: Address,
    client: AgentAccountClient<'static>,
    am: AdManagerContractClient<'static>,
    dm: DisputeManagerContractClient<'static>,
    token: test_token::TokenContractClient<'static>,
    bond: test_token::TokenContractClient<'static>,
    root: ChaosRootVerifierClient<'static>,
    keys: ChaosKeyRegistryClient<'static>,
    fee_pool: Address,
    ad_token: BytesN<32>,
    order_token: BytesN<32>,
    portal: BytesN<32>,
    order_chain_id: u128,
    agent: Agent,
    /// The agent key's own Stellar account (the ed25519 key as a G address).
    agent_addr: Address,
    /// The bridger's payout address on this chain: the order's `order_recipient`.
    bridger: Address,
    nonce: Cell<i64>,
}

fn new_token(env: &Env, admin: &Address, code: &str) -> Address {
    env.register(
        test_token::TokenContract,
        (
            admin.clone(),
            0_i128,
            7_u32,
            String::from_str(env, code),
            String::from_str(env, code),
        ),
    )
}

/// The account owns two funded ads; one agent may lock on `AD` only, within the caps.
fn chaos() -> Chaos {
    let env = Env::default();
    env.ledger().set_timestamp(T0);
    env.mock_all_auths();
    env.ledger().set_protocol_version(PROTOCOL);
    env.cost_estimate().budget().reset_unlimited();

    let admin = Address::generate(&env);
    let owner = env.register(MockAuthContract, ());
    let ad_manager = env.register(ad_manager::AdManagerContract, ());
    let merkle = env.register(merkle_manager::ProofBridgeMerkleManagerContract, ());
    let verifier = env.register(ChaosProofVerifier, ());
    let token_id = new_token(&env, &admin, "TST");
    let bond_id = new_token(&env, &admin, "WXLM");
    let (account, client) = deploy(&env, &owner, &vec![&env, ad_manager.clone()]);

    let ad_token = address_to_bytes32(&env, &token_id);
    let order_token = b32(&env, 0xBB);
    let portal = b32(&env, 0xFF);
    let order_chain_id: u128 = 1;

    let mm = merkle_manager::ProofBridgeMerkleManagerContractClient::new(&env, &merkle);
    mm.initialize(&admin);
    mm.set_manager(&ad_manager, &true);

    let am = AdManagerContractClient::new(&env, &ad_manager);
    am.initialize(&admin, &verifier, &merkle, &bond_id, &2_000_000_002_u128);
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
    let keys_id = env.register(ChaosKeyRegistry, ());
    am.set_key_registry(&keys_id);
    // Wired before any lock: a verifier set after a lock denies its co-signed payout.
    let root_id = env.register(ChaosRootVerifier, ());
    am.set_root_verifier(&order_chain_id, &root_id);

    let dm_id = env.register(dispute_manager::DisputeManagerContract, ());
    let dm = DisputeManagerContractClient::new(&env, &dm_id);
    let arbiter = Address::generate(&env);
    let fee_pool = Address::generate(&env);
    dm.initialize(&admin, &bond_id);
    dm.set_escrow(&ad_manager, &true);
    dm.set_arbiter(&arbiter);
    dm.set_protocol_fee_pool(&fee_pool);
    dm.set_dispute_params(
        &order_chain_id,
        &proofbridge_core::types::DisputeParams {
            challenge_period: 3_600,
            bond_floor: BOND,
        },
    );
    am.set_dispute_manager(&dm_id);

    let token = test_token::TokenContractClient::new(&env, &token_id);
    token.mint(&account, &((AD_FUNDS + OTHER_FUNDS) as i128));
    let signer = address_to_bytes32(&env, &account);
    for (id, funds) in [(AD, AD_FUNDS), (OTHER_AD, OTHER_FUNDS)] {
        am.create_ad(
            &account,
            &String::from_str(&env, id),
            &ad_token,
            &funds,
            &order_chain_id,
            &b32(&env, 0xCC),
            &signer,
        );
    }

    let agent = Agent::new(7);
    client.set_account_limit(
        &ad_token,
        &Limit {
            capacity: u128::MAX / 2,
            refill_per_second: 1,
        },
    );
    client.set_policy(
        &agent.id(&env),
        &lock_for_order(&env),
        &vec![&env, tl(&ad_token, MAX_PER_ORDER, CAPACITY, 1)],
        &vec![&env, order_token.clone()],
        &0_u64,
        &signer,
        &Some(vec![&env, String::from_str(&env, AD)]),
    );

    let agent_addr = proofbridge_core::token::bytes32_to_account_address(&env, &agent.id(&env))
        .expect("an ed25519 key is a G address");
    let bridger =
        proofbridge_core::token::bytes32_to_account_address(&env, &b32(&env, 0x11)).unwrap();

    Chaos {
        owner,
        account,
        client,
        am,
        dm,
        token,
        bond: test_token::TokenContractClient::new(&env, &bond_id),
        root: ChaosRootVerifierClient::new(&env, &root_id),
        keys: ChaosKeyRegistryClient::new(&env, &keys_id),
        fee_pool,
        ad_token,
        order_token,
        portal,
        order_chain_id,
        agent,
        agent_addr,
        bridger,
        nonce: Cell::new(1),
        env,
    }
}

fn order(c: &Chaos, ad_id: &str, amount: u128, salt: u128) -> OrderParams {
    let me = address_to_bytes32(&c.env, &c.account);
    OrderParams {
        order_chain_token: c.order_token.clone(),
        ad_chain_token: c.ad_token.clone(),
        amount,
        bridger: b32(&c.env, 0xDD),
        order_chain_id: c.order_chain_id,
        src_order_portal: c.portal.clone(),
        order_recipient: b32(&c.env, 0x11),
        ad_id: String::from_str(&c.env, ad_id),
        ad_creator: me.clone(),
        ad_recipient: b32(&c.env, 0xCC),
        salt: soroban_sdk::U256::from_u128(&c.env, salt),
        order_decimals: 7,
        ad_decimals: 7,
        deadline: T0 + 86_400,
        ad_settlement_signer: me,
        lp_fee_bps: 0,
        protocol_fee_bps: 0,
    }
}

fn lock_args(c: &Chaos, p: &OrderParams) -> Vec<Val> {
    vec![&c.env, p.clone().into_val(&c.env), 0u32.into_val(&c.env)]
}

fn sym_(c: &Chaos, s: &str) -> Symbol {
    Symbol::new(&c.env, s)
}

fn next_nonce(c: &Chaos) -> i64 {
    let n = c.nonce.get();
    c.nonce.set(n + 1);
    n
}

/// The agent key signs a real auth entry, as the account, for `contract.fn_name(args)` and submits it.
fn as_agent(
    c: &Chaos,
    contract: &Address,
    fn_name: &str,
    args: &Vec<Val>,
) -> Result<Val, Result<soroban_sdk::Error, InvokeError>> {
    let exp = c.env.ledger().sequence() + 100;
    let nonce = next_nonce(c);
    let sc_args = args.iter().map(|v| sc_val(&c.env, v)).collect();
    let inv = invocation(contract, fn_name, sc_args);
    let payload = payload_hash(&c.env, &c.account, &inv, nonce, exp, Creds::V2);
    let sig = sc_val(&c.env, c.agent.sign(&c.env, &payload).into_val(&c.env));
    c.env
        .set_auths(&[entry(&c.account, inv, nonce, exp, sig, Creds::V2)]);
    let r = c.env.try_invoke_contract::<Val, soroban_sdk::Error>(
        contract,
        &sym_(c, fn_name),
        args.clone(),
    );
    c.env.mock_all_auths();
    r.map(|ok| ok.unwrap())
}

/// The account's own verdict on the agent signing for this one call.
fn check_as_agent(
    c: &Chaos,
    contract: &Address,
    fn_name: &str,
    args: &Vec<Val>,
) -> Result<(), Result<AccountError, InvokeError>> {
    let payload = b32(&c.env, 0x01);
    let sig = c.agent.sign(&c.env, &payload);
    let ctxs = vec![
        &c.env,
        Context::Contract(ContractContext {
            contract: contract.clone(),
            fn_name: sym_(c, fn_name),
            args: args.clone(),
        }),
    ];
    c.env.try_invoke_contract_check_auth::<AccountError>(
        &c.account,
        &payload,
        sig.into_val(&c.env),
        &ctxs,
    )
}

/// The agent's lock, end to end through `__check_auth`.
fn agent_lock(c: &Chaos, amount: u128, salt: u128) -> (OrderParams, BytesN<32>) {
    let p = order(c, AD, amount, salt);
    let h: BytesN<32> = BytesN::try_from_val(
        &c.env,
        &as_agent(c, &c.am.address, "lock_for_order", &lock_args(c, &p)).expect("in policy"),
    )
    .unwrap();
    assert_eq!(h, c.am.hash_order(&p));
    assert_eq!(c.am.get_order_status(&h), Status::Open);
    (p, h)
}

#[derive(Debug, PartialEq)]
struct Snapshot {
    ad: (u128, u128),
    other: (u128, u128),
    /// The agent's policy and its buckets, as XDR (the struct has no `PartialEq`).
    policy: ScVal,
    account_balance: i128,
    agent_balance: i128,
}

fn snapshot(c: &Chaos) -> Snapshot {
    let ad = |id: &str| {
        let a = c.am.get_ad(&String::from_str(&c.env, id)).unwrap();
        (a.balance, a.locked)
    };
    Snapshot {
        ad: ad(AD),
        other: ad(OTHER_AD),
        policy: sc_val(
            &c.env,
            c.client
                .policy(&c.agent.id(&c.env))
                .unwrap()
                .into_val(&c.env),
        ),
        account_balance: c.token.balance(&c.account),
        agent_balance: c.token.balance(&c.agent_addr),
    }
}

/// The agent key's call refused by the account with `reason`, and end to end; nothing moved, nothing debited.
fn thief_refused(
    c: &Chaos,
    contract: &Address,
    fn_name: &str,
    args: Vec<Val>,
    reason: AccountError,
) {
    let before = snapshot(c);
    assert_eq!(
        check_as_agent(c, contract, fn_name, &args),
        Err(Ok(reason)),
        "{fn_name}"
    );
    assert!(
        as_agent(c, contract, fn_name, &args).is_err(),
        "{fn_name} landed"
    );
    assert_eq!(snapshot(c), before, "{fn_name} moved something");
}

/// An owner-only door of the account, tried by the agent key signing as the account, and with no owner auth.
fn owner_door_shut(c: &Chaos, fn_name: &str, args: Vec<Val>) {
    let before = snapshot(c);
    assert!(
        as_agent(c, &c.account, fn_name, &args).is_err(),
        "{fn_name} as the account"
    );
    // Whatever the agent signs for itself, the owner's authorization is what is missing.
    c.env.set_auths(&[]);
    let r =
        c.env
            .try_invoke_contract::<Val, soroban_sdk::Error>(&c.account, &sym_(c, fn_name), args);
    c.env.mock_all_auths();
    assert!(r.is_err(), "{fn_name} without the owner");
    assert_eq!(snapshot(c), before, "{fn_name} moved something");
    assert_eq!(c.client.owner(), c.owner);
    assert_eq!(c.client.targets(), vec![&c.env, c.am.address.clone()]);
}

fn nullifier(c: &Chaos, label: u8) -> BytesN<32> {
    let mut n = [0u8; 32];
    n[31] = label;
    BytesN::from_array(&c.env, &n)
}

fn ad_of(c: &Chaos) -> ad_manager::Ad {
    c.am.get_ad(&String::from_str(&c.env, AD)).unwrap()
}

fn liquidity_now(c: &Chaos) -> u128 {
    c.am.available_liquidity(&String::from_str(&c.env, AD))
}

/// The co-signed unlock (root and proof mocked) pays the order's recipient exactly the lock, from the ad.
fn settles(c: &Chaos, p: &OrderParams, h: &BytesN<32>, label: u8) {
    let before = c.token.balance(&c.bridger);
    let balance = ad_of(c).balance;
    c.am.unlock(
        p,
        &nullifier(c, label),
        &b32(&c.env, 0x01),
        &Bytes::new(&c.env),
        &Bytes::new(&c.env),
    );
    assert_eq!(c.am.get_order_status(h), Status::Filled, "settled");
    assert_eq!(
        c.token.balance(&c.bridger),
        before + p.amount as i128,
        "the order's recipient is paid"
    );
    assert_eq!(ad_of(c).balance, balance - p.amount, "out of the ad");
    assert_eq!(
        c.token.balance(&c.account),
        0,
        "nothing rests in the account"
    );
    assert_eq!(c.token.balance(&c.agent_addr), 0, "the agent got nothing");
}

fn revoke(c: &Chaos) {
    c.client.revoke_agent(&c.agent.id(&c.env));
    assert!(c.client.is_revoked(&c.agent.id(&c.env)));
}

fn revoked_lock_refused(c: &Chaos) {
    let p = order(c, AD, 100, 2);
    thief_refused(
        c,
        &c.am.address,
        "lock_for_order",
        lock_args(c, &p),
        AccountError::AgentRevoked,
    );
}

/// The agent locks, then the bridger files against that lock.
fn disputed_agent_lock(c: &Chaos, salt: u128) -> (OrderParams, BytesN<32>) {
    let (p, h) = agent_lock(c, AMOUNT, salt);
    c.bond.mint(&c.bridger, &(BOND as i128));
    c.env.mock_all_auths_allowing_non_root_auth();
    assert_eq!(c.am.dispute(&p, &c.bridger, &b32(&c.env, 0xE1)), BOND);
    c.env.mock_all_auths();
    assert_eq!(c.dm.initiator_of(&h), Some(c.bridger.clone()));
    assert_eq!(c.am.get_order_status(&h), Status::Disputed);
    assert_eq!(c.bond.balance(&c.dm.address), BOND as i128, "one bond held");
    (p, h)
}

fn rule_and_finalize(c: &Chaos, p: &OrderParams, h: &BytesN<32>, outcome: DisputeOutcome) {
    c.dm.resolve_dispute(h, &outcome);
    c.env.ledger().set_timestamp(c.am.dispute_finalizes_at(p));
    c.am.finalize_dispute(p);
    assert_eq!(c.am.get_order_status(h), Status::Resolved);
}

fn assert_bond_gone(c: &Chaos, h: &BytesN<32>) {
    assert_eq!(
        c.bond.balance(&c.dm.address),
        0,
        "no bond left in the module"
    );
    assert!(!c.dm.is_disputed(h));
    assert_eq!(
        c.token.balance(&c.account),
        0,
        "nothing rests in the account"
    );
}

// ---------------------------------------------------------------------------
// C1: the agent's key is stolen mid-trade
// ---------------------------------------------------------------------------

/// The thief holds the agent key while its lock is open: nothing outside "lock within the policy" gets through.
#[test]
fn test_chaos_c1_stolen_key_cannot_defund_the_ad_or_touch_the_policy() {
    let c = chaos();
    let (p, h) = agent_lock(&c, AMOUNT, 1);
    let ad = String::from_str(&c.env, AD);
    let other = String::from_str(&c.env, OTHER_AD);
    let thief = c.agent_addr.clone();

    // Signing as the account: no withdraw, close, signer swap or token move.
    let am = c.am.address.clone();
    thief_refused(
        &c,
        &am,
        "withdraw_from_ad",
        vec![
            &c.env,
            ad.to_val(),
            (AD_FUNDS - AMOUNT).into_val(&c.env),
            thief.to_val(),
        ],
        AccountError::ActionNotAllowed,
    );
    thief_refused(
        &c,
        &am,
        "close_ad",
        vec![&c.env, other.to_val(), thief.to_val()],
        AccountError::ActionNotAllowed,
    );
    thief_refused(
        &c,
        &am,
        "set_settlement_signer",
        vec![&c.env, ad.to_val(), c.agent.id(&c.env).to_val()],
        AccountError::ActionNotAllowed,
    );
    thief_refused(
        &c,
        &c.token.address,
        "transfer",
        vec![
            &c.env,
            c.account.to_val(),
            thief.to_val(),
            1_i128.into_val(&c.env),
        ],
        AccountError::TargetNotAllowed,
    );

    // Every owner door of the account is shut to the agent key, as the account or as itself.
    c.token.mint(&c.account, &1); // something for a sweep to take
    let wide_open = vec![&c.env, tl(&c.ad_token, u128::MAX / 2, u128::MAX / 2, 1)];
    owner_door_shut(
        &c,
        "set_policy",
        vec![
            &c.env,
            c.agent.id(&c.env).to_val(),
            lock_for_order(&c.env).to_val(),
            wide_open.to_val(),
            vec![&c.env, c.order_token.clone()].to_val(),
            0_u64.into_val(&c.env),
            address_to_bytes32(&c.env, &c.account).to_val(),
            Option::<Vec<String>>::None.into_val(&c.env),
        ],
    );
    owner_door_shut(
        &c,
        "set_account_limit",
        vec![
            &c.env,
            c.ad_token.to_val(),
            Limit {
                capacity: u128::MAX / 2,
                refill_per_second: 1_000,
            }
            .into_val(&c.env),
        ],
    );
    owner_door_shut(
        &c,
        "set_targets",
        vec![
            &c.env,
            vec![&c.env, am.clone(), c.token.address.clone()].to_val(),
        ],
    );
    owner_door_shut(
        &c,
        "sweep",
        vec![
            &c.env,
            c.token.address.to_val(),
            thief.to_val(),
            1_u128.into_val(&c.env),
        ],
    );
    owner_door_shut(
        &c,
        "call",
        vec![
            &c.env,
            am.to_val(),
            sym_(&c, "withdraw_from_ad").to_val(),
            vec![&c.env, ad.to_val(), 1_u128.into_val(&c.env), thief.to_val()].to_val(),
            Option::<(Address, u128)>::None.into_val(&c.env),
            Vec::<InvokerContractAuthEntry>::new(&c.env).to_val(),
        ],
    );
    let wasm = c.env.deployer().upload_contract_wasm(ACCOUNT_WASM);
    owner_door_shut(&c, "upgrade", vec![&c.env, wasm.to_val()]);

    assert_eq!(
        c.am.get_order_status(&h),
        Status::Open,
        "the open trade is untouched"
    );
    assert_eq!(ad_of(&c).balance, AD_FUNDS, "nothing left the ad");
    assert_eq!(
        liquidity_now(&c),
        AD_FUNDS - AMOUNT,
        "and only the trade's amount is locked"
    );
    assert_eq!(c.token.balance(&thief), 0);

    // The order's payout is frozen in its hash: a re-pointed recipient is a different, unlocked order.
    let mut redirected = p.clone();
    redirected.order_recipient = c.agent.id(&c.env);
    assert_eq!(
        c.am.try_unlock(
            &redirected,
            &nullifier(&c, 0xC1),
            &b32(&c.env, 0x01),
            &Bytes::new(&c.env),
            &Bytes::new(&c.env),
        ),
        Err(Ok(AdErr::OrderNotOpen))
    );
}

/// The thief can lock, but only inside the caps, the ad scope and the settlement signer the owner set.
#[test]
fn test_chaos_c1_stolen_key_stays_inside_the_caps() {
    let c = chaos();
    agent_lock(&c, AMOUNT, 1);
    let am = c.am.address.clone();
    let lock = |p: &OrderParams| lock_args(&c, p);
    thief_refused(
        &c,
        &am,
        "lock_for_order",
        lock(&order(&c, AD, MAX_PER_ORDER + 1, 2)),
        AccountError::CapExceeded,
    );
    thief_refused(
        &c,
        &am,
        "lock_for_order",
        lock(&order(&c, OTHER_AD, 100, 3)),
        AccountError::AdNotAllowed,
    );
    let mut own_signer = order(&c, AD, 100, 4);
    own_signer.ad_settlement_signer = c.agent.id(&c.env);
    thief_refused(
        &c,
        &am,
        "lock_for_order",
        lock(&own_signer),
        AccountError::SettlementSignerMismatch,
    );

    // Drain at the per-order cap: the bucket runs dry and the next lock is refused before the escrow.
    let level = |c: &Chaos| {
        c.client
            .policy(&c.agent.id(&c.env))
            .unwrap()
            .buckets
            .get(0)
            .unwrap()
            .bucket
            .level
    };
    let mut landed = 0u128;
    while landed < 10 && level(&c) >= MAX_PER_ORDER {
        agent_lock(&c, MAX_PER_ORDER, 10 + landed);
        landed += 1;
    }
    assert_eq!(
        landed,
        (CAPACITY - AMOUNT) / MAX_PER_ORDER,
        "exactly the capacity landed"
    );
    thief_refused(
        &c,
        &am,
        "lock_for_order",
        lock(&order(&c, AD, MAX_PER_ORDER, 99)),
        AccountError::VolumeExceeded,
    );
    assert_eq!(
        liquidity_now(&c),
        AD_FUNDS - AMOUNT - landed * MAX_PER_ORDER
    );
}

/// The owner revokes the stolen key: its next lock is refused and the open trade still settles to its parties.
#[test]
fn test_chaos_c1_after_the_revoke_the_open_trade_still_settles_to_its_parties() {
    let c = chaos();
    let (p, h) = agent_lock(&c, AMOUNT, 1);
    revoke(&c);
    revoked_lock_refused(&c);
    settles(&c, &p, &h, 0xC1);
}

// ---------------------------------------------------------------------------
// C3: the agent is revoked while its trade is open
// ---------------------------------------------------------------------------

#[test]
fn test_chaos_c3_revoked_mid_trade_the_open_order_settles() {
    let c = chaos();
    let (p, h) = agent_lock(&c, AMOUNT, 1);
    revoke(&c);
    assert_eq!(
        c.am.get_order_status(&h),
        Status::Open,
        "the revoke left it open"
    );
    assert_eq!(liquidity_now(&c), AD_FUNDS - AMOUNT, "and still locked");

    settles(&c, &p, &h, 0xC3);
    revoked_lock_refused(&c);
}

/// No co-signed unlock comes: past the deadline the lock goes back to the ad and the CANCEL leaf
/// (the bridger's refund on the order chain) is appended once.
#[test]
fn test_chaos_c3_revoked_mid_trade_the_bridger_is_refunded_after_the_deadline() {
    let c = chaos();
    let (p, h) = agent_lock(&c, AMOUNT, 1);
    revoke(&c);

    c.env.ledger().set_timestamp(p.deadline);
    c.am.claim_cancel(&p);
    c.env.ledger().set_timestamp(c.am.cancel_finalizes_at(&p));
    let leaves = c.am.get_merkle_leaf_count();
    c.am.finalize_cancel(&p);

    assert_eq!(c.am.get_order_status(&h), Status::Cancelled);
    assert_eq!(c.am.get_merkle_leaf_count(), leaves + 1, "the CANCEL leaf");
    assert_eq!(liquidity_now(&c), AD_FUNDS, "the lock is back in the ad");
    assert_eq!(ad_of(&c).balance, AD_FUNDS);
    assert_eq!(c.token.balance(&c.bridger), 0, "the ad paid nobody");
    // Back inside the unlock window, so the status is what refuses.
    c.env.ledger().set_timestamp(p.deadline);
    assert_eq!(
        c.am.try_unlock(
            &p,
            &nullifier(&c, 0xC3),
            &b32(&c.env, 0x01),
            &Bytes::new(&c.env),
            &Bytes::new(&c.env),
        ),
        Err(Ok(AdErr::OrderNotOpen))
    );
    revoked_lock_refused(&c);
}

/// The tombstone is permanent: the owner cannot reinstall the revoked id, so a stolen key stays dead.
#[test]
fn test_chaos_c3_the_revoke_is_permanent() {
    let c = chaos();
    agent_lock(&c, AMOUNT, 1);
    revoke(&c);
    assert_eq!(
        c.client.try_set_policy(
            &c.agent.id(&c.env),
            &lock_for_order(&c.env),
            &vec![&c.env, tl(&c.ad_token, MAX_PER_ORDER, CAPACITY, 1)],
            &vec![&c.env, c.order_token.clone()],
            &0_u64,
            &address_to_bytes32(&c.env, &c.account),
            &None,
        ),
        Err(Ok(AccountError::AgentRevoked))
    );
    revoked_lock_refused(&c);
}

// ---------------------------------------------------------------------------
// C4: a settlement key is added while the agent's order is open
// ---------------------------------------------------------------------------

/// A new co-signing slot mid-trade: the order stays pinned to the slot it locked with and settles on it;
/// the new slot cannot vouch for it; the ad stays open.
#[test]
fn test_chaos_c4_a_key_added_mid_trade_leaves_the_order_on_its_pin() {
    let c = chaos();
    let (p, h) = agent_lock(&c, AMOUNT, 1);
    c.keys.add_slot();
    assert_eq!(c.keys.slots(), 2);

    assert_eq!(
        c.am.get_order(&h).pinned_slot,
        0,
        "still pinned to the lock's slot"
    );
    assert!(ad_of(&c).open, "no ad is closed");
    assert_eq!(c.am.get_order_status(&h), Status::Open);

    c.root.expect(&1);
    assert_eq!(
        c.am.try_unlock(
            &p,
            &nullifier(&c, 0xC4),
            &b32(&c.env, 0x01),
            &Bytes::new(&c.env),
            &Bytes::new(&c.env),
        ),
        Err(Ok(AdErr::RootNotValid))
    );
    c.root.expect(&0);
    settles(&c, &p, &h, 0xC4);
}

// ---------------------------------------------------------------------------
// C5: a dispute against a lock the agent made
// ---------------------------------------------------------------------------

#[test]
fn test_chaos_c5_mutual_refund_lock_back_to_the_ad_bond_back_to_the_filer() {
    let c = chaos();
    let (p, h) = disputed_agent_lock(&c, 1);
    rule_and_finalize(&c, &p, &h, DisputeOutcome::MutualRefund);
    assert_eq!(liquidity_now(&c), AD_FUNDS, "the lock is back in the ad");
    assert_eq!(ad_of(&c).balance, AD_FUNDS);
    assert_eq!(c.token.balance(&c.bridger), 0);
    assert_eq!(
        c.bond.balance(&c.bridger),
        BOND as i128,
        "the bond came back"
    );
    assert_bond_gone(&c, &h);
}

#[test]
fn test_chaos_c5_bridger_forfeit_lock_back_to_the_ad_bond_to_the_fee_pool() {
    let c = chaos();
    let (p, h) = disputed_agent_lock(&c, 2);
    rule_and_finalize(&c, &p, &h, DisputeOutcome::BridgerForfeit);
    assert_eq!(liquidity_now(&c), AD_FUNDS, "the lock is back in the ad");
    assert_eq!(c.token.balance(&c.bridger), 0);
    assert_eq!(
        c.bond.balance(&c.bridger),
        0,
        "the losing filer's bond is kept"
    );
    assert_eq!(c.bond.balance(&c.fee_pool), BOND as i128, "by the fee pool");
    assert_bond_gone(&c, &h);
}

#[test]
fn test_chaos_c5_maker_forfeit_the_recipient_is_paid_from_the_ad_bond_back_to_the_filer() {
    let c = chaos();
    let (p, h) = disputed_agent_lock(&c, 3);
    rule_and_finalize(&c, &p, &h, DisputeOutcome::MakerForfeit);
    assert_eq!(
        c.token.balance(&c.bridger),
        AMOUNT as i128,
        "the bridger's recipient is paid the lock"
    );
    assert_eq!(
        ad_of(&c).balance,
        AD_FUNDS - AMOUNT,
        "out of the account's ad"
    );
    assert_eq!(liquidity_now(&c), AD_FUNDS - AMOUNT);
    assert_eq!(
        c.bond.balance(&c.bridger),
        BOND as i128,
        "the vindicated filer's bond came back"
    );
    assert_bond_gone(&c, &h);
}

/// TradeProceeds comes only from evidence: the co-signed unlock settles the disputed order and the bond
/// of a filer who disputed a settleable trade goes to the fee pool.
#[test]
fn test_chaos_c5_trade_proceeds_by_evidence_settles_bond_to_the_fee_pool() {
    let c = chaos();
    let (p, h) = disputed_agent_lock(&c, 4);
    assert_eq!(
        c.dm.try_resolve_dispute(&h, &DisputeOutcome::TradeProceeds),
        Err(Ok(DmErr::ArbiterCannotSettle))
    );

    c.am.unlock(
        &p,
        &nullifier(&c, 0xC5),
        &b32(&c.env, 0x01),
        &Bytes::new(&c.env),
        &Bytes::new(&c.env),
    );
    assert_eq!(c.am.get_order_status(&h), Status::Filled);
    assert_eq!(c.token.balance(&c.bridger), AMOUNT as i128);
    assert_eq!(
        c.bond.balance(&c.fee_pool),
        BOND as i128,
        "the bond went to the fee pool"
    );
    assert_eq!(c.bond.balance(&c.bridger), 0);
    assert!(!c.dm.is_disputed(&h), "the evidence closed the dispute");
    assert_bond_gone(&c, &h);
}

/// The agent key has no hand in the dispute: it cannot file, answer or rule, and a finalize it sends
/// pays by the ruling, never to itself. The account (the maker) still answers through its owner.
#[test]
fn test_chaos_c5_the_agent_cannot_answer_rule_or_profit_from_the_dispute() {
    let c = chaos();
    let (p, h) = disputed_agent_lock(&c, 5);
    let am = c.am.address.clone();
    let thief = c.agent_addr.clone();
    let agent_evidence = b32(&c.env, 0xA6);

    // Signing as the account: the policy allows a lock and nothing else.
    let p_val: Val = p.clone().into_val(&c.env);
    thief_refused(
        &c,
        &am,
        "respond_to_dispute",
        vec![&c.env, p_val, c.account.to_val(), agent_evidence.to_val()],
        AccountError::ActionNotAllowed,
    );
    thief_refused(
        &c,
        &am,
        "dispute",
        vec![&c.env, p_val, c.account.to_val(), agent_evidence.to_val()],
        AccountError::ActionNotAllowed,
    );
    // `finalize_dispute` takes no one's auth; the account still would not sign for it.
    assert_eq!(
        check_as_agent(&c, &am, "finalize_dispute", &vec![&c.env, p_val]),
        Err(Ok(AccountError::ActionNotAllowed))
    );

    // As itself: the agent key is neither party nor arbiter, and has no credit to claim.
    assert_eq!(
        c.am.try_respond_to_dispute(&p, &thief, &agent_evidence),
        Err(Ok(AdErr::NotAParty))
    );
    c.env.set_auths(&[]); // no arbiter's authorization
    assert!(
        c.dm.try_resolve_dispute(&h, &DisputeOutcome::MutualRefund)
            .is_err(),
        "only the arbiter rules"
    );
    c.env.mock_all_auths();
    assert_eq!(c.dm.try_claim(&thief), Err(Ok(DmErr::NothingToClaim)));
    assert_eq!(c.dm.get_dispute(&h).unwrap().ruling, DisputeOutcome::None);

    // The owner answers for the maker through `call`, approving exactly the module's record_response.
    let answer = b32(&c.env, 0xE2);
    let respond = sym_(&c, "respond_to_dispute");
    let args = vec![&c.env, p_val, c.account.to_val(), answer.to_val()];
    let approval = vec![
        &c.env,
        InvokerContractAuthEntry::Contract(soroban_sdk::auth::SubContractInvocation {
            context: ContractContext {
                contract: c.dm.address.clone(),
                fn_name: sym_(&c, "record_response"),
                args: vec![
                    &c.env,
                    am.to_val(),
                    h.to_val(),
                    c.account.to_val(),
                    answer.to_val(),
                ],
            },
            sub_invocations: Vec::new(&c.env),
        }),
    ];
    c.env.mock_all_auths_allowing_non_root_auth();
    c.client.call(&am, &respond, &args, &None, &approval);
    c.env.mock_all_auths();
    assert_eq!(
        c.dm.get_dispute(&h).unwrap().responder_evidence,
        answer,
        "the maker's answer, from the owner"
    );

    rule_and_finalize(&c, &p, &h, DisputeOutcome::MakerForfeit);
    assert_eq!(
        c.token.balance(&c.bridger),
        AMOUNT as i128,
        "paid by the ruling"
    );
    assert_eq!(c.token.balance(&thief), 0, "not to the agent key");
    assert_eq!(c.bond.balance(&thief), 0);
    assert_bond_gone(&c, &h);
}

// ---------------------------------------------------------------------------
// C6 / C8: one dispute, and none once settled
// ---------------------------------------------------------------------------

/// The other party's second filing is refused, as is a repeat: one bond is held, and paid out once.
#[test]
fn test_chaos_c6_a_second_filing_is_refused_one_bond_held_once() {
    let c = chaos();
    let (p, h) = disputed_agent_lock(&c, 6);
    c.bond.mint(&c.account, &(BOND as i128));
    c.bond.mint(&c.bridger, &(BOND as i128));
    c.env.mock_all_auths_allowing_non_root_auth();
    assert_eq!(
        c.am.try_dispute(&p, &c.account, &b32(&c.env, 0xE3)),
        Err(Ok(AdErr::NotDisputable)),
        "the maker's filing"
    );
    assert_eq!(
        c.am.try_dispute(&p, &c.bridger, &b32(&c.env, 0xE4)),
        Err(Ok(AdErr::NotDisputable)),
        "the filer again"
    );
    c.env.mock_all_auths();
    assert_eq!(c.bond.balance(&c.dm.address), BOND as i128, "one bond held");
    assert_eq!(
        c.dm.get_dispute(&h).unwrap().initiator,
        c.bridger,
        "the first filing stands"
    );

    rule_and_finalize(&c, &p, &h, DisputeOutcome::MutualRefund);
    assert_eq!(
        c.bond.balance(&c.bridger),
        2 * BOND as i128,
        "the held bond back once, the refused one never taken"
    );
    assert_eq!(
        c.bond.balance(&c.account),
        BOND as i128,
        "the maker's refused filing took nothing"
    );
    assert_eq!(
        c.bond.balance(&c.dm.address),
        0,
        "no bond left in the module"
    );
    assert_eq!(c.am.try_finalize_dispute(&p), Err(Ok(AdErr::NotClaimable)));
}

/// A leg that already settled cannot be disputed, and no ruling exists to undo it.
#[test]
fn test_chaos_c8_a_settled_trade_cannot_be_disputed_or_ruled() {
    let c = chaos();
    let (p, h) = agent_lock(&c, AMOUNT, 8);
    settles(&c, &p, &h, 0xC8);

    c.bond.mint(&c.bridger, &(BOND as i128));
    c.env.mock_all_auths_allowing_non_root_auth();
    assert_eq!(
        c.am.try_dispute(&p, &c.bridger, &b32(&c.env, 0xE5)),
        Err(Ok(AdErr::NotDisputable))
    );
    c.env.mock_all_auths();
    assert_eq!(
        c.dm.try_resolve_dispute(&h, &DisputeOutcome::MakerForfeit),
        Err(Ok(DmErr::NotDisputed))
    );
    assert_eq!(c.am.try_finalize_dispute(&p), Err(Ok(AdErr::NotClaimable)));

    assert_eq!(c.token.balance(&c.bridger), AMOUNT as i128, "paid once");
    assert_eq!(c.bond.balance(&c.bridger), BOND as i128, "no bond taken");
    assert_eq!(c.am.get_order_status(&h), Status::Filled);
}
