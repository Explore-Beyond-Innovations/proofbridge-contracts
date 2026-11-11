# ProofBridge Stellar contracts

The Soroban (Rust) implementation of ProofBridge for the Stellar network.

The protocol, the contract set and the shared rules (fees, timelock, route timing, disputes) are in
the [contracts README](../README.md). This page covers what is specific to Stellar.

## Stellar specifics

* **Authorization.** State-changing calls use Soroban `require_auth` on the acting address (the
  maker, the bridger, the admin). Calls that act for someone take that address as an argument,
  for example `create_ad(creator, …)`, `halt_settlement(maker)` and `dispute(params, filer, …)`.
  `unlock` is permissionless: the proof and the co-signature are the authorization.
* **Root verification.** `unlock` needs the route's root verifier (`counterparty-verifier`). Until
  one is set it fails with `RootVerifierNotSet`.
* **Setup.** Contracts are deployed, then configured with `initialize`. The escrows take
  `initialize(admin, verifier, merkle_manager, w_native_token, chain_id)`. The verifier is the
  exception: its verification key is passed to `__constructor` at deploy and never changes.
* **Addresses.** Every cross-chain field is a 32-byte `BytesN<32>`: a `C...` contract id or a
  `G...` ed25519 account key, without the strkey encoding.
* **Chain ids.** Stellar has no numeric chain id, so ProofBridge assigns one: `1000001` for
  localnet and `1000002` for testnet (`deploy/src/deploy-env.ts`).

### Tokens

The escrows move every token through the standard Soroban token interface, so three kinds of
asset work the same way:

| Kind | What it is | How the escrow holds it |
| --- | --- | --- |
| `NATIVE` | XLM | Named by the all-`0xEE` sentinel in an order. The escrow pays through the native XLM Stellar Asset Contract, configured as `w_native_token`. |
| `SAC` | A classic issued asset | Through the asset's Stellar Asset Contract. |
| `SEP41` | A Soroban contract token | Through the token contract itself. |

Every non-native deposit checks that the escrow's balance rose by exactly the amount
(`TransferShort` otherwise), so a fee-on-transfer token cannot leave the escrow short.

## Structs

The order as each escrow takes it. From `contracts/order-portal/src/types.rs`:

```rust
pub struct OrderParams {
    pub order_chain_token: BytesN<32>,
    pub ad_chain_token: BytesN<32>,
    pub amount: u128,
    pub bridger: BytesN<32>,
    pub order_recipient: BytesN<32>,
    pub ad_chain_id: u128,
    pub ad_manager: BytesN<32>,
    pub ad_id: String,
    pub ad_creator: BytesN<32>,
    pub ad_recipient: BytesN<32>,
    pub salt: U256,
    pub order_decimals: u32,
    pub ad_decimals: u32,
    pub deadline: u64,
    pub ad_settlement_signer: BytesN<32>,
    pub lp_fee_bps: u32,
    pub protocol_fee_bps: u32,
}
```

From `contracts/ad-manager/src/types.rs`, which names the order chain and its portal instead:

```rust
pub struct OrderParams {
    pub order_chain_token: BytesN<32>,
    pub ad_chain_token: BytesN<32>,
    pub amount: u128,
    pub bridger: BytesN<32>,
    pub order_chain_id: u128,
    pub src_order_portal: BytesN<32>,
    pub order_recipient: BytesN<32>,
    pub ad_id: String,
    pub ad_creator: BytesN<32>,
    pub ad_recipient: BytesN<32>,
    pub salt: U256,
    pub order_decimals: u32,
    pub ad_decimals: u32,
    pub deadline: u64,
    pub ad_settlement_signer: BytesN<32>,
    pub lp_fee_bps: u32,
    pub protocol_fee_bps: u32,
}
```

The escrow adds its own chain id and address to make the canonical 19-field order, the one
`lib/proofbridge-core/src/eip712.rs` hashes:

```rust
pub struct Order {
    pub order_chain_token: [u8; 32],
    pub ad_chain_token: [u8; 32],
    pub amount: u128,
    pub bridger: [u8; 32],
    pub order_chain_id: u128,
    pub order_portal: [u8; 32],
    pub order_recipient: [u8; 32],
    pub ad_chain_id: u128,
    pub ad_manager: [u8; 32],
    pub ad_id_hash: [u8; 32],
    pub ad_creator: [u8; 32],
    pub ad_recipient: [u8; 32],
    pub salt: [u8; 32],
    pub order_decimals: u32,
    pub ad_decimals: u32,
    pub deadline: u64,
    pub ad_settlement_signer: [u8; 32],
    pub lp_fee_bps: u32,
    pub protocol_fee_bps: u32,
}
```

It produces the same EIP-712 hash as the EVM `OrderHash` library for the same values. CI checks
this against `test-vectors/order-hash-v2.json`.

## Contract surface

The functions match the EVM contracts in snake case (`lock_for_order`, `claim_cancel`,
`present_settled`, `refund_by_cancel`, `pay_maker_by_forfeit` and so on). The differences:

| Stellar | EVM | Difference |
| --- | --- | --- |
| `set_chain(chain_id, peer)`, `remove_chain(chain_id)` | `setPeerEscrow(chainId, peer)` | Removal is its own call. |
| `set_token_route(ad_token, order_token, order_chain_id)` on ad-manager | `setTokenRoute(localToken, peerChainId, peerToken)` | Argument order. The order-portal takes `(order_token, ad_chain_id, ad_token)`. |
| `set_root_verifier(chain_id, module)`, `unset_root_verifier(chain_id)` | `setRootVerifier(chainId, verifier)` | Unwiring (the instant brake) is its own call. |
| `propose_action(fn_name, args)` | `proposeAction(bytes data)` | A proposal is the function name plus its argument list. |
| `claim(recipient, token)` | `claim`, `claimTo` | No `claim_to` on the escrows. |
| `append_order_hash(manager, order_hash, side)` | `appendOrderHash(orderHash, side)` | The appender passes itself. |
| `verify_proof(public_inputs, proof_bytes)` | `verify(proof, publicInputs)` | The key is fixed at deploy, not compiled in. |

The timelock is the same on both chains: `activate_timelock`, `propose_action`, `cancel_action`,
`timelock_active` and `timelock_eta`, with a 24-hour delay and a 14-day grace
(`lib/proofbridge-core/src/timelock.rs`).

### Agent account

`agent-account` is a maker's Soroban custom account. It is the ad's maker on the ad-manager and an
authorization gateway; what the owner pays in goes from the owner's wallet to the escrow in the
same call.

* The **owner** (any `G...` or `C...` address) calls the account's own functions: `create_ad`,
  `fund_ad`, `call`, `sweep`, the policy and guard-rail setters, `schedule` and `cancel`.
* An **agent** signs the Soroban auth payload. The account's `__check_auth` lets it make only calls
  that fit its policy: a pinned escrow, the allowed action, and lock arguments inside the policy's
  token lists, per-order cap and settlement identity. `revoke_agent` is instant.
* The owner's **guard rail** delays extractive calls on a guarded ad. A delay is at most 30 days and
  a window at least 1 hour (`MAX_GUARD_DELAY`, `MIN_GUARD_WINDOW` in
  `contracts/agent-account/src/policy.rs`).
* The account is owner-upgradeable (`upgrade`). While any ad is guarded, an upgrade waits behind
  the same delay.

## Project structure

```text
stellar/
├── contracts/
│   ├── ad-manager/             # The maker's leg: ads, locks, the bridger's unlock, cancels, disputes
│   ├── order-portal/           # The bridger's leg: deposits, the maker's unlock, refunds
│   ├── merkle-manager/         # Poseidon2 MMR of order leaves
│   ├── verifier/               # UltraHonk verifier, key passed at deploy
│   ├── counterparty-verifier/  # Root verifier: the parties' BLS co-signature
│   ├── bls-key-registry/       # BLS key slots per account
│   ├── root-anchor/            # Notarized peer-chain roots for the evidence paths
│   ├── dispute-manager/        # Filing, bonds, ruling, fallback
│   ├── registrar/              # REGISTERED leaves for registration by proof
│   ├── agent-account/          # The maker's custody account and agent policy
│   └── test-token/             # SEP-41 token for tests and localnet
├── lib/
│   └── proofbridge-core/       # Shared code (below)
├── tests/
│   ├── integration_test.rs     # Cross-contract tests with real proofs
│   └── fixtures/
│       ├── generate_fixtures.ts
│       └── package.json
├── deploy/                     # Deploy CLI (runs from the ProofBridge monorepo)
├── src/lib.rs
└── Cargo.toml                  # Workspace
```

The generated fixtures (proofs, public inputs, `vk`, `test_params.json`) are written into
`tests/fixtures/` and are not committed.

### proofbridge-core

The library both escrows (and several other contracts) use:

| Module | What it holds |
| --- | --- |
| `escrow_ops` | What both escrows do the same way: admin, payouts, the termination core. Its `Fault` enum is the one error type the crate returns; each escrow maps it into its own error enum. |
| `escrow_storage`, `escrow_events` | The storage and events both escrows share. |
| `eip712` | The domain separator and the 19-field order hash. |
| `token` | `BytesN<32>` to `Address` conversion, the native sentinel, transfers with the exact-amount check. |
| `cross_contract` | Clients for the merkle-manager and the verifier. |
| `types` | Shared types: `Status`, `RouteTiming`, `DisputeParams`, `BondConfig`, order and claim records. |
| `timelock`, `timing`, `dispute`, `fees` | The admin delay, route-timing bounds, dispute bounds and bond rule, the fee split. Each mirrors its EVM library. |
| `decimal_scaling` | Scaling amounts between the two chains' decimals. |
| `rate_limit` | Token-bucket volume accounting for the agent account. |
| `secp` | secp256k1 recovery to an EVM address, shared by the key registry and the agent account. |
| `auth` | Small auth helpers. |
| `ttl` | Storage TTL policy. |

## Build

You need Rust with the `wasm32v1-none` target and the Stellar CLI. CI uses Stellar CLI `v28.0.0`.
Build each package from `stellar/`, as CI does (`.github/workflows/stellar-contracts.yml`):

```bash
cd stellar
rustup target add wasm32v1-none

for pkg in ad-manager order-portal merkle-manager verifier counterparty-verifier \
           agent-account bls-key-registry root-anchor registrar dispute-manager; do
  stellar contract build --optimize --package "$pkg"
done
```

The WASMs land in `target/wasm32v1-none/release/`. `--optimize` runs wasm-opt; the metering test
in the integration suite fails on unoptimized builds.

## Tests

Several tests load the built WASMs and circuit artifacts, so build first. The circuits come from
[proofbridge-circuits](https://github.com/Explore-Beyond-Innovations/proofbridge-circuits), checked
out at the commit in [`CIRCUITS_COMMIT`](../CIRCUITS_COMMIT), next to this repo as
`../proof_circuits`. From the repo root:

```bash
scripts/build_circuits.sh ../proof_circuits/events                # the event circuit's vk
scripts/build_circuits.sh stellar/contracts/verifier/tests --prove # the verifier's own test circuit
pnpm install --frozen-lockfile                                     # fixture generator dependencies
```

Then, from `stellar/`:

```bash
cargo fmt --all -- --check

# Unit tests, every contract and proofbridge-core
cargo test --workspace --exclude proofbridge-stellar

# Order-hash parity against the shared vectors
cargo test -p ad-manager -p order-portal order_hash_parity -- --nocapture

# Generate the proof fixtures, then run the integration suite
(cd tests/fixtures && npx tsx generate_fixtures.ts)
cargo test --test integration_test -- --nocapture

# The unlock compute-cost gate on its own
cargo test --test integration_test test_unlock_metering -- --nocapture
```

The integration suite deploys the contracts into the Soroban test environment and runs them with
real proofs. It covers the lock and unlock on both legs, nullifier replay, the co-signature gate,
pause rules, payouts and credits, slot pinning and re-pinning, the cancel and refund paths, the
settlement halt, key-registry kills and migrations, route timing, disputes and bonds,
registration by proof, and the metering ceilings.

## Deploy

The deploy CLI is in [`deploy/`](./deploy/README.md). Like the EVM one, it depends on a manifest
schema package that lives in the ProofBridge monorepo, so deploys run from there. It writes the
chain's manifest to `stellar/deployments/<chainId>.json` (testnet:
`stellar/deployments/1000002.json`). Manifests are not committed.

## Dependencies

From `Cargo.toml`:

* **soroban-sdk** `28.0.0-rc.1`
* **soroban-poseidon**: Poseidon2 for the MMR (pinned git revision)
* **ultrahonk_soroban_verifier**: on-chain UltraHonk verification (pinned git revision)
* **stellar-tokens**: the fungible token base, used by `test-token` (pinned git revision)
* **stellar-strkey** `0.0.16`: strkey encoding and decoding
