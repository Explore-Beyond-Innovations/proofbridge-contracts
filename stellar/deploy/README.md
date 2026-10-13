# Stellar per-chain deploy

Node CLI wrapping the `stellar` command line. Emits a
[shared manifest](../../../packages/deployment-manifest/README.md) at
`contracts/stellar/deployments/<chainId>.json`.

## Prerequisites

- `stellar` CLI on `$PATH` (configured with the target network + a funded
  source account)
- Built WASMs under `contracts/stellar/target/wasm32v1-none/release/`
  (run `stellar contract build` for each package)
- The deposit verifier key at
  `proof_circuits/deposits/target/vk`

## Commands

### `deploy`

Deploys (or reuses) Verifier, MerkleManager, native XLM SAC
(`w_native_token`), AdManager, OrderPortal. Calls `initialize` on each
and wires `set_escrow_appender` on MerkleManager for both AdManager + OrderPortal.
The Registrar is deployed but not made a manager: that is a step of proof
registration's T3 flip (`set_manager(registrar, true)`).

```bash
pnpm --filter @proofbridge/stellar-deploy cli deploy
# or with overrides
pnpm --filter @proofbridge/stellar-deploy cli deploy --chain-id 1000001
```

Re-runs are idempotent: addresses already present in the manifest are
reused; missing ones are deployed and merged in.

Two contracts are reused only under the code they were deployed from. The
deploy records the wasm hash of the `bls-key-registry` and the
`counterparty-verifier` in the manifest (`wasmHashes.blsKeyRegistry`,
`wasmHashes.counterpartyVerifier`, beside `wasmHashes.agentAccount`), and a
re-run compares each recorded hash with the hash of the wasm it is about to
deploy before anything is sent. A different hash refuses, naming the
contract and both hashes; a manifest with no recorded hash (written before
the hash was recorded) refuses too, saying why. Either way the fix is to
deploy the contract again (drop it from the manifest) or, once you have
checked that the code on chain is this bundle's, to pass
`deploy --allow-wasm-mismatch` (the `allowWasmMismatch` option) to that one
run; the override reuses without reading the bundle's wasm, leaves the
recorded hash as it was, and is announced as a warning, once up front and
once per contract it skipped. On a local stack `STELLAR_ALLOW_WASM_MISMATCH=1`
(exactly `1`) does the same from the environment; outside local the variable
is ignored, and the CLI says so, because the deploy orchestrator sources env
files with `set -a` and a variable left in one would carry into every later
run on a real network. The flag is the only override there.

### `deploy-test-tokens`

Registers the native XLM SAC as a tradeable token under `pairKey="xlm"`
and deploys two SEP-41 test tokens (`wETH`, `PB`).

```bash
pnpm --filter @proofbridge/stellar-deploy cli deploy-test-tokens
```

**Do not run this against production.** Curate the manifest by hand
for prod token registration.

### `link --peer <peer-manifest>`

Wires `set_chain` + `set_token_route` on this chain so AdManager +
OrderPortal accept proofs from the peer chain.

```bash
pnpm --filter @proofbridge/stellar-deploy cli link \
  --peer ../../evm/deployments/11155111.json
```

### `handover --to <G…>` / `handover --verify`

Every contract is initialized with the source account as admin. `handover --to` nominates the
real admin on every admin-bearing contract (the same six as on EVM) over `transfer_admin` /
`accept_admin`; the nominee calls `accept_admin` on each, and `handover --verify` records it.
The contracts expose no pending admin, so a second `handover` re-nominates the same key: safe,
not silent. After the handover, `deploy` and `link` describe admin-only calls as the
`stellar contract invoke` lines the admin has to run, send nothing, and exit 2.

### `retirements-audit --file <vault-export.json>`

A one-off check (review 50-4): each pre-signed retirement in the relayer vault's export
(`[{ account, keyCommitment, validUntil, scheme, sig }]`) is replayed against this chain's
registry as a simulated `set_valid_until` and listed as `current`, `stale-format` (signed under an
older RetireKey message; collect it again), `no-slot` or `already-shorter`. Exits 1 when any row is
stale or could not be checked.

### `timelock status` / `timelock activate --confirm` / `timelock {propose|execute|cancel}`

The 24-hour admin delay (#586) on the ad-manager, the order-portal, the merkle-manager, the
dispute-manager, the root-anchor and the bls-key-registry. Until `activate`, their setters are the
admin's and instant: that setup window is how `deploy` and `link` configure a fresh chain. `timelock
activate --confirm` closes it for good on every one of them (the manifest records
`timelock.activatedAt` once all are on). From then on a change is proposed by the admin, waits 24 hours,
and is executed by anyone with exactly the proposed arguments; the admin may cancel it first. Pause,
unpause and the admin handover stay instant.

- **Grants wait, revocations do not.** On the root-anchor and the bls-key-registry only the setters
  that add trust are delayed (a new signer set, a shorter anchor delay, a lower sequence pin, switching
  the sequence check off, the position guards, enabling proof registration, an upgrade). Revoking an
  anchor, raising a delay or a pin, switching the check on and disabling proof registration stay
  instant. On the merkle-manager, removing a non-escrow appender (`set_manager(x, false)`) is instant;
  the escrows are escrow appenders, added and removed only through the delayed `set_escrow_appender`.
- **A brake voids what would undo it.** An instant revocation voids every pending proposal that would
  reverse it. The voided proposal still holds its id: cancel it, then propose again.
- **Proposals expire.** A proposal can run for 14 days after its 24 hours are up, then never; propose
  it again. An admin handover voids every proposal the previous admin made.
- **Activation is checked.** Outside `local`, `activate` refuses a manifest missing any of the six
  contracts before sending anything. If any contract fails to activate, the command exits 1 naming
  each one, and does not record the activation. It prints `status` at the end either way.
- **A redeploy into an activated chain activates what it adds.** A contract `deploy` deploys into a
  chain whose manifest records the activation is wired while still in setup, then activated in the
  same run. `status` flags any contract still in setup on an activated chain.

`deploy` and `link` follow the delay on their own: on a contract whose delay is on, a call they would
have sent is proposed instead (or, when the signer is not the admin, the `propose_action` is described),
the command exits 2, and the same command re-run after 24 hours executes it. The fee pool and the fee
split are proposed in the same run, so one 24-hour round sets both. For a change neither makes, use the
commands directly; `--args` names each argument, and the CLI encodes the list the
contract keys the proposal by:

```bash
stellar-deploy timelock propose --contract AdManager --fn set_fee_bps --args '{"lp_bps": 30, "protocol_bps": 20}'
stellar-deploy timelock execute --contract AdManager --fn set_fee_bps --args '{"lp_bps": 30, "protocol_bps": 20}'   # 24 hours later, any key
stellar-deploy timelock cancel  --contract AdManager --fn set_fee_bps --args '{"lp_bps": 30, "protocol_bps": 20}'   # admin, before then
```

## Moving to a new key registry

Pointing the AdManager at a new registry (`set_key_registry`, with every co-signature verifier on the same one)
starts that registry empty. Before ads lock again, each settlement signer must:

- register its key on the new registry, and
- file its maker approvals again (`approve_maker`, one per maker that names it): a signer that is not
  the ad's maker is refused at the lock until it has approved that maker on the registry the
  escrow reads now.

Orders locked before the move finish on their own registry epoch; only new locks need the above.

### Key registry storage change (one key commitment)

The registry stores keccak256 of a key's EIP-2537 128-byte form as the slot commitment (the
value EVM stores and the owner messages name); earlier builds stored keccak256 of the 96-byte
key plus a separate fingerprint, and old slots do not decode under the new `KeySlot`. So a
registry is not `upgrade`d across this change: redeploy it (and the counterparty verifier that
reads it) and register the keys again. `deploy` enforces this: it refuses to reuse a registry
or verifier whose recorded wasm hash is not this bundle's (see `deploy` above).

### Replacing a Soroban key registry (cut-over)

The redeploy is a deliberate step, because the relayer and the vault keep work that names the
registry:

1. **Drain the relayer's open Stellar key legs first.** A key publication stores its filing,
   including the registry address it was signed for; re-drives and the landed check use that
   stored address. A register or retirement leg still `PENDING` / `SUBMITTED` for the Stellar
   chain when the registry changes is sent to the **old** registry, lands there, and is recorded
   `CONFIRMED` while the new registry has no slot. Before changing the relayer's chain row: stop
   taking new key publications for that chain (disable the key publisher or hold the Stellar
   lane), wait until no publication for the chain is `PENDING` or `SUBMITTED`, and finalize or fail
   what is left by hand.
2. **Check the retirement vault for that chain.** `PreSignedRetirement` rows are per registry chain
   and record the slot id the key held on that registry. The signature itself names the key, not
   the registry or the slot, so it stays valid for the same key once it is registered again; but
   the row is sent against the chain row's current registry at submit time and its slot id is the
   old registry's. After the keys are registered again, run the retirement drill for the chain and
   fix what it reports: a key with no usable pre-signed retirement on the new registry has lost its
   kill switch until one is exported again.
3. Redeploy the registry and the verifier: drop `blsKeyRegistry` and `counterpartyVerifier` (and
   their `wasmHashes` entries) from the manifest and run `deploy`, which deploys what is missing,
   re-wires the position guards (`[AdManager, OrderPortal]`) and records the new hashes; then point
   the relayer's chain row (`blsKeyRegistryAddress`) and the frontend / pods at the new address.
   A re-run against an old manifest stops at the hash check instead of keeping the old registry;
   outside local the only override is `deploy --allow-wasm-mismatch` on the one run that needs it,
   once the on-chain code has been checked (the env variable counts on a local stack only).
4. Every account registers its keys again; the relayer names no maker key for a Stellar trade
   until the maker's key is live on the new registry.
5. **Regenerate the Soroban integration fixtures** (`stellar/tests/fixtures`,
   `npx tsx generate_fixtures.ts`): the registration subject binds the commitment, so fixtures a
   checkout holds from before the change fail the register-by-proof tests until regenerated.

The monorepo's `scripts/deploy/README.md` carries the same section for the operator running the
orchestrator.

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `STELLAR_NETWORK` | `local` (`DEPLOY_ENV=local` only) | Name of the `stellar network` profile to use. Required outside local; `deploy` and `link` refuse unless its RPC's passphrase (`stellar network info`) is the env's network |
| `STELLAR_SOURCE_ACCOUNT` | `admin` | `stellar keys` identity that signs deploys, and the admin until `handover` |
| `STELLAR_WASM_DIR` | `contracts/stellar/target/wasm32v1-none/release` | Build artifacts |
| `STELLAR_EVENT_VK` | `proof_circuits/events/target/vk` | Verifier key for `Verifier.initialize`; its sha256 is recorded as `meta.vkSha256`. Missing refuses outside local |
| `STELLAR_DEPLOYMENTS_DIR` | `contracts/stellar/deployments` | Manifest output dir |
| `CHAIN_NAME` | `stellar-<chainId>` | Name stamped in the manifest |
| `DEPLOY_ENV` | *required* | `meta.env` (`local`/`testnet`/`mainnet`); must match the network's passphrase |
| `GIT_COMMIT` | `unknown` | `meta.commit` |
| `DISPUTE_ARBITER` | admin (`local` only) | The only account that may rule a dispute (2.3g). Must not be the admin outside `local`: its whole containment is that it holds no escrow powers |
| `DISPUTE_FEE_POOL` | admin (`local` only) | Where forfeited bonds go. Unset, every forfeited bond returns to the filer |
| `PROTOCOL_FEE_POOL` | admin (`local` only) | #586: where the ad-manager pays the protocol fee: a Stellar account (G…), paid like a payout recipient. Its own setting, even when it names the same address as `DISPUTE_FEE_POOL` |
| `LP_FEE_BPS` | `30` (`local` only) | #586: the maker's share of the bridge fee, kept in the ad, in bps (at most 100) |
| `PROTOCOL_FEE_BPS` | `20` (`local` only) | #586: the protocol's share, paid to the pool, in bps (at most 100; above 0 needs the pool) |
| `DISPUTE_TOKEN_BONDS` | unset | #586 (`link`): `{"<pairKey>": {"minBond": "<base units>", "bondBps": <0..500>}}` — routes whose dispute bond is `max(minBond, amount × bondBps / 10,000)` in the order's own token. A route not named keeps `DISPUTE_BOND_FLOOR` in native |
| `DISPUTE_CHALLENGE_PERIOD_S` | `3600` (`local` only) | How long the arbiter has to rule. A floor, never a licence to finish early — no dispute completes before the order's own `deadline + buffer` |
| `DISPUTE_BOND_FLOOR` | `1` (`local` only) | The route's dispute bond, flat for every order, in wrapped-native base units. Must be ≥ 1; the contract rejects zero. No default outside `local`, and there it must be at least `10000000` (1 XLM): the floor is the whole bond, so a dust floor would make disputes free. A sanity bound, not the tuned value (the operating rules size each route) |
| `DISPUTE_BOND_BPS` | — | Removed: the bond is the flat floor. `link` refuses to run while it is still set |
