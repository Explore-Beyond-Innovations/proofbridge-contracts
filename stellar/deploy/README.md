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
and wires `set_manager` on MerkleManager for both AdManager + OrderPortal.
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
| `DISPUTE_CHALLENGE_PERIOD_S` | `3600` (`local` only) | How long the arbiter has to rule. A floor, never a licence to finish early — no dispute completes before the order's own `deadline + buffer` |
| `DISPUTE_BOND_FLOOR` | `1` (`local` only) | The route's dispute bond, flat for every order, in wrapped-native base units. Must be ≥ 1; the contract rejects zero. No default outside `local`, and there it must be at least `10000000` (1 XLM): the floor is the whole bond, so a dust floor would make disputes free. A sanity bound, not the tuned value (the operating rules size each route) |
| `DISPUTE_BOND_BPS` | — | Removed: the bond is the flat floor. `link` refuses to run while it is still set |
