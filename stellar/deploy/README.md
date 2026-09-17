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

```bash
pnpm --filter @proofbridge/stellar-deploy cli deploy
# or with overrides
pnpm --filter @proofbridge/stellar-deploy cli deploy --chain-id 1000001
```

Re-runs are idempotent: addresses already present in the manifest are
reused; missing ones are deployed and merged in.

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

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `STELLAR_NETWORK` | `testnet` | Name of the `stellar network` profile to use |
| `STELLAR_SOURCE_ACCOUNT` | `admin` | `stellar keys` identity that signs deploys |
| `STELLAR_WASM_DIR` | `contracts/stellar/target/wasm32v1-none/release` | Build artifacts |
| `STELLAR_DEPOSIT_VK` | `proof_circuits/deposits/target/vk` | Verifier key for `Verifier.initialize` |
| `STELLAR_DEPLOYMENTS_DIR` | `contracts/stellar/deployments` | Manifest output dir |
| `CHAIN_NAME` | `stellar-<chainId>` | Name stamped in the manifest |
| `DEPLOY_ENV` | `local` | `meta.env` (`local`/`testnet`/`mainnet`) |
| `GIT_COMMIT` | `unknown` | `meta.commit` |
| `DISPUTE_ARBITER` | admin (`local` only) | The only account that may rule a dispute (2.3g). Must not be the admin outside `local`: its whole containment is that it holds no escrow powers |
| `DISPUTE_FEE_POOL` | admin (`local` only) | Where forfeited bonds go. Unset, every forfeited bond returns to the filer |
| `DISPUTE_CHALLENGE_PERIOD_S` | `3600` (`local` only) | How long the arbiter has to rule. A floor, never a licence to finish early — no dispute completes before the order's own `deadline + buffer` |
| `DISPUTE_BOND_FLOOR` | `1` (`local` only) | Bond floor in wrapped-native base units. Must be ≥ 1; the contract rejects zero |
| `DISPUTE_BOND_BPS` | `0` (`local` only) | Bond as basis points of the order amount, capped at 1000 (10%) |
