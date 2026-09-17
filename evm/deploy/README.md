# EVM per-chain deploy

Node/ethers CLI for deploying ProofBridge on one EVM chain. Emits a
[shared manifest](../../../packages/deployment-manifest/README.md) at
`contracts/evm/deployments/<chainId>.json`.

## Prerequisites

- `forge build` has produced artifacts under `contracts/evm/out/`
- `EVM_RPC_URL` and `EVM_ADMIN_PRIVATE_KEY` are set

## Commands

### `deploy`

Deploys (or reuses) Verifier, MerkleManager, wNativeToken, AdManager,
OrderPortal. Grants `MANAGER_ROLE` on MerkleManager to AdManager +
OrderPortal. Writes/updates the manifest.

```bash
pnpm --filter @proofbridge/evm-deploy cli deploy
# or, with a custom output path
pnpm --filter @proofbridge/evm-deploy cli deploy --out /tmp/sepolia.json
```

Re-runs are idempotent: any address already in the manifest is reused.
Delete the manifest file (or pass a fresh `--out`) to force a clean deploy.

### `deploy-test-tokens`

Deploys the default dev/testnet token set (`WXLM`, `PB`, native ETH
sentinel). Merges them into the manifest under `tokens[]` with
`isTestToken=true`.

```bash
pnpm --filter @proofbridge/evm-deploy cli deploy-test-tokens
```

**Do not run this against production.** For prod deploys the token list
is hand-curated in the manifest.

### `link --peer <peer-manifest>`

Wires `setPeerEscrow` + `setTokenRoute` on this chain's AdManager +
OrderPortal so they accept proofs from the peer chain. Run this after
both chains have been deployed *and* have their test tokens registered.

```bash
pnpm --filter @proofbridge/evm-deploy cli link \
  --peer ../../stellar/deployments/1000001.json
```

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `EVM_RPC_URL` | *required* | JSON-RPC endpoint |
| `EVM_ADMIN_PRIVATE_KEY` | *required* | Deployer + initial admin |
| `ADMIN` | deployer | Overrides the contract admin address |
| `CHAIN_NAME` | `evm-<chainId>` | Human-readable name in the manifest |
| `DEPLOY_ENV` | `local` | Logical env tag (`local`/`testnet`/`mainnet`) |
| `GIT_COMMIT` | `unknown` | Commit sha stamped into `meta.commit` |
| `WNATIVE_NAME` | `Wrapped Native` | wNativeToken `name()` |
| `WNATIVE_SYMBOL` | `WNATIVE` | wNativeToken `symbol()` |
| `WNATIVE_DECIMALS` | `18` | wNativeToken `decimals()` |
| `EVM_OUT_DIR` | `contracts/evm/out` | Override Foundry artifact dir |
| `EVM_DEPLOYMENTS_DIR` | `contracts/evm/deployments` | Override manifest output dir |
| `DISPUTE_ARBITER` | admin (`local` only) | The only account that may rule a dispute (2.3g). Must not be the admin outside `local`: its whole containment is that it holds no escrow powers |
| `DISPUTE_FEE_POOL` | admin (`local` only) | Where forfeited bonds go. Unset, every forfeited bond returns to the filer |
| `DISPUTE_CHALLENGE_PERIOD_S` | `3600` (`local` only) | How long the arbiter has to rule. A floor, never a licence to finish early — no dispute completes before the order's own `deadline + buffer` |
| `DISPUTE_BOND_FLOOR` | `1` (`local` only) | Bond floor in wrapped-native base units. Must be ≥ 1; the contract rejects zero |
| `DISPUTE_BOND_BPS` | `0` (`local` only) | Bond as basis points of the order amount, capped at 1000 (10%) |
