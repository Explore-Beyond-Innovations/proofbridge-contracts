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

Wires `setChain` + `setTokenRoute` on this chain's AdManager +
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
