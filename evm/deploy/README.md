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
OrderPortal. Sets AdManager and OrderPortal as MerkleManager managers
(`setManager`). The Registrar is deployed but not made a manager: that is a
step of proof registration's T3 flip (`setManager(registrar, true)`).
Writes/updates the manifest.

A rerun refuses, before sending anything, a manifest whose MerkleManager
predates the manager list (no `isManager`), or whose AdManager, OrderPortal
or Registrar is bound to a different MerkleManager. Deploy fresh instead.
It also refuses (as does `link`) an AdManager and DisputeManager that do not
agree with this build on `settleBond`: the escrow calls the module by that
selector, and it changed when the bond-return flag was added, so the two must
come from one build. The check reads both contracts' code for the bundle's
selector (`PUSH4`); redeploy the one that differs, or run the bundle both came
from.

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

### `handover --to <address>` / `handover --verify`

Every contract is deployed with the deployer as admin. `handover --to` nominates the real admin (a
multisig, in production) on every admin-bearing contract — `MerkleManager`, `AdManager`,
`OrderPortal`, `BLSKeyRegistry`, `RootAnchor`, `DisputeManager` — over the two-step
`transferAdmin` / `acceptAdmin`, and records `pending` in the manifest. The nominee then calls
`acceptAdmin()` on each, and `handover --verify` reads the chain and records `current`.

```
pnpm --filter @proofbridge/evm-deploy cli handover --to 0x…
# ...the nominee accepts on all six...
pnpm --filter @proofbridge/evm-deploy cli handover --verify
```

After the handover, `deploy` and `link` read `admin()` on every contract they configure before the
first transaction. A call to a contract whose admin is no longer the signer is **described**
(target, function, arguments, calldata) for the admin to make, not sent, not recorded, and the
command exits 2. A contract deployed fresh after the handover has the deployer as admin, is wired
in that run, and needs its own `handover`.

### `retirements-audit --file <vault-export.json>`

A one-off check (review 50-4): each pre-signed retirement in the relayer vault's export
(`[{ account, keyCommitment, validUntil, scheme, sig, evmSig }]`) is replayed against this chain's
registry as a simulated `setValidUntil` and listed as `current`, `stale-format` (signed under an
older RetireKey message; collect it again), `no-slot` or `already-shorter`. Exits 1 when any row is
stale or could not be checked.

### `timelock status` / `timelock activate --confirm` / `timelock {propose|execute|cancel}`

The 24-hour admin delay (#586) on the AdManager, the OrderPortal, the MerkleManager and the
DisputeManager. Until `activate`, their setters are the admin's and instant: that setup window is how
`deploy` and `link` configure a fresh chain. `timelock activate --confirm` closes it for good on every
one of them (the manifest records `timelock.activatedAt`). From then on a change is proposed by the
admin, waits 24 hours, and is executed by anyone with exactly the proposed arguments; the admin may
cancel it first. Pause, unpause and the admin handover stay instant.

`deploy` and `link` follow the delay on their own: on a contract whose delay is on, a call they would
have sent is proposed instead (or, when the signer is not the admin, the `proposeAction` is described),
the command exits 2, and the same command re-run after 24 hours executes it. For a change neither
makes, use the commands directly:

```bash
evm-deploy timelock propose --contract AdManager --fn setFeeBps --args '[30, 20]'
evm-deploy timelock execute --contract AdManager --fn setFeeBps --args '[30, 20]'   # 24 hours later, any key
evm-deploy timelock cancel  --contract AdManager --fn setFeeBps --args '[30, 20]'   # admin, before then
```

## Moving to a new key registry

Pointing the AdManager at a new registry (`setKeyRegistry`, with every co-signature verifier on the same one)
starts that registry empty. Before ads lock again, each settlement signer must:

- register its key on the new registry, and
- file its maker approvals again (`approveMaker`, one per maker that names it): a signer that is not
  the ad's maker is refused at the lock until it has approved that maker on the registry the
  escrow reads now.

Orders locked before the move finish on their own registry epoch; only new locks need the above.

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `EVM_RPC_URL` | *required* | JSON-RPC endpoint |
| `EVM_ADMIN_PRIVATE_KEY` | *required* | Deployer, and the admin until `handover` |
| `ADMIN` | — | **No longer read.** The deployer is always the admin at deploy time (deploy and link are admin-only); `deploy` refuses it if set to anyone else. Hand over afterwards with `handover` (#424). |
| `CHAIN_NAME` | `evm-<chainId>` | Human-readable name in the manifest |
| `DEPLOY_ENV` | *required* | `local`/`testnet`/`mainnet`; must match the RPC's chain id |
| `LOCAL_EVM_CHAIN_IDS` / `TESTNET_EVM_CHAIN_IDS` / `MAINNET_EVM_CHAIN_IDS` | — | Extra chain ids for that env (comma-separated). Built in: local 31337, 1337; testnet Sepolia, Base Sepolia, Arbitrum Sepolia, OP Sepolia, Holesky, Amoy; mainnet 1, 10, 56, 137, 8453, 42161, 43114. An unlisted id is refused in every env |
| `GIT_COMMIT` | `unknown` | Commit sha stamped into `meta.commit` |
| `WNATIVE_NAME` | `Wrapped Native` | wNativeToken `name()` |
| `WNATIVE_SYMBOL` | `WNATIVE` | wNativeToken `symbol()` |
| `WNATIVE_DECIMALS` | `18` | wNativeToken `decimals()` |
| `EVM_OUT_DIR` | `contracts/evm/out` | Override Foundry artifact dir |
| `EVM_DEPLOYMENTS_DIR` | `contracts/evm/deployments` | Override manifest output dir |
| `DISPUTE_ARBITER` | admin (`local` only) | The only account that may rule a dispute (2.3g). Must not be the admin outside `local`: its whole containment is that it holds no escrow powers |
| `DISPUTE_FEE_POOL` | admin (`local` only) | Where forfeited bonds go. Unset, every forfeited bond returns to the filer |
| `PROTOCOL_FEE_POOL` | admin (`local` only) | #586: where the AdManager pays the protocol fee. Its own setting, even when it names the same address as `DISPUTE_FEE_POOL` |
| `LP_FEE_BPS` | `30` (`local` only) | #586: the maker's share of the bridge fee, kept in the ad, in bps (at most 100) |
| `PROTOCOL_FEE_BPS` | `20` (`local` only) | #586: the protocol's share, paid to the pool, in bps (at most 100; above 0 needs the pool) |
| `DISPUTE_TOKEN_BONDS` | unset | #586 (`link`): `{"<pairKey>": {"minBond": "<base units>", "bondBps": <0..500>}}` — routes whose dispute bond is `max(minBond, amount × bondBps / 10,000)` in the order's own token. A route not named keeps `DISPUTE_BOND_FLOOR` in native |
| `DISPUTE_CHALLENGE_PERIOD_S` | `3600` (`local` only) | How long the arbiter has to rule. A floor, never a licence to finish early — no dispute completes before the order's own `deadline + buffer` |
| `DISPUTE_BOND_FLOOR` | `1` (`local` only) | The route's dispute bond, flat for every order, in wrapped-native base units. Must be ≥ 1; the contract rejects zero. No default outside `local`, and there it must be at least `1000000000000000` (0.001 ETH): the floor is the whole bond, so a dust floor would make disputes free. A sanity bound, not the tuned value (the operating rules size each route) |
| `DISPUTE_BOND_BPS` | — | Removed: the bond is the flat floor. `link` refuses to run while it is still set |
