# ProofBridge EVM contracts

The Solidity implementation of ProofBridge, built with Foundry.

The protocol, the contract set and the shared rules (fees, timelock, route timing, disputes) are in
the [contracts README](../README.md). This page covers what is specific to EVM.

## EVM specifics

* **Admin.** Each contract has one two-step admin (`TwoStepAdmin`: `transferAdmin`, then
  `acceptAdmin`) and a 24-hour delay on its setters (`AdminTimelock`). The MerkleManager keeps its
  appenders in two plain mappings: `isManager` (anyone who may append) and `isEscrowAppender`
  (the escrows, changed only through the delayed `setEscrowAppender`).
* **Reentrancy.** The escrows and the custody account use OpenZeppelin's `ReentrancyGuardTransient`,
  which keeps the lock in transient storage (EIP-1153). The build targets `evm_version = "prague"`.
* **Native token.** The all-`0xEE` sentinel address stands for the native token. `wNativeToken`
  wraps it on deposit and unwraps it on withdrawal, so the escrows treat it as an ERC20.
* **Addresses.** Every cross-chain field is `bytes32`. An EVM address is left-padded with zeros
  (the top 12 bytes are zero); a Stellar key fills all 32 bytes.
* **Contract size.** The escrows sit close to the EIP-170 limit (24,576 bytes). Shared logic lives
  in `ProofBridgeUtils`, a deployed library both escrows link and call by `DELEGATECALL`. The build
  uses `optimizer_runs = 1` (`foundry.toml`).

## Structs

From `src/interfaces/IOrderPortal.sol`, the order as the order chain sees it:

```solidity
struct OrderParams {
    bytes32 orderChainToken;
    bytes32 adChainToken;
    uint256 amount;
    bytes32 bridger;
    bytes32 orderRecipient;
    uint256 adChainId;
    bytes32 adManager;
    string adId;
    bytes32 adCreator;
    bytes32 adRecipient;
    uint256 salt;
    uint8 orderDecimals;
    uint8 adDecimals;
    uint256 deadline;
    bytes32 adSettlementSigner;
    uint16 lpFeeBps;
    uint16 protocolFeeBps;
}
```

From `src/interfaces/IAdManager.sol`, the order as the ad chain sees it. It names the peer chain
and its portal (`orderChainId`, `srcOrderPortal`) where the OrderPortal names the ad chain and its
AdManager:

```solidity
struct OrderParams {
    bytes32 orderChainToken;
    bytes32 adChainToken;
    uint256 amount;
    bytes32 bridger;
    uint256 orderChainId;
    bytes32 srcOrderPortal;
    bytes32 orderRecipient;
    string adId;
    bytes32 adCreator;
    bytes32 adRecipient;
    uint256 salt;
    uint8 orderDecimals;
    uint8 adDecimals;
    uint256 deadline;
    bytes32 adSettlementSigner;
    uint16 lpFeeBps;
    uint16 protocolFeeBps;
}
```

Each is 17 fields. The escrow adds its own chain id and address to make the 19-field `Order` that
is hashed (`src/libraries/OrderHash.sol`).

The ad and the fee setting, also from `IAdManager.sol`:

```solidity
struct Ad {
    address maker;
    bool open;
    address token;
    uint256 orderChainId;
    bytes32 adRecipient;
    bytes32 orderChainToken;
    bytes32 settlementSigner;
    uint256 balance;
    uint256 locked;
}

struct FeeConfig {
    address pool;
    uint16 lpBps;
    uint16 protocolBps;
}
```

## Install and build

You need Foundry (CI pins `v1.7.1`; the gas baselines were measured on it), Node 20 and pnpm.

```bash
git clone --recurse-submodules https://github.com/Explore-Beyond-Innovations/proofbridge-contracts.git
cd proofbridge-contracts
pnpm install --frozen-lockfile   # at the repo root: the agent tests import ModuleKit from node_modules

cd evm
forge fmt --check
forge build --sizes --skip test
node test/size-budget.mjs        # fails when a contract is within 256 bytes of EIP-170
```

`forge build --skip test` builds what ships. The test tree pulls in account factories that are
far over EIP-170, so the size check runs on the shipping build only.

## Tests

These are the commands CI runs (`.github/workflows/evm-contracts.yml`), from `evm/`:

```bash
# Unit and integration tests (invariants run separately)
forge test -vvv --no-match-contract Invariant

# Invariant campaigns (256 runs x 500 calls, from foundry.toml)
forge test --match-contract Invariant -vvv

# Order-hash parity against the shared test vectors
forge test --match-contract OrderHashParity -vvv

# The agent module on each ERC-7579 account implementation
ACCOUNT_TYPE=SAFE forge test --match-path 'test/agent/**' -vvv   # also DEFAULT, KERNEL, NEXUS

# ERC-4337 validation rules over the agent module (needs -vvv and the raised gas limit)
AGENT_RULES=1 forge test --match-contract ValidationRules --gas-limit 900000000000 -vvv

# Gas baselines for unlock and the escrow entry points
forge test --match-contract 'UnlockGas|EscrowDoorGas' -vv
```

## Regenerating the verifier

`src/Verifier.sol` is generated from the event circuit's verification key, so it must change
whenever the circuit does. CI fails if the committed file differs from the generated one.

Check out [proofbridge-circuits](https://github.com/Explore-Beyond-Innovations/proofbridge-circuits)
at the commit in [`CIRCUITS_COMMIT`](../CIRCUITS_COMMIT), next to this repo as `../proof_circuits`.
Then, from the repo root:

```bash
scripts/build_circuits.sh ../proof_circuits/events   # installs the pinned nargo and bb, writes the vk
scripts/gen-verifier.sh                              # rewrites evm/src/Verifier.sol
scripts/gen-verifier.sh --check                      # what CI runs
```

Set `CIRCUITS_DIR` if the circuits are somewhere else.

## Deploy

The deploy CLI is in [`deploy/`](./deploy/README.md). It is not part of this repo's pnpm workspace:
it depends on a manifest schema package that lives in the ProofBridge monorepo, so deploys run from
there. The CLI deploys from the built `out/` artifacts with `ethers.ContractFactory`, not with
`forge script`.

```bash
pnpm --filter @proofbridge/evm-deploy deploy
```

The CLI writes the chain's manifest to `evm/deployments/<chainId>.json` (Sepolia:
`evm/deployments/11155111.json`). Manifests are not committed.

## Post-deploy wiring

The CLI's `deploy` and `link` commands make these calls. They are listed so a manual setup, or a
review of one, knows what a working chain needs.

On deploy, per chain:

| Contract | Call |
| --- | --- |
| MerkleManager | `setEscrowAppender(adManager, true)`, `setEscrowAppender(orderPortal, true)` |
| AdManager | `setKeyRegistry(blsKeyRegistry)`, `setProtocolFeePool(pool)`, `setFeeBps(lpBps, protocolBps)` |
| AdManager, OrderPortal | `setRootVerifier(peerChainId, counterpartyVerifier)` |
| BLSKeyRegistry | `setPositionGuards([adManager, orderPortal])` |
| DisputeManager | `setArbiter(arbiter)`, `setProtocolFeePool(pool)` |

On link, per peer chain:

| Contract | Call |
| --- | --- |
| OrderPortal | `setPeerEscrow(adChainId, adManager)`, `setTokenRoute(orderToken, adChainId, adToken)` |
| AdManager | `setPeerEscrow(orderChainId, orderPortal)`, `setTokenRoute(adToken, orderChainId, orderToken)` |
| AdManager, OrderPortal | `setRouteTiming(peerChainId, timing)`, `setRootAnchor(rootAnchor)`, `setRootVerifier(peerChainId, counterpartyVerifier)` |
| AdManager | `setDisputeManager(disputeManager)` |
| DisputeManager | `setEscrow(adManager, true)`, `setEscrow(orderPortal, true)`, `setDisputeParams(peerChainId, params)`, `setBondConfig(token, peerChainId, config)` for routes with a token bond |
| RootAnchor | `setAnchorDelay(peerChainId, delay)` |

`setPeerEscrow` takes the peer as `bytes32`; zero removes the chain. Both escrows take
`setTokenRoute(localToken, peerChainId, peerToken)` in the same argument order.

The Registrar is deployed but not made an appender. Turning on proof registration is a later
`setManager(registrar, true)`.

After wiring, `handover` moves admin to the real admin, and `timelock activate --confirm` turns on
the 24-hour delay for good. See [`deploy/README.md`](./deploy/README.md).

## Agent accounts

A maker can run its ads through a custody account, so a bot can trade for it inside fixed limits.
The contracts are in `src/agent/`:

| Contract | Role |
| --- | --- |
| `CustodyAccountFactory` | `deploy(uint256 salt, address[] targets)` makes the caller's account as an EIP-1167 clone and pins `targets` (the escrows). `predict(owner, salt)` gives the address first. |
| `ProofBridgeCustodyAccount` | The ad's maker on the AdManager. Owned by the maker's wallet. It never holds funds between calls: `createAdFunded`, `fundAdFunded` and `disputeFunded` take the amount from the owner and pass it to the escrow in the same call. |
| `CustodyGuardRail` | The owner's guard rail, mixed into the account. On a guarded ad, large withdrawals, closes and manual locks must be announced (`schedule`) and wait out a delay (at most 30 days, with a window of at least 1 hour). Protective calls are never delayed. |
| `ProofBridgeAgentPolicy` | An ERC-7579 module (validator and hook) that checks and counts each agent call against the maker's policy: pinned targets, token lists, per-order caps, volume buckets. |
| `AgentPolicyCodec`, `AgentRateLimit` | The policy's byte format and the token-bucket arithmetic. |

The owner acts with ordinary transactions (`execute`, `executeBatch`, `sweep`). An agent acts
through `executeAsAgent`, which the policy module checks before the call runs. The same module
also validates ERC-4337 UserOps for a smart account that installs it directly.
