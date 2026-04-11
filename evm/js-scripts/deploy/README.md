# Proofbridge Deployment System

Unified TypeScript deployment system for Proofbridge cross-chain bridge contracts.

> **Note:** This deployment suite is still under development. For the most stable and reliable deployment experience, we recommend using the `sepolia-hedera` scenario, which is currently the best-tested configuration.

## Overview

This deployment system provides:

- 🚀 **Contract Deployment**: Deploy all required contracts on two chains
- 🔐 **Role Management**: Grant MANAGER_ROLE to AdManager and OrderPortal
- 🔗 **Chain Linking**: Bidirectionally link AdManager ↔ OrderPortal across chains
- 🪙 **Token Routes**: Configure token mappings for cross-chain transfers
- 💎 **Native Token Support**: Automatic handling of native token wrapping
- 🎯 **Deployment Scenarios**: Standard and specialized deployments

## Quick Start

### 1. Prerequisites

```bash
cd apps/contracts

# Install dependencies
pnpm install or npm install

# Compile contracts
forge build
```

### 2. Configure

```bash
cd js-scripts/deploy

# Create config from template
cp config.template.json config.json

# Edit config - update admin addresses
nano config.json
```

### 3. Deploy

```bash
# Set private key
export PRIVATE_KEY="0x..."

# Standard deployment: Hedera <-> Base Sepolia
npm run deploy -- --chain1 296 --chain2 84532

# Sepolia-Hedera specialized deployment
npm run deploy -- --chain1 11155111 --chain2 296 --scenario sepolia-hedera
```

## Deployment Scenarios

### Standard Scenario (Default)

Standard two-chain deployment with configurable token routes.

```bash
npm run deploy -- --chain1 296 --chain2 84532
```

**What it deploys:**

- HonkVerifier (ZK proof verifier)
- MerkleManager (MMR order storage)
- WNativeToken (native token wrapper)
- AdManager (liquidity management)
- OrderPortal (order creation)

**What it configures:**

- MANAGER_ROLE grants
- Bidirectional chain linking
- Token routes from config file

### Sepolia-Hedera Scenario

Specialized deployment with native token wrapping and custom token routes.

```bash
npm run deploy -- --chain1 11155111 --chain2 296 --scenario sepolia-hedera
```

**Additional deployments:**

- wHBAR (Wrapped HBAR) on Hedera
- wETH (Wrapped ETH) on Sepolia
- wETH ERC20 on Hedera (for bridging Sepolia native ETH)
- wHBAR ERC20 on Sepolia (for bridging Hedera native HBAR)
- ProofBridge mock tokens on both chains

**Token routes configured:**

1. Native ETH (Sepolia) ↔ wETH ERC20 (Hedera)
2. wHBAR ERC20 (Sepolia) ↔ Native HBAR (Hedera)
3. ProofBridge Token (Sepolia) ↔ ProofBridge Token (Hedera)

## File Structure

```
deploy/
├── deploy.ts                  # Main CLI orchestrator
├── core/                      # Core deployment logic
│   ├── types.ts              # TypeScript type definitions
│   ├── utils.ts              # Helper functions & constants
│   ├── deployer.ts           # Contract deployment logic
│   └── setup.ts              # Chain linking & token route setup
├── scenarios/                 # Deployment scenarios
│   ├── standard.ts           # Standard two-chain deployment
│   └── sepolia-hedera.ts     # Specialized Sepolia-Hedera
├── config.template.json       # Configuration template
├── config.json                # Your configuration (gitignored)
├── deployments.json           # Deployed contract addresses
└── README.md                  # This file
```

## CLI Options

```
--chain1 <chainId>           First chain ID (required)
--chain2 <chainId>           Second chain ID (required)
--scenario <name>            Deployment scenario (default: standard)
--mode <mode>                Mode: deploy | setup | full (default: full)
--dry-run                    Preview actions without executing
--skip-confirmation          Skip confirmation prompts
--config <path>              Custom config file path
--deployments <path>         Custom deployments file path
--help                       Show help message
```

### Scenarios

- **standard**: Standard two-chain deployment (default)
- **sepolia-hedera**: Specialized Sepolia-Hedera with native token wrapping

### Modes

- **deploy**: Deploy contracts only (no setup)
- **setup**: Setup existing contracts (link chains, configure routes)
- **full**: Deploy + Setup (default)

## Configuration

### Chain Configuration

Each chain in `config.json` has the following structure:

```json
{
  "chains": {
    "296": {
      "name": "Hedera Testnet",
      "rpc": "https://testnet.hashio.io/api",
      "chainId": "296",
      "admin": "0x...",
      "contracts": {
        "verifier": "",         // Optional: reuse existing
        "merkleManager": "",    // Optional: reuse existing
        "wNativeToken": "",     // Optional: reuse existing
        "adManager": "",        // Optional: reuse existing
        "orderPortal": ""       // Optional: reuse existing
      },
      "nativeToken": {
        "symbol": "HBAR",
        "address": "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"
      },
      "explorerUrl": "https://hashscan.io/testnet"
    }
  }
}
```

### Token Routes

Token routes define which tokens can bridge between chains:

```json
{
  "tokenRoutes": [
    {
      "chain1": {
        "chainId": "296",
        "token": "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE",
        "isNative": true
      },
      "chain2": {
        "chainId": "84532",
        "token": "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE",
        "isNative": true
      }
    }
  ]
}
```

**Native Token Handling:**

- Set `isNative: true` for native tokens (ETH, HBAR, MATIC, etc.)
- The script automatically uses `wNativeToken` contract for routing
- Native token address: `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE`

## Examples

### Standard Deployments

```bash
# Hedera ↔ Base Sepolia
npm run deploy -- --chain1 296 --chain2 84532

# Ethereum Sepolia ↔ Arbitrum Sepolia
npm run deploy -- --chain1 11155111 --chain2 421614

# Preview deployment (dry run)
npm run deploy -- --chain1 296 --chain2 84532 --dry-run
```

### Specialized Deployments

```bash
# Sepolia-Hedera with custom token routes
npm run deploy -- --chain1 11155111 --chain2 296 --scenario sepolia-hedera

# Deploy contracts only (manual setup later)
npm run deploy -- --chain1 11155111 --chain2 296 --scenario sepolia-hedera --mode deploy

# Setup existing contracts
npm run deploy -- --chain1 11155111 --chain2 296 --scenario sepolia-hedera --mode setup
```

## Supported Chains

Pre-configured in `config.template.json`:

| Chain ID | Network          | Native Token |
| -------- | ---------------- | ------------ |
| 296      | Hedera Testnet   | HBAR         |
| 84532    | Base Sepolia     | ETH          |
| 11155111 | Ethereum Sepolia | ETH          |
| 80002    | Polygon Amoy     | MATIC        |
| 421614   | Arbitrum Sepolia | ETH          |

## Advanced Usage

### Custom Configuration

```bash
npm run deploy -- \
  --chain1 296 \
  --chain2 84532 \
  --config ./custom-config.json \
  --deployments ./custom-deployments.json
```

### Reusing Contracts

To share Verifier or MerkleManager across multiple chain pairs:

1. Deploy once and note the address
2. Add address to `config.json` for other chains:

```json
{
  "chains": {
    "296": {
      "contracts": {
        "verifier": "0x...",  // Reuse this verifier
        ...
      }
    }
  }
}
```

### Creating Custom Scenarios

Add a new scenario in `scenarios/`:

```typescript
// scenarios/my-custom.ts
import { DeploymentConfig, DeploymentOptions } from "../core/types";

export async function executeMyCustomScenario(
  config: DeploymentConfig,
  options: DeploymentOptions,
  privateKey: string
) {
  // Your custom deployment logic
}
```

Then update `deploy.ts` to include your scenario.

## Troubleshooting

### "PRIVATE_KEY not set"

```bash
export PRIVATE_KEY="0x..."
# or add to .env file
```

### "Config file not found"

```bash
cd js-scripts/deploy
cp config.template.json config.json
```

### "Missing contract addresses for setup mode"

Run deploy first:

```bash
npm run deploy -- --chain1 296 --chain2 84532 --mode deploy
```

### Transaction failures

- Check admin address has sufficient funds
- Verify admin address matches deployer address
- Use `--dry-run` to preview actions first

## Security Considerations

1. **Private Key**: Never commit `PRIVATE_KEY` to version control
2. **Admin Address**: Use a secure multisig for production
3. **Dry Run**: Always test with `--dry-run` first
4. **Verification**: Verify contracts on block explorers after deployment
5. **Manager Roles**: Only grant to trusted contracts

## Next Steps

After deployment:

1. ✅ Verify contracts on block explorers
2. ✅ Test token bridging with small amounts
3. ✅ Set up monitoring for contract events
4. ✅ Configure off-chain relayer system
5. ✅ Generate ZK proofs for unlocking

## Support

For issues or questions:

- Check logs for detailed error messages
- Use `--dry-run` to preview operations
- Consult contract documentation in `apps/contracts/README.md`
*