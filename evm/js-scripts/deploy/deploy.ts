#!/usr/bin/env node

import * as fs from "fs";
import * as path from "path";
import {
  DeploymentConfig,
  DeploymentOptions,
  ContractAddresses,
  DeploymentScenario,
} from "./core/types";
import { parseArgs } from "./core/utils";
import { executeStandardScenario } from "./scenarios/standard";
import { executeSepoliaHederaScenario } from "./scenarios/sepolia-hedera";

const DEFAULT_CONFIG_PATH = path.join(__dirname, "config.json");
const DEFAULT_DEPLOYMENTS_PATH = path.join(__dirname, "deployments.json");

import * as dotenv from "dotenv";
dotenv.config();

/**
 * Load deployment configuration
 */
function loadConfig(configPath: string): DeploymentConfig {
  if (!fs.existsSync(configPath)) {
    console.error(`\n✗ Config file not found: ${configPath}`);
    console.log(
      `\nPlease create a config file. See config.template.json for reference.\n`
    );
    process.exit(1);
  }

  try {
    const data = fs.readFileSync(configPath, "utf-8");
    return JSON.parse(data);
  } catch (error) {
    console.error(`\n✗ Failed to load config:`, error);
    process.exit(1);
  }
}

/**
 * Display usage information
 */
function displayUsage(): void {
  console.log(`
Proofbridge Deployment & Setup Script

Usage:
  npm run deploy -- [options]

Options:
  --chain1 <chainId>           First chain ID (required)
  --chain2 <chainId>           Second chain ID (required)
  --scenario <name>            Deployment scenario (default: standard)
  --mode <mode>                Mode: deploy | setup | full (default: full)
  --dry-run                    Preview actions without executing
  --skip-confirmation          Skip confirmation prompts
  --config <path>              Custom config file path
  --deployments <path>         Custom deployments file path
  --help                       Show this help message

Scenarios:
  standard                     Standard two-chain deployment (default)
  sepolia-hedera               Specialized Sepolia <-> Hedera deployment
                               with native token wrapping and custom routes

Modes:
  deploy    Deploy contracts only (no setup)
  setup     Setup existing contracts (link chains, configure routes)
  full      Deploy + Setup (default)

Examples:
  # Standard deployment: Hedera <-> Base Sepolia
  npm run deploy -- --chain1 296 --chain2 84532

  # Sepolia-Hedera specialized deployment
  npm run deploy -- --chain1 11155111 --chain2 296 --scenario sepolia-hedera

  # Deploy contracts only
  npm run deploy -- --chain1 296 --chain2 84532 --mode deploy

  # Setup existing contracts
  npm run deploy -- --chain1 296 --chain2 84532 --mode setup

  # Dry run (preview actions)
  npm run deploy -- --chain1 296 --chain2 84532 --dry-run

Chain IDs in config.template.json:
  296       Hedera Testnet
  84532     Base Sepolia
  11155111  Ethereum Sepolia
  80002     Polygon Amoy
  421614    Arbitrum Sepolia
`);
}

/**
 * Display deployment summary
 */
function displaySummary(
  chain1Id: string,
  chain1Contracts: ContractAddresses,
  chain2Id: string,
  chain2Contracts: ContractAddresses,
  config: DeploymentConfig
): void {
  console.log(`\n${"=".repeat(60)}`);
  console.log(`DEPLOYMENT SUMMARY`);
  console.log(`${"=".repeat(60)}\n`);

  console.log(`Chain 1: ${config.chains[chain1Id].name} (${chain1Id})`);
  console.log(`  Verifier:       ${chain1Contracts.verifier}`);
  console.log(`  MerkleManager:  ${chain1Contracts.merkleManager}`);
  console.log(`  wNativeToken:   ${chain1Contracts.wNativeToken}`);
  console.log(`  AdManager:      ${chain1Contracts.adManager}`);
  console.log(`  OrderPortal:    ${chain1Contracts.orderPortal}`);

  console.log(`\nChain 2: ${config.chains[chain2Id].name} (${chain2Id})`);
  console.log(`  Verifier:       ${chain2Contracts.verifier}`);
  console.log(`  MerkleManager:  ${chain2Contracts.merkleManager}`);
  console.log(`  wNativeToken:   ${chain2Contracts.wNativeToken}`);
  console.log(`  AdManager:      ${chain2Contracts.adManager}`);
  console.log(`  OrderPortal:    ${chain2Contracts.orderPortal}`);

  console.log(`\n${"=".repeat(60)}\n`);
}

/**
 * Main deployment orchestrator
 */
async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    displayUsage();
    return;
  }

  // Parse options
  const options: DeploymentOptions = {
    chain1: args.chain1 || "",
    chain2: args.chain2 || "",
    mode: (args.mode as any) || "full",
    scenario: (args.scenario as DeploymentScenario) || "standard",
    dryRun: args["dry-run"] === "true",
    skipConfirmation: args["skip-confirmation"] === "true",
    configPath: args.config,
    deploymentsPath: args.deployments || DEFAULT_DEPLOYMENTS_PATH,
  };

  // Validate required parameters
  if (!options.chain1 || !options.chain2) {
    console.error("\n✗ Error: --chain1 and --chain2 are required\n");
    displayUsage();
    process.exit(1);
  }

  if (!["deploy", "setup", "full"].includes(options.mode)) {
    console.error(`\n✗ Error: Invalid mode "${options.mode}"\n`);
    displayUsage();
    process.exit(1);
  }

  const validScenarios = ["standard", "sepolia-hedera"];
  if (!validScenarios.includes(options.scenario)) {
    console.error(`\n✗ Error: Invalid scenario "${options.scenario}"`);
    console.error(`Valid scenarios: ${validScenarios.join(", ")}\n`);
    displayUsage();
    process.exit(1);
  }

  // Load configuration
  const config = loadConfig(options.configPath || DEFAULT_CONFIG_PATH);

  // Validate chains exist in config
  if (!config.chains[options.chain1]) {
    console.error(`\n✗ Error: Chain ${options.chain1} not found in config\n`);
    process.exit(1);
  }

  if (!config.chains[options.chain2]) {
    console.error(`\n✗ Error: Chain ${options.chain2} not found in config\n`);
    process.exit(1);
  }

  const chain1Config = config.chains[options.chain1];
  const chain2Config = config.chains[options.chain2];

  // Get private key from environment
  const privateKey = process.env.PRIVATE_KEY;
  if (!privateKey) {
    console.error("\n✗ Error: PRIVATE_KEY environment variable not set\n");
    process.exit(1);
  }

  console.log(`
╔════════════════════════════════════════════════════════════╗
║          Proofbridge Deployment & Setup Script             ║
╚════════════════════════════════════════════════════════════╝
`);

  console.log(`Scenario: ${options.scenario.toUpperCase()}`);
  console.log(`Mode: ${options.mode.toUpperCase()}`);
  console.log(`Chain 1: ${chain1Config.name} (${options.chain1})`);
  console.log(`Chain 2: ${chain2Config.name} (${options.chain2})`);
  console.log(`Dry Run: ${options.dryRun ? "YES" : "NO"}`);

  if (!options.skipConfirmation && !options.dryRun) {
    console.log(
      `\nPress Ctrl+C to cancel, or waiting 5 seconds to continue...`
    );
    await new Promise((resolve) => setTimeout(resolve, 5000));
  }

  try {
    let chain1Contracts: ContractAddresses;
    let chain2Contracts: ContractAddresses;

    // Execute scenario
    if (options.scenario === "sepolia-hedera") {
      const result = await executeSepoliaHederaScenario(
        config,
        options,
        privateKey
      );
      chain1Contracts = result.chain1Contracts;
      chain2Contracts = result.chain2Contracts;

      // Display additional token info for sepolia-hedera
      console.log(`\n${"=".repeat(60)}`);
      console.log(`ADDITIONAL TOKENS DEPLOYED`);
      console.log(`${"=".repeat(60)}\n`);
      console.log(`Sepolia:`);
      console.log(`  wHBAR ERC20:        ${result.tokens.sepolia.wHbarErc20}`);
      console.log(
        `  ProofBridge Token:  ${result.tokens.sepolia.proofBridgeToken}`
      );
      console.log(`\nHedera:`);
      console.log(`  wETH ERC20:         ${result.tokens.hedera.wEthErc20}`);
      console.log(
        `  ProofBridge Token:  ${result.tokens.hedera.proofBridgeToken}`
      );
      console.log(`\n${"=".repeat(60)}\n`);
    } else {
      // Standard scenario
      const result = await executeStandardScenario(config, options, privateKey);
      chain1Contracts = result.chain1Contracts;
      chain2Contracts = result.chain2Contracts;
    }

    // Display summary
    displaySummary(
      options.chain1,
      chain1Contracts,
      options.chain2,
      chain2Contracts,
      config
    );

    console.log(`✓ All operations completed successfully!\n`);
  } catch (error) {
    console.error(`\n✗ Deployment/Setup failed:`, error);
    process.exit(1);
  }
}

// Run main function
main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
