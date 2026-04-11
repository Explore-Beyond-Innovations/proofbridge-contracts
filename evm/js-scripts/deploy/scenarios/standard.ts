/**
 * Standard Two-Chain Deployment Scenario
 *
 * Deploys core contracts and sets up bidirectional bridge between any two chains.
 * This is the default deployment scenario.
 */

import {
  DeploymentConfig,
  DeploymentOptions,
  ContractAddresses,
} from "../core/types";
import { deployChain, grantManagerRoles } from "../core/deployer";
import { setupChainPair } from "../core/setup";
import { saveDeployments, loadDeployments } from "../core/utils";

export interface StandardScenarioResult {
  chain1Contracts: ContractAddresses;
  chain2Contracts: ContractAddresses;
}

/**
 * Execute standard deployment scenario
 */
export async function executeStandardScenario(
  config: DeploymentConfig,
  options: DeploymentOptions,
  privateKey: string
): Promise<StandardScenarioResult> {
  const chain1Config = config.chains[options.chain1];
  const chain2Config = config.chains[options.chain2];

  let chain1Contracts: ContractAddresses = { ...chain1Config.contracts };
  let chain2Contracts: ContractAddresses = { ...chain2Config.contracts };

  // DEPLOY MODE
  if (options.mode === "deploy" || options.mode === "full") {
    console.log(`\n${"=".repeat(60)}`);
    console.log(`DEPLOYING CORE CONTRACTS`);
    console.log(`${"=".repeat(60)}\n`);

    // Deploy Chain 1
    console.log(
      `\n→ Deploying to ${chain1Config.name} (${options.chain1})...\n`
    );
    const result1 = await deployChain(chain1Config, privateKey, options.dryRun);
    chain1Contracts = result1.contracts;

    if (!options.dryRun) {
      saveDeployments(options.deploymentsPath, options.chain1, chain1Contracts);
    }

    // Deploy Chain 2
    console.log(
      `\n→ Deploying to ${chain2Config.name} (${options.chain2})...\n`
    );
    const result2 = await deployChain(chain2Config, privateKey, options.dryRun);
    chain2Contracts = result2.contracts;

    if (!options.dryRun) {
      saveDeployments(options.deploymentsPath, options.chain2, chain2Contracts);
    }

    // Grant manager roles on both chains
    console.log(`\n→ Granting MANAGER_ROLE on both chains...\n`);
    await grantManagerRoles(
      chain1Config,
      chain1Contracts,
      privateKey,
      options.dryRun
    );
    await grantManagerRoles(
      chain2Config,
      chain2Contracts,
      privateKey,
      options.dryRun
    );
  }

  // SETUP MODE
  if (options.mode === "setup" || options.mode === "full") {
    console.log(`\n${"=".repeat(60)}`);
    console.log(`CONFIGURING CHAIN PAIR`);
    console.log(`${"=".repeat(60)}\n`);

    // Load existing deployments if in setup-only mode
    if (options.mode === "setup") {
      const deployments = loadDeployments(options.deploymentsPath);
      chain1Contracts = deployments[options.chain1] || chain1Config.contracts;
      chain2Contracts = deployments[options.chain2] || chain2Config.contracts;

      // Validate all required contracts are present
      const required = [
        "verifier",
        "merkleManager",
        "wNativeToken",
        "adManager",
        "orderPortal",
      ];
      for (const contract of required) {
        if (
          !chain1Contracts[contract as keyof ContractAddresses] ||
          !chain2Contracts[contract as keyof ContractAddresses]
        ) {
          throw new Error(
            `Missing contract addresses for setup mode. Deploy first.`
          );
        }
      }
    }

    // Filter token routes for this chain pair
    const relevantRoutes = config.tokenRoutes.filter(
      (route) =>
        (route.chain1.chainId === options.chain1 &&
          route.chain2.chainId === options.chain2) ||
        (route.chain1.chainId === options.chain2 &&
          route.chain2.chainId === options.chain1)
    );

    if (relevantRoutes.length === 0) {
      console.warn(
        `\n⚠ Warning: No token routes configured for this chain pair\n`
      );
    }

    // Setup chain pair
    await setupChainPair(
      chain1Config,
      chain1Contracts,
      chain2Config,
      chain2Contracts,
      relevantRoutes,
      privateKey,
      options.dryRun
    );
  }

  return {
    chain1Contracts,
    chain2Contracts,
  };
}
