/**
 * Sepolia ↔ Hedera Specialized Deployment Scenario
 *
 * Deploys core contracts plus specialized token setup:
 * - Wrapped native tokens (wHBAR on Hedera, wETH on Sepolia)
 * - ERC20 alternate tokens (wETH ERC20 on Hedera, wHBAR ERC20 on Sepolia)
 * - ProofBridge mock tokens on both chains
 * - Complex bidirectional token routes for native token bridging
 *
 * Token Routes:
 * 1. Native ETH (Sepolia) ↔ wETH ERC20 (Hedera)
 * 2. wHBAR ERC20 (Sepolia) ↔ Native HBAR (Hedera)
 * 3. ProofBridge Token (Sepolia) ↔ ProofBridge Token (Hedera)
 */

import { ethers } from "ethers";
import {
  DeploymentConfig,
  DeploymentOptions,
  ContractAddresses,
  ChainConfig,
} from "../core/types";
import {
  deployChain,
  grantManagerRoles,
  deployContract,
} from "../core/deployer";
import { linkChains, callContractFunction } from "../core/setup";
import {
  saveDeployments,
  loadDeployments,
  sleep,
  withRetry,
} from "../core/utils";

// Constants
const NATIVE_TOKEN = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";
const SEPOLIA_CHAIN_ID = "11155111";
const HEDERA_CHAIN_ID = "296";

export interface SepoliaHederaTokens {
  sepolia: {
    wNativeToken: string; // wETH (for wrapping native ETH)
    wHbarErc20: string; // wHBAR ERC20 (for receiving bridged HBAR)
    proofBridgeToken: string; // ProofBridge test token
  };
  hedera: {
    wNativeToken: string; // wHBAR (for wrapping native HBAR)
    wEthErc20: string; // wETH ERC20 (for receiving bridged ETH)
    proofBridgeToken: string; // ProofBridge test token
  };
}

export interface SepoliaHederaResult {
  chain1Contracts: ContractAddresses;
  chain2Contracts: ContractAddresses;
  tokens: SepoliaHederaTokens;
}

/**
 * Validate chain IDs are correct for this scenario
 */
function validateChains(
  chain1Id: string,
  chain2Id: string
): { sepoliaId: string; hederaId: string } {
  const hasSepolia =
    chain1Id === SEPOLIA_CHAIN_ID || chain2Id === SEPOLIA_CHAIN_ID;
  const hasHedera =
    chain1Id === HEDERA_CHAIN_ID || chain2Id === HEDERA_CHAIN_ID;

  if (!hasSepolia || !hasHedera) {
    throw new Error(
      `sepolia-hedera scenario requires chains ${SEPOLIA_CHAIN_ID} (Sepolia) and ${HEDERA_CHAIN_ID} (Hedera)`
    );
  }

  return {
    sepoliaId: chain1Id === SEPOLIA_CHAIN_ID ? chain1Id : chain2Id,
    hederaId: chain1Id === HEDERA_CHAIN_ID ? chain1Id : chain2Id,
  };
}

/**
 * Deploy token contracts on both chains
 */
async function deployTokens(
  sepoliaConfig: ChainConfig,
  hederaConfig: ChainConfig,
  privateKey: string,
  dryRun: boolean
): Promise<SepoliaHederaTokens> {
  console.log(`\n${"=".repeat(60)}`);
  console.log(`DEPLOYING TOKEN CONTRACTS`);
  console.log(`${"=".repeat(60)}\n`);

  // Phase 1: Deploy wrapped native tokens (already deployed as wNativeToken in core)
  // These are deployed by the standard deployment, so we'll use those addresses

  // Phase 2: Deploy ERC20 alternate tokens
  console.log(`→ Phase 1: Deploying ERC20 alternate tokens...\n`);

  // Deploy wETH ERC20 on Hedera (to represent Sepolia native ETH)
  let wEthErc20Hedera = hederaConfig.tokens.wAltChainToken;
  if (!wEthErc20Hedera) {
    console.log(`  → Deploying wETH ERC20 on Hedera...`);
    const ethDecimals = sepoliaConfig.nativeToken.decimals;
    wEthErc20Hedera = await withRetry(
      () =>
        deployContract(
          "MockERC20",
          [
            "Wrapped ETH",
            "WETH",
            ethers.parseEther("1000000"),
            Number(ethDecimals),
          ],
          hederaConfig.rpc,
          privateKey,
          dryRun
        ),
      { maxRetries: 3, delayMs: 5000 }
    );
    await sleep(2000);
  }

  // Deploy wHBAR ERC20 on Sepolia (to represent Hedera native HBAR)
  console.log(`  → Deploying wHBAR ERC20 on Sepolia...`);
  let wHbarErc20Sepolia = sepoliaConfig.tokens.wAltChainToken;
  const hbarDecimals = hederaConfig.nativeToken.decimals;
  if (!wHbarErc20Sepolia) {
    wHbarErc20Sepolia = await withRetry(
      () =>
        deployContract(
          "MockERC20",
          [
            "Wrapped HBAR",
            "WHBAR",
            ethers.parseEther("1000000"),
            Number(hbarDecimals),
          ],
          sepoliaConfig.rpc,
          privateKey,
          dryRun
        ),
      { maxRetries: 3, delayMs: 5000 }
    );
    await sleep(2000);
  }

  // Phase 3: Deploy ProofBridge mock tokens
  console.log(`\n→ Phase 2: Deploying ProofBridge mock tokens...\n`);

  console.log(`  → Deploying ProofBridge token on Sepolia...`);
  let pbTokenSepolia = sepoliaConfig.tokens.proofbridge;
  if (!pbTokenSepolia) {
    pbTokenSepolia = await withRetry(
      () =>
        deployContract(
          "MockERC20",
          [
            "ProofBridge Token",
            "PBT",
            ethers.parseEther("1000000"),
            Number(18),
          ],
          sepoliaConfig.rpc,
          privateKey,
          dryRun
        ),
      { maxRetries: 3, delayMs: 5000 }
    );
    await sleep(2000);
  }

  console.log(`  → Deploying ProofBridge token on Hedera...`);
  let pbTokenHedera = hederaConfig.tokens.proofbridge;
  if (!pbTokenHedera) {
    pbTokenHedera = await withRetry(
      () =>
        deployContract(
          "MockERC20",
          [
            "ProofBridge Token",
            "PBT",
            ethers.parseEther("1000000"),
            Number(18),
          ],
          hederaConfig.rpc,
          privateKey,
          dryRun
        ),
      { maxRetries: 3, delayMs: 5000 }
    );
    await sleep(2000);
  }

  // Note: wNativeToken addresses come from core deployment
  return {
    sepolia: {
      wNativeToken: "", // Will be filled from core deployment
      wHbarErc20: wHbarErc20Sepolia,
      proofBridgeToken: pbTokenSepolia,
    },
    hedera: {
      wNativeToken: "", // Will be filled from core deployment
      wEthErc20: wEthErc20Hedera,
      proofBridgeToken: pbTokenHedera,
    },
  };
}

/**
 * Configure complex token routes for Sepolia-Hedera bridge
 */
async function configureTokenRoutes(
  sepoliaConfig: any,
  sepoliaContracts: ContractAddresses,
  hederaConfig: any,
  hederaContracts: ContractAddresses,
  tokens: SepoliaHederaTokens,
  privateKey: string,
  dryRun: boolean
): Promise<void> {
  console.log(`\n${"=".repeat(60)}`);
  console.log(`CONFIGURING TOKEN ROUTES`);
  console.log(`${"=".repeat(60)}\n`);

  console.log(`Route 1: Native ETH (Sepolia) ↔ wETH ERC20 (Hedera)`);
  console.log(`Route 2: wHBAR ERC20 (Sepolia) ↔ Native HBAR (Hedera)`);
  console.log(
    `Route 3: ProofBridge Token (Sepolia) ↔ ProofBridge Token (Hedera)`
  );
  console.log();

  // --- Sepolia AdManager Token Routes ---
  console.log(`→ Configuring Sepolia AdManager...\n`);

  // Route 1: Native ETH -> wETH ERC20 on Hedera
  console.log(`  → Native ETH -> wETH ERC20 (Hedera)`);
  await withRetry(
    () =>
      callContractFunction(
        sepoliaContracts.adManager!,
        "setTokenRoute",
        [
          tokens.sepolia.wNativeToken,
          tokens.hedera.wEthErc20,
          Number(HEDERA_CHAIN_ID),
        ],
        sepoliaConfig.rpc,
        privateKey,
        dryRun
      ),
    { maxRetries: 3, delayMs: 5000 }
  );
  await sleep(2000);

  // Route 2: ProofBridge Sepolia -> ProofBridge Hedera
  console.log(`  → ProofBridge (Sepolia) -> ProofBridge (Hedera)`);
  await withRetry(
    () =>
      callContractFunction(
        sepoliaContracts.adManager!,
        "setTokenRoute",
        [
          tokens.sepolia.proofBridgeToken,
          tokens.hedera.proofBridgeToken,
          Number(HEDERA_CHAIN_ID),
        ],
        sepoliaConfig.rpc,
        privateKey,
        dryRun
      ),
    { maxRetries: 3, delayMs: 5000 }
  );
  await sleep(2000);

  // Route 3: wHBAR ERC20 (Sepolia) -> Native HBAR on Hedera
  console.log(`  → wHBAR ERC20 (Sepolia) -> Native HBAR (Hedera)`);
  await withRetry(
    () =>
      callContractFunction(
        sepoliaContracts.adManager!,
        "setTokenRoute",
        [
          tokens.sepolia.wHbarErc20,
          tokens.hedera.wNativeToken,
          Number(HEDERA_CHAIN_ID),
        ],
        sepoliaConfig.rpc,
        privateKey,
        dryRun
      ),
    { maxRetries: 3, delayMs: 5000 }
  );
  await sleep(2000);

  // --- Sepolia OrderPortal Token Routes ---
  console.log(`\n→ Configuring Sepolia OrderPortal...\n`);

  // Route 1: wHBAR ERC20 (Sepolia) -> Native HBAR (Hedera)
  console.log(`  → wHBAR ERC20 (Sepolia) -> Native HBAR`);
  await withRetry(
    () =>
      callContractFunction(
        sepoliaContracts.orderPortal!,
        "setTokenRoute",
        [
          tokens.sepolia.wHbarErc20,
          Number(HEDERA_CHAIN_ID),
          tokens.hedera.wNativeToken,
        ],
        sepoliaConfig.rpc,
        privateKey,
        dryRun
      ),
    { maxRetries: 3, delayMs: 5000 }
  );
  await sleep(2000);

  // Route 2: ProofBridge Sepolia -> ProofBridge Hedera
  console.log(`  → ProofBridge (Sepolia) -> ProofBridge (Hedera)`);
  await withRetry(
    () =>
      callContractFunction(
        sepoliaContracts.orderPortal!,
        "setTokenRoute",
        [
          tokens.sepolia.proofBridgeToken,
          Number(HEDERA_CHAIN_ID),
          tokens.hedera.proofBridgeToken,
        ],
        sepoliaConfig.rpc,
        privateKey,
        dryRun
      ),
    { maxRetries: 3, delayMs: 5000 }
  );
  await sleep(2000);

  // Route 3: Native ETH (Sepolia) -> wETH ERC20 on Hedera
  console.log(`  → Native ETH (Sepolia) -> wETH ERC20 (Hedera)`);
  await withRetry(
    () =>
      callContractFunction(
        sepoliaContracts.orderPortal!,
        "setTokenRoute",
        [
          tokens.sepolia.wNativeToken,
          Number(HEDERA_CHAIN_ID),
          tokens.hedera.wEthErc20,
        ],
        sepoliaConfig.rpc,
        privateKey,
        dryRun
      ),
    { maxRetries: 3, delayMs: 5000 }
  );
  await sleep(2000);

  // --- Hedera AdManager Token Routes ---
  console.log(`\n→ Configuring Hedera AdManager...\n`);

  // Route 1: Native HBAR -> wHBAR ERC20 on Sepolia
  console.log(`  → Native HBAR -> wHBAR ERC20 (Sepolia)`);
  await withRetry(
    () =>
      callContractFunction(
        hederaContracts.adManager!,
        "setTokenRoute",
        [
          tokens.hedera.wNativeToken,
          tokens.sepolia.wHbarErc20,
          Number(SEPOLIA_CHAIN_ID),
        ],
        hederaConfig.rpc,
        privateKey,
        dryRun
      ),
    { maxRetries: 3, delayMs: 5000 }
  );
  await sleep(2000);

  // Route 2: ProofBridge Hedera -> ProofBridge Sepolia
  console.log(`  → ProofBridge (Hedera) -> ProofBridge (Sepolia)`);
  await withRetry(
    () =>
      callContractFunction(
        hederaContracts.adManager!,
        "setTokenRoute",
        [
          tokens.hedera.proofBridgeToken,
          tokens.sepolia.proofBridgeToken,
          Number(SEPOLIA_CHAIN_ID),
        ],
        hederaConfig.rpc,
        privateKey,
        dryRun
      ),
    { maxRetries: 3, delayMs: 5000 }
  );
  await sleep(2000);

  // Route 3: wETH ERC20 (Hedera) -> Native ETH on Sepolia
  console.log(`  → wETH ERC20 (Hedera) -> Native ETH (Sepolia)`);
  await withRetry(
    () =>
      callContractFunction(
        hederaContracts.adManager!,
        "setTokenRoute",
        [
          tokens.hedera.wEthErc20,
          tokens.sepolia.wNativeToken,
          Number(SEPOLIA_CHAIN_ID),
        ],
        hederaConfig.rpc,
        privateKey,
        dryRun
      ),
    { maxRetries: 3, delayMs: 5000 }
  );
  await sleep(2000);

  // --- Hedera OrderPortal Token Routes ---
  console.log(`\n→ Configuring Hedera OrderPortal...\n`);

  // Route 1: wETH ERC20 (Hedera) -> Native ETH (Sepolia)
  console.log(`  → wETH ERC20 (Hedera) -> Native ETH`);
  await withRetry(
    () =>
      callContractFunction(
        hederaContracts.orderPortal!,
        "setTokenRoute",
        [
          tokens.hedera.wEthErc20,
          Number(SEPOLIA_CHAIN_ID),
          tokens.sepolia.wNativeToken,
        ],
        hederaConfig.rpc,
        privateKey,
        dryRun
      ),
    { maxRetries: 3, delayMs: 5000 }
  );
  await sleep(2000);

  // Route 2: ProofBridge Hedera -> ProofBridge Sepolia
  console.log(`  → ProofBridge (Hedera) -> ProofBridge (Sepolia)`);
  await withRetry(
    () =>
      callContractFunction(
        hederaContracts.orderPortal!,
        "setTokenRoute",
        [
          tokens.hedera.proofBridgeToken,
          Number(SEPOLIA_CHAIN_ID),
          tokens.sepolia.proofBridgeToken,
        ],
        hederaConfig.rpc,
        privateKey,
        dryRun
      ),
    { maxRetries: 3, delayMs: 5000 }
  );
  await sleep(2000);

  // Route 3: Native HBAR (Hedera) -> wHBAR ERC20 on Sepolia
  console.log(`  → Native HBAR (Hedera) -> wHBAR ERC20 (Sepolia)`);
  await withRetry(
    () =>
      callContractFunction(
        hederaContracts.orderPortal!,
        "setTokenRoute",
        [
          tokens.hedera.wNativeToken,
          Number(SEPOLIA_CHAIN_ID),
          tokens.sepolia.wHbarErc20,
        ],
        hederaConfig.rpc,
        privateKey,
        dryRun
      ),
    { maxRetries: 3, delayMs: 5000 }
  );
  await sleep(2000);
}

/**
 * Execute Sepolia-Hedera specialized deployment scenario
 */
export async function executeSepoliaHederaScenario(
  config: DeploymentConfig,
  options: DeploymentOptions,
  privateKey: string
): Promise<SepoliaHederaResult> {
  // Validate chains
  const { sepoliaId, hederaId } = validateChains(
    options.chain1,
    options.chain2
  );

  const sepoliaConfig = config.chains[sepoliaId];
  const hederaConfig = config.chains[hederaId];

  let sepoliaContracts: ContractAddresses = { ...sepoliaConfig.contracts };
  let hederaContracts: ContractAddresses = { ...hederaConfig.contracts };

  // DEPLOY MODE - Deploy core contracts first
  if (options.mode === "deploy" || options.mode === "full") {
    console.log(`\n${"=".repeat(60)}`);
    console.log(`DEPLOYING CORE CONTRACTS`);
    console.log(`${"=".repeat(60)}\n`);

    // Deploy Sepolia
    console.log(`\n→ Deploying to Sepolia (${sepoliaId})...\n`);
    const result1 = await withRetry(
      () => deployChain(sepoliaConfig, privateKey, options.dryRun),
      { maxRetries: 3, delayMs: 5000 }
    );
    sepoliaContracts = result1.contracts;

    if (!options.dryRun) {
      saveDeployments(options.deploymentsPath, sepoliaId, sepoliaContracts);
    }

    // Deploy Hedera
    console.log(`\n→ Deploying to Hedera (${hederaId})...\n`);
    const result2 = await withRetry(
      () => deployChain(hederaConfig, privateKey, options.dryRun),
      { maxRetries: 3, delayMs: 5000 }
    );
    hederaContracts = result2.contracts;

    if (!options.dryRun) {
      saveDeployments(options.deploymentsPath, hederaId, hederaContracts);
    }

    // Grant manager roles on both chains
    console.log(`\n→ Granting MANAGER_ROLE on both chains...\n`);
    await withRetry(
      () =>
        grantManagerRoles(
          sepoliaConfig,
          sepoliaContracts,
          privateKey,
          options.dryRun
        ),
      { maxRetries: 3, delayMs: 5000 }
    );
    await withRetry(
      () =>
        grantManagerRoles(
          hederaConfig,
          hederaContracts,
          privateKey,
          options.dryRun
        ),
      { maxRetries: 3, delayMs: 5000 }
    );
  }

  // Load existing contracts if in setup mode
  if (options.mode === "setup") {
    const deployments = loadDeployments(options.deploymentsPath);
    sepoliaContracts = deployments[sepoliaId] || sepoliaConfig.contracts;
    hederaContracts = deployments[hederaId] || hederaConfig.contracts;

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
        !sepoliaContracts[contract as keyof ContractAddresses] ||
        !hederaContracts[contract as keyof ContractAddresses]
      ) {
        throw new Error(
          `Missing contract addresses for setup mode. Deploy first.`
        );
      }
    }
  }

  // Deploy additional token contracts
  const tokens = await withRetry(
    () => deployTokens(sepoliaConfig, hederaConfig, privateKey, options.dryRun),
    { maxRetries: 3, delayMs: 5000 }
  );

  // Fill in wNativeToken addresses from core deployment
  tokens.sepolia.wNativeToken = sepoliaConfig.nativeToken.address!;
  tokens.hedera.wNativeToken = hederaConfig.nativeToken.address!;

  // SETUP MODE
  if (options.mode === "setup" || options.mode === "full") {
    // Link chains bidirectionally
    console.log(`\n${"=".repeat(60)}`);
    console.log(`LINKING CHAINS`);
    console.log(`${"=".repeat(60)}\n`);

    await withRetry(
      () =>
        linkChains(
          sepoliaConfig,
          sepoliaContracts,
          hederaConfig,
          hederaContracts,
          privateKey,
          options.dryRun
        ),
      { maxRetries: 3, delayMs: 5000 }
    );

    // Configure token routes
    await withRetry(
      () =>
        configureTokenRoutes(
          sepoliaConfig,
          sepoliaContracts,
          hederaConfig,
          hederaContracts,
          tokens,
          privateKey,
          options.dryRun
        ),
      { maxRetries: 3, delayMs: 5000 }
    );
  }

  return {
    chain1Contracts:
      options.chain1 === sepoliaId ? sepoliaContracts : hederaContracts,
    chain2Contracts:
      options.chain1 === sepoliaId ? hederaContracts : sepoliaContracts,
    tokens,
  };
}
