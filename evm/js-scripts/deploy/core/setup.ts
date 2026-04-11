import { ethers } from "ethers";
import {
  ChainConfig,
  ContractAddresses,
  TokenRoute,
  SetupResult,
} from "./types";
import {
  createSigner,
  waitForTransaction,
  displayTxSummary,
  sleep,
  AD_MANAGER_ABI,
  ORDER_PORTAL_ABI,
} from "./utils";

/**
 * Generic function to call a contract function
 * Used by specialized scenarios for custom contract interactions
 */
export async function callContractFunction(
  contractAddress: string,
  functionName: string,
  args: any[],
  rpcUrl: string,
  privateKey: string,
  dryRun: boolean = false
): Promise<string | null> {
  if (dryRun) {
    console.log(`  [DRY RUN] Would call ${functionName} on ${contractAddress}`);
    return null;
  }

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const signer = new ethers.Wallet(privateKey, provider);

  // Use appropriate ABI based on function name
  let abi: string[];
  if (functionName === "setTokenRoute") {
    // Check if it's AdManager or OrderPortal based on args length
    if (args.length === 3 && typeof args[2] === "number") {
      // AdManager: setTokenRoute(address adToken, address orderToken, uint256 orderChainId)
      abi = AD_MANAGER_ABI;
    } else {
      // OrderPortal: setTokenRoute(address orderToken, uint256 adChainId, address adToken)
      abi = ORDER_PORTAL_ABI;
    }
  } else {
    throw new Error(`Unknown function: ${functionName}`);
  }

  const contract = new ethers.Contract(contractAddress, abi, signer);

  try {
    const tx = await contract.setTokenRoute(...args);
    console.log(`  Tx: ${tx.hash}`);
    await waitForTransaction(tx);
    return tx.hash;
  } catch (error) {
    console.error(`  ✗ Failed to call ${functionName}:`, error);
    throw error;
  }
}

/**
 * Link two chains bidirectionally
 * Chain1.AdManager <-> Chain2.OrderPortal
 * Chain2.AdManager <-> Chain1.OrderPortal
 */
export async function linkChains(
  chain1Config: ChainConfig,
  chain1Contracts: ContractAddresses,
  chain2Config: ChainConfig,
  chain2Contracts: ContractAddresses,
  privateKey: string,
  dryRun: boolean = false
): Promise<string[]> {
  console.log(`\n${"=".repeat(60)}`);
  console.log(`Linking Chains Bidirectionally`);
  console.log(`${chain1Config.name} <-> ${chain2Config.name}`);
  console.log(`${"=".repeat(60)}\n`);

  const txHashes: string[] = [];

  if (dryRun) {
    console.log("DRY RUN MODE - No transactions will be sent\n");
    return txHashes;
  }

  try {
    // Link Chain1 AdManager -> Chain2 OrderPortal
    console.log(
      `1. ${chain1Config.name} AdManager → ${chain2Config.name} OrderPortal`
    );
    const signer1 = createSigner(chain1Config, privateKey);
    const adManager1 = new ethers.Contract(
      chain1Contracts.adManager!,
      AD_MANAGER_ABI,
      signer1
    );

    // Check if already configured
    const chain1Info = await adManager1.chains(chain2Config.chainId);
    if (
      chain1Info.supported &&
      chain1Info.orderPortal.toLowerCase() ===
        chain2Contracts.orderPortal!.toLowerCase()
    ) {
      console.log("  ✓ Already configured");
    } else {
      const tx1 = await adManager1.setChain(
        chain2Config.chainId,
        chain2Contracts.orderPortal!,
        true
      );
      console.log(`  Tx: ${tx1.hash}`);
      await waitForTransaction(tx1);
      txHashes.push(tx1.hash);
      displayTxSummary(
        chain1Config.name,
        "setChain on AdManager",
        tx1.hash,
        chain1Config.explorerUrl
      );
      await sleep(2000);
    }

    // Link Chain1 OrderPortal -> Chain2 AdManager
    console.log(
      `\n2. ${chain1Config.name} OrderPortal → ${chain2Config.name} AdManager`
    );
    const orderPortal1 = new ethers.Contract(
      chain1Contracts.orderPortal!,
      ORDER_PORTAL_ABI,
      signer1
    );

    const chain1OrderPortalInfo = await orderPortal1.chains(
      chain2Config.chainId
    );

    if (
      chain1OrderPortalInfo.supported &&
      chain1OrderPortalInfo.adManager.toLowerCase() ===
        chain2Contracts.adManager!.toLowerCase()
    ) {
      console.log("  ✓ Already configured");
    } else {
      const tx2 = await orderPortal1.setChain(
        chain2Config.chainId,
        chain2Contracts.adManager!,
        true
      );
      console.log(`  Tx: ${tx2.hash}`);
      await waitForTransaction(tx2);
      txHashes.push(tx2.hash);
      displayTxSummary(
        chain1Config.name,
        "setChain on OrderPortal",
        tx2.hash,
        chain1Config.explorerUrl
      );
      await sleep(2000);
    }

    // Link Chain2 AdManager -> Chain1 OrderPortal
    console.log(
      `\n3. ${chain2Config.name} AdManager → ${chain1Config.name} OrderPortal`
    );
    const signer2 = createSigner(chain2Config, privateKey);
    const adManager2 = new ethers.Contract(
      chain2Contracts.adManager!,
      AD_MANAGER_ABI,
      signer2
    );

    const chain2Info = await adManager2.chains(chain1Config.chainId);
    if (
      chain2Info.supported &&
      chain2Info.orderPortal.toLowerCase() ===
        chain1Contracts.orderPortal!.toLowerCase()
    ) {
      console.log("  ✓ Already configured");
    } else {
      const tx3 = await adManager2.setChain(
        chain1Config.chainId,
        chain1Contracts.orderPortal!,
        true
      );
      console.log(`  Tx: ${tx3.hash}`);
      await waitForTransaction(tx3);
      txHashes.push(tx3.hash);
      displayTxSummary(
        chain2Config.name,
        "setChain on AdManager",
        tx3.hash,
        chain2Config.explorerUrl
      );
      await sleep(2000);
    }

    // Link Chain2 OrderPortal -> Chain1 AdManager
    console.log(
      `\n4. ${chain2Config.name} OrderPortal → ${chain1Config.name} AdManager`
    );
    const orderPortal2 = new ethers.Contract(
      chain2Contracts.orderPortal!,
      ORDER_PORTAL_ABI,
      signer2
    );

    const chain2OrderPortalInfo = await orderPortal2.chains(
      chain1Config.chainId
    );
    if (
      chain2OrderPortalInfo.supported &&
      chain2OrderPortalInfo.adManager.toLowerCase() ===
        chain1Contracts.adManager!.toLowerCase()
    ) {
      console.log("  ✓ Already configured");
    } else {
      const tx4 = await orderPortal2.setChain(
        chain1Config.chainId,
        chain1Contracts.adManager!,
        true
      );
      console.log(`  Tx: ${tx4.hash}`);
      await waitForTransaction(tx4);
      txHashes.push(tx4.hash);
      displayTxSummary(
        chain2Config.name,
        "setChain on OrderPortal",
        tx4.hash,
        chain2Config.explorerUrl
      );
      await sleep(2000);
    }

    console.log(`\n✓ Chains linked successfully\n`);
  } catch (error) {
    console.error("\n✗ Failed to link chains:", error);
    throw error;
  }

  return txHashes;
}

/**
 * Configure token routes bidirectionally
 */
export async function configureTokenRoutes(
  chain1Config: ChainConfig,
  chain1Contracts: ContractAddresses,
  chain2Config: ChainConfig,
  chain2Contracts: ContractAddresses,
  tokenRoutes: TokenRoute[],
  privateKey: string,
  dryRun: boolean = false
): Promise<string[]> {
  console.log(`\n${"=".repeat(60)}`);
  console.log(`Configuring Token Routes`);
  console.log(`${"=".repeat(60)}\n`);

  const txHashes: string[] = [];

  if (dryRun) {
    console.log("DRY RUN MODE - No transactions will be sent\n");
    return txHashes;
  }

  const signer1 = createSigner(chain1Config, privateKey);
  const signer2 = createSigner(chain2Config, privateKey);

  const adManager1 = new ethers.Contract(
    chain1Contracts.adManager!,
    AD_MANAGER_ABI,
    signer1
  );
  const adManager2 = new ethers.Contract(
    chain2Contracts.adManager!,
    AD_MANAGER_ABI,
    signer2
  );
  const orderPortal1 = new ethers.Contract(
    chain1Contracts.orderPortal!,
    ORDER_PORTAL_ABI,
    signer1
  );
  const orderPortal2 = new ethers.Contract(
    chain2Contracts.orderPortal!,
    ORDER_PORTAL_ABI,
    signer2
  );

  try {
    for (let i = 0; i < tokenRoutes.length; i++) {
      const route = tokenRoutes[i];
      console.log(`\nToken Route ${i + 1}/${tokenRoutes.length}`);

      // Determine which chain is which
      const isChain1First = route.chain1.chainId === chain1Config.chainId;

      if (!isChain1First && route.chain2.chainId !== chain1Config.chainId) {
        console.log("  ⊘ Skipping - route doesn't involve these chains");
        continue;
      }

      const token1 = isChain1First ? route.chain1.token : route.chain2.token;
      const token2 = isChain1First ? route.chain2.token : route.chain1.token;
      const isNative1 = isChain1First
        ? route.chain1.isNative
        : route.chain2.isNative;
      const isNative2 = isChain1First
        ? route.chain2.isNative
        : route.chain1.isNative;

      console.log(`  ${chain1Config.name}: ${isNative1 ? "Native" : token1}`);
      console.log(`  ${chain2Config.name}: ${isNative2 ? "Native" : token2}`);

      // For native tokens, use the wNativeToken address for routes
      const routeToken1 = isNative1 ? chain1Contracts.wNativeToken! : token1;
      const routeToken2 = isNative2 ? chain2Contracts.wNativeToken! : token2;

      // Chain1 AdManager: adToken (chain1) -> orderToken (chain2), orderChainId (chain2)
      console.log(`\n  Setting route on ${chain1Config.name} AdManager...`);
      const existingRoute1 = await adManager1.tokenRoute(
        routeToken1,
        chain2Config.chainId
      );

      if (existingRoute1.toLowerCase() === routeToken2.toLowerCase()) {
        console.log("    ✓ Already configured");
      } else {
        const tx1 = await adManager1.setTokenRoute(
          routeToken1, // adToken on chain1
          routeToken2, // orderToken on chain2
          chain2Config.chainId // orderChainId
        );
        console.log(`    Tx: ${tx1.hash}`);
        await waitForTransaction(tx1);
        txHashes.push(tx1.hash);
        await sleep(2000);
      }

      // Chain2 OrderPortal: orderToken (chain2) -> adChainId (chain1) -> adToken (chain1)
      console.log(`\n  Setting route on ${chain2Config.name} OrderPortal...`);
      const existingRoute2 = await orderPortal2.tokenRoute(
        routeToken2,
        chain1Config.chainId
      );

      if (existingRoute2.toLowerCase() === routeToken1.toLowerCase()) {
        console.log("    ✓ Already configured");
      } else {
        const tx2 = await orderPortal2.setTokenRoute(
          routeToken2, // orderToken on chain2
          chain1Config.chainId, // adChainId
          routeToken1 // adToken on chain1
        );
        console.log(`    Tx: ${tx2.hash}`);
        await waitForTransaction(tx2);
        txHashes.push(tx2.hash);
        await sleep(2000);
      }

      // Chain2 AdManager: adToken (chain2) -> orderToken (chain1), orderChainId (chain1)
      console.log(`\n  Setting route on ${chain2Config.name} AdManager...`);
      const existingRoute3 = await adManager2.tokenRoute(
        routeToken2,
        chain1Config.chainId
      );

      if (existingRoute3.toLowerCase() === routeToken1.toLowerCase()) {
        console.log("    ✓ Already configured");
      } else {
        const tx3 = await adManager2.setTokenRoute(
          routeToken2, // adToken on chain2
          routeToken1, // orderToken on chain1
          chain1Config.chainId // orderChainId
        );
        console.log(`    Tx: ${tx3.hash}`);
        await waitForTransaction(tx3);
        txHashes.push(tx3.hash);
        await sleep(2000);
      }

      // Chain1 OrderPortal: orderToken (chain1) -> adChainId (chain2) -> adToken (chain2)
      console.log(`\n  Setting route on ${chain1Config.name} OrderPortal...`);
      const existingRoute4 = await orderPortal1.tokenRoute(
        routeToken1,
        chain2Config.chainId
      );

      if (existingRoute4.toLowerCase() === routeToken2.toLowerCase()) {
        console.log("    ✓ Already configured");
      } else {
        const tx4 = await orderPortal1.setTokenRoute(
          routeToken1, // orderToken on chain1
          chain2Config.chainId, // adChainId
          routeToken2 // adToken on chain2
        );
        console.log(`    Tx: ${tx4.hash}`);
        await waitForTransaction(tx4);
        txHashes.push(tx4.hash);
        await sleep(2000);
      }
    }

    console.log(`\n✓ Token routes configured successfully\n`);
  } catch (error) {
    console.error("\n✗ Failed to configure token routes:", error);
    throw error;
  }

  return txHashes;
}

/**
 * Complete setup: grant roles, link chains, configure token routes
 */
export async function setupChainPair(
  chain1Config: ChainConfig,
  chain1Contracts: ContractAddresses,
  chain2Config: ChainConfig,
  chain2Contracts: ContractAddresses,
  tokenRoutes: TokenRoute[],
  privateKey: string,
  dryRun: boolean = false
): Promise<SetupResult> {
  console.log(`\n${"#".repeat(60)}`);
  console.log(`SETUP: ${chain1Config.name} <-> ${chain2Config.name}`);
  console.log(`${"#".repeat(60)}`);

  const result: SetupResult = {
    chain1: chain1Config.chainId,
    chain2: chain2Config.chainId,
    managerRolesGranted: false,
    chainsLinked: false,
    tokenRoutesConfigured: 0,
    transactions: [],
  };

  try {
    // 1. Link chains
    const linkTxs = await linkChains(
      chain1Config,
      chain1Contracts,
      chain2Config,
      chain2Contracts,
      privateKey,
      dryRun
    );
    result.chainsLinked = true;
    linkTxs.forEach((hash) => {
      result.transactions.push({
        hash,
        type: "Link Chains",
        chainId: "multi",
        timestamp: Date.now(),
      });
    });

    // 2. Configure token routes
    const routeTxs = await configureTokenRoutes(
      chain1Config,
      chain1Contracts,
      chain2Config,
      chain2Contracts,
      tokenRoutes,
      privateKey,
      dryRun
    );
    result.tokenRoutesConfigured = tokenRoutes.length;
    routeTxs.forEach((hash) => {
      result.transactions.push({
        hash,
        type: "Configure Token Route",
        chainId: "multi",
        timestamp: Date.now(),
      });
    });

    console.log(`\n${"#".repeat(60)}`);
    console.log(`✓ SETUP COMPLETE`);
    console.log(`${"#".repeat(60)}\n`);
  } catch (error) {
    console.error("\n✗ Setup failed:", error);
    throw error;
  }

  return result;
}
