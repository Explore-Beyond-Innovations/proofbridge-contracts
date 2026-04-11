import { ethers } from "ethers";
import { ChainConfig, ContractAddresses, DeploymentResult } from "./types";
import {
  createSigner,
  getContractFactory,
  waitForTransaction,
  displayTxSummary,
  sleep,
  MANAGER_ROLE,
} from "./utils";

/**
 * Generic contract deployment function
 * Used by specialized scenarios to deploy additional contracts
 */
export async function deployContract(
  contractName: string,
  constructorArgs: any[],
  rpcUrl: string,
  privateKey: string,
  dryRun: boolean = false
): Promise<string> {
  if (dryRun) {
    console.log(`  [DRY RUN] Would deploy ${contractName}`);
    return "0x0000000000000000000000000000000000000000";
  }

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const signer = new ethers.Wallet(privateKey, provider);

  try {
    const factory = await getContractFactory(contractName, signer);
    console.log(`  Deploying ${contractName}...`);
    const contract = await factory.deploy(...constructorArgs);
    await contract.waitForDeployment();
    const address = await contract.getAddress();
    console.log(`  ✓ Deployed at: ${address}`);
    return address;
  } catch (error) {
    console.error(`  ✗ Failed to deploy ${contractName}:`, error);
    throw error;
  }
}

/**
 * Deploy all contracts for a single chain
 */
export async function deployChain(
  chainConfig: ChainConfig,
  privateKey: string,
  dryRun: boolean = false
): Promise<DeploymentResult> {
  console.log(`\n${"=".repeat(60)}`);
  console.log(
    `Deploying on ${chainConfig.name} (Chain ID: ${chainConfig.chainId})`
  );
  console.log(`${"=".repeat(60)}\n`);

  const signer = createSigner(chainConfig, privateKey);
  const deployerAddress = await signer.getAddress();
  console.log(`Deployer: ${deployerAddress}`);
  console.log(`Admin: ${chainConfig.admin}\n`);

  if (dryRun) {
    console.log("DRY RUN MODE - No transactions will be sent\n");
  }

  const result: DeploymentResult = {
    chainId: chainConfig.chainId,
    chainName: chainConfig.name,
    contracts: { ...chainConfig.contracts },
    transactions: [],
  };

  try {
    // 1. Deploy or reuse Verifier
    console.log("1. Verifier");
    if (chainConfig.contracts.verifier) {
      console.log(`  ✓ Reusing: ${chainConfig.contracts.verifier}`);
      result.contracts.verifier = chainConfig.contracts.verifier;
    } else if (!dryRun) {
      const Verifier = await getContractFactory("HonkVerifier", signer);
      console.log("  Deploying HonkVerifier...");
      const verifier = await Verifier.deploy();
      await verifier.waitForDeployment();
      const verifierAddress = await verifier.getAddress();
      result.contracts.verifier = verifierAddress;
      console.log(`  ✓ Deployed: ${verifierAddress}`);

      result.transactions.push({
        hash: verifier.deploymentTransaction()?.hash || "",
        type: "Deploy Verifier",
        timestamp: Date.now(),
      });
      await sleep(2000);
    }

    // 2. Deploy or reuse MerkleManager
    console.log("\n2. MerkleManager");
    if (chainConfig.contracts.merkleManager) {
      console.log(`  ✓ Reusing: ${chainConfig.contracts.merkleManager}`);
      result.contracts.merkleManager = chainConfig.contracts.merkleManager;
    } else if (!dryRun) {
      const MerkleManager = await getContractFactory("MerkleManager", signer);
      console.log(
        `  Deploying MerkleManager with admin: ${chainConfig.admin}...`
      );
      const merkleManager = await MerkleManager.deploy(chainConfig.admin);
      await merkleManager.waitForDeployment();
      const merkleManagerAddress = await merkleManager.getAddress();
      result.contracts.merkleManager = merkleManagerAddress;
      console.log(`  ✓ Deployed: ${merkleManagerAddress}`);

      result.transactions.push({
        hash: merkleManager.deploymentTransaction()?.hash || "",
        type: "Deploy MerkleManager",
        timestamp: Date.now(),
      });
      await sleep(2000);
    }

    // 3. Deploy or reuse wNativeToken
    console.log("\n3. wNativeToken");
    if (chainConfig.contracts.wNativeToken) {
      console.log(`  ✓ Reusing: ${chainConfig.contracts.wNativeToken}`);
      result.contracts.wNativeToken = chainConfig.contracts.wNativeToken;
    } else if (!dryRun) {
      const WNativeToken = await getContractFactory("wNativeToken", signer);
      const tokenName = `Wrapped ${chainConfig.nativeToken.symbol}`;
      const tokenSymbol = `W${chainConfig.nativeToken.symbol}`;
      console.log(`  Deploying wNativeToken (${tokenName}, ${tokenSymbol})...`);
      const decimals = chainConfig.nativeToken.decimals;
      const wNativeToken = await WNativeToken.deploy(
        tokenName,
        tokenSymbol,
        decimals
      );
      await wNativeToken.waitForDeployment();
      const wNativeTokenAddress = await wNativeToken.getAddress();
      result.contracts.wNativeToken = wNativeTokenAddress;
      console.log(`  ✓ Deployed: ${wNativeTokenAddress}`);

      result.transactions.push({
        hash: wNativeToken.deploymentTransaction()?.hash || "",
        type: "Deploy wNativeToken",
        timestamp: Date.now(),
      });
      await sleep(2000);
    }

    // 4. Deploy or reuse AdManager
    console.log("\n4. AdManager");
    if (chainConfig.contracts.adManager) {
      console.log(`  ✓ Reusing: ${chainConfig.contracts.adManager}`);
      result.contracts.adManager = chainConfig.contracts.adManager;
    } else if (!dryRun) {
      const AdManager = await getContractFactory("AdManager", signer);
      console.log("  Deploying AdManager...");
      const adManager = await AdManager.deploy(
        chainConfig.admin,
        result.contracts.verifier!,
        result.contracts.merkleManager!,
        result.contracts.wNativeToken!
      );
      await adManager.waitForDeployment();
      const adManagerAddress = await adManager.getAddress();
      result.contracts.adManager = adManagerAddress;
      console.log(`  ✓ Deployed: ${adManagerAddress}`);

      result.transactions.push({
        hash: adManager.deploymentTransaction()?.hash || "",
        type: "Deploy AdManager",
        timestamp: Date.now(),
      });
      await sleep(2000);
    }

    // 5. Deploy or reuse OrderPortal
    console.log("\n5. OrderPortal");
    if (chainConfig.contracts.orderPortal) {
      console.log(`  ✓ Reusing: ${chainConfig.contracts.orderPortal}`);
      result.contracts.orderPortal = chainConfig.contracts.orderPortal;
    } else if (!dryRun) {
      const OrderPortal = await getContractFactory("OrderPortal", signer);
      console.log("  Deploying OrderPortal...");
      const orderPortal = await OrderPortal.deploy(
        chainConfig.admin,
        result.contracts.verifier!,
        result.contracts.merkleManager!,
        result.contracts.wNativeToken!
      );
      await orderPortal.waitForDeployment();
      const orderPortalAddress = await orderPortal.getAddress();
      result.contracts.orderPortal = orderPortalAddress;
      console.log(`  ✓ Deployed: ${orderPortalAddress}`);

      result.transactions.push({
        hash: orderPortal.deploymentTransaction()?.hash || "",
        type: "Deploy OrderPortal",
        timestamp: Date.now(),
      });
      await sleep(2000);
    }

    console.log(`\n${"=".repeat(60)}`);
    console.log(`✓ Deployment complete for ${chainConfig.name}`);
    console.log(`${"=".repeat(60)}\n`);
  } catch (error) {
    console.error(`\n✗ Deployment failed for ${chainConfig.name}:`, error);
    throw error;
  }

  return result;
}

/**
 * Grant MANAGER_ROLE to AdManager and OrderPortal on MerkleManager
 */
export async function grantManagerRoles(
  chainConfig: ChainConfig,
  contracts: ContractAddresses,
  privateKey: string,
  dryRun: boolean = false
): Promise<string[]> {
  console.log(`\n${"-".repeat(60)}`);
  console.log(`Granting Manager Roles on ${chainConfig.name}`);
  console.log(`${"-".repeat(60)}\n`);

  const signer = createSigner(chainConfig, privateKey);
  const txHashes: string[] = [];

  if (
    !contracts.merkleManager ||
    !contracts.adManager ||
    !contracts.orderPortal
  ) {
    throw new Error("Missing required contract addresses for role grants");
  }

  if (dryRun) {
    console.log("DRY RUN MODE - No transactions will be sent\n");
    return txHashes;
  }

  try {
    const merkleManagerAbi = [
      "function grantRole(bytes32 role, address account) external",
      "function hasRole(bytes32 role, address account) external view returns (bool)",
    ];

    const merkleManager = new ethers.Contract(
      contracts.merkleManager,
      merkleManagerAbi,
      signer
    );

    // Grant to AdManager
    console.log("1. Granting MANAGER_ROLE to AdManager");
    const hasRoleAdManager = await merkleManager.hasRole(
      MANAGER_ROLE,
      contracts.adManager
    );

    if (hasRoleAdManager) {
      console.log("  ✓ AdManager already has MANAGER_ROLE");
    } else {
      const tx1 = await merkleManager.grantRole(
        MANAGER_ROLE,
        contracts.adManager
      );
      console.log(`  Tx: ${tx1.hash}`);
      await waitForTransaction(tx1);
      txHashes.push(tx1.hash);
      displayTxSummary(
        chainConfig.name,
        "Grant MANAGER_ROLE to AdManager",
        tx1.hash,
        chainConfig.explorerUrl
      );
      await sleep(2000);
    }

    // Grant to OrderPortal
    console.log("\n2. Granting MANAGER_ROLE to OrderPortal");
    const hasRoleOrderPortal = await merkleManager.hasRole(
      MANAGER_ROLE,
      contracts.orderPortal
    );

    if (hasRoleOrderPortal) {
      console.log("  ✓ OrderPortal already has MANAGER_ROLE");
    } else {
      const tx2 = await merkleManager.grantRole(
        MANAGER_ROLE,
        contracts.orderPortal
      );
      console.log(`  Tx: ${tx2.hash}`);
      await waitForTransaction(tx2);
      txHashes.push(tx2.hash);
      displayTxSummary(
        chainConfig.name,
        "Grant MANAGER_ROLE to OrderPortal",
        tx2.hash,
        chainConfig.explorerUrl
      );
      await sleep(2000);
    }

    console.log(`\n✓ Manager roles granted on ${chainConfig.name}\n`);
  } catch (error) {
    console.error(
      `\n✗ Failed to grant manager roles on ${chainConfig.name}:`,
      error
    );
    throw error;
  }

  return txHashes;
}
