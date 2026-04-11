import { ethers } from "ethers";
import { ChainConfig, ContractAddresses } from "./types";
import * as fs from "fs";
import * as path from "path";

export const NATIVE_TOKEN_ADDRESS =
  "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";
export const MANAGER_ROLE = ethers.keccak256(
  ethers.toUtf8Bytes("MANAGER_ROLE")
);
export const ADMIN_ROLE = ethers.ZeroHash; // DEFAULT_ADMIN_ROLE

// ABI fragments for contract interactions
export const VERIFIER_ABI = [
  "function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool)",
];

export const MERKLE_MANAGER_ABI = [
  "function grantRole(bytes32 role, address account) external",
  "function hasRole(bytes32 role, address account) external view returns (bool)",
  "function getRoot() external view returns (bytes32)",
  "function getWidth() external view returns (uint256)",
];

export const AD_MANAGER_ABI = [
  "function setChain(uint256 orderChainId, address orderPortal, bool supported) external",
  "function setTokenRoute(address adToken, address orderToken, uint256 orderChainId) external",
  "function chains(uint256) external view returns (bool supported, address orderPortal)",
  "function tokenRoute(address, uint256) external view returns (address)",
  "function i_merkleManager() external view returns (address)",
  "function i_verifier() external view returns (address)",
];

export const ORDER_PORTAL_ABI = [
  "function setChain(uint256 adChainId, address adManager, bool supported) external",
  "function setTokenRoute(address orderToken, uint256 adChainId, address adToken) external",
  "function chains(uint256) external view returns (bool supported, address adManager)",
  "function tokenRoute(address, uint256) external view returns (address)",
  "function i_merkleManager() external view returns (address)",
  "function i_verifier() external view returns (address)",
];

export const WNATIVE_TOKEN_ABI = [
  "function name() external view returns (string)",
  "function symbol() external view returns (string)",
];

/**
 * Create a provider for a given chain configuration
 */
export function createProvider(
  chainConfig: ChainConfig
): ethers.JsonRpcProvider {
  return new ethers.JsonRpcProvider(chainConfig.rpc);
}

/**
 * Create a signer for deployment
 */
export function createSigner(
  chainConfig: ChainConfig,
  privateKey: string
): ethers.Wallet {
  const provider = createProvider(chainConfig);
  return new ethers.Wallet(privateKey, provider);
}

/**
 * Wait for transaction confirmation with retries
 */
export async function waitForTransaction(
  tx: ethers.ContractTransactionResponse,
  confirmations: number = 2
): Promise<ethers.ContractTransactionReceipt | null> {
  console.log(`  Waiting for tx: ${tx.hash}`);
  const receipt = await tx.wait(confirmations);
  if (receipt && receipt.status === 1) {
    console.log(`  ✓ Confirmed in block ${receipt.blockNumber}`);
  } else {
    console.log(`  ✗ Transaction failed`);
  }
  return receipt;
}

/**
 * Load contract addresses from deployments file
 */
export function loadDeployments(
  deploymentsPath: string
): Record<string, ContractAddresses> {
  if (!fs.existsSync(deploymentsPath)) {
    return {};
  }

  try {
    const data = fs.readFileSync(deploymentsPath, "utf-8");
    return JSON.parse(data);
  } catch (error) {
    console.warn(`Failed to load deployments from ${deploymentsPath}:`, error);
    return {};
  }
}

/**
 * Save contract addresses to deployments file
 */
export function saveDeployments(
  deploymentsPath: string,
  chainId: string,
  contracts: ContractAddresses
): void {
  const deployments = loadDeployments(deploymentsPath);
  deployments[chainId] = contracts;

  const dir = path.dirname(deploymentsPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.writeFileSync(
    deploymentsPath,
    JSON.stringify(deployments, null, 2),
    "utf-8"
  );
  console.log(`✓ Saved deployments to ${deploymentsPath}`);
}

/**
 * Format address for display
 */
export function formatAddress(address: string): string {
  if (!address || address === ethers.ZeroAddress) {
    return "Not deployed";
  }
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

/**
 * Check if address is native token placeholder
 */
export function isNativeToken(address: string): boolean {
  return address.toLowerCase() === NATIVE_TOKEN_ADDRESS.toLowerCase();
}

/**
 * Prompt user for confirmation
 */
export async function promptConfirmation(message: string): Promise<boolean> {
  // For now, return true. In a real CLI, use readline or inquirer
  console.log(`\n${message}`);
  console.log("Proceeding... (use --skip-confirmation to suppress)");
  return true;
}

/**
 * Sleep for specified milliseconds
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Retry configuration options
 */
export interface RetryOptions {
  maxRetries?: number; // Default: 3
  delayMs?: number; // Default: 5000 (5 seconds)
  onRetry?: (error: Error, attempt: number) => void;
}

/**
 * Retry an async operation with configurable delay and max attempts
 * Useful for handling transient RPC failures
 */
export async function withRetry<T>(
  operation: () => Promise<T>,
  options: RetryOptions = {}
): Promise<T> {
  const { maxRetries = 3, delayMs = 5000, onRetry } = options;

  let lastError: Error;
  for (let attempt = 1; attempt <= maxRetries + 1; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error as Error;

      if (attempt <= maxRetries) {
        const retryMsg = `  ⚠ Attempt ${attempt} failed: ${lastError.message}`;
        console.log(retryMsg);
        console.log(`  ⏳ Retrying in ${delayMs / 1000}s... (${maxRetries - attempt + 1} retries left)`);

        if (onRetry) {
          onRetry(lastError, attempt);
        }

        await sleep(delayMs);
      }
    }
  }

  throw new Error(
    `Operation failed after ${maxRetries + 1} attempts. Last error: ${lastError!.message}`
  );
}

/**
 * Get contract factory from compiled artifacts
 */
export async function getContractFactory(
  contractName: string,
  signer: ethers.Wallet
): Promise<ethers.ContractFactory> {
  const contractFileName =
    contractName === "HonkVerifier" ? "Verifier" : contractName;
  const artifactPath = path.join(
    __dirname,
    "../../../out",
    `${contractFileName}.sol`,
    `${contractName}.json`
  );

  if (!fs.existsSync(artifactPath)) {
    throw new Error(
      `Artifact not found for ${contractName} at ${artifactPath}`
    );
  }

  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf-8"));
  return new ethers.ContractFactory(
    artifact.abi,
    artifact.bytecode.object,
    signer
  );
}

/**
 * Estimate gas with buffer
 */
export async function estimateGasWithBuffer(
  contract: ethers.Contract,
  method: string,
  args: any[],
  bufferPercent: number = 20
): Promise<bigint> {
  const estimated = await contract[method].estimateGas(...args);
  const buffer = (estimated * BigInt(bufferPercent)) / 100n;
  return estimated + buffer;
}

/**
 * Display transaction summary
 */
export function displayTxSummary(
  chainName: string,
  txType: string,
  txHash: string,
  explorerUrl?: string
): void {
  console.log(`\n  ${chainName} - ${txType}`);
  console.log(`  Tx: ${txHash}`);
  if (explorerUrl) {
    console.log(`  Explorer: ${explorerUrl}/tx/${txHash}`);
  }
}

/**
 * Validate Ethereum address
 */
export function isValidAddress(address: string): boolean {
  return ethers.isAddress(address);
}

/**
 * Parse command line arguments
 */
export function parseArgs(args: string[]): Record<string, string> {
  const parsed: Record<string, string> = {};

  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith("--")) {
      const key = args[i].slice(2);
      const value =
        args[i + 1] && !args[i + 1].startsWith("--") ? args[i + 1] : "true";
      parsed[key] = value;
      if (value !== "true") i++;
    }
  }

  return parsed;
}
