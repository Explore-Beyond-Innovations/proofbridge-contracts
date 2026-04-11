// Type definitions for deployment and setup script

export interface ContractAddresses {
  verifier?: string;
  merkleManager?: string;
  wNativeToken?: string;
  adManager?: string;
  orderPortal?: string;
}

export interface NativeTokenConfig {
  symbol: string;
  address: string; // 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE for native
  decimals: number;
}

export interface Tokens {
  proofbridge: string;
  wAltChainToken: string;
}
export interface ChainConfig {
  name: string;
  rpc: string;
  chainId: string;
  admin: string;
  privateKey?: string; // Optional: for deployment
  contracts: ContractAddresses;
  nativeToken: NativeTokenConfig;
  tokens: Tokens;
  explorerUrl?: string;
}

export interface TokenPair {
  token: string;
  isNative: boolean;
}

export interface TokenRoute {
  chain1: {
    chainId: string;
    token: string;
    isNative: boolean;
  };
  chain2: {
    chainId: string;
    token: string;
    isNative: boolean;
  };
}

export interface DeploymentConfig {
  chains: Record<string, ChainConfig>;
  tokenRoutes: TokenRoute[];
}

export interface DeploymentResult {
  chainId: string;
  chainName: string;
  contracts: ContractAddresses;
  transactions: {
    hash: string;
    type: string;
    timestamp: number;
  }[];
}

export interface SetupResult {
  chain1: string;
  chain2: string;
  managerRolesGranted: boolean;
  chainsLinked: boolean;
  tokenRoutesConfigured: number;
  transactions: {
    hash: string;
    type: string;
    chainId: string;
    timestamp: number;
  }[];
}

export type DeploymentMode = "deploy" | "setup" | "full";
export type DeploymentScenario = "standard" | "sepolia-hedera";

export interface DeploymentOptions {
  chain1: string;
  chain2: string;
  mode: DeploymentMode;
  scenario: DeploymentScenario;
  dryRun: boolean;
  skipConfirmation: boolean;
  configPath?: string;
  deploymentsPath: string;
}
