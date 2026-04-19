import * as path from "path";
import {
  type ChainDeploymentManifest,
  type ContractEntry,
  type TokenEntry,
  ChainDeploymentManifestSchema,
  CHAIN_DEPLOYMENT_MANIFEST_VERSION,
  readManifest,
  writeManifest,
} from "@proofbridge/deployment-manifest";
import { deploymentsDir, evmAddressToBytes32 } from "./common.js";

export function manifestPath(chainId: bigint | string): string {
  const id = String(chainId);
  // Reject non-decimal inputs so a caller-supplied string can't path-traverse out of deployments/.
  if (!/^\d+$/.test(id)) {
    throw new Error(`invalid chainId for manifest path: ${id}`);
  }
  return path.join(deploymentsDir(), `${id}.json`);
}

export function evmContractEntry(address: string): ContractEntry {
  return {
    address: address,
    addressBytes32: evmAddressToBytes32(address),
  };
}

export interface EvmTokenInput {
  pairKey: string;
  symbol: string;
  name: string;
  address: string;
  kind: "NATIVE" | "ERC20";
  decimals: number;
  isTestToken?: boolean;
}

export function tokenEntry(tok: EvmTokenInput): TokenEntry {
  return {
    pairKey: tok.pairKey,
    symbol: tok.symbol,
    name: tok.name,
    address: tok.address,
    addressBytes32: evmAddressToBytes32(tok.address),
    kind: tok.kind,
    decimals: tok.decimals,
    assetIssuer: null,
    isTestToken: tok.isTestToken ?? false,
  };
}

export interface BuildManifestInput {
  chainName: string;
  chainId: bigint;
  env: string;
  commit: string;
  deployer: string;
  contracts: {
    verifier: string;
    merkleManager: string;
    wNativeToken: string;
    adManager: string;
    orderPortal: string;
  };
  tokens: EvmTokenInput[];
}

export function buildManifest(
  input: BuildManifestInput,
): ChainDeploymentManifest {
  const manifest: ChainDeploymentManifest = {
    version: CHAIN_DEPLOYMENT_MANIFEST_VERSION,
    chain: {
      name: input.chainName,
      kind: "EVM",
      chainId: input.chainId.toString(),
    },
    contracts: {
      verifier: evmContractEntry(input.contracts.verifier),
      merkleManager: evmContractEntry(input.contracts.merkleManager),
      wNativeToken: evmContractEntry(input.contracts.wNativeToken),
      adManager: evmContractEntry(input.contracts.adManager),
      orderPortal: evmContractEntry(input.contracts.orderPortal),
    },
    tokens: input.tokens.map(tokenEntry),
    meta: {
      deployedAt: new Date().toISOString(),
      deployer: input.deployer,
      commit: input.commit,
      env: input.env,
    },
  };
  return ChainDeploymentManifestSchema.parse(manifest);
}

/** Merge a partial update into the on-disk manifest (e.g. `deploy-test-tokens` appending tokens). */
export async function patchManifest(
  filePath: string,
  patch: (m: ChainDeploymentManifest) => ChainDeploymentManifest,
): Promise<ChainDeploymentManifest> {
  const current = await readManifest(filePath);
  const next = patch(current);
  await writeManifest(filePath, next);
  return next;
}

export async function loadOrNull(
  filePath: string,
): Promise<ChainDeploymentManifest | null> {
  // Only "file doesn't exist" maps to null — permission / I/O errors bubble up.
  try {
    return await readManifest(filePath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
}

export { readManifest, writeManifest };
