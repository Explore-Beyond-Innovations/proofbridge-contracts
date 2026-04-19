import * as path from "path";
import { promises as fs } from "fs";
import {
  type ChainDeploymentManifest,
  type ContractEntry,
  type TokenEntry,
  ChainDeploymentManifestSchema,
  CHAIN_DEPLOYMENT_MANIFEST_VERSION,
  readManifest,
  writeManifest,
} from "@proofbridge/deployment-manifest";
import { deploymentsDir } from "./common.js";
import { strkeyToHex } from "./stellar-cli.js";

export function manifestPath(chainId: bigint | string): string {
  return path.join(deploymentsDir(), `${String(chainId)}.json`);
}

export function stellarContractEntry(strkey: string): ContractEntry {
  return { address: strkey, addressBytes32: strkeyToHex(strkey) };
}

export interface StellarTokenInput {
  pairKey: string;
  symbol: string;
  name: string;
  /** Contract id (C...) or — for SAC-convention XLM — the native SAC id. */
  contractId: string;
  kind: "NATIVE" | "SAC" | "SEP41";
  decimals: number;
  assetIssuer?: string | null;
  isTestToken?: boolean;
}

export function tokenEntry(tok: StellarTokenInput): TokenEntry {
  return {
    pairKey: tok.pairKey,
    symbol: tok.symbol,
    name: tok.name,
    address: tok.contractId,
    addressBytes32: strkeyToHex(tok.contractId),
    kind: tok.kind,
    decimals: tok.decimals,
    assetIssuer: tok.assetIssuer ?? null,
    isTestToken: tok.isTestToken ?? false,
  };
}

export interface BuildStellarManifestInput {
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
  tokens: StellarTokenInput[];
}

export function buildManifest(
  input: BuildStellarManifestInput,
): ChainDeploymentManifest {
  const m: ChainDeploymentManifest = {
    version: CHAIN_DEPLOYMENT_MANIFEST_VERSION,
    chain: {
      name: input.chainName,
      kind: "STELLAR",
      chainId: input.chainId.toString(),
    },
    contracts: {
      verifier: stellarContractEntry(input.contracts.verifier),
      merkleManager: stellarContractEntry(input.contracts.merkleManager),
      wNativeToken: stellarContractEntry(input.contracts.wNativeToken),
      adManager: stellarContractEntry(input.contracts.adManager),
      orderPortal: stellarContractEntry(input.contracts.orderPortal),
    },
    tokens: input.tokens.map(tokenEntry),
    meta: {
      deployedAt: new Date().toISOString(),
      deployer: input.deployer,
      commit: input.commit,
      env: input.env,
    },
  };
  return ChainDeploymentManifestSchema.parse(m);
}

export async function loadOrNull(
  filePath: string,
): Promise<ChainDeploymentManifest | null> {
  try {
    await fs.access(filePath);
  } catch {
    return null;
  }
  return readManifest(filePath);
}

export async function patchManifest(
  filePath: string,
  patch: (m: ChainDeploymentManifest) => ChainDeploymentManifest,
): Promise<ChainDeploymentManifest> {
  const current = await readManifest(filePath);
  const next = patch(current);
  await writeManifest(filePath, next);
  return next;
}

export { readManifest, writeManifest };
