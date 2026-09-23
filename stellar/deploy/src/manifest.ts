import * as path from "path";
import {
  type AdminHandover,
  type ChainDeploymentManifest,
  type ContractEntry,
  type TokenEntry,
  ChainDeploymentManifestSchema,
  CHAIN_DEPLOYMENT_MANIFEST_VERSION,
  readManifest,
  writeManifest,
  type RootAnchorConfig,
  type RouteTiming,
  type DisputeParams,
} from "@proofbridge/deployment-manifest";
import { deploymentsDir } from "./common.js";
import { strkeyToHex } from "./stellar-cli.js";

export function manifestPath(chainId: bigint | string): string {
  const id = String(chainId);
  // Reject non-decimal inputs so a caller-supplied string can't path-traverse out of deployments/.
  if (!/^\d+$/.test(id)) {
    throw new Error(`invalid chainId for manifest path: ${id}`);
  }
  return path.join(deploymentsDir(), `${id}.json`);
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
    merkleManagerDeployBlock?: string;
    wNativeToken: string;
    adManager: string;
    orderPortal: string;
    blsKeyRegistry?: string;
    counterpartyVerifier?: string;
    rootAnchor?: string;
    registrar?: string;
    disputeManager?: string;
  };
  tokens: StellarTokenInput[];
  rootAnchorConfig?: RootAnchorConfig;
  /** Per peer chain id → the clocks link set; preserved across redeploys, written by link. */
  routeTiming?: Record<string, RouteTiming>;
  /** Per peer chain id → the dispute params link set; preserved the same way (2.3g). */
  disputeParams?: Record<string, DisputeParams>;
  /** Who holds admin (#424): the source account until `handover`; preserved across redeploys. */
  admin?: AdminHandover;
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
      merkleManager: {
        ...stellarContractEntry(input.contracts.merkleManager),
        ...(input.contracts.merkleManagerDeployBlock
          ? { deployBlock: input.contracts.merkleManagerDeployBlock }
          : {}),
      },
      wNativeToken: stellarContractEntry(input.contracts.wNativeToken),
      adManager: stellarContractEntry(input.contracts.adManager),
      ...(input.contracts.blsKeyRegistry
        ? { blsKeyRegistry: stellarContractEntry(input.contracts.blsKeyRegistry) }
        : {}),
      ...(input.contracts.counterpartyVerifier
        ? {
            counterpartyVerifier: stellarContractEntry(
              input.contracts.counterpartyVerifier,
            ),
          }
        : {}),
      orderPortal: stellarContractEntry(input.contracts.orderPortal),
      ...(input.contracts.rootAnchor
        ? { rootAnchor: stellarContractEntry(input.contracts.rootAnchor) }
        : {}),
      ...(input.contracts.registrar
        ? { registrar: stellarContractEntry(input.contracts.registrar) }
        : {}),
      ...(input.contracts.disputeManager
        ? { disputeManager: stellarContractEntry(input.contracts.disputeManager) }
        : {}),
    },
    tokens: input.tokens.map(tokenEntry),
    ...(input.rootAnchorConfig ? { rootAnchorConfig: input.rootAnchorConfig } : {}),
    routeTiming: input.routeTiming ?? {},
    disputeParams: input.disputeParams ?? {},
    ...(input.admin ? { admin: input.admin } : {}),
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
  // Only "file doesn't exist" maps to null — permission / I/O errors bubble up.
  try {
    return await readManifest(filePath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
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
