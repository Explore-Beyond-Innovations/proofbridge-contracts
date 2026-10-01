import * as fs from "fs";
import { ethers } from "ethers";
import { readManifest } from "@proofbridge/deployment-manifest";
import { getAbi } from "./artifacts.js";
import { requireEnv } from "./common.js";
import { manifestPath } from "./manifest.js";

// Review 50-4: a pre-signed retirement from before the current RetireKey message (the pre-2.6 per-slot
// digest, or a 2.6 one without the environment) no longer verifies. This one-off check replays each
// stored retirement against this chain's registry as a call, so the registry itself decides.

/** One stored retirement, as the relayer's vault exports it (hex bytes, decimal validUntil). */
export interface StoredRetirement {
  account: string;
  keyCommitment: string;
  validUntil: string;
  scheme: "secp256k1" | "sep53";
  /** secp256k1: r‖s‖v (65 B). sep53: the bare 64 B signature. */
  sig: string;
  /** sep53 on EVM: abi.encode(r, s, edX, edY). Required for sep53 here. */
  evmSig?: string;
}

export type AuditStatus = "current" | "stale-format" | "no-slot" | "already-shorter" | "unchecked";

/** The call's revert (its error name, null when it would apply) as an audit status. */
export function classifyRetirement(revert: string | null): AuditStatus {
  if (revert === null) return "current";
  if (revert === "OwnerMismatch" || revert === "BadLength" || revert === "LegMismatch") return "stale-format";
  if (revert === "NoSuchSlot") return "no-slot";
  if (revert === "BadValidUntil") return "already-shorter";
  return "unchecked";
}

export interface AuditRow extends StoredRetirement {
  status: AuditStatus;
  detail?: string;
}

export async function auditRetirements(
  registry: ethers.Contract,
  rows: StoredRetirement[],
): Promise<AuditRow[]> {
  const out: AuditRow[] = [];
  for (const r of rows) {
    const sig = r.scheme === "sep53" ? r.evmSig : r.sig;
    if (!sig) {
      out.push({ ...r, status: "unchecked", detail: "sep53 without evmSig" });
      continue;
    }
    const owner = { scheme: r.scheme === "sep53" ? 1 : 0, legs: [], sig };
    try {
      await registry.getFunction("setValidUntil").staticCall(r.account, owner, r.keyCommitment, BigInt(r.validUntil));
      out.push({ ...r, status: "current" });
    } catch (e) {
      const name = revertName(registry, e);
      out.push({ ...r, status: classifyRetirement(name), ...(name ? {} : { detail: String((e as Error).message).slice(0, 120) }) });
    }
  }
  return out;
}

function revertName(registry: ethers.Contract, e: unknown): string | null {
  const data = (e as { data?: string }).data ?? (e as { info?: { error?: { data?: string } } }).info?.error?.data;
  if (typeof data !== "string" || data.length < 10) return (e as { revert?: { name?: string } }).revert?.name ?? null;
  try {
    return registry.interface.parseError(data)?.name ?? null;
  } catch {
    return null;
  }
}

export interface RetirementsAuditOptions {
  file: string;
  rpcUrl?: string;
  manifest?: string;
}

/** `retirements-audit --file <vault export>`: prints one row per retirement and returns them. */
export async function retirementsAudit(opts: RetirementsAuditOptions): Promise<AuditRow[]> {
  const rpcUrl = opts.rpcUrl ?? requireEnv("EVM_RPC_URL");
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const chainId = (await provider.getNetwork()).chainId;
  const manifest = await readManifest(opts.manifest ?? manifestPath(chainId));
  const address = manifest.contracts.blsKeyRegistry?.address;
  if (!address) throw new Error("retirements-audit: the manifest names no blsKeyRegistry");
  const rows = JSON.parse(fs.readFileSync(opts.file, "utf8")) as StoredRetirement[];
  const registry = new ethers.Contract(address, getAbi("BLSKeyRegistry", "BLSKeyRegistry"), provider);
  const result = await auditRetirements(registry, rows);
  for (const r of result) {
    console.log(`  ${r.status.padEnd(15)} ${r.account} key ${r.keyCommitment} validUntil ${r.validUntil}${r.detail ? ` (${r.detail})` : ""}`);
  }
  const stale = result.filter((r) => r.status === "stale-format").length;
  console.log(`[retirements-audit] ${result.length} checked on chain ${chainId}; ${stale} stale-format (collect them again)`);
  provider.destroy();
  return result;
}
