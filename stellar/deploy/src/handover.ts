import { readManifest, type ChainDeploymentManifest } from "@proofbridge/deployment-manifest";
import { DEFAULT_STELLAR_CHAIN_ID } from "./common.js";
import { getAddress, invokeContract } from "./stellar-cli.js";
import { manifestPath, writeManifest } from "./manifest.js";

/**
 * The admin handover (#424), Stellar half.
 *
 * Every contract is initialized with the source account as its admin, because the wiring `deploy`
 * and `link` do afterwards is admin-only and the source account is what signs them. The real admin
 * is nominated last, here, over the two-step transfer every admin-bearing contract carries
 * (`transfer_admin` / `accept_admin`). Its only job is to accept.
 *
 * `handover --to <G...>` nominates on every admin-bearing contract the manifest names and records
 * the nomination. `handover --verify` reads the admin on each and records acceptance once every one
 * of them answers with the nominee.
 *
 * The contracts do not expose a pending admin, so a nomination cannot be read back; nominating
 * twice simply overwrites the same nominee, which is why `handover` is safe to rerun.
 */

/** Manifest key → how to read the admin. Each contract grew its view at a different time. */
export const ADMIN_BEARING = [
  { key: "merkleManager", label: "MerkleManager", view: "get_admin", field: null },
  { key: "adManager", label: "AdManager", view: "get_config", field: "admin" },
  { key: "orderPortal", label: "OrderPortal", view: "get_config", field: "admin" },
  { key: "blsKeyRegistry", label: "BLSKeyRegistry", view: "admin", field: null },
  { key: "rootAnchor", label: "RootAnchor", view: "admin", field: null },
  { key: "disputeManager", label: "DisputeManager", view: "get_admin", field: null },
] as const;

type AdminBearingKey = (typeof ADMIN_BEARING)[number]["key"];

export interface StellarHandoverOptions {
  manifest?: string;
  chainId?: bigint;
  to?: string;
  verify?: boolean;
}

export interface StellarHandoverResult {
  nominated: string[];
  accepted: string[];
  outstanding: string[];
}

interface Seen {
  key: AdminBearingKey;
  label: string;
  address: string;
  admin: string;
}

/** The last line of a read-only invoke, parsed: the CLI prints the return value as JSON. */
function readValue(contractId: string, fn: string): unknown {
  const out = invokeContract(contractId, fn, [], { send: false });
  const last = out.split("\n").filter(Boolean).pop() ?? "null";
  return JSON.parse(last);
}

/** Who a contract answers with. `Option<Address>` views print `null` before initialize. */
export function readAdmin(contractId: string, spec: (typeof ADMIN_BEARING)[number]): string {
  const v = readValue(contractId, spec.view);
  const admin = spec.field ? (v as Record<string, unknown> | null)?.[spec.field] : v;
  if (typeof admin !== "string" || !admin.startsWith("G") && !admin.startsWith("C")) {
    throw new Error(`handover: ${spec.label} at ${contractId} did not answer ${spec.view} with an address: ${JSON.stringify(v)}`);
  }
  return admin;
}

export async function handover(opts: StellarHandoverOptions): Promise<StellarHandoverResult> {
  const chainId = opts.chainId ?? DEFAULT_STELLAR_CHAIN_ID;
  const path = opts.manifest ?? manifestPath(chainId);
  const manifest = await readManifest(path);
  if (manifest.chain.kind !== "STELLAR" || BigInt(manifest.chain.chainId) !== chainId) {
    throw new Error(`handover: ${path} is for ${manifest.chain.kind} chain ${manifest.chain.chainId}, expected STELLAR ${chainId}`);
  }
  const me = getAddress();

  // Read before anything is sent: the chain is the fact, the manifest is the record.
  const seen: Seen[] = [];
  for (const spec of ADMIN_BEARING) {
    const entry = manifest.contracts[spec.key];
    if (!entry?.address) continue;
    seen.push({ key: spec.key, label: spec.label, address: entry.address, admin: readAdmin(entry.address, spec) });
  }
  if (seen.length === 0) throw new Error(`handover: ${path} names no admin-bearing contract`);

  if (opts.verify) return verify(manifest, path, seen, me);

  const to = opts.to;
  if (!to) throw new Error("handover: --to <G...> is required (or --verify)");
  if (to === me) throw new Error(`handover: --to ${to} is the source account; nothing to hand over`);

  const result: StellarHandoverResult = { nominated: [], accepted: [], outstanding: [] };
  for (const s of seen) {
    if (s.admin === to) {
      console.log(`  [done] ${s.label}: admin is already ${to}`);
      result.accepted.push(s.label);
      continue;
    }
    if (s.admin !== me) {
      throw new Error(
        `handover: ${s.label} at ${s.address} has admin ${s.admin}, which is neither the source account (${me}) nor ${to}; nothing was sent`,
      );
    }
  }

  for (const s of seen) {
    if (s.admin === to) continue;
    invokeContract(s.address, "transfer_admin", ["--to", to]);
    console.log(`  [nominate] ${s.label}.transfer_admin(${to})`);
    result.nominated.push(s.label);
    result.outstanding.push(s.label);
  }

  manifest.admin = { current: me, pending: to, nominatedAt: new Date().toISOString() };
  await writeManifest(path, manifest);
  console.log(
    `[stellar-handover] ${result.nominated.length} nominated, ${result.outstanding.length} awaiting accept_admin from ${to}. ` +
      `Run \`handover --verify\` once it has accepted.`,
  );
  return result;
}

async function verify(manifest: ChainDeploymentManifest, path: string, seen: Seen[], me: string): Promise<StellarHandoverResult> {
  const target = manifest.admin?.pending;
  const result: StellarHandoverResult = { nominated: [], accepted: [], outstanding: [] };
  for (const s of seen) {
    const label = `${s.label} at ${s.address}`;
    if (target && s.admin === target) {
      console.log(`  [accepted] ${label}: admin is ${s.admin}`);
      result.accepted.push(s.label);
    } else if (s.admin === me) {
      console.log(`  [outstanding] ${label}: admin is still the source account${target ? `, ${target} has not accepted` : ""}`);
      result.outstanding.push(s.label);
    } else {
      console.log(`  [other] ${label}: admin is ${s.admin}`);
      result.outstanding.push(s.label);
    }
  }

  if (target && result.outstanding.length === 0) {
    manifest.admin = { current: target, acceptedAt: new Date().toISOString() };
    await writeManifest(path, manifest);
    console.log(`[stellar-handover] every contract answers with ${target}; recorded as current`);
  } else if (target) {
    console.log(`[stellar-handover] ${result.accepted.length} accepted, ${result.outstanding.length} outstanding; manifest unchanged`);
  } else {
    const admins = new Set(seen.map((s) => s.admin));
    console.log(
      admins.size === 1
        ? `[stellar-handover] no nomination recorded; every contract answers with ${seen[0]!.admin}`
        : `[stellar-handover] no nomination recorded, and the contracts disagree about their admin`,
    );
  }
  return result;
}

/** Who holds admin on the manifest's admin-bearing contracts, and whether `me` holds all of them. */
export function signerHoldsAdmin(
  contracts: ChainDeploymentManifest["contracts"],
  me: string,
  command: string,
): boolean {
  const foreign: string[] = [];
  for (const spec of ADMIN_BEARING) {
    const address = contracts[spec.key]?.address;
    if (!address) continue;
    const admin = readAdmin(address, spec);
    if (admin !== me) foreign.push(`${spec.label} (admin ${admin})`);
  }
  if (foreign.length === 0) return true;
  console.warn(
    `[${command}] the source account ${me} is not the admin of: ${foreign.join(", ")}. Admin-only calls will be described, not sent.`,
  );
  return false;
}
