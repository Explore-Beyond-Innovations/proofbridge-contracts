import { StrKey } from "@stellar/stellar-sdk";
import { readManifest, type ChainDeploymentManifest } from "@proofbridge/deployment-manifest";
import { DEFAULT_STELLAR_CHAIN_ID } from "./common.js";
import { getAddress, invokeContract, readView } from "./stellar-cli.js";
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

export type AdminBearingKey = (typeof ADMIN_BEARING)[number]["key"];

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

export interface HeldAdmin {
  key: AdminBearingKey;
  label: string;
  address: string;
  admin: string;
}

/** Who a contract answers with. `Option<Address>` views print `null` before initialize. */
export function readAdmin(contractId: string, spec: (typeof ADMIN_BEARING)[number]): string {
  const v = readView(contractId, spec.view);
  const admin = spec.field ? (v as Record<string, unknown> | null)?.[spec.field] : v;
  if (typeof admin !== "string" || !admin.startsWith("G") && !admin.startsWith("C")) {
    throw new Error(`handover: ${spec.label} at ${contractId} did not answer ${spec.view} with an address: ${JSON.stringify(v)}`);
  }
  return admin;
}

/**
 * Who holds admin on the manifest's admin-bearing contracts (all six, or `keys` of them), read
 * from the chain. The one reader `deploy`, `link` and `handover` share.
 */
export function adminsOf(
  contracts: ChainDeploymentManifest["contracts"],
  keys: readonly AdminBearingKey[] = ADMIN_BEARING.map((s) => s.key),
): HeldAdmin[] {
  const held: HeldAdmin[] = [];
  for (const spec of ADMIN_BEARING) {
    if (!keys.includes(spec.key)) continue;
    const address = contracts[spec.key]?.address;
    if (!address) continue;
    held.push({ key: spec.key, label: spec.label, address, admin: readAdmin(address, spec) });
  }
  return held;
}

/** The contract ids among `held` whose admin is not `me`; logs them. Empty = the signer holds all. */
export function foreignAdmins(me: string, held: HeldAdmin[], command: string): string[] {
  const foreign = held.filter((h) => h.admin !== me);
  if (foreign.length > 0) {
    console.warn(
      `[${command}] the source account ${me} is not the admin of: ${foreign.map((h) => `${h.label} (admin ${h.admin})`).join(", ")}. ` +
        `Calls to those will be described, not sent.`,
    );
  }
  return foreign.map((h) => h.address);
}

type AdminBlock = NonNullable<ChainDeploymentManifest["admin"]>;

/**
 * The manifest's `admin` block, from what the chain answered (#424 H3): every reused contract
 * agreeing on one address makes it `current`, and if that is the recorded nominee the handover is
 * recorded as accepted. Disagreement keeps the old block, with a warning. Nothing reused means
 * everything deployed in this run has the source account as admin.
 */
export function adminBlockFromChain(
  existing: AdminBlock | undefined,
  held: HeldAdmin[],
  me: string,
  command: string,
): AdminBlock {
  if (held.length === 0) return existing ?? { current: me };
  const admins = new Set(held.map((h) => h.admin));
  if (admins.size !== 1) {
    console.warn(`[${command}] the reused contracts disagree about their admin; the manifest's admin block is left as it was`);
    return existing ?? { current: me };
  }
  const current = held[0]!.admin;
  if (existing?.current === current) return existing;
  if (existing?.pending === current) return { current, acceptedAt: new Date().toISOString() };
  return { current };
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
  const seen = adminsOf(manifest.contracts);
  if (seen.length === 0) throw new Error(`handover: ${path} names no admin-bearing contract`);

  if (opts.verify) return verify(manifest, path, seen, me);

  const to = opts.to;
  if (!to) throw new Error("handover: --to <G...> is required (or --verify)");
  // An account (G…) or a contract (C…, a multisig): anything else is a typo nobody could accept
  // from, refused before a nomination is sent.
  if (!StrKey.isValidEd25519PublicKey(to) && !StrKey.isValidContract(to)) {
    throw new Error(`handover: --to ${to} is not a Stellar account or contract address; nothing was sent`);
  }
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

  // The manifest changes only when something was nominated: after every contract has accepted,
  // `current` is the nominee, and a rerun must not rewrite it as the source account (#424 H2).
  if (result.nominated.length > 0) {
    manifest.admin = { current: me, pending: to, nominatedAt: new Date().toISOString() };
    await writeManifest(path, manifest);
  }
  console.log(
    result.outstanding.length === 0
      ? `[stellar-handover] every contract already answers with ${to}; nothing nominated, manifest unchanged (run \`handover --verify\` to record it)`
      : `[stellar-handover] ${result.nominated.length} nominated, ${result.outstanding.length} awaiting accept_admin from ${to}. ` +
          `Run \`handover --verify\` once it has accepted.`,
  );
  return result;
}

async function verify(manifest: ChainDeploymentManifest, path: string, seen: HeldAdmin[], me: string): Promise<StellarHandoverResult> {
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
