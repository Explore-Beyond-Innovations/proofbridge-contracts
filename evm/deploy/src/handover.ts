import { readManifest, type ChainDeploymentManifest } from "@proofbridge/deployment-manifest";
import { connect, requireEnv } from "./common.js";
import { attachContract } from "./artifacts.js";
import { manifestPath, writeManifest } from "./manifest.js";

/**
 * The admin handover (#424).
 *
 * Every contract is deployed with the deployer as its admin, because the wiring `deploy` and `link`
 * do afterwards is admin-only and the deployer is the key that runs them. The real admin — a
 * multisig, in production — is nominated last, here, over the two-step transfer every
 * admin-bearing contract carries (`transferAdmin` / `acceptAdmin`). Its only job is to accept.
 *
 * `handover --to <address>` nominates on every admin-bearing contract the manifest names and records
 * the nomination. `handover --verify` reads `admin()` on each and records acceptance once every one
 * of them answers with the nominee. Both are idempotent: nothing already done is sent again.
 */

/** Manifest key → artifact, for every contract with an admin. Order is the order of nomination. */
const ADMIN_BEARING = [
  ["merkleManager", "MerkleManager"],
  ["adManager", "AdManager"],
  ["orderPortal", "OrderPortal"],
  ["blsKeyRegistry", "BLSKeyRegistry"],
  ["rootAnchor", "RootAnchor"],
  ["disputeManager", "DisputeManager"],
] as const;

type AdminBearingKey = (typeof ADMIN_BEARING)[number][0];

export interface HandoverOptions {
  rpcUrl?: string;
  privateKey?: string;
  /** Path to this chain's manifest. Defaults to deployments/<chainId>.json. */
  manifest?: string;
  /** The address to nominate. Required unless `verify`. */
  to?: string;
  /** Read `admin()` everywhere and record acceptance; nominate nothing. */
  verify?: boolean;
}

export interface HandoverResult {
  /** Contracts nominated by this run (not those already pending). */
  nominated: string[];
  /** Contracts whose `admin()` is the manifest's `pending` (verify) or already the target. */
  accepted: string[];
  /** Contracts still answering with the deployer, or with someone else. */
  outstanding: string[];
}

interface Seen {
  key: AdminBearingKey;
  artifact: string;
  address: string;
  admin: string;
  pendingAdmin: string;
}

const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

export async function handover(opts: HandoverOptions): Promise<HandoverResult> {
  const rpcUrl = opts.rpcUrl ?? requireEnv("EVM_RPC_URL");
  const privateKey = opts.privateKey ?? requireEnv("EVM_ADMIN_PRIVATE_KEY");
  const { signer, nonces, chainId, address: me } = await connect(rpcUrl, privateKey);

  const path = opts.manifest ?? manifestPath(chainId);
  const manifest = await readManifest(path);
  if (manifest.chain.kind !== "EVM" || BigInt(manifest.chain.chainId) !== chainId) {
    throw new Error(`handover: ${path} is for ${manifest.chain.kind} chain ${manifest.chain.chainId}, connected to ${chainId}`);
  }

  // Read before anything is sent: the chain is the fact, the manifest is the record.
  const seen: Seen[] = [];
  for (const [key, artifact] of ADMIN_BEARING) {
    const entry = manifest.contracts[key];
    if (!entry?.address) continue;
    const c = attachContract(entry.address, artifact, artifact, signer);
    seen.push({
      key,
      artifact,
      address: entry.address,
      admin: String(await c.getFunction("admin")()),
      pendingAdmin: String(await c.getFunction("pendingAdmin")()),
    });
  }
  if (seen.length === 0) throw new Error(`handover: ${path} names no admin-bearing contract`);

  if (opts.verify) return verify(manifest, path, seen, me);

  const to = opts.to;
  if (!to) throw new Error("handover: --to <address> is required (or --verify)");
  if (same(to, me)) throw new Error(`handover: --to ${to} is the deployer; nothing to hand over`);

  const result: HandoverResult = { nominated: [], accepted: [], outstanding: [] };
  for (const s of seen) {
    if (same(s.admin, to)) {
      console.log(`  [done] ${s.artifact}: admin is already ${to}`);
      result.accepted.push(s.artifact);
      continue;
    }
    if (same(s.pendingAdmin, to)) {
      console.log(`  [pending] ${s.artifact}: ${to} is nominated and has not accepted`);
      result.outstanding.push(s.artifact);
      continue;
    }
    if (!same(s.admin, me)) {
      // Not ours to hand over, and not already handed to the target: somebody else holds it.
      throw new Error(
        `handover: ${s.artifact} at ${s.address} has admin ${s.admin}, which is neither the deployer (${me}) nor ${to}; nothing was sent`,
      );
    }
  }

  // Everything is either done, pending, or ours to nominate. Now send.
  for (const s of seen) {
    if (same(s.admin, to) || same(s.pendingAdmin, to)) continue;
    const c = attachContract(s.address, s.artifact, s.artifact, signer);
    const tx = await c.getFunction("transferAdmin")(to, { nonce: nonces.next() });
    await tx.wait();
    console.log(`  [nominate] ${s.artifact}.transferAdmin(${to})`);
    result.nominated.push(s.artifact);
    result.outstanding.push(s.artifact);
  }

  manifest.admin = {
    current: me,
    pending: to,
    nominatedAt: new Date().toISOString(),
  };
  await writeManifest(path, manifest);
  console.log(
    `[evm-handover] ${result.nominated.length} nominated, ${result.outstanding.length} awaiting acceptAdmin() from ${to}. ` +
      `Run \`handover --verify\` once it has accepted.`,
  );
  return result;
}

async function verify(manifest: ChainDeploymentManifest, path: string, seen: Seen[], me: string): Promise<HandoverResult> {
  const target = manifest.admin?.pending;
  const result: HandoverResult = { nominated: [], accepted: [], outstanding: [] };
  for (const s of seen) {
    const label = `${s.artifact} at ${s.address}`;
    if (target && same(s.admin, target)) {
      console.log(`  [accepted] ${label}: admin is ${s.admin}`);
      result.accepted.push(s.artifact);
    } else if (same(s.admin, me)) {
      console.log(`  [outstanding] ${label}: admin is still the deployer${target ? `, ${target} has not accepted` : ""}`);
      result.outstanding.push(s.artifact);
    } else {
      console.log(`  [other] ${label}: admin is ${s.admin}`);
      result.outstanding.push(s.artifact);
    }
  }

  if (target && result.outstanding.length === 0) {
    manifest.admin = { current: target, acceptedAt: new Date().toISOString() };
    await writeManifest(path, manifest);
    console.log(`[evm-handover] every contract answers with ${target}; recorded as current`);
  } else if (target) {
    console.log(`[evm-handover] ${result.accepted.length} accepted, ${result.outstanding.length} outstanding; manifest unchanged`);
  } else {
    // No nomination on record: report what the chain says and leave the manifest alone.
    const admins = new Set(seen.map((s) => s.admin.toLowerCase()));
    console.log(
      admins.size === 1
        ? `[evm-handover] no nomination recorded; every contract answers with ${seen[0]!.admin}`
        : `[evm-handover] no nomination recorded, and the contracts disagree about their admin`,
    );
  }
  return result;
}
