import { ethers } from "ethers";
import { readManifest, type ChainDeploymentManifest } from "@proofbridge/deployment-manifest";
import { ADMIN_BEARING, adminsOf, connect, requireEnv, type HeldAdmin } from "./common.js";
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

const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

export async function handover(opts: HandoverOptions): Promise<HandoverResult> {
  const rpcUrl = opts.rpcUrl ?? requireEnv("EVM_RPC_URL");
  const privateKey = opts.privateKey ?? requireEnv("EVM_ADMIN_PRIVATE_KEY");
  const { signer, nonces, chainId, address: me, provider } = await connect(rpcUrl, privateKey);

  const path = opts.manifest ?? manifestPath(chainId);
  const manifest = await readManifest(path);
  if (manifest.chain.kind !== "EVM" || BigInt(manifest.chain.chainId) !== chainId) {
    throw new Error(`handover: ${path} is for ${manifest.chain.kind} chain ${manifest.chain.chainId}, connected to ${chainId}`);
  }

  // Read before anything is sent: the chain is the fact, the manifest is the record. The same
  // reader deploy and link use, so there is one list of what has an admin.
  const seen = await adminsOf(
    ADMIN_BEARING.flatMap(([key, artifact]) => {
      const address = manifest.contracts[key]?.address;
      return address ? [{ label: artifact, artifact, address }] : [];
    }),
    (a, f, n) => attachContract(a, f, n, signer),
  );
  if (seen.length === 0) throw new Error(`handover: ${path} names no admin-bearing contract`);

  if (opts.verify) return verify(manifest, path, seen, me);

  const to = opts.to;
  if (!to) throw new Error("handover: --to <address> is required (or --verify)");
  // The zero address is `transferAdmin`'s cancel path; a mistyped one is a contract nobody can
  // reach. Both are refused before anything is nominated. A target with no code is allowed but
  // named: a multisig has code, a typo does not.
  if (!ethers.isAddress(to) || to === ethers.ZeroAddress) {
    throw new Error(`handover: --to ${to} is not a usable address; nothing was sent`);
  }
  if (same(to, me)) throw new Error(`handover: --to ${to} is the deployer; nothing to hand over`);
  if ((await provider.getCode(to)) === "0x") {
    console.warn(`  [note] ${to} has no code on chain ${chainId}: an externally owned account, not a multisig`);
  }

  const result: HandoverResult = { nominated: [], accepted: [], outstanding: [] };
  for (const s of seen) {
    if (same(s.admin, to)) {
      console.log(`  [done] ${s.label}: admin is already ${to}`);
      result.accepted.push(s.label);
      continue;
    }
    if (same(s.pendingAdmin, to)) {
      console.log(`  [pending] ${s.label}: ${to} is nominated and has not accepted`);
      result.outstanding.push(s.label);
      continue;
    }
    if (!same(s.admin, me)) {
      // Not ours to hand over, and not already handed to the target: somebody else holds it.
      throw new Error(
        `handover: ${s.label} at ${s.address} has admin ${s.admin}, which is neither the deployer (${me}) nor ${to}; nothing was sent`,
      );
    }
  }

  // Everything is either done, pending, or ours to nominate. Now send.
  for (const s of seen) {
    if (same(s.admin, to) || same(s.pendingAdmin, to)) continue;
    const c = attachContract(s.address, s.label, s.label, signer);
    const tx = await c.getFunction("transferAdmin")(to, { nonce: nonces.next() });
    await tx.wait();
    console.log(`  [nominate] ${s.label}.transferAdmin(${to})`);
    result.nominated.push(s.label);
    result.outstanding.push(s.label);
  }

  // The manifest changes only when something was nominated. A rerun with nothing to do leaves a
  // true record alone: after every contract has accepted, `current` is the nominee, and rewriting
  // it as the deployer would be the manifest claiming what the chain denies.
  if (result.nominated.length > 0) {
    manifest.admin = { current: me, pending: to, nominatedAt: new Date().toISOString() };
    await writeManifest(path, manifest);
  }
  console.log(
    result.outstanding.length === 0
      ? `[evm-handover] every contract already answers with ${to}; nothing nominated, manifest unchanged (run \`handover --verify\` to record it)`
      : `[evm-handover] ${result.nominated.length} nominated, ${result.outstanding.length} awaiting acceptAdmin() from ${to}. ` +
          `Run \`handover --verify\` once it has accepted.`,
  );
  return result;
}

async function verify(manifest: ChainDeploymentManifest, path: string, seen: HeldAdmin[], me: string): Promise<HandoverResult> {
  const target = manifest.admin?.pending;
  const result: HandoverResult = { nominated: [], accepted: [], outstanding: [] };
  for (const s of seen) {
    const label = `${s.label} at ${s.address}`;
    if (target && same(s.admin, target)) {
      console.log(`  [accepted] ${label}: admin is ${s.admin}`);
      result.accepted.push(s.label);
    } else if (same(s.admin, me)) {
      console.log(`  [outstanding] ${label}: admin is still the deployer${target ? `, ${target} has not accepted` : ""}`);
      result.outstanding.push(s.label);
    } else {
      console.log(`  [other] ${label}: admin is ${s.admin}`);
      result.outstanding.push(s.label);
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
