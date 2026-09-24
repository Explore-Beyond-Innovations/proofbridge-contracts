import { ethers } from "ethers";
import * as path from "path";
import { fileURLToPath } from "url";

export const MANAGER_ROLE = ethers.keccak256(
  ethers.toUtf8Bytes("MANAGER_ROLE"),
);

/** NATIVE_TOKEN_ADDRESS from contracts/evm/src/{OrderPortal,AdManager}.sol — native token sentinel. */
export const EVM_NATIVE_TOKEN_ADDRESS =
  "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE" as const;

/** Resolve `contracts/evm/` from anywhere inside `contracts/evm/deploy/`. */
export function evmRoot(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(here, "..", "..");
}

/** Foundry output dir. Defaults to contracts/evm/out; override via EVM_OUT_DIR (bundle). */
export function artifactsDir(): string {
  return process.env.EVM_OUT_DIR ?? path.join(evmRoot(), "out");
}

export function deploymentsDir(): string {
  return (
    process.env.EVM_DEPLOYMENTS_DIR ?? path.join(evmRoot(), "deployments")
  );
}

export function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`env ${name} is required`);
  return v;
}

export function envOrDefault(name: string, fallback: string): string {
  const v = process.env[name];
  return v && v.length > 0 ? v : fallback;
}

/** Zero-pad a 20-byte EVM address to 32 bytes (`0x` + 64 hex). */
export function evmAddressToBytes32(addr: string): string {
  const clean = addr.replace(/^0x/i, "").toLowerCase();
  if (clean.length !== 40) {
    throw new Error(`expected 20-byte EVM address, got 0x${clean}`);
  }
  return "0x" + "0".repeat(24) + clean;
}

/** Local nonce counter seeded from `pending` — sidesteps ethers' `latest`-based race on shared-key wallets. */
export class NonceTracker {
  private counter = 0;
  private initialized = false;

  constructor(private readonly signer: ethers.Wallet) {}

  async init(): Promise<void> {
    this.counter = await this.signer.getNonce("pending");
    this.initialized = true;
  }

  next(): number {
    if (!this.initialized) throw new Error("NonceTracker used before init()");
    return this.counter++;
  }
}

export async function connect(
  rpcUrl: string,
  privateKey: string,
): Promise<{
  provider: ethers.JsonRpcProvider;
  signer: ethers.Wallet;
  nonces: NonceTracker;
  chainId: bigint;
  address: string;
}> {
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const signer = new ethers.Wallet(privateKey, provider);
  const nonces = new NonceTracker(signer);
  await nonces.init();
  const network = await provider.getNetwork();
  const address = await signer.getAddress();
  return { provider, signer, nonces, chainId: network.chainId, address };
}

/** One call the CLI would have made, for the admin to make instead (#424). */
export interface DescribedCall {
  label: string;
  to: string;
  fn: string;
  args: string[];
  /** ABI-encoded calldata, ready for a multisig transaction builder. */
  data: string;
}

const show = (v: unknown): string =>
  typeof v === "bigint" ? v.toString() : Array.isArray(v) ? `[${v.map(show).join(", ")}]` : String(v);

/**
 * The CLI acts while it is the admin and describes when it is not (#424).
 *
 * Every wiring call goes through `call`. The decision is **per contract**: a call to a contract
 * whose admin is the signer is sent; a call to one whose admin is someone else — it was handed
 * over — is recorded with its calldata and printed at the end for the admin to make, and the
 * command exits 2 so no script mistakes "described" for "done". A contract deployed in this run has
 * the deployer as admin and is always sendable, whatever happened to the others. Which contracts
 * are foreign is decided up front, from `admin()` on chain, before the first transaction.
 */
export class Acting {
  readonly described: DescribedCall[] = [];
  private readonly foreign: Set<string>;

  /** @param foreign addresses whose `admin()` is not the signer (lower-cased or not; compared case-insensitively). */
  constructor(
    foreign: Iterable<string>,
    private readonly nonces: NonceTracker,
    private readonly tag: string,
  ) {
    this.foreign = new Set([...foreign].map((a) => a.toLowerCase()));
  }

  /** Whether a call to `address` would be sent. */
  canSendTo(address: string): boolean {
    return !this.foreign.has(address.toLowerCase());
  }

  /** True when every contract this command touches is the signer's. */
  get allMine(): boolean {
    return this.foreign.size === 0;
  }

  /** Send `fn(args)` on `contract`, or describe it. Returns whether it was sent. */
  async call(
    contract: ethers.Contract,
    label: string,
    fn: string,
    args: unknown[],
    line: string,
  ): Promise<boolean> {
    const to = await contract.getAddress();
    if (!this.canSendTo(to)) {
      this.described.push({
        label,
        to,
        fn,
        args: args.map(show),
        data: contract.interface.encodeFunctionData(fn, args),
      });
      console.log(`  [describe] ${line}`);
      return false;
    }
    const tx = await contract.getFunction(fn)(...args, { nonce: this.nonces.next() });
    await tx.wait();
    console.log(`  [${this.tag}] ${line}`);
    return true;
  }

  /** Print what the admin has to do. Nothing to print means everything was sent (or already set). */
  report(): void {
    if (this.described.length === 0) return;
    console.log(
      `\n[${this.tag}] the signer is not the admin, so nothing was sent. The admin has to make these ${this.described.length} call(s):`,
    );
    for (const d of this.described) {
      console.log(`  ${d.label}.${d.fn}(${d.args.join(", ")})\n    to:   ${d.to}\n    data: ${d.data}`);
    }
  }
}

/** Manifest key → artifact, for every contract that has an admin. */
export const ADMIN_BEARING = [
  ["merkleManager", "MerkleManager"],
  ["adManager", "AdManager"],
  ["orderPortal", "OrderPortal"],
  ["blsKeyRegistry", "BLSKeyRegistry"],
  ["rootAnchor", "RootAnchor"],
  ["disputeManager", "DisputeManager"],
] as const;

export interface HeldAdmin {
  label: string;
  address: string;
  admin: string;
  /** `pendingAdmin()`: a nomination not yet accepted, or the zero address. */
  pendingAdmin: string;
}

/**
 * Who holds admin on each of `contracts`, read from chain. `attach` is `attachContract` from
 * artifacts.ts, passed in so this file stays free of the artifact loader.
 */
export async function adminsOf(
  contracts: { label: string; artifact: string; address: string }[],
  attach: (address: string, file: string, name: string) => ethers.Contract,
): Promise<HeldAdmin[]> {
  const held: HeldAdmin[] = [];
  for (const c of contracts) {
    const contract = attach(c.address, c.artifact, c.artifact);
    held.push({
      label: c.label,
      address: c.address,
      admin: String(await contract.getFunction("admin")()),
      pendingAdmin: String(await contract.getFunction("pendingAdmin")()),
    });
  }
  return held;
}

/** The addresses among `held` whose admin is not `me`; logs them. Empty means the signer holds all. */
export function foreignAdmins(me: string, held: HeldAdmin[], command: string): string[] {
  const foreign = held.filter((h) => h.admin.toLowerCase() !== me.toLowerCase());
  if (foreign.length > 0) {
    console.warn(
      `[${command}] the signer ${me} is not the admin of: ${foreign.map((h) => `${h.label} (admin ${h.admin})`).join(", ")}. ` +
        `Calls to those will be described, not sent.`,
    );
  }
  return foreign.map((h) => h.address);
}

/**
 * The manifest's `admin` block, from what the chain answered (H3 of the #424 review: the manifest
 * is a claim, the chain is the fact). Every reused contract agreeing on one address makes that
 * address `current`; if it is the recorded nominee, the handover is recorded as accepted. Contracts
 * that disagree keep the old block, with a warning. Nothing reused means everything deployed in
 * this run has `deployer` as admin.
 */
export function adminBlockFromChain(
  existing: { current: string; pending?: string; nominatedAt?: string; acceptedAt?: string } | undefined,
  held: HeldAdmin[],
  deployer: string,
  command: string,
): { current: string; pending?: string; nominatedAt?: string; acceptedAt?: string } {
  if (held.length === 0) return existing ?? { current: deployer };
  const admins = new Set(held.map((h) => h.admin.toLowerCase()));
  if (admins.size !== 1) {
    console.warn(`[${command}] the reused contracts disagree about their admin; the manifest's admin block is left as it was`);
    return existing ?? { current: deployer };
  }
  const current = held[0]!.admin;
  if (existing && existing.current.toLowerCase() === current.toLowerCase()) return existing;
  if (existing?.pending && existing.pending.toLowerCase() === current.toLowerCase()) {
    return { current, acceptedAt: new Date().toISOString() };
  }
  return { current };
}
