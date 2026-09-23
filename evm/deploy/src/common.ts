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
 * Every wiring call goes through `call`. When the signer holds admin on the contracts a command is
 * about to configure, the call is sent. When it does not — the admin has been handed over — the
 * call is recorded with its calldata and printed at the end for the admin to make, nothing is sent,
 * and the command exits 2 so no script mistakes "described" for "done". Which of the two happens is
 * decided up front, from `admin()` on chain, before the first transaction.
 */
export class Acting {
  readonly described: DescribedCall[] = [];

  constructor(
    readonly canSend: boolean,
    private readonly nonces: NonceTracker,
    private readonly tag: string,
  ) {}

  /** Send `fn(args)` on `contract`, or describe it. Returns whether it was sent. */
  async call(
    contract: ethers.Contract,
    label: string,
    fn: string,
    args: unknown[],
    line: string,
  ): Promise<boolean> {
    if (!this.canSend) {
      this.described.push({
        label,
        to: await contract.getAddress(),
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
    const admin = String(await attach(c.address, c.artifact, c.artifact).getFunction("admin")());
    held.push({ label: c.label, address: c.address, admin });
  }
  return held;
}

/** True when `me` holds admin on every one of `held`; logs the ones it does not. */
export function signerHoldsAdmin(me: string, held: HeldAdmin[], command: string): boolean {
  const foreign = held.filter((h) => h.admin.toLowerCase() !== me.toLowerCase());
  if (foreign.length === 0) return true;
  console.warn(
    `[${command}] the signer ${me} is not the admin of: ${foreign.map((h) => `${h.label} (admin ${h.admin})`).join(", ")}. ` +
      `Admin-only calls will be described, not sent.`,
  );
  return false;
}
