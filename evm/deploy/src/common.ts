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
