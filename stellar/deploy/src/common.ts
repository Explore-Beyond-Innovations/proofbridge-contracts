import * as path from "path";
import { fileURLToPath } from "url";

/** Default internal chain-id used for Stellar Testnet throughout ProofBridge. */
export const DEFAULT_STELLAR_CHAIN_ID = 1000001n;

/** Resolve `contracts/stellar/` from anywhere inside `contracts/stellar/deploy/`. */
export function stellarRoot(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(here, "..", "..");
}

export function wasmDir(): string {
  return (
    process.env.STELLAR_WASM_DIR ??
    path.join(stellarRoot(), "target", "wasm32v1-none", "release")
  );
}

export function vkPath(): string {
  return (
    process.env.STELLAR_DEPOSIT_VK ??
    path.join(stellarRoot(), "..", "..", "proof_circuits", "deposits", "target", "vk")
  );
}

export function deploymentsDir(): string {
  return (
    process.env.STELLAR_DEPLOYMENTS_DIR ??
    path.join(stellarRoot(), "deployments")
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
