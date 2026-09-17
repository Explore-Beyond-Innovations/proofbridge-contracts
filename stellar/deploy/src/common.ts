import * as path from "path";
import { fileURLToPath } from "url";

/**
 * Fallback internal chain-id when `STELLAR_CHAIN_ID` is not set.
 *
 * This is ProofBridge's synthetic id, bound into the BLS registration domain and the order hash — a
 * deployment initialised with one id will reject every signature made under another, with no error
 * until verification.
 *
 * `1000001` is the legacy catch-all that today's testnet deployment still uses. Note the encodings
 * spec (`docs/engineering/t1/1.2-build/01-bls-encodings.md` §4) assigns `1000001` to **pubnet** and
 * `1000002` to testnet, with testnet switching at the redeploy — so this default is deliberately the
 * deployed value, not the spec value, and the two stop agreeing the moment that redeploy happens.
 * Set `STELLAR_CHAIN_ID` explicitly rather than relying on it.
 */
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
    process.env.STELLAR_EVENT_VK ??
    path.join(stellarRoot(), "..", "..", "proof_circuits", "events", "target", "vk")
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
