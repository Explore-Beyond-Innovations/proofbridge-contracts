import * as fs from "fs";
import { sha256Hex } from "./vk.js";

/** Set to `1` to reuse a registry or verifier whose recorded wasm hash is missing or differs. */
export const WASM_MISMATCH_OVERRIDE = "STELLAR_ALLOW_WASM_MISMATCH";

/** The hash `stellar contract install` reports for a wasm file: hex sha256, no 0x. */
export function wasmSha256(file: string, label = "stellar-deploy"): string {
  if (!fs.existsSync(file)) {
    throw new Error(`${label}: wasm file ${file} is missing, so the reused contract cannot be compared with this bundle`);
  }
  return sha256Hex(fs.readFileSync(file)).slice(2);
}

/**
 * A reused contract whose stored data would not decode under the code this bundle carries (the
 * key registry's slot shape, the verifier that reads it) is refused unless the recorded wasm hash
 * is this bundle's. A manifest from before the hash was recorded cannot be compared and refuses
 * too. `override` (the operator has checked the on-chain code) reuses either way.
 */
export function assertReusableWasm(
  label: string,
  recorded: string | undefined,
  local: () => string,
  override: boolean,
): "match" | "overridden" {
  if (override) return "overridden";
  const current = local();
  if (!recorded) {
    throw new Error(
      `${label}: the manifest records no wasm hash for the reused contract, so this bundle's wasm (${current}) cannot be compared with the code on chain ` +
        `(manifests from before the hash was recorded). Deploy it again (drop it from the manifest), or set ${WASM_MISMATCH_OVERRIDE}=1 once you have checked the on-chain code is this bundle's.`,
    );
  }
  if (recorded.toLowerCase() !== current.toLowerCase()) {
    throw new Error(
      `${label}: the reused contract was deployed from wasm ${recorded}, but this bundle's wasm hashes to ${current}. ` +
        `Its stored data may not decode under the new code. Deploy it again (drop it from the manifest), or set ${WASM_MISMATCH_OVERRIDE}=1 to reuse it anyway.`,
    );
  }
  return "match";
}
