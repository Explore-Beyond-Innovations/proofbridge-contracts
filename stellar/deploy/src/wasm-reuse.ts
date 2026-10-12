import * as fs from "fs";
import type { DeployEnv } from "./deploy-env.js";
import { sha256Hex } from "./vk.js";

/** Set to exactly `1` on a local stack to reuse a registry or verifier whose recorded wasm hash is missing or differs. */
export const WASM_MISMATCH_OVERRIDE = "STELLAR_ALLOW_WASM_MISMATCH";
/** The `deploy` flag that does the same in every environment, for the one run it is passed to. */
export const WASM_MISMATCH_FLAG = "--allow-wasm-mismatch";

/** The hash `stellar contract install` reports for a wasm file: hex sha256, no 0x. */
export function wasmSha256(file: string, label = "stellar-deploy"): string {
  if (!fs.existsSync(file)) {
    throw new Error(`${label}: wasm file ${file} is missing, so the reused contract cannot be compared with this bundle`);
  }
  return sha256Hex(fs.readFileSync(file)).slice(2);
}

/**
 * Whether this run reuses past a wasm mismatch. The option (the CLI's `--allow-wasm-mismatch`)
 * counts everywhere; the environment variable only on a local stack, and only as exactly `1`. The
 * deploy orchestrator sources env files with `set -a`, so a variable left in one would otherwise
 * apply to every later run on a real network. `ignoredEnv` says the variable was set and not read.
 */
export function wasmMismatchOverride(
  deployEnv: DeployEnv,
  option: boolean | undefined,
  env: NodeJS.ProcessEnv = process.env,
): { allow: boolean; ignoredEnv: boolean } {
  if (option !== undefined) return { allow: option, ignoredEnv: false };
  const v = env[WASM_MISMATCH_OVERRIDE];
  if (!v) return { allow: false, ignoredEnv: false };
  if (deployEnv !== "local") return { allow: false, ignoredEnv: true };
  return { allow: v === "1", ignoredEnv: false };
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
  const how = `Deploy it again (drop it from the manifest), or pass ${WASM_MISMATCH_FLAG} to this one run once you have checked the on-chain code is this bundle's (on a local stack ${WASM_MISMATCH_OVERRIDE}=1 also counts).`;
  if (!recorded) {
    throw new Error(
      `${label}: the manifest records no wasm hash for the reused contract, so this bundle's wasm (${current}) cannot be compared with the code on chain ` +
        `(manifests from before the hash was recorded). ${how}`,
    );
  }
  if (recorded.toLowerCase() !== current.toLowerCase()) {
    throw new Error(
      `${label}: the reused contract was deployed from wasm ${recorded}, but this bundle's wasm hashes to ${current}. ` +
        `Its stored data may not decode under the new code. ${how}`,
    );
  }
  return "match";
}
