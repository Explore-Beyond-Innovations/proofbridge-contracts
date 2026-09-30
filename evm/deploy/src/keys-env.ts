import { ethers } from "ethers";
import { getAbi } from "./artifacts.js";

// Review D3: the key registry binds its owner messages to the environment it was deployed for.

/** The environment a registry holds, or null when it predates the binding (no `keysEnv()`). */
export async function registryEnvOf(address: string, runner: ethers.ContractRunner): Promise<string | null> {
  try {
    return String(await new ethers.Contract(address, getAbi("BLSKeyRegistry", "BLSKeyRegistry"), runner).getFunction("keysEnv")());
  } catch {
    return null;
  }
}

/** A reused registry must hold this deploy's environment: its signatures would fail everywhere else. */
export function assertRegistryEnv(address: string, have: string | null, want: string): void {
  if (have === want) return;
  const what = have === null ? "predates the environment binding (no keysEnv())" : `was deployed for env=${have}`;
  throw new Error(
    `BLSKeyRegistry ${address} ${what}, but DEPLOY_ENV=${want}: every owner signature names the environment. ` +
      `Remove its manifest entry to deploy a registry for ${want}. Nothing was sent.`,
  );
}
