import * as fs from "fs";
import { createHash } from "crypto";

// The EVM Verifier bakes the event-circuit VK in; the Soroban verifier is handed it at deploy. If a
// reused verifier checks against another VK than the bundle's, one chain refuses every proof, and
// nothing says why until a settlement fails. So each manifest records the VK's hash (and the circuits
// commit it came from), and a reuse compares it.

export function sha256Hex(bytes: Uint8Array): string {
  return "0x" + createHash("sha256").update(bytes).digest("hex");
}

export interface VkRecord {
  vkSha256?: string;
  circuitsCommit?: string;
}

/** The VK file's hash, and CIRCUITS_COMMIT when the bundle fetch exported it. */
export function vkRecord(vkFile: string | undefined, env: NodeJS.ProcessEnv = process.env): VkRecord {
  const rec: VkRecord = {};
  if (vkFile && fs.existsSync(vkFile)) rec.vkSha256 = sha256Hex(fs.readFileSync(vkFile));
  const c = env.CIRCUITS_COMMIT;
  if (c && /^[0-9a-f]{7,40}$/.test(c)) rec.circuitsCommit = c;
  return rec;
}

/**
 * A reused verifier must check proofs against the VK this deploy carries. `onChain` is the fact where
 * the chain can answer (Soroban `get_vk`); otherwise `recorded` is the manifest's claim.
 */
export function assertReusedVk(
  label: string,
  current: string | undefined,
  recorded: string | undefined,
  onChain?: string,
): "match" | "unknown" {
  const have = onChain ?? recorded;
  if (!current || !have) return "unknown";
  if (have.toLowerCase() !== current.toLowerCase()) {
    throw new Error(
      `${label}: the reused verifier checks proofs against VK ${have}, but this bundle's VK is ${current}. ` +
        `One chain would refuse every proof. Deploy the verifier again (drop it from the manifest) or use the bundle it was built from.`,
    );
  }
  return "match";
}
