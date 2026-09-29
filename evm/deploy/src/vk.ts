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
  // A-3: a deploy without the VK file cannot compare a reused verifier, and recording nothing would
  // erase the manifest's hash on the next write. The bundle fetch guarantees the file outside local;
  // refuse without it there. A local stack (Anvil, the e2e harnesses) may run without built circuits.
  if (!vkFile || !fs.existsSync(vkFile)) {
    if (env.DEPLOY_ENV === "local") {
      console.warn(`[vk] no VK file at ${vkFile ?? "<unset>"} — local deploy, the manifest records no VK hash`);
    } else {
      throw new Error(`the event-circuit VK file is missing (${vkFile ?? "unset"}); point EVENT_VK at the bundle's proof_circuits/events/target/vk`);
    }
  } else {
    rec.vkSha256 = sha256Hex(fs.readFileSync(vkFile));
  }
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

/**
 * A-3: on EVM the chain CAN answer whether a reused Verifier is the bundle's — its runtime code
 * is the artifact's `deployedBytecode`. Compared byte for byte (the same source, compiler and
 * metadata give the same code); a match with no recorded VK hash is then safe to record.
 */
export function assertVerifierCode(label: string, onChainCode: string, artifactCode: string): void {
  const norm = (h: string) => h.toLowerCase().replace(/^0x/, "");
  if (norm(onChainCode) === "" ) throw new Error(`${label}: no code at the reused verifier address`);
  if (norm(onChainCode) !== norm(artifactCode)) {
    throw new Error(
      `${label}: the reused verifier's code is not this bundle's Verifier. It was deployed from another build (another VK or compiler); ` +
        `deploy the verifier again (drop it from the manifest) or use the bundle it was built from.`,
    );
  }
}

