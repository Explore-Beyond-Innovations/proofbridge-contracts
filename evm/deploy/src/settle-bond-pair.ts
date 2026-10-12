import type { ethers } from "ethers";
import { deployedCode, methodIdentifiers } from "./artifacts.js";

/**
 * The AdManager and the DisputeManager share one call the ABI cannot check at deploy time:
 * `settleBond`, which the escrow makes when a dispute ends. Its shape changed when the bond-return
 * flag was added, and a call under the old selector lands in the module's fallback, so every
 * dispute close would revert. The two must come from one build. A fresh pair always does; a reused
 * escrow next to a fresh module (or the reverse) is the mix a manifest can carry, and this is the
 * check that refuses it before anything is sent.
 *
 * The smallest fact both codes carry is the selector itself: solc emits every selector a contract
 * dispatches, and every one it calls, as a `PUSH4` constant. So the module's code must dispatch
 * this build's `settleBond` and the escrow's code must call it.
 */

/** `settleBond`'s selector as solc recorded it for this build's DisputeManager (4 bytes, no 0x). */
export function settleBondSelector(): { signature: string; selector: string } {
  const ids = methodIdentifiers("DisputeManager", "DisputeManager");
  const found = Object.entries(ids).filter(([sig]) => sig.startsWith("settleBond("));
  if (found.length !== 1) {
    throw new Error(`DisputeManager artifact records ${found.length} settleBond selectors, expected exactly one`);
  }
  const [signature, selector] = found[0]!;
  return { signature, selector: selector.toLowerCase() };
}

/** Does this runtime code carry `PUSH4 <selector>`? (`0x63` is PUSH4.) */
export function carriesSelector(runtimeCode: string, selector: string): boolean {
  const code = runtimeCode.replace(/^0x/, "").toLowerCase();
  const sel = selector.replace(/^0x/, "").toLowerCase();
  if (sel.length !== 8) throw new Error(`not a 4-byte selector: ${selector}`);
  return code.includes("63" + sel);
}

/**
 * Refuse an AdManager / DisputeManager pair that does not agree with this build on `settleBond`.
 * Pure: the caller passes the on-chain runtime codes; nothing is sent.
 */
export function assertSettleBondPair(o: {
  adManager: { address: string; code: string };
  disputeManager: { address: string; code: string };
  where: string;
}): void {
  const { signature, selector } = settleBondSelector();
  const shape = `${signature} (0x${selector})`;
  const wrong: string[] = [];
  if (!carriesSelector(o.disputeManager.code, selector)) {
    wrong.push(`DisputeManager at ${o.disputeManager.address} does not dispatch this build's ${shape}`);
  }
  if (!carriesSelector(o.adManager.code, selector)) {
    wrong.push(`AdManager at ${o.adManager.address} does not call this build's ${shape}`);
  }
  if (wrong.length === 0) return;
  throw new Error(
    `${o.where}: settleBond pair — ${wrong.join("; ")}. The escrow and the dispute module must come from one build, ` +
      `or every dispute close reverts in the module's fallback. Redeploy the one that differs with this bundle ` +
      `(remove its manifest entry), or run the bundle both were deployed from. Nothing was sent.`,
  );
}

/**
 * The same check against the chain. A side with an address is read from the chain (a reused
 * contract); a side without one is the contract this run is about to deploy, so it is this build's
 * own runtime code. Read before anything is sent.
 */
export async function assertSettleBondPairOnChain(
  provider: ethers.Provider,
  reused: { adManager?: string; disputeManager?: string },
  where: string,
): Promise<void> {
  const side = async (artifact: "AdManager" | "DisputeManager", address: string | undefined) =>
    address
      ? { address, code: await provider.getCode(address) }
      : { address: `(deployed by this run)`, code: deployedCode(artifact, artifact) };
  assertSettleBondPair({
    adManager: await side("AdManager", reused.adManager),
    disputeManager: await side("DisputeManager", reused.disputeManager),
    where,
  });
}
