import { ethers } from "ethers";
import { attachContract, deployedCode, linkedLibraryIn, methodIdentifier } from "./artifacts.js";

/**
 * `ProofBridgeUtils`: the one deployed library both escrows link (EIP-170 headroom). Ownerless, one
 * per chain. An escrow is only ever reused together with the library its own code names, so the
 * manifest entry is a record of what the chain says, never an input.
 */
export const UTILS_LIBRARY = "ProofBridgeUtils";

/**
 * `.vectors[0]` ("canonical-equal") of `contracts/test-vectors/order-hash-v2.json`, frozen here
 * because the bundle a deploy runs from carries no vectors. `test/utils-library.spec.ts` holds the
 * two equal; `OrderHashParity.t.sol` proves the hash in-process, this probe proves it through the link.
 * The field order is the struct's: it is ABI-encoded positionally.
 */
export const ORDER_VECTOR_0 = {
  order: {
    orderChainToken: "0xc3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3",
    adChainToken: "0xd4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4",
    amount: 1000000n,
    bridger: "0xe5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5",
    orderChainId: 11155111n,
    orderPortal: "0xb2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
    orderRecipient: "0xf6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6",
    adChainId: 1000002n,
    adManager: "0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
    adId: "test-ad-1",
    adCreator: "0x1717171717171717171717171717171717171717171717171717171717171717",
    adRecipient: "0x2828282828282828282828282828282828282828282828282828282828282828",
    salt: 12345n,
    orderDecimals: 7,
    adDecimals: 7,
    deadline: 1767225600n,
    adSettlementSigner: "0x1717171717171717171717171717171717171717171717171717171717171717",
  },
  orderHash: "0xa4051971fa4ca8e6761659de7f41ac804d32c302d0b009109cc085dc28529d2b",
};

/** `OrderHash.Order` as an ABI tuple, in struct order. */
const ORDER_TUPLE =
  "tuple(bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes32,uint256,bytes32,string,bytes32,bytes32,uint256,uint8,uint8,uint256,bytes32)";

/**
 * Whether the code at a library's address is this build's artifact. The library has no immutables
 * and the build sets `bytecode_hash = "none"`, so the two are byte-equal — except that solc may
 * stamp the library's own address into its runtime code (call protection: `PUSH20 <self>` at the
 * start, zeros in the artifact). Both forms are accepted; nothing else is.
 */
export function libraryCodeMatches(artifactRuntime: string, onChain: string, address: string): boolean {
  const want = artifactRuntime.replace(/^0x/, "").toLowerCase();
  const have = onChain.replace(/^0x/, "").toLowerCase();
  if (want.length === 0 || have.length === 0) return false;
  if (want === have) return true;
  const self = "73" + "0".repeat(40);
  if (want.startsWith(self)) {
    return have === "73" + address.replace(/^0x/, "").toLowerCase() + want.slice(self.length);
  }
  return false;
}

/**
 * The library answers as the library: the frozen vector hashes through the link, scaling scales, and
 * an out-of-range decimals value reverts with the typed error. Null when it does; otherwise what
 * mismatched, so the deploy log names it.
 */
export async function probeUtilsLibrary(address: string, signer: ethers.Wallet): Promise<string | null> {
  const lib = attachContract(address, "ProofBridgeUtils", "ProofBridgeUtils", signer);
  try {
    // `digest` by raw call: solc hashes a library's struct parameter by its declared name, so the
    // selector ethers derives from the ABI's tuple is one the library does not answer (see
    // `methodIdentifier`). The argument encoding itself is the ordinary tuple encoding.
    const data = ethers.concat([
      methodIdentifier("ProofBridgeUtils", "ProofBridgeUtils", "digest(OrderHash.Order)"),
      ethers.AbiCoder.defaultAbiCoder().encode([ORDER_TUPLE], [Object.values(ORDER_VECTOR_0.order)]),
    ]);
    const digest = await signer.provider!.call({ to: address, data });
    if (digest.toLowerCase() !== ORDER_VECTOR_0.orderHash) {
      return `digest(vector 0) = ${digest}, expected ${ORDER_VECTOR_0.orderHash}`;
    }
    const scaled = (await lib.getFunction("scale").staticCall(1_000_000n, 6, 18)) as bigint;
    if (scaled !== 10n ** 18n) return `scale(1e6, 6, 18) = ${scaled}, expected 1e18`;
  } catch (err) {
    // Only a revert is the library's answer; an RPC failure or a stripped artifact is not "does
    // not answer", it is the error it is, and the caller must not turn it into a redeploy.
    if (!isRevert(err)) throw err;
    return `does not answer as ${UTILS_LIBRARY}: ${(err as Error).message ?? err}`;
  }
  try {
    await lib.getFunction("assertInRange").staticCall(31);
    return "assertInRange(31) did not revert";
  } catch (err) {
    if (!isRevert(err)) throw err;
    const data = (err as { data?: string }).data ?? "";
    const want = ethers.id("DecimalScaling__DecimalsOutOfRange(uint8)").slice(0, 10);
    if (!String(data).toLowerCase().startsWith(want)) {
      return `assertInRange(31) reverted with ${data || "no data"}, expected DecimalScaling__DecimalsOutOfRange`;
    }
  }
  return null;
}

/** An ethers CALL_EXCEPTION: the call ran and reverted (or returned nothing decodable). */
function isRevert(err: unknown): boolean {
  return (err as { code?: string } | null)?.code === "CALL_EXCEPTION";
}

/** Code-equal to this build, or at least answering as the library (an earlier build's copy). */
export type LibraryVerdict = { ok: true; sameBuild: boolean } | { ok: false; why: string };

export async function verifyUtilsLibrary(address: string, signer: ethers.Wallet): Promise<LibraryVerdict> {
  const onChain = await signer.provider!.getCode(address);
  if (onChain === "0x") return { ok: false, why: "no code" };
  if (libraryCodeMatches(deployedCode("ProofBridgeUtils", "ProofBridgeUtils"), onChain, address)) {
    return { ok: true, sameBuild: true };
  }
  const why = await probeUtilsLibrary(address, signer);
  return why ? { ok: false, why: `code differs from this build's ${UTILS_LIBRARY} and ${why}` } : { ok: true, sameBuild: false };
}

/**
 * The library a reused escrow is linked to, read out of its code: at this build's link offset, or,
 * for an escrow from a build that laid its code out differently, the manifest's entry if the
 * escrow's code carries it. Only an address that verifies counts. Null when nothing does.
 * `verdicts` memoizes per address across the escrows, so one library is verified (and logged) once.
 */
export async function utilsLibraryLinkedBy(
  escrowArtifact: string,
  escrowAddress: string,
  signer: ethers.Wallet,
  manifestEntry: string | undefined,
  log: (line: string) => void,
  verdicts: Map<string, LibraryVerdict> = new Map(),
): Promise<string | null> {
  const code = (await signer.provider!.getCode(escrowAddress)).toLowerCase();
  const candidates = [
    linkedLibraryIn(escrowArtifact, escrowArtifact, UTILS_LIBRARY, code),
    manifestEntry && code.includes(manifestEntry.slice(2).toLowerCase()) ? manifestEntry : null,
  ].filter((c, i, all): c is string => !!c && all.findIndex((o) => o?.toLowerCase() === c.toLowerCase()) === i);
  for (const c of candidates) {
    const key = c.toLowerCase();
    const seen = verdicts.has(key);
    const v = verdicts.get(key) ?? (await verifyUtilsLibrary(c, signer));
    verdicts.set(key, v);
    if (seen) {
      if (v.ok) return c;
      continue;
    }
    if (v.ok) {
      if (!v.sameBuild) log(`  [note] ${escrowArtifact} ${escrowAddress} links ${UTILS_LIBRARY} ${c}, which answers as the library but is not this build's code (an earlier build); kept.`);
      return c;
    }
    log(`  [ignore] ${escrowArtifact} ${escrowAddress} names ${c} as ${UTILS_LIBRARY}, which ${v.why}`);
  }
  return null;
}
