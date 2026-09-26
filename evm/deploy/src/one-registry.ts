/**
 * #464/#465: the escrow's key registry (the lock gate and the denied rule) and every co-signature
 * verifier's registry (the co-signed unlock) must be one contract; otherwise a kill in the
 * verifier's registry never reaches the denied rule. The escrow refuses to lock on a split and
 * denies the payout of an order whose verifier left its registry; the CLI never leaves one.
 */
export function assertOneRegistry(escrowRegistry: string, verifierRegistry: string, where: string): void {
  if (escrowRegistry.toLowerCase() !== verifierRegistry.toLowerCase()) {
    throw new Error(
      `${where}: registry split — the escrow's key registry is ${escrowRegistry} but the CounterpartyVerifier ` +
        `checks co-signatures against ${verifierRegistry}; redeploy the verifier on the escrow's registry`,
    );
  }
}

const isZero = (a: string) => /^0x0*$/i.test(a);
const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

/** One escrow's per-peer root-verifier wiring, as the CLI reads and writes it. */
export interface EscrowWiring {
  name: string;
  rootVerifier(peer: string): Promise<string>;
  /** Resolves true when sent, false when only described (the admin is someone else). */
  setRootVerifier(peer: string, verifier: string): Promise<boolean>;
}

/** #465 (46-4): a verifier the CLI relies on must answer `registry()`; one that does not is named. */
export async function verifierRegistry(
  registryOf: (verifier: string) => Promise<string>,
  verifier: string,
  where: string,
): Promise<string> {
  try {
    return await registryOf(verifier);
  } catch (err) {
    throw new Error(
      `${where}: the verifier ${verifier} does not answer registry() — initialize it before wiring it, ` +
        `or it is not a CounterpartyVerifier: ${err}`,
    );
  }
}

/** #465 (46-2): every peer's wired verifier must read `escrowRegistry`. */
export async function checkPeers(o: {
  escrows: EscrowWiring[];
  peers: string[];
  escrowRegistry: string;
  registryOf: (verifier: string) => Promise<string>;
  where: string;
}): Promise<void> {
  for (const e of o.escrows) {
    for (const peer of o.peers) {
      const v = await e.rootVerifier(peer);
      if (isZero(v)) continue;
      const reg = await verifierRegistry(o.registryOf, v, o.where);
      assertOneRegistry(o.escrowRegistry, reg, `${o.where}: ${e.name} peer ${peer}`);
    }
  }
}

/**
 * #465: point the AdManager at a new registry without ever leaving a split behind, in G1's order:
 * every wired peer is re-pointed at the verifier on the new registry first, then the registry is
 * swapped, then every peer is read back. Open orders keep the registry they locked under.
 */
export async function switchKeyRegistry(o: {
  escrows: EscrowWiring[];
  peers: string[];
  newRegistry: string;
  newVerifier: string;
  registryOf: (verifier: string) => Promise<string>;
  setKeyRegistry(): Promise<boolean>;
}): Promise<void> {
  assertOneRegistry(o.newRegistry, await verifierRegistry(o.registryOf, o.newVerifier, "deploy"), "deploy");
  let allSent = true;
  for (const e of o.escrows) {
    for (const peer of o.peers) {
      const cur = await e.rootVerifier(peer);
      if (isZero(cur) || same(cur, o.newVerifier)) continue;
      allSent = (await e.setRootVerifier(peer, o.newVerifier)) && allSent;
    }
  }
  allSent = (await o.setKeyRegistry()) && allSent;
  if (!allSent) {
    console.log("  [one-registry] some wiring was described, not sent: re-run once the admin has sent it");
    return;
  }
  await checkPeers({ escrows: o.escrows, peers: o.peers, escrowRegistry: o.newRegistry, registryOf: o.registryOf, where: "deploy" });
}
