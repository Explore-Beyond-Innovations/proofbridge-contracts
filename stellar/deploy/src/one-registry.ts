/**
 * #464/#465: the escrow's key registry (the lock gate and the denied rule) and every co-signature
 * verifier's registry (the co-signed unlock) must be one contract; otherwise a kill in the
 * verifier's registry never reaches the denied rule. The escrow refuses to lock on a split and
 * denies the payout of an order whose verifier left its registry; the CLI never leaves one.
 */
export function assertOneRegistry(escrowRegistry: string, verifierRegistry: string, where: string): void {
  if (escrowRegistry !== verifierRegistry) {
    throw new Error(
      `${where}: registry split — the escrow's key registry is ${escrowRegistry} but the CounterpartyVerifier ` +
        `checks co-signatures against ${verifierRegistry}; redeploy the verifier on the escrow's registry`,
    );
  }
}

/** One escrow's per-peer root-verifier wiring, as the CLI reads and writes it. */
export interface EscrowWiring {
  name: string;
  /** The verifier wired for `peer`, or null. */
  rootVerifier(peer: string): string | null;
  /** True when sent, false when only described (the admin is someone else). */
  setRootVerifier(peer: string, verifier: string): boolean;
}

/** #465 (46-4): a verifier the CLI relies on must answer `registry()`; a Soroban verifier wired
 *  before `initialize` panics there. One that does not answer is named. */
export function verifierRegistry(registryOf: (verifier: string) => string, verifier: string, where: string): string {
  let reg: unknown;
  try {
    reg = registryOf(verifier);
  } catch (err) {
    throw new Error(
      `${where}: the verifier ${verifier} does not answer registry() — initialize it before wiring it, ` +
        `or it is not a CounterpartyVerifier: ${err}`,
    );
  }
  if (typeof reg !== "string" || reg === "") {
    throw new Error(`${where}: the verifier ${verifier} answered registry() with ${JSON.stringify(reg)}`);
  }
  return reg;
}

/** #465 (46-2): every peer's wired verifier must read `escrowRegistry`. */
export function checkPeers(o: {
  escrows: EscrowWiring[];
  peers: string[];
  escrowRegistry: string;
  registryOf: (verifier: string) => string;
  where: string;
}): void {
  for (const e of o.escrows) {
    for (const peer of o.peers) {
      const v = e.rootVerifier(peer);
      if (!v) continue;
      const reg = verifierRegistry(o.registryOf, v, o.where);
      assertOneRegistry(o.escrowRegistry, reg, `${o.where}: ${e.name} peer ${peer}`);
    }
  }
}

/**
 * #465: point the AdManager at a new registry without ever leaving a split behind, in G1's order:
 * every wired peer is re-pointed at the verifier on the new registry first, then the registry is
 * swapped, then every peer is read back. Open orders keep the registry they locked under.
 */
export function switchKeyRegistry(o: {
  escrows: EscrowWiring[];
  peers: string[];
  newRegistry: string;
  newVerifier: string;
  registryOf: (verifier: string) => string;
  setKeyRegistry(): boolean;
}): void {
  assertOneRegistry(o.newRegistry, verifierRegistry(o.registryOf, o.newVerifier, "deploy"), "deploy");
  let allSent = true;
  for (const e of o.escrows) {
    for (const peer of o.peers) {
      const cur = e.rootVerifier(peer);
      if (!cur || cur === o.newVerifier) continue;
      allSent = e.setRootVerifier(peer, o.newVerifier) && allSent;
    }
  }
  allSent = o.setKeyRegistry() && allSent;
  if (!allSent) {
    console.log("  [one-registry] some wiring was described, not sent: re-run once the admin has sent it");
    return;
  }
  checkPeers({ escrows: o.escrows, peers: o.peers, escrowRegistry: o.newRegistry, registryOf: o.registryOf, where: "deploy" });
}
