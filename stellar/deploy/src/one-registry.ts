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

/**
 * #466: the chain as the one-registry steps see it. `link` and `deploy-core` build one from the
 * Stellar CLI and call only the steps below, so the specs drive exactly what the commands run.
 */
export interface EscrowChain {
  /** The escrow's `root_verifier(chain_id)`, or null. */
  rootVerifier(escrow: string, peer: string): string | null;
  /** The escrow's `wired_chains()`; throws on an escrow built before #466. */
  wiredChains(escrow: string): string[];
  /** A verifier's `registry()`; throws when it does not answer. */
  registryOf(verifier: string): string;
  /** The AdManager's `key_registry()`. */
  keyRegistry(adManager: string): string;
  /** Sends (true) or only describes (false). */
  setRootVerifier(escrow: string, name: string, peer: string, verifier: string): boolean;
  setKeyRegistry(adManager: string, registry: string): boolean;
}

export interface EscrowIds {
  adManager: string;
  orderPortal: string;
}

function wiring(chain: EscrowChain, ids: EscrowIds): EscrowWiring[] {
  return (
    [
      ["AdManager", ids.adManager],
      ["OrderPortal", ids.orderPortal],
    ] as const
  ).map(([name, id]) => ({
    name,
    rootVerifier: (peer: string) => chain.rootVerifier(id, peer),
    setRootVerifier: (peer: string, v: string) => chain.setRootVerifier(id, name, peer, v),
  }));
}

/** #466: the manifest's peers and every chain either escrow says it wired, including by hand. */
export function allPeers(chain: EscrowChain, ids: EscrowIds, manifestPeers: string[], where: string): string[] {
  const peers = new Set(manifestPeers.map(String));
  for (const [name, id] of [
    ["AdManager", ids.adManager],
    ["OrderPortal", ids.orderPortal],
  ] as const) {
    try {
      for (const c of chain.wiredChains(id)) peers.add(String(c));
    } catch {
      console.log(`  [${where}] ${name} does not list its wired chains (pre-#466 wasm?); checking the manifest's peers only`);
    }
  }
  return [...peers];
}

/** #466: `link`'s step — every peer the escrows wired, this one included, reads the AdManager's registry. */
export function linkCheckStep(chain: EscrowChain, ids: EscrowIds, peer: string): void {
  checkPeers({
    escrows: wiring(chain, ids),
    peers: allPeers(chain, ids, [peer], "link"),
    escrowRegistry: chain.keyRegistry(ids.adManager),
    registryOf: (v) => chain.registryOf(v),
    where: "link",
  });
}

/**
 * #466: `deploy-core`'s step — point the AdManager at `registry` without leaving a split: check
 * every wired peer when the registry is unchanged, switch in G1's order when it changes.
 */
export function deployRegistryStep(
  chain: EscrowChain,
  ids: EscrowIds,
  o: { registry: string; verifier: string; manifestPeers: string[] },
): void {
  const escrows = wiring(chain, ids);
  const peers = allPeers(chain, ids, o.manifestPeers, "deploy");
  const registryOf = (v: string) => chain.registryOf(v);
  if (chain.keyRegistry(ids.adManager) === o.registry) {
    console.log(`  [skip] AdManager.set_key_registry already ${o.registry}`);
    checkPeers({ escrows, peers, escrowRegistry: o.registry, registryOf, where: "deploy" });
  } else {
    // #465: the peers move to the verifier on the new registry first, then the registry; never a split.
    switchKeyRegistry({
      escrows,
      peers,
      newRegistry: o.registry,
      newVerifier: o.verifier,
      registryOf,
      setKeyRegistry: () => chain.setKeyRegistry(ids.adManager, o.registry),
    });
  }
}
