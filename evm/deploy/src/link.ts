import {
  readManifest,
  type ChainDeploymentManifest,
  type RouteTiming,
  type DisputeParams,
  type TokenBondConfig,
  TokenBondConfigSchema,
  duplicatePairKeys,
} from "@proofbridge/deployment-manifest";
import { Acting, adminsOf, connect, foreignAdmins, requireEnv, timelockedOf, type DescribedCall, type PendingCall } from "./common.js";
import { attachContract } from "./artifacts.js";
import { allPeers, assertOneRegistry, checkPeers, verifierRegistry, type EscrowWiring } from "./one-registry.js";
import { assertSettleBondPairOnChain } from "./settle-bond-pair.js";
import { manifestPath, writeManifest } from "./manifest.js";

export interface LinkOptions {
  rpcUrl?: string;
  privateKey?: string;
  /** Path to this chain's own manifest. Defaults to deployments/<chainId>.json. */
  localManifest?: string;
  /** Path to the peer chain's manifest. Required. */
  peerManifest: string;
  /**
   * Wire the local CounterpartyVerifier as the root-auth module for the peer
   * chain (setRootVerifier on both escrows). This ENFORCES the BLS co-sign
   * gate on every unlock referencing the peer chain - only enable once the
   * relayer submits real cosigData. Default false (transitional pre-auth).
   */
  /** Ignored: the root gate is always wired. Kept so old callers still parse. */
  enforceBls?: boolean;
}

export interface LinkResult {
  localChainId: string;
  peerChainId: string;
  chainTxs: number;
  routeTxs: number;
  /** Calls the signer could not make because the admin was handed over; empty when all were sent. */
  described: DescribedCall[];
  /** #586: calls under the 24-hour delay, proposed by this run or still waiting; re-run after them. */
  pending: PendingCall[];
}

/** Wires setPeerEscrow + setTokenRoute on this chain's AdManager + OrderPortal from the peer manifest. Idempotent. */
export async function link(opts: LinkOptions): Promise<LinkResult> {
  const rpcUrl = opts.rpcUrl ?? requireEnv("EVM_RPC_URL");
  const privateKey = opts.privateKey ?? requireEnv("EVM_ADMIN_PRIVATE_KEY");
  const { signer, nonces, chainId } = await connect(rpcUrl, privateKey);

  const localPath = opts.localManifest ?? manifestPath(chainId);
  const local = await readManifest(localPath);
  const peer = await readManifest(opts.peerManifest);

  if (local.chain.kind !== "EVM") {
    throw new Error(
      `link: local manifest ${localPath} has kind=${local.chain.kind}, expected EVM`,
    );
  }
  if (BigInt(local.chain.chainId) !== chainId) {
    throw new Error(
      `link: connected chainId=${chainId} does not match local manifest chainId=${local.chain.chainId}`,
    );
  }

  console.log(
    `[evm-link] local=${local.chain.name}(${local.chain.chainId}) ↔ peer=${peer.chain.name}(${peer.chain.chainId}, kind=${peer.chain.kind})`,
  );

  const adManager = attachContract(
    local.contracts.adManager.address,
    "AdManager",
    "AdManager",
    signer,
  );
  const orderPortal = attachContract(
    local.contracts.orderPortal.address,
    "OrderPortal",
    "OrderPortal",
    signer,
  );

  const peerChainId = BigInt(peer.chain.chainId);

  // Every clock and dispute param is read before anything is sent: a missing one refuses the link up front.
  routeTimingFromEnv(local.meta.env);
  if (local.contracts.disputeManager) disputeParamsFromEnv(local.meta.env);
  const tokenBonds = tokenBondsFromEnv();
  assertPeerCompatible(local, peer);
  // The module link wires below is only usable if the escrow calls `settleBond` under the selector
  // the module dispatches: both from one build, read from the chain before anything is sent.
  if (local.contracts.disputeManager) {
    await assertSettleBondPairOnChain(
      signer.provider!,
      { adManager: local.contracts.adManager.address, disputeManager: local.contracts.disputeManager.address },
      "link",
    );
  }

  const registryOf = async (v: string): Promise<string> =>
    String(await attachContract(v, "CounterpartyVerifier", "CounterpartyVerifier", signer).getFunction("registry")());
  const sameHex = (a: unknown, b: string) =>
    String(a).toLowerCase() === b.toLowerCase();

  // Who holds admin on what this command configures, read before anything is sent. After a
  // handover the signer is not the admin, and every call below is described, not sent (#424).
  const me = await signer.getAddress();
  const toConfigure = [
    { label: "AdManager", artifact: "AdManager", address: local.contracts.adManager.address },
    { label: "OrderPortal", artifact: "OrderPortal", address: local.contracts.orderPortal.address },
    ...(local.contracts.rootAnchor ? [{ label: "RootAnchor", artifact: "RootAnchor", address: local.contracts.rootAnchor.address }] : []),
    ...(local.contracts.disputeManager ? [{ label: "DisputeManager", artifact: "DisputeManager", address: local.contracts.disputeManager.address }] : []),
  ];
  const held = await adminsOf(toConfigure, (a, f, n) => attachContract(a, f, n, signer));
  // #586: on a contract whose delay is on, every call below is proposed, and sent by a later run.
  const timelocked = await timelockedOf(toConfigure, (a, f, n) => attachContract(a, f, n, signer));
  const acting = new Acting(foreignAdmins(me, held, "evm-link"), nonces, "link", timelocked);
  // A section of the manifest is written only when its value is on chain — already there, or
  // sent by this run. A described call was not made, so the section it would have set stays as
  // it was: what the manifest says was set has to have been.
  const record = async () => writeManifest(localPath, local);

  // ── Chain-level linking ────────────────────────────────────────────
  // Local adManager accepts from peer orderPortal; local orderPortal accepts
  // from peer adManager. Every write is check-first: state already on-chain
  // is skipped, never resent.
  let chainTxs = 0;

  {
    const cur = await adManager.getFunction("peerEscrow")(peerChainId);
    if (sameHex(cur, peer.contracts.orderPortal.addressBytes32)) {
      console.log(`  [skip] AdManager.setPeerEscrow(${peerChainId}) already set`);
    } else {
      if (await acting.call(adManager, "AdManager", "setPeerEscrow", [peerChainId, peer.contracts.orderPortal.addressBytes32],
        `AdManager.setPeerEscrow(${peerChainId}, peerOrderPortal=${peer.contracts.orderPortal.address})`)) chainTxs++;
    }
  }
  {
    const cur = await orderPortal.getFunction("peerEscrow")(peerChainId);
    if (sameHex(cur, peer.contracts.adManager.addressBytes32)) {
      console.log(`  [skip] OrderPortal.setPeerEscrow(${peerChainId}) already set`);
    } else {
      if (await acting.call(orderPortal, "OrderPortal", "setPeerEscrow", [peerChainId, peer.contracts.adManager.addressBytes32],
        `OrderPortal.setPeerEscrow(${peerChainId}, peerAdManager=${peer.contracts.adManager.address})`)) chainTxs++;
    }
  }

  // ── Root-auth module (module C) ───────────────────────────────────
  // Always wired: pre-auth is gone (1.5i), so an escrow with no root verifier for a peer can never
  // settle an unlock from it. `--enforce-bls` / ENFORCE_BLS are accepted and ignored.
  {
    const verifierEntry = local.contracts.counterpartyVerifier;
    if (!verifierEntry) {
      throw new Error(
        "link: local manifest has no counterpartyVerifier, so no unlock could settle - redeploy core first",
      );
    }
    // #464/#465: never wire a verifier that does not answer registry() or reads another registry.
    assertOneRegistry(
      String(await adManager.getFunction("keyRegistry")()),
      await verifierRegistry(registryOf, verifierEntry.address, "link"),
      "link",
    );
    for (const [name, escrow] of [
      ["AdManager", adManager],
      ["OrderPortal", orderPortal],
    ] as const) {
      const cur = await escrow.getFunction("rootVerifier")(peerChainId);
      if (sameHex(cur, verifierEntry.address)) {
        console.log(`  [skip] ${name}.setRootVerifier(${peerChainId}) already set`);
        continue;
      }
      if (await acting.call(escrow, name, "setRootVerifier", [peerChainId, verifierEntry.address],
        `${name}.setRootVerifier(${peerChainId}, ${verifierEntry.address}) - BLS gate ENFORCED for peer roots`)) chainTxs++;
    }
  }

  // #465 (46-2): whatever was wired for this peer, reads the
  // AdManager's registry.
  {
    const escrows: EscrowWiring[] = ([["AdManager", adManager], ["OrderPortal", orderPortal]] as const).map(
      ([name, c]) => ({
        name,
        rootVerifier: async (peer: string) => String(await c.getFunction("rootVerifier")(peer)),
        setRootVerifier: async () => false, // link wires above; here it only reads
        wiredChains: async () => (await c.getFunction("wiredChains")()).map((x: bigint) => x.toString()),
      }),
    );
    await checkPeers({
      escrows,
      // #466: this peer and every other the escrows say they wired.
      peers: await allPeers([peerChainId.toString()], escrows, "link"),
      escrowRegistry: String(await adManager.getFunction("keyRegistry")()),
      registryOf,
      where: "link",
    });
  }

  // ── Anchor delay for the peer route (2.3f) ─────────────────────────
  // Seconds an anchor of the peer chain must age before isAnchored is true:
  // ANCHOR_DELAY_S (default 0 — local / dev; the spec wants minutes-to-an-hour live).
  if (local.contracts.rootAnchor) {
    const delay = BigInt(process.env.ANCHOR_DELAY_S ?? "0");
    // The delay is the watchtower's window — the whole safety story of 2.3f. Outside a local
    // deploy a forgotten variable must not ship a zero and record it as intended.
    if (delay === 0n && local.meta.env !== "local") {
      throw new Error(
        `link: ANCHOR_DELAY_S is 0 for env=${local.meta.env}; set the route's anchor delay (seconds) or deploy with DEPLOY_ENV=local`,
      );
    }
    const anchor = attachContract(
      local.contracts.rootAnchor.address,
      "RootAnchor",
      "RootAnchor",
      signer,
    );
    const cur = BigInt(await anchor.getFunction("anchorDelay")(peerChainId));
    let onChain = cur === delay;
    if (onChain) {
      console.log(`  [skip] RootAnchor.setAnchorDelay(${peerChainId}) already ${delay}s`);
    } else {
      // #586: a raise only lengthens the watchtower's window, so it is instant even under the delay.
      onChain = await acting.call(anchor, "RootAnchor", "setAnchorDelay", [peerChainId, delay], `RootAnchor.setAnchorDelay(${peerChainId}, ${delay}s)`, delay > cur);
      if (onChain) chainTxs++;
    }
    if (onChain && local.rootAnchorConfig) {
      local.rootAnchorConfig.anchorDelays[peerChainId.toString()] = delay.toString();
      await record();
    }
  } else {
    console.log("  [link] no RootAnchor in the local manifest; redeploy core to add the notary");
  }

  // ── Termination clocks + notary reference for the peer route (2.3e) ──
  // ROUTE_{MIN_WINDOW,BUFFER,MARGIN,CLAIM_STAGGER}_S. Local deploys default to the smallest
  // legal clocks; anywhere else every variable must be set explicitly, like the anchor delay — a
  // forgotten clock must not ship a default and record it as intended. Timing is versioned on
  // chain: each write is a new version (the first creates version 1) and orders already open keep
  // theirs, so the comparison is against the current version only.
  {
    const timing = routeTimingFromEnv(local.meta.env);
    let onChain = true;
    for (const [name, escrow] of [
      ["AdManager", adManager],
      ["OrderPortal", orderPortal],
    ] as const) {
      const version = await escrow.getFunction("timingVersion")(peerChainId);
      const cur = await escrow.getFunction("routeTimingAt")(peerChainId, version);
      const same =
        BigInt(version) !== 0n &&
        BigInt(cur[0]) === BigInt(timing.minWindow) &&
        BigInt(cur[1]) === BigInt(timing.buffer) &&
        BigInt(cur[2]) === BigInt(timing.margin) &&
        BigInt(cur[3]) === BigInt(timing.claimStagger);
      if (same) {
        console.log(`  [skip] ${name}.setRouteTiming(${peerChainId}) already set`);
        continue;
      }
      if (await acting.call(escrow, name, "setRouteTiming",
        [peerChainId, [timing.minWindow, timing.buffer, timing.margin, timing.claimStagger]],
        `${name}.setRouteTiming(${peerChainId}, minWindow=${timing.minWindow}s buffer=${timing.buffer}s margin=${timing.margin}s claimStagger=${timing.claimStagger}s)`)) chainTxs++;
      else onChain = false;
    }
    if (onChain) {
      local.routeTiming[peerChainId.toString()] = timing;
      await record();
    }
  }
  if (local.contracts.rootAnchor) {
    const anchorAddr = local.contracts.rootAnchor.address;
    for (const [name, escrow] of [
      ["AdManager", adManager],
      ["OrderPortal", orderPortal],
    ] as const) {
      const cur = await escrow.getFunction("rootAnchor")();
      if (sameHex(cur, anchorAddr)) {
        console.log(`  [skip] ${name}.setRootAnchor already ${anchorAddr}`);
        continue;
      }
      if (await acting.call(escrow, name, "setRootAnchor", [anchorAddr], `${name}.setRootAnchor(${anchorAddr}) - evidence paths live`)) chainTxs++;
    }
  } else {
    console.log("  [link] no RootAnchor in the local manifest; the escrows' evidence paths stay fail-closed");
  }

  // ── Dispute module: both directions, then the route's params (2.3g) ──
  // The escrow must know the module to file, and the module must know the escrow to accept the
  // filing. Wiring one without the other leaves disputes dead in a way that only shows at use,
  // so both edges are set here or neither is.
  if (local.contracts.disputeManager) {
    const moduleAddr = local.contracts.disputeManager.address;
    const disputeManager = attachContract(
      moduleAddr,
      "DisputeManager",
      "DisputeManager",
      signer,
    );
    // The primary only. The OrderPortal is the follower: it has no dispute, no arbiter and no clock
    // of its own, and learns how one ended from an anchored proof of the primary's leaf. Wiring a
    // module to it would be the first step of the mistake review pass 1 found, so there is nothing
    // here to wire it with.
    for (const [name, escrow] of [["AdManager", adManager]] as const) {
      const cur = await escrow.getFunction("disputeManager")();
      if (sameHex(cur, moduleAddr)) {
        console.log(`  [skip] ${name}.setDisputeManager already ${moduleAddr}`);
      } else {
        if (await acting.call(escrow, name, "setDisputeManager", [moduleAddr], `${name}.setDisputeManager(${moduleAddr})`)) chainTxs++;
      }
      const escrowAddr = await escrow.getAddress();
      if (await disputeManager.getFunction("isEscrow")(escrowAddr)) {
        console.log(`  [skip] DisputeManager.setEscrow(${name}) already allowed`);
      } else {
        if (await acting.call(disputeManager, "DisputeManager", "setEscrow", [escrowAddr, true], `DisputeManager.setEscrow(${name}=${escrowAddr}, true)`)) chainTxs++;
      }
    }

    // DISPUTE_{CHALLENGE_PERIOD_S,BOND_FLOOR}. Same rule as the clocks and the anchor delay: local
    // deploys get the smallest legal values, anywhere else every variable is explicit, because a
    // bond that silently defaults is a bond nobody chose. The floor is the whole bond: one flat
    // amount per route, in this chain's wrapped native.
    const params = disputeParamsFromEnv(local.meta.env);
    const cur = await disputeManager.getFunction("disputeParams")(peerChainId);
    const same =
      BigInt(cur[0]) === BigInt(params.challengePeriod) &&
      BigInt(cur[1]) === BigInt(params.bondFloor);
    let onChain = same;
    if (onChain) {
      console.log(`  [skip] DisputeManager.setDisputeParams(${peerChainId}) already set`);
    } else {
      onChain = await acting.call(disputeManager, "DisputeManager", "setDisputeParams",
        [peerChainId, [params.challengePeriod, params.bondFloor]],
        `DisputeManager.setDisputeParams(${peerChainId}, challengePeriod=${params.challengePeriod}s bondFloor=${params.bondFloor})`);
      if (onChain) chainTxs++;
    }
    if (onChain) {
      local.disputeParams[peerChainId.toString()] = params;
      await record();
    }
  } else {
    console.log("  [link] no DisputeManager in the local manifest; disputes stay unavailable on this chain");
  }

  // ── Per-pair token routes (two directions per pairKey) ────────────
  //
  // `pairKey` is the deployer's claim that the two sides are the SAME underlying asset, and the
  // protocol relies on it rather than checking it: an order carries one `amount`, the counterpart
  // figure is a power-of-ten decimal rescale, and nothing prices one token against the other. A
  // pairKey shared by two different assets settles them 1:1 and silently mis-pays — and re-opens
  // risk 01 F4, whose rate floor was withdrawn *because* routes are same-asset (design 01 §1.3).
  //
  // Same-asset is not machine-checkable across chains: WXLM and XLM are one asset under two
  // symbols. What is checkable is that the claim is well formed, and this is the moment it is being
  // made, with both manifests in hand. A duplicate key is the plausible way a wrong pairing
  // arrives, and `find` below would silently route whichever row came first.
  for (const [side, m] of [["local", local], ["peer", peer]] as const) {
    const dupes = duplicatePairKeys(m.tokens);
    if (dupes.length) {
      throw new Error(
        `link: the ${side} manifest uses pairKey ${dupes.map((d) => `"${d}"`).join(", ")} more than once — ` +
          `a pairKey names one asset, and routing would pick one of the rows arbitrarily`,
      );
    }
  }

  let routeTxs = 0;
  for (const localTok of local.tokens) {
    const peerTok = peer.tokens.find((t) => t.pairKey === localTok.pairKey);
    if (!peerTok) {
      console.warn(
        `  [skip] no peer token for pairKey="${localTok.pairKey}" — skipping`,
      );
      continue;
    }

    // Direction A: local is ad-side. Both escrows share one signature now:
    // setTokenRoute(address localToken, uint256 peerChainId, bytes32 peerToken).
    {
      const cur = await adManager.getFunction("tokenRoute")(localTok.address, peerChainId);
      if (sameHex(cur, peerTok.addressBytes32)) {
        console.log(`  [skip] AdManager route "${localTok.pairKey}" already set`);
      } else {
        // setTokenRoute(adToken, orderChainId, orderToken)
        if (await acting.call(adManager, "AdManager", "setTokenRoute", [localTok.address, peerChainId, peerTok.addressBytes32],
          `AdManager.setTokenRoute("${localTok.pairKey}")`)) routeTxs++;
      }
    }
    // Direction B: local is order-side.
    // OrderPortal.setTokenRoute(address orderToken, uint256 adChainId, bytes32 adToken)
    {
      const cur = await orderPortal.getFunction("tokenRoute")(localTok.address, peerChainId);
      if (sameHex(cur, peerTok.addressBytes32)) {
        console.log(`  [skip] OrderPortal route "${localTok.pairKey}" already set`);
      } else {
        // setTokenRoute(orderToken, adChainId, adToken)
        if (await acting.call(orderPortal, "OrderPortal", "setTokenRoute", [localTok.address, peerChainId, peerTok.addressBytes32],
          `OrderPortal.setTokenRoute("${localTok.pairKey}")`)) routeTxs++;
      }
    }
    console.log(
      `  [link] route "${localTok.pairKey}": ${localTok.symbol} ↔ ${peerTok.symbol}`,
    );

    // #586: the route's dispute bond in the order's own token, when DISPUTE_TOKEN_BONDS names this pair.
    const bond = tokenBonds[localTok.pairKey];
    if (bond && local.contracts.disputeManager) {
      const dm = attachContract(local.contracts.disputeManager.address, "DisputeManager", "DisputeManager", signer);
      const cur = await dm.getFunction("bondConfig")(localTok.address, peerChainId);
      let onChain = BigInt(cur[0]) === BigInt(bond.minBond) && Number(cur[1]) === bond.bondBps;
      if (onChain) console.log(`  [skip] DisputeManager.setBondConfig("${localTok.pairKey}") already set`);
      else {
        onChain = await acting.call(dm, "DisputeManager", "setBondConfig", [localTok.address, peerChainId, [bond.minBond, bond.bondBps]],
          `DisputeManager.setBondConfig("${localTok.pairKey}", minBond=${bond.minBond} bondBps=${bond.bondBps})`);
        if (onChain) routeTxs++;
      }
      if (onChain) {
        (local.tokenBonds[peerChainId.toString()] ??= {})[localTok.address] = bond;
        await record();
      }
    }
  }

  console.log(
    `[evm-link] done: ${chainTxs} chain tx(s), ${routeTxs} route tx(s)${acting.described.length ? `, ${acting.described.length} described` : ""}`,
  );
  acting.report();
  return {
    localChainId: local.chain.chainId,
    peerChainId: peer.chain.chainId,
    chainTxs,
    routeTxs,
    described: acting.described,
    pending: acting.pending,
  };
}

/** The largest route bond ratio the DisputeManager accepts, in bps (5%): the manifest schema's bound. */
export const MAX_BOND_BPS = TokenBondConfigSchema.shape.bondBps.maxValue!;

/**
 * #586: `DISPUTE_TOKEN_BONDS`, a JSON object `{ "<pairKey>": { "minBond": "<base units>", "bondBps": <n> } }`:
 * the routes whose dispute bond is priced in the order's own token. Unset or `{}` = every route keeps
 * the flat native floor. Checked here, before anything is sent, by the manifest's own schema.
 */
export function tokenBondsFromEnv(vars: Record<string, string | undefined> = process.env): Record<string, TokenBondConfig> {
  const raw = vars.DISPUTE_TOKEN_BONDS;
  if (raw === undefined || raw.trim() === "") return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`link: DISPUTE_TOKEN_BONDS is not JSON: ${raw}`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("link: DISPUTE_TOKEN_BONDS must be an object keyed by pairKey");
  }
  const out: Record<string, TokenBondConfig> = {};
  for (const [pairKey, v] of Object.entries(parsed as Record<string, unknown>)) {
    const r = TokenBondConfigSchema.safeParse(v);
    if (!r.success) {
      const why = r.error.issues.map((i) => `${i.path.join(".") || "entry"}: ${i.message}`).join("; ");
      throw new Error(
        `link: DISPUTE_TOKEN_BONDS["${pairKey}"] is invalid (${why}); minBond is whole base units, at least 1, and bondBps a whole number 0..${MAX_BOND_BPS}`,
      );
    }
    out[pairKey] = r.data;
  }
  return out;
}

/** The route clocks from env: local deploys get the smallest legal set; elsewhere every var is required. */
function routeTimingFromEnv(env: string, vars: Record<string, string | undefined> = process.env): RouteTiming {
  const local = env === "local";
  const read = (name: string, localDefault: string): string => {
    const v = vars[name];
    if (v !== undefined) {
      if (!/^\d+$/.test(v)) throw new Error(`link: ${name}="${v}" is not a whole number of seconds`);
      return v;
    }
    if (local) return localDefault;
    throw new Error(
      `link: ${name} is unset for env=${env}; set every ROUTE_*_S clock (seconds) or deploy with DEPLOY_ENV=local`,
    );
  };
  const timing = {
    minWindow: read("ROUTE_MIN_WINDOW_S", "0"),
    buffer: read("ROUTE_BUFFER_S", "1800"),
    margin: read("ROUTE_MARGIN_S", "0"),
    claimStagger: read("ROUTE_CLAIM_STAGGER_S", "0"),
  };
  // Mirror of `RouteTiming.validate` / `timing::validate` field 2 (`margin <= buffer / 2`): refused
  // here, before anything is sent. The contract stays the authority; a change to the cap touches both.
  if (BigInt(timing.margin) > BigInt(timing.buffer) / 2n) {
    throw new Error(
      `link: ROUTE_MARGIN_S=${timing.margin} exceeds half of ROUTE_BUFFER_S=${timing.buffer}; the escrows refuse a margin above half the buffer`,
    );
  }
  return timing;
}

/**
 * The smallest floor `link` accepts outside `local`: 0.001 of the wrapped native (10^15 wei). The floor is the whole
 * bond, so a dust floor makes a dispute free in practice. A sanity bound, not the tuned value: the
 * operating rules size each route's floor above it.
 */
export const MIN_BOND_FLOOR_OUTSIDE_LOCAL = 1_000_000_000_000_000n;

/**
 * The contract's challenge period is 1 hour to 7 days and its bond floor at least 1; both are
 * re-checked by the manifest schema, so a bad value fails before it reaches a transaction. Outside
 * `local` the floor must also clear `MIN_BOND_FLOOR_OUTSIDE_LOCAL`, and a `DISPUTE_BOND_BPS` left in
 * the env is refused: the percentage term is gone, so a value there would be silently ignored.
 */
export function disputeParamsFromEnv(env: string, vars: Record<string, string | undefined> = process.env): DisputeParams {
  const isLocal = env === "local";
  if (vars.DISPUTE_BOND_BPS !== undefined) {
    throw new Error(
      "link: DISPUTE_BOND_BPS is set, but the percentage term was removed: the bond is the route's flat DISPUTE_BOND_FLOOR. Unset it",
    );
  }
  const read = (name: string, localDefault: string): string => {
    const v = vars[name];
    if (v !== undefined) {
      if (!/^\d+$/.test(v)) throw new Error(`link: ${name}="${v}" is not a whole number`);
      return v;
    }
    if (isLocal) return localDefault;
    throw new Error(
      `link: ${name} is unset for env=${env}; set every DISPUTE_* parameter or deploy with DEPLOY_ENV=local`,
    );
  };
  // 1, not 0: `Dispute.validate` rejects a zero floor, because the floor is the whole bond and a
  // zero one is a free dispute. "The smallest legal value" is the rule everywhere here, and for
  // this parameter the smallest legal value is one. Outside local there is no default.
  const bondFloor = read("DISPUTE_BOND_FLOOR", "1");
  if (!isLocal && BigInt(bondFloor) < MIN_BOND_FLOOR_OUTSIDE_LOCAL) {
    throw new Error(
      `link: DISPUTE_BOND_FLOOR=${bondFloor} is below the ${MIN_BOND_FLOOR_OUTSIDE_LOCAL} minimum for env=${env}; the floor is the whole bond, so a dust floor makes disputes free`,
    );
  }
  return {
    challengePeriod: read("DISPUTE_CHALLENGE_PERIOD_S", "3600"),
    bondFloor,
  };
}

export type { ChainDeploymentManifest };

/**
 * A-6: two chains linked into one route must have been deployed for the same environment and
 * against the same event-circuit VK; otherwise every cross-chain proof one side makes, the other
 * refuses — and nothing says why until a settlement fails.
 */
export function assertPeerCompatible(local: ChainDeploymentManifest, peer: ChainDeploymentManifest): void {
  if (local.meta.env !== peer.meta.env) {
    throw new Error(`link: this chain was deployed for env=${local.meta.env} but the peer for env=${peer.meta.env}; a route cannot span environments`);
  }
  const a = local.meta.vkSha256?.toLowerCase();
  const b = peer.meta.vkSha256?.toLowerCase();
  if (a && b && a !== b) {
    throw new Error(`link: this chain's verifier VK is ${a} but the peer's is ${b}; the two would refuse each other's proofs. Redeploy one from the other's bundle`);
  }
}
