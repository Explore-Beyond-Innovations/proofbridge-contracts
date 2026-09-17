import {
  readManifest,
  type ChainDeploymentManifest,
  type RouteTiming,
  type DisputeParams,
} from "@proofbridge/deployment-manifest";
import { connect, requireEnv } from "./common.js";
import { attachContract } from "./artifacts.js";
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
  enforceBls?: boolean;
}

export interface LinkResult {
  localChainId: string;
  peerChainId: string;
  chainTxs: number;
  routeTxs: number;
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
  const sameHex = (a: unknown, b: string) =>
    String(a).toLowerCase() === b.toLowerCase();

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
      const tx = await adManager.getFunction("setPeerEscrow")(
        peerChainId,
        peer.contracts.orderPortal.addressBytes32,
        { nonce: nonces.next() },
      );
      await tx.wait();
      chainTxs++;
      console.log(
        `  [link] AdManager.setPeerEscrow(${peerChainId}, peerOrderPortal=${peer.contracts.orderPortal.address})`,
      );
    }
  }
  {
    const cur = await orderPortal.getFunction("peerEscrow")(peerChainId);
    if (sameHex(cur, peer.contracts.adManager.addressBytes32)) {
      console.log(`  [skip] OrderPortal.setPeerEscrow(${peerChainId}) already set`);
    } else {
      const tx = await orderPortal.getFunction("setPeerEscrow")(
        peerChainId,
        peer.contracts.adManager.addressBytes32,
        { nonce: nonces.next() },
      );
      await tx.wait();
      chainTxs++;
      console.log(
        `  [link] OrderPortal.setPeerEscrow(${peerChainId}, peerAdManager=${peer.contracts.adManager.address})`,
      );
    }
  }

  // ── Root-auth module (module C) ───────────────────────────────────
  const enforceBls =
    opts.enforceBls ?? process.env.ENFORCE_BLS === "true";
  if (enforceBls) {
    const verifierEntry = local.contracts.counterpartyVerifier;
    if (!verifierEntry) {
      throw new Error(
        "link --enforce-bls: local manifest has no counterpartyVerifier - redeploy core first",
      );
    }
    for (const [name, escrow] of [
      ["AdManager", adManager],
      ["OrderPortal", orderPortal],
    ] as const) {
      const cur = await escrow.getFunction("rootVerifier")(peerChainId);
      if (sameHex(cur, verifierEntry.address)) {
        console.log(`  [skip] ${name}.setRootVerifier(${peerChainId}) already set`);
        continue;
      }
      const tx = await escrow.getFunction("setRootVerifier")(
        peerChainId,
        verifierEntry.address,
        { nonce: nonces.next() },
      );
      await tx.wait();
      chainTxs++;
      console.log(
        `  [link] ${name}.setRootVerifier(${peerChainId}, ${verifierEntry.address}) - BLS gate ENFORCED for peer roots`,
      );
    }
  } else {
    console.log(
      "  [link] BLS gate not wired (transitional pre-auth); rerun with --enforce-bls to enable",
    );
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
    if (cur === delay) {
      console.log(`  [skip] RootAnchor.setAnchorDelay(${peerChainId}) already ${delay}s`);
    } else {
      const tx = await anchor.getFunction("setAnchorDelay")(peerChainId, delay, {
        nonce: nonces.next(),
      });
      await tx.wait();
      chainTxs++;
      console.log(`  [link] RootAnchor.setAnchorDelay(${peerChainId}, ${delay}s)`);
    }
    if (local.rootAnchorConfig) {
      local.rootAnchorConfig.anchorDelays[peerChainId.toString()] = delay.toString();
      await writeManifest(localPath, local);
    }
  } else {
    console.log("  [link] no RootAnchor in the local manifest; redeploy core to add the notary");
  }

  // ── Termination clocks + notary reference for the peer route (2.3e) ──
  // ROUTE_{MIN_WINDOW,BUFFER,MARGIN,LONG_BACKSTOP,CLAIM_STAGGER}_S. Local deploys default to
  // the smallest legal clocks; anywhere else every variable must be set explicitly, like the
  // anchor delay — a forgotten clock must not ship a default and record it as intended.
  {
    const timing = routeTimingFromEnv(local.meta.env);
    for (const [name, escrow] of [
      ["AdManager", adManager],
      ["OrderPortal", orderPortal],
    ] as const) {
      const cur = await escrow.getFunction("routeTiming")(peerChainId);
      const same =
        BigInt(cur[0]) === BigInt(timing.minWindow) &&
        BigInt(cur[1]) === BigInt(timing.buffer) &&
        BigInt(cur[2]) === BigInt(timing.margin) &&
        BigInt(cur[3]) === BigInt(timing.longBackstop) &&
        BigInt(cur[4]) === BigInt(timing.claimStagger);
      if (same) {
        console.log(`  [skip] ${name}.setRouteTiming(${peerChainId}) already set`);
        continue;
      }
      const tx = await escrow.getFunction("setRouteTiming")(
        peerChainId,
        [timing.minWindow, timing.buffer, timing.margin, timing.longBackstop, timing.claimStagger],
        { nonce: nonces.next() },
      );
      await tx.wait();
      chainTxs++;
      console.log(
        `  [link] ${name}.setRouteTiming(${peerChainId}, minWindow=${timing.minWindow}s buffer=${timing.buffer}s margin=${timing.margin}s longBackstop=${timing.longBackstop}s claimStagger=${timing.claimStagger}s)`,
      );
    }
    local.routeTiming[peerChainId.toString()] = timing;
    await writeManifest(localPath, local);
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
      const tx = await escrow.getFunction("setRootAnchor")(anchorAddr, { nonce: nonces.next() });
      await tx.wait();
      chainTxs++;
      console.log(`  [link] ${name}.setRootAnchor(${anchorAddr}) - evidence paths live`);
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
    for (const [name, escrow] of [
      ["AdManager", adManager],
      ["OrderPortal", orderPortal],
    ] as const) {
      const cur = await escrow.getFunction("disputeManager")();
      if (sameHex(cur, moduleAddr)) {
        console.log(`  [skip] ${name}.setDisputeManager already ${moduleAddr}`);
      } else {
        const tx = await escrow.getFunction("setDisputeManager")(moduleAddr, {
          nonce: nonces.next(),
        });
        await tx.wait();
        chainTxs++;
        console.log(`  [link] ${name}.setDisputeManager(${moduleAddr})`);
      }
      const escrowAddr = await escrow.getAddress();
      if (await disputeManager.getFunction("isEscrow")(escrowAddr)) {
        console.log(`  [skip] DisputeManager.setEscrow(${name}) already allowed`);
      } else {
        const tx = await disputeManager.getFunction("setEscrow")(escrowAddr, true, {
          nonce: nonces.next(),
        });
        await tx.wait();
        chainTxs++;
        console.log(`  [link] DisputeManager.setEscrow(${name}=${escrowAddr}, true)`);
      }
    }

    // DISPUTE_{CHALLENGE_PERIOD_S,BOND_FLOOR,BOND_BPS}. Same rule as the clocks and the anchor
    // delay: local deploys get the smallest legal values, anywhere else every variable is
    // explicit, because a bond that silently defaults is a bond nobody chose.
    const params = disputeParamsFromEnv(local.meta.env);
    const cur = await disputeManager.getFunction("disputeParams")(peerChainId);
    const same =
      BigInt(cur[0]) === BigInt(params.challengePeriod) &&
      BigInt(cur[1]) === BigInt(params.bondFloor) &&
      Number(cur[2]) === params.bondBps;
    if (same) {
      console.log(`  [skip] DisputeManager.setDisputeParams(${peerChainId}) already set`);
    } else {
      const tx = await disputeManager.getFunction("setDisputeParams")(
        peerChainId,
        [params.challengePeriod, params.bondFloor, params.bondBps],
        { nonce: nonces.next() },
      );
      await tx.wait();
      chainTxs++;
      console.log(
        `  [link] DisputeManager.setDisputeParams(${peerChainId}, challengePeriod=${params.challengePeriod}s bondFloor=${params.bondFloor} bondBps=${params.bondBps})`,
      );
    }
    local.disputeParams[peerChainId.toString()] = params;
    await writeManifest(localPath, local);
  } else {
    console.log("  [link] no DisputeManager in the local manifest; disputes stay unavailable on this chain");
  }

  // ── Per-pair token routes (two directions per pairKey) ────────────
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
        const tx = await adManager.getFunction("setTokenRoute")(
          localTok.address, // adToken
          peerChainId, // orderChainId
          peerTok.addressBytes32, // orderToken (bytes32)
          { nonce: nonces.next() },
        );
        await tx.wait();
        routeTxs++;
      }
    }
    // Direction B: local is order-side.
    // OrderPortal.setTokenRoute(address orderToken, uint256 adChainId, bytes32 adToken)
    {
      const cur = await orderPortal.getFunction("tokenRoute")(localTok.address, peerChainId);
      if (sameHex(cur, peerTok.addressBytes32)) {
        console.log(`  [skip] OrderPortal route "${localTok.pairKey}" already set`);
      } else {
        const tx = await orderPortal.getFunction("setTokenRoute")(
          localTok.address, // orderToken
          peerChainId, // adChainId
          peerTok.addressBytes32, // adToken (bytes32)
          { nonce: nonces.next() },
        );
        await tx.wait();
        routeTxs++;
      }
    }
    console.log(
      `  [link] route "${localTok.pairKey}": ${localTok.symbol} ↔ ${peerTok.symbol}`,
    );
  }

  console.log(
    `[evm-link] done: ${chainTxs} chain tx(s), ${routeTxs} route tx(s)`,
  );
  return {
    localChainId: local.chain.chainId,
    peerChainId: peer.chain.chainId,
    chainTxs,
    routeTxs,
  };
}

/** The route clocks from env: local deploys get the smallest legal set; elsewhere every var is required. */
function routeTimingFromEnv(env: string): RouteTiming {
  const local = env === "local";
  const read = (name: string, localDefault: string): string => {
    const v = process.env[name];
    if (v !== undefined) {
      if (!/^\d+$/.test(v)) throw new Error(`link: ${name}="${v}" is not a whole number of seconds`);
      return v;
    }
    if (local) return localDefault;
    throw new Error(
      `link: ${name} is unset for env=${env}; set every ROUTE_*_S clock (seconds) or deploy with DEPLOY_ENV=local`,
    );
  };
  return {
    minWindow: read("ROUTE_MIN_WINDOW_S", "0"),
    buffer: read("ROUTE_BUFFER_S", "1800"),
    margin: read("ROUTE_MARGIN_S", "0"),
    longBackstop: read("ROUTE_LONG_BACKSTOP_S", "86400"),
    claimStagger: read("ROUTE_CLAIM_STAGGER_S", "0"),
  };
}

/**
 * The contract's own floor is 1 hour and its bond cap is 10%; both are re-checked by the manifest
 * schema, so a bad value fails before it reaches a transaction.
 */
function disputeParamsFromEnv(env: string): DisputeParams {
  const isLocal = env === "local";
  const read = (name: string, localDefault: string): string => {
    const v = process.env[name];
    if (v !== undefined) {
      if (!/^\d+$/.test(v)) throw new Error(`link: ${name}="${v}" is not a whole number`);
      return v;
    }
    if (isLocal) return localDefault;
    throw new Error(
      `link: ${name} is unset for env=${env}; set every DISPUTE_* parameter or deploy with DEPLOY_ENV=local`,
    );
  };
  return {
    challengePeriod: read("DISPUTE_CHALLENGE_PERIOD_S", "3600"),
    bondFloor: read("DISPUTE_BOND_FLOOR", "0"),
    bondBps: Number(read("DISPUTE_BOND_BPS", "0")),
  };
}

export type { ChainDeploymentManifest };
