import {
  readManifest,
  type ChainDeploymentManifest,
  type RouteTiming,
  type DisputeParams,
} from "@proofbridge/deployment-manifest";
import { DEFAULT_STELLAR_CHAIN_ID } from "./common.js";
import { invokeContract } from "./stellar-cli.js";
import { manifestPath, writeManifest } from "./manifest.js";

export interface StellarLinkOptions {
  /** Path to this chain's own manifest. Defaults to deployments/<chainId>.json. */
  localManifest?: string;
  /** Path to the peer chain's manifest. Required. */
  peerManifest: string;
  /** Override local chain id (rarely needed — defaults to 1000001). */
  localChainId?: bigint;
  /**
   * Wire the local CounterpartyVerifier as the root-auth module for the peer
   * chain (set_root_verifier on both escrows). This ENFORCES the BLS co-sign
   * gate on every unlock referencing the peer chain - only enable once the
   * relayer submits real cosig_data. Default false (transitional pre-auth).
   */
  enforceBls?: boolean;
}

export interface StellarLinkResult {
  localChainId: string;
  peerChainId: string;
  chainTxs: number;
  routeTxs: number;
}

/** Wires set_chain + set_token_route on this chain's AdManager + OrderPortal from the peer manifest. Idempotent. */
export async function link(
  opts: StellarLinkOptions,
): Promise<StellarLinkResult> {
  const chainId = opts.localChainId ?? DEFAULT_STELLAR_CHAIN_ID;
  const localPath = opts.localManifest ?? manifestPath(chainId);
  const local = await readManifest(localPath);
  const peer = await readManifest(opts.peerManifest);

  if (local.chain.kind !== "STELLAR") {
    throw new Error(
      `link: local manifest ${localPath} has kind=${local.chain.kind}, expected STELLAR`,
    );
  }
  if (BigInt(local.chain.chainId) !== chainId) {
    throw new Error(
      `link: chainId=${chainId} does not match local manifest chainId=${local.chain.chainId}`,
    );
  }

  console.log(
    `[stellar-link] local=${local.chain.name}(${local.chain.chainId}) ↔ peer=${peer.chain.name}(${peer.chain.chainId}, kind=${peer.chain.kind})`,
  );

  const peerChainId = peer.chain.chainId;

  // ── Chain-level linking ────────────────────────────────────────────
  // Stellar CLI takes bytes without the `0x` prefix.
  const stripHex = (h: string) => h.replace(/^0x/, "");
  let chainTxs = 0;

  // Check-first: a read-only get_chain simulation decides whether the write
  // is needed; already-linked state is never resent.
  const chainAlreadySet = (escrow: string, peerField: string, want: string): boolean => {
    try {
      const out = invokeContract(
        escrow,
        "get_chain",
        ["--chain_id", peerChainId],
        { send: false },
      );
      const parsed = JSON.parse(out.split("\n").filter(Boolean).pop() ?? "null");
      return (
        !!parsed &&
        parsed.supported === true &&
        String(parsed[peerField]).toLowerCase() === stripHex(want).toLowerCase()
      );
    } catch {
      return false;
    }
  };

  if (chainAlreadySet(local.contracts.adManager.address, "order_portal", peer.contracts.orderPortal.addressBytes32)) {
    console.log(`  [skip] AdManager.set_chain(${peerChainId}) already set`);
  } else {
    invokeContract(local.contracts.adManager.address, "set_chain", [
      "--order_chain_id",
      peerChainId,
      "--order_portal",
      stripHex(peer.contracts.orderPortal.addressBytes32),
      "--supported",
      "true",
    ]);
    chainTxs++;
    console.log(
      `  [link] AdManager.set_chain(${peerChainId}, peerOrderPortal=${peer.contracts.orderPortal.address})`,
    );
  }

  if (chainAlreadySet(local.contracts.orderPortal.address, "ad_manager", peer.contracts.adManager.addressBytes32)) {
    console.log(`  [skip] OrderPortal.set_chain(${peerChainId}) already set`);
  } else {
    invokeContract(local.contracts.orderPortal.address, "set_chain", [
      "--ad_chain_id",
      peerChainId,
      "--ad_manager",
      stripHex(peer.contracts.adManager.addressBytes32),
      "--supported",
      "true",
    ]);
    chainTxs++;
    console.log(
      `  [link] OrderPortal.set_chain(${peerChainId}, peerAdManager=${peer.contracts.adManager.address})`,
    );
  }

  // ── Root-auth module (module C) ───────────────────────────────────
  const enforceBls = opts.enforceBls ?? process.env.ENFORCE_BLS === "true";
  if (enforceBls) {
    const verifierEntry = local.contracts.counterpartyVerifier;
    if (!verifierEntry) {
      throw new Error(
        "link --enforce-bls: local manifest has no counterpartyVerifier - redeploy core first",
      );
    }
    for (const [name, escrow] of [
      ["AdManager", local.contracts.adManager.address],
      ["OrderPortal", local.contracts.orderPortal.address],
    ] as const) {
      invokeContract(escrow, "set_root_verifier", [
        "--chain_id",
        peerChainId,
        "--module",
        verifierEntry.address,
      ]);
      chainTxs++;
      console.log(
        `  [link] ${name}.set_root_verifier(${peerChainId}, ${verifierEntry.address}) - BLS gate ENFORCED for peer roots`,
      );
    }
  } else {
    console.log(
      "  [link] BLS gate not wired (transitional pre-auth); rerun with --enforce-bls to enable",
    );
  }

  // ── Anchor delay for the peer route (2.3f) ─────────────────────────
  // Seconds an anchor of the peer chain must age before is_anchored is true:
  // ANCHOR_DELAY_S (default 0 — local / dev; the spec wants minutes-to-an-hour live).
  if (local.contracts.rootAnchor) {
    const delay = process.env.ANCHOR_DELAY_S ?? "0";
    // The delay is the watchtower's window — the whole safety story of 2.3f. Outside a local
    // deploy a forgotten variable must not ship a zero and record it as intended.
    if (BigInt(delay) === 0n && local.meta.env !== "local") {
      throw new Error(
        `link: ANCHOR_DELAY_S is 0 for env=${local.meta.env}; set the route's anchor delay (seconds) or deploy with DEPLOY_ENV=local`,
      );
    }
    const cur = invokeContract(
      local.contracts.rootAnchor.address,
      "anchor_delay",
      ["--source_chain_id", peerChainId],
      { send: false },
    ).trim();
    if (cur.replace(/"/g, "") === delay) {
      console.log(`  [skip] RootAnchor.set_anchor_delay(${peerChainId}) already ${delay}s`);
    } else {
      invokeContract(local.contracts.rootAnchor.address, "set_anchor_delay", [
        "--source_chain_id",
        peerChainId,
        "--delay",
        delay,
      ]);
      chainTxs++;
      console.log(`  [link] RootAnchor.set_anchor_delay(${peerChainId}, ${delay}s)`);
    }
    if (local.rootAnchorConfig) {
      local.rootAnchorConfig.anchorDelays[peerChainId] = delay;
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
    // The CLI reads a JSON string in a u64 slot as an enum variant name and rejects the call
    // (monorepo 69486f0): every field goes out as a JSON number, exact to 2^53.
    const u64 = (name: string, v: string): number => {
      const n = BigInt(v);
      if (n > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error(`link: ${name}=${v} exceeds 2^53; the CLI JSON path cannot carry it exactly`);
      }
      return Number(n);
    };
    const timingArg = JSON.stringify({
      min_window: u64("ROUTE_MIN_WINDOW_S", timing.minWindow),
      buffer: u64("ROUTE_BUFFER_S", timing.buffer),
      margin: u64("ROUTE_MARGIN_S", timing.margin),
      long_backstop: u64("ROUTE_LONG_BACKSTOP_S", timing.longBackstop),
      claim_stagger: u64("ROUTE_CLAIM_STAGGER_S", timing.claimStagger),
    });
    const timingAlreadySet = (escrow: string): boolean => {
      try {
        const out = invokeContract(escrow, "get_route_timing", ["--chain_id", peerChainId], {
          send: false,
        });
        const parsed = JSON.parse(out.split("\n").filter(Boolean).pop() ?? "null");
        return (
          !!parsed &&
          BigInt(parsed.min_window) === BigInt(timing.minWindow) &&
          BigInt(parsed.buffer) === BigInt(timing.buffer) &&
          BigInt(parsed.margin) === BigInt(timing.margin) &&
          BigInt(parsed.long_backstop) === BigInt(timing.longBackstop) &&
          BigInt(parsed.claim_stagger) === BigInt(timing.claimStagger)
        );
      } catch {
        return false;
      }
    };
    for (const [name, escrow] of [
      ["AdManager", local.contracts.adManager.address],
      ["OrderPortal", local.contracts.orderPortal.address],
    ] as const) {
      if (timingAlreadySet(escrow)) {
        console.log(`  [skip] ${name}.set_route_timing(${peerChainId}) already set`);
        continue;
      }
      invokeContract(escrow, "set_route_timing", [
        "--chain_id",
        peerChainId,
        "--timing",
        timingArg,
      ]);
      chainTxs++;
      console.log(
        `  [link] ${name}.set_route_timing(${peerChainId}, minWindow=${timing.minWindow}s buffer=${timing.buffer}s margin=${timing.margin}s longBackstop=${timing.longBackstop}s claimStagger=${timing.claimStagger}s)`,
      );
    }
    local.routeTiming[peerChainId] = timing;
    await writeManifest(localPath, local);
  }
  if (local.contracts.rootAnchor) {
    const anchorAddr = local.contracts.rootAnchor.address;
    const anchorAlreadySet = (escrow: string): boolean => {
      try {
        const out = invokeContract(escrow, "get_root_anchor", [], { send: false });
        const parsed = JSON.parse(out.split("\n").filter(Boolean).pop() ?? "null");
        return typeof parsed === "string" && parsed === anchorAddr;
      } catch {
        return false;
      }
    };
    for (const [name, escrow] of [
      ["AdManager", local.contracts.adManager.address],
      ["OrderPortal", local.contracts.orderPortal.address],
    ] as const) {
      if (anchorAlreadySet(escrow)) {
        console.log(`  [skip] ${name}.set_root_anchor already ${anchorAddr}`);
        continue;
      }
      invokeContract(escrow, "set_root_anchor", ["--anchor", anchorAddr]);
      chainTxs++;
      console.log(`  [link] ${name}.set_root_anchor(${anchorAddr}) - evidence paths live`);
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
    const readOne = (contract: string, fn: string, args: string[]): unknown => {
      try {
        const out = invokeContract(contract, fn, args, { send: false });
        return JSON.parse(out.split("\n").filter(Boolean).pop() ?? "null");
      } catch {
        return null;
      }
    };
    for (const [name, escrow] of [
      ["AdManager", local.contracts.adManager.address],
      ["OrderPortal", local.contracts.orderPortal.address],
    ] as const) {
      if (readOne(escrow, "get_dispute_manager", []) === moduleAddr) {
        console.log(`  [skip] ${name}.set_dispute_manager already ${moduleAddr}`);
      } else {
        invokeContract(escrow, "set_dispute_manager", ["--manager", moduleAddr]);
        chainTxs++;
        console.log(`  [link] ${name}.set_dispute_manager(${moduleAddr})`);
      }
      if (readOne(moduleAddr, "is_escrow", ["--escrow", escrow]) === true) {
        console.log(`  [skip] DisputeManager.set_escrow(${name}) already allowed`);
      } else {
        invokeContract(moduleAddr, "set_escrow", ["--escrow", escrow, "--allowed", "true"]);
        chainTxs++;
        console.log(`  [link] DisputeManager.set_escrow(${name}=${escrow}, true)`);
      }
    }

    // DISPUTE_{CHALLENGE_PERIOD_S,BOND_FLOOR,BOND_BPS}. Same rule as the clocks and the anchor
    // delay: local deploys get the smallest legal values, anywhere else every variable is
    // explicit, because a bond that silently defaults is a bond nobody chose.
    const params = disputeParamsFromEnv(local.meta.env);
    // u64/u32 slots go out as JSON numbers (a string there is read as an enum variant name);
    // the u128 bond floor goes out as a string, which is how the CLI carries a u128.
    const challengePeriod = BigInt(params.challengePeriod);
    if (challengePeriod > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error(
        `link: DISPUTE_CHALLENGE_PERIOD_S=${params.challengePeriod} exceeds 2^53; the CLI JSON path cannot carry it exactly`,
      );
    }
    const paramsArg = JSON.stringify({
      challenge_period: Number(challengePeriod),
      bond_floor: params.bondFloor,
      bond_bps: params.bondBps,
    });
    const cur = readOne(moduleAddr, "dispute_params", ["--chain_id", peerChainId]) as {
      challenge_period?: string | number;
      bond_floor?: string | number;
      bond_bps?: string | number;
    } | null;
    const same =
      !!cur &&
      BigInt(cur.challenge_period ?? -1) === challengePeriod &&
      BigInt(cur.bond_floor ?? -1) === BigInt(params.bondFloor) &&
      Number(cur.bond_bps ?? -1) === params.bondBps;
    if (same) {
      console.log(`  [skip] DisputeManager.set_dispute_params(${peerChainId}) already set`);
    } else {
      invokeContract(moduleAddr, "set_dispute_params", [
        "--chain_id",
        peerChainId,
        "--params",
        paramsArg,
      ]);
      chainTxs++;
      console.log(
        `  [link] DisputeManager.set_dispute_params(${peerChainId}, challengePeriod=${params.challengePeriod}s bondFloor=${params.bondFloor} bondBps=${params.bondBps})`,
      );
    }
    local.disputeParams[peerChainId] = params;
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
        `  [skip] no peer token for pairKey="${localTok.pairKey}"`,
      );
      continue;
    }

    invokeContract(local.contracts.adManager.address, "set_token_route", [
      "--ad_token",
      stripHex(localTok.addressBytes32),
      "--order_token",
      stripHex(peerTok.addressBytes32),
      "--order_chain_id",
      peerChainId,
    ]);
    routeTxs++;

    invokeContract(local.contracts.orderPortal.address, "set_token_route", [
      "--order_token",
      stripHex(localTok.addressBytes32),
      "--ad_chain_id",
      peerChainId,
      "--ad_token",
      stripHex(peerTok.addressBytes32),
    ]);
    routeTxs++;

    console.log(
      `  [link] route "${localTok.pairKey}": ${localTok.symbol} ↔ ${peerTok.symbol}`,
    );
  }

  console.log(
    `[stellar-link] done: ${chainTxs} chain tx(s), ${routeTxs} route tx(s)`,
  );
  return {
    localChainId: local.chain.chainId,
    peerChainId: peer.chain.chainId,
    chainTxs,
    routeTxs,
  };
}

export type { ChainDeploymentManifest };

/**
 * The dispute params from env, same rule as the clocks. The contract's floor is 1 hour and its bond
 * cap is 10%; both are re-checked by the manifest schema, so a bad value fails before a transaction.
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
