import {
  readManifest,
  type ChainDeploymentManifest,
} from "@proofbridge/deployment-manifest";
import { DEFAULT_STELLAR_CHAIN_ID } from "./common.js";
import { invokeContract } from "./stellar-cli.js";
import { manifestPath } from "./manifest.js";

export interface StellarLinkOptions {
  /** Path to this chain's own manifest. Defaults to deployments/<chainId>.json. */
  localManifest?: string;
  /** Path to the peer chain's manifest. Required. */
  peerManifest: string;
  /** Override local chain id (rarely needed — defaults to 1000001). */
  localChainId?: bigint;
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
