import {
  readManifest,
  type ChainDeploymentManifest,
} from "@proofbridge/deployment-manifest";
import { connect, requireEnv } from "./common.js";
import { attachContract } from "./artifacts.js";
import { manifestPath } from "./manifest.js";

export interface LinkOptions {
  rpcUrl?: string;
  privateKey?: string;
  /** Path to this chain's own manifest. Defaults to deployments/<chainId>.json. */
  localManifest?: string;
  /** Path to the peer chain's manifest. Required. */
  peerManifest: string;
}

export interface LinkResult {
  localChainId: string;
  peerChainId: string;
  chainTxs: number;
  routeTxs: number;
}

/** Wires setChain + setTokenRoute on this chain's AdManager + OrderPortal from the peer manifest. Idempotent. */
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

  // ── Chain-level linking ────────────────────────────────────────────
  // Local adManager accepts from peer orderPortal; local orderPortal accepts from peer adManager.
  let chainTxs = 0;

  {
    const tx = await adManager.getFunction("setChain")(
      peerChainId,
      peer.contracts.orderPortal.addressBytes32,
      true,
      { nonce: nonces.next() },
    );
    await tx.wait();
    chainTxs++;
    console.log(
      `  [link] AdManager.setChain(${peerChainId}, peerOrderPortal=${peer.contracts.orderPortal.address})`,
    );
  }
  {
    const tx = await orderPortal.getFunction("setChain")(
      peerChainId,
      peer.contracts.adManager.addressBytes32,
      true,
      { nonce: nonces.next() },
    );
    await tx.wait();
    chainTxs++;
    console.log(
      `  [link] OrderPortal.setChain(${peerChainId}, peerAdManager=${peer.contracts.adManager.address})`,
    );
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

    // Direction A: local is ad-side.
    // AdManager.setTokenRoute(address adToken, bytes32 orderToken, uint256 orderChainId)
    {
      const tx = await adManager.getFunction("setTokenRoute")(
        localTok.address, // adToken
        peerTok.addressBytes32, // orderToken (bytes32)
        peerChainId, // orderChainId
        { nonce: nonces.next() },
      );
      await tx.wait();
      routeTxs++;
    }
    // Direction B: local is order-side.
    // OrderPortal.setTokenRoute(address orderToken, uint256 adChainId, bytes32 adToken)
    // Args 2/3 swap vs AdManager — mis-ordering here would silently mis-wire routes.
    {
      const tx = await orderPortal.getFunction("setTokenRoute")(
        localTok.address, // orderToken
        peerChainId, // adChainId
        peerTok.addressBytes32, // adToken (bytes32)
        { nonce: nonces.next() },
      );
      await tx.wait();
      routeTxs++;
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

export type { ChainDeploymentManifest };
