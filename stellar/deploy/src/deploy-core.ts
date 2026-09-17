import * as path from "path";
import {
  DEFAULT_STELLAR_CHAIN_ID,
  envOrDefault,
  requireEnv,
  vkPath,
  wasmDir,
} from "./common.js";
import {
  deployContract,
  deploySAC,
  getAddress,
  invokeContract,
  latestLedger,
} from "./stellar-cli.js";
import {
  buildManifest,
  loadOrNull,
  manifestPath,
  writeManifest,
  type BuildStellarManifestInput,
} from "./manifest.js";

export interface DeployStellarCoreOptions {
  chainId?: bigint;
  chainName?: string;
  env?: string;
  commit?: string;
  adminStrkey?: string;
  /** Absolute path to the wasm build dir. Defaults to contracts/stellar/target/... */
  wasmDir?: string;
  vkPath?: string;
  manifestOut?: string;
  reuseExisting?: boolean;
}

export interface DeployStellarCoreResult {
  manifestPath: string;
  chainId: bigint;
  adminStrkey: string;
  contracts: {
    verifier: string;
    merkleManager: string;
    wNativeToken: string;
    adManager: string;
    orderPortal: string;
    blsKeyRegistry: string;
    counterpartyVerifier: string;
    rootAnchor: string;
    disputeManager: string;
    registrar: string;
  };
}

export async function deployCore(
  opts: DeployStellarCoreOptions = {},
): Promise<DeployStellarCoreResult> {
  const chainId = opts.chainId ?? DEFAULT_STELLAR_CHAIN_ID;
  const env = opts.env ?? envOrDefault("DEPLOY_ENV", "local");
  const commit = opts.commit ?? envOrDefault("GIT_COMMIT", "unknown");
  const chainName =
    opts.chainName ?? envOrDefault("CHAIN_NAME", `stellar-${chainId}`);
  const wasmBase = opts.wasmDir ?? wasmDir();
  const vk = opts.vkPath ?? vkPath();
  const outPath = opts.manifestOut ?? manifestPath(chainId);
  const reuse = opts.reuseExisting ?? true;
  const existing = reuse ? await loadOrNull(outPath) : null;

  const adminStrkey = opts.adminStrkey ?? getAddress();

  console.log(`[stellar-deploy] chain=${chainName} (id=${chainId}) env=${env}`);
  console.log(`[stellar-deploy] admin=${adminStrkey}`);
  if (existing) {
    console.log(`[stellar-deploy] reusing addresses from ${outPath}`);
  }

  function reused(existingAddr: string | undefined): string | undefined {
    return existingAddr;
  }

  // ── Verifier ────────────────────────────────────────────────────
  let verifier = reused(existing?.contracts.verifier.address);
  if (!verifier) {
    verifier = deployContract(path.join(wasmBase, "verifier.wasm"), [
      "--vk_bytes-file-path",
      vk,
    ]);
    console.log(`  [deploy] Verifier: ${verifier}`);
  } else {
    console.log(`  [reuse] Verifier: ${verifier}`);
  }

  // ── MerkleManager ───────────────────────────────────────────────
  let merkleManager = reused(existing?.contracts.merkleManager.address);
  let merkleManagerDeployBlock = existing?.contracts.merkleManager.deployBlock;
  if (!merkleManager) {
    // Pre-deploy ledger: a safe lower bound for the ingester's scan start.
    merkleManagerDeployBlock = latestLedger() ?? merkleManagerDeployBlock;
    merkleManager = deployContract(path.join(wasmBase, "merkle_manager.wasm"));
    invokeContract(merkleManager, "initialize", ["--admin", adminStrkey]);
    console.log(`  [deploy] MerkleManager: ${merkleManager}`);
  } else {
    console.log(`  [reuse] MerkleManager: ${merkleManager}`);
  }

  // ── wNativeToken (native XLM SAC) ───────────────────────────────
  let wNativeToken = reused(existing?.contracts.wNativeToken.address);
  if (!wNativeToken) {
    wNativeToken = deploySAC("native");
    console.log(`  [deploy] wNativeToken (native XLM SAC): ${wNativeToken}`);
  } else {
    console.log(`  [reuse] wNativeToken: ${wNativeToken}`);
  }

  // ── AdManager ──────────────────────────────────────────────────
  let adManager = reused(existing?.contracts.adManager.address);
  if (!adManager) {
    adManager = deployContract(path.join(wasmBase, "ad_manager.wasm"));
    invokeContract(adManager, "initialize", [
      "--admin",
      adminStrkey,
      "--verifier",
      verifier,
      "--merkle_manager",
      merkleManager,
      "--w_native_token",
      wNativeToken,
      "--chain_id",
      chainId.toString(),
    ]);
    console.log(`  [deploy] AdManager: ${adManager}`);
  } else {
    console.log(`  [reuse] AdManager: ${adManager}`);
  }

  // ── OrderPortal ────────────────────────────────────────────────
  let orderPortal = reused(existing?.contracts.orderPortal.address);
  if (!orderPortal) {
    orderPortal = deployContract(path.join(wasmBase, "order_portal.wasm"));
    invokeContract(orderPortal, "initialize", [
      "--admin",
      adminStrkey,
      "--verifier",
      verifier,
      "--merkle_manager",
      merkleManager,
      "--w_native_token",
      wNativeToken,
      "--chain_id",
      chainId.toString(),
    ]);
    console.log(`  [deploy] OrderPortal: ${orderPortal}`);
  } else {
    console.log(`  [reuse] OrderPortal: ${orderPortal}`);
  }

  // ── BLS stack (1.2): key registry + module C verifier ──────────
  let blsKeyRegistry = reused(existing?.contracts.blsKeyRegistry?.address);
  if (!blsKeyRegistry) {
    blsKeyRegistry = deployContract(path.join(wasmBase, "bls_key_registry.wasm"));
    invokeContract(blsKeyRegistry, "initialize", [
      "--admin",
      adminStrkey,
      "--chain_id",
      chainId.toString(),
    ]);
    console.log(`  [deploy] BLSKeyRegistry: ${blsKeyRegistry}`);
  } else {
    console.log(`  [reuse] BLSKeyRegistry: ${blsKeyRegistry}`);
  }

  let counterpartyVerifier = reused(
    existing?.contracts.counterpartyVerifier?.address,
  );
  if (!counterpartyVerifier) {
    counterpartyVerifier = deployContract(
      path.join(wasmBase, "counterparty_verifier.wasm"),
    );
    invokeContract(counterpartyVerifier, "initialize", [
      "--registry",
      blsKeyRegistry,
    ]);
    console.log(`  [deploy] CounterpartyVerifier: ${counterpartyVerifier}`);
  } else {
    console.log(`  [reuse] CounterpartyVerifier: ${counterpartyVerifier}`);
  }

  // ── Wire the escrows as the registry's revoke guards (idempotent) ──
  invokeContract(blsKeyRegistry, "set_position_guards", [
    "--guards",
    JSON.stringify([adManager, orderPortal]),
  ]);

  // ── Point the AdManager at the registry (2.3c; idempotent) ─────────
  // create_ad / set_settlement_signer / lock_for_order fail closed until this is set: an
  // ad's settlement signer must hold a live, unexpired key.
  invokeContract(adManager, "set_key_registry", ["--registry", blsKeyRegistry]);

  // ── RootAnchor (2.3f) + Registrar (2.1b) ───────────────────────────
  // T2 notary: the publisher key(s) in ANCHOR_PUBLISHER (comma-separated G-addresses,
  // default admin) at ANCHOR_THRESHOLD (default 1). Per-route delays are set at link time.
  const anchorSigners = envOrDefault("ANCHOR_PUBLISHER", adminStrkey)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const anchorThreshold = Number(envOrDefault("ANCHOR_THRESHOLD", "1"));
  let rootAnchor = reused(existing?.contracts.rootAnchor?.address);
  if (!rootAnchor) {
    rootAnchor = deployContract(path.join(wasmBase, "root_anchor.wasm"));
    invokeContract(rootAnchor, "initialize", [
      "--admin",
      adminStrkey,
      "--signers",
      JSON.stringify(anchorSigners),
      "--threshold",
      String(anchorThreshold),
    ]);
    console.log(`  [deploy] RootAnchor: ${rootAnchor}`);
  } else {
    console.log(`  [reuse] RootAnchor: ${rootAnchor}`);
  }

  // The home-chain REGISTERED-leaf appender; a manager on the MerkleManager (set below). The
  // registry's proof path stays switched off (2.1b §7); nothing wires it here.
  let registrar = reused(existing?.contracts.registrar?.address);
  if (!registrar) {
    registrar = deployContract(path.join(wasmBase, "registrar.wasm"));
    invokeContract(registrar, "initialize", ["--merkle_manager", merkleManager]);
    console.log(`  [deploy] Registrar: ${registrar}`);
  } else {
    console.log(`  [reuse] Registrar: ${registrar}`);
  }

  // The dispute module (2.3g) both escrows share. Holds bonds, never escrow funds, and takes no
  // MerkleManager role — disputes append no leaf. Escrow ↔ module wiring happens at link time.
  let disputeManager = reused(existing?.contracts.disputeManager?.address);
  if (!disputeManager) {
    disputeManager = deployContract(path.join(wasmBase, "dispute_manager.wasm"));
    invokeContract(disputeManager, "initialize", [
      "--admin",
      adminStrkey,
      "--w_native",
      wNativeToken,
    ]);
    console.log(`  [deploy] DisputeManager: ${disputeManager}`);
  } else {
    console.log(`  [reuse] DisputeManager: ${disputeManager}`);
  }

  // The arbiter and the fee pool, without which the module is deployed but inert: `resolve_dispute`
  // fails for every caller, so every dispute falls to the fallback, and an unset fee pool returns
  // every forfeited bond to the filer. A half-wired dispute module looks exactly like a working one
  // until someone files, so both are set at deploy rather than left to a follow-up.
  //
  // The arbiter must not be the admin (2.3g D6): its containment is that it holds no escrow powers.
  {
    const arbiterAddr = disputeRole("DISPUTE_ARBITER", env, adminStrkey);
    const feePoolAddr = disputeRole("DISPUTE_FEE_POOL", env, adminStrkey);
    if (env !== "local" && arbiterAddr === adminStrkey) {
      throw new Error(
        "deploy-core: DISPUTE_ARBITER must not be the admin — the arbiter's containment is that it holds no escrow powers",
      );
    }
    invokeContract(disputeManager, "set_arbiter", ["--arbiter", arbiterAddr]);
    invokeContract(disputeManager, "set_protocol_fee_pool", ["--pool", feePoolAddr]);
    console.log(`  [deploy] DisputeManager arbiter=${arbiterAddr} feePool=${feePoolAddr}`);
  }

  // ── Grant MANAGER permission on MerkleManager (idempotent) ─────
  for (const manager of [adManager, orderPortal, registrar]) {
    invokeContract(merkleManager, "set_manager", [
      "--manager",
      manager,
      "--status",
      "true",
    ]);
  }

  // ── manifest ───────────────────────────────────────────────────
  const manifest = buildManifest({
    chainName,
    chainId,
    env,
    commit,
    deployer: adminStrkey,
    contracts: {
      verifier,
      merkleManager,
      merkleManagerDeployBlock,
      wNativeToken,
      adManager,
      orderPortal,
      blsKeyRegistry,
      counterpartyVerifier,
      rootAnchor,
      registrar,
      disputeManager,
    },
    // What the anchor was configured with; per-route delays are added by link.
    // The route clocks link set last time; a redeploy keeps them until link runs again.
    routeTiming: existing?.routeTiming,
    // Same rule as the clocks: a redeploy keeps the dispute params until link runs again.
    disputeParams: existing?.disputeParams,
    rootAnchorConfig: existing?.contracts.rootAnchor
      ? existing.rootAnchorConfig
      : { signers: anchorSigners, threshold: anchorThreshold, anchorDelays: {} },
    // Preserve tokens already in the manifest (test / curated). XLM entry is (re)set by deploy-test-tokens.
    tokens: (existing?.tokens.map((t) => ({
      pairKey: t.pairKey,
      symbol: t.symbol,
      name: t.name,
      contractId: t.address,
      kind: t.kind as "NATIVE" | "SAC" | "SEP41",
      decimals: t.decimals,
      assetIssuer: t.assetIssuer ?? null,
      isTestToken: t.isTestToken,
    })) ?? []) as BuildStellarManifestInput["tokens"],
  });

  await writeManifest(outPath, manifest);
  console.log(`[stellar-deploy] wrote manifest → ${outPath}`);

  return {
    manifestPath: outPath,
    chainId,
    adminStrkey,
    contracts: {
      verifier,
      merkleManager,
      wNativeToken,
      adManager,
      orderPortal,
      blsKeyRegistry,
      counterpartyVerifier,
      rootAnchor,
      registrar,
      disputeManager,
    },
  };
}

/// A dispute role address from env. Local deploys fall back to the admin so a dev stack works out of
/// the box; everywhere else it must be named, like every other dispute parameter.
function disputeRole(name: string, env: string, fallback: string): string {
  const v = process.env[name];
  if (v) return v;
  if (env === "local") return fallback;
  throw new Error(
    `deploy-core: ${name} is unset for env=${env}; set it or deploy with DEPLOY_ENV=local`,
  );
}
