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

  // ── Grant MANAGER permission on MerkleManager (idempotent) ─────
  for (const manager of [adManager, orderPortal]) {
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
    },
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
    },
  };
}
