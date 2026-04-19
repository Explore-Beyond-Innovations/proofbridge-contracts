import { ethers } from "ethers";
import {
  MANAGER_ROLE,
  connect,
  envOrDefault,
  requireEnv,
} from "./common.js";
import { contractFactory, attachContract } from "./artifacts.js";
import {
  buildManifest,
  loadOrNull,
  manifestPath,
  writeManifest,
  type BuildManifestInput,
} from "./manifest.js";

export interface DeployCoreOptions {
  /** JSON-RPC URL. Defaults to EVM_RPC_URL. */
  rpcUrl?: string;
  /** Deployer + initial admin private key. Defaults to EVM_ADMIN_PRIVATE_KEY. */
  privateKey?: string;
  /** Human-readable chain name, stored in the manifest. Defaults to CHAIN_NAME or <chainId>. */
  chainName?: string;
  /** Logical environment tag. Defaults to DEPLOY_ENV or "local". */
  env?: string;
  /** Commit sha stamped into the manifest. Defaults to GIT_COMMIT or "unknown". */
  commit?: string;
  /** Admin address. Defaults to $ADMIN or deployer. */
  admin?: string;
  /** wNativeToken branding. Defaults: Wrapped Native / WNATIVE / 18. */
  wNative?: { name?: string; symbol?: string; decimals?: number };
  /** Manifest write path. Defaults to contracts/evm/deployments/<chainId>.json. */
  manifestOut?: string;
  /** Reuse already-deployed addresses from the existing manifest. Default true. */
  reuseExisting?: boolean;
}

export interface DeployCoreResult {
  manifestPath: string;
  chainId: bigint;
  contracts: {
    verifier: string;
    merkleManager: string;
    wNativeToken: string;
    adManager: string;
    orderPortal: string;
  };
}

export async function deployCore(
  opts: DeployCoreOptions = {},
): Promise<DeployCoreResult> {
  const rpcUrl = opts.rpcUrl ?? requireEnv("EVM_RPC_URL");
  const privateKey =
    opts.privateKey ?? requireEnv("EVM_ADMIN_PRIVATE_KEY");

  const { signer, nonces, chainId, address: deployer } = await connect(
    rpcUrl,
    privateKey,
  );

  const admin = opts.admin ?? envOrDefault("ADMIN", deployer);
  const env = opts.env ?? envOrDefault("DEPLOY_ENV", "local");
  const commit = opts.commit ?? envOrDefault("GIT_COMMIT", "unknown");
  const chainName =
    opts.chainName ?? envOrDefault("CHAIN_NAME", `evm-${chainId}`);
  const wName = opts.wNative?.name ?? envOrDefault("WNATIVE_NAME", "Wrapped Native");
  const wSym = opts.wNative?.symbol ?? envOrDefault("WNATIVE_SYMBOL", "WNATIVE");
  const wDec = opts.wNative?.decimals ?? Number(envOrDefault("WNATIVE_DECIMALS", "18"));

  const outPath = opts.manifestOut ?? manifestPath(chainId);
  const reuse = opts.reuseExisting ?? true;
  const existing = reuse ? await loadOrNull(outPath) : null;

  console.log(`[evm-deploy] chain=${chainName} (id=${chainId}) env=${env}`);
  console.log(`[evm-deploy] deployer=${deployer} admin=${admin}`);
  if (existing) {
    console.log(`[evm-deploy] reusing addresses from ${outPath}`);
  }

  async function deployIfMissing(
    label: string,
    reused: string | undefined,
    deployFn: () => Promise<ethers.Contract>,
  ): Promise<string> {
    if (reused) {
      console.log(`  [reuse] ${label}: ${reused}`);
      return reused;
    }
    console.log(`  [deploy] ${label}...`);
    const c = await deployFn();
    const addr = await c.getAddress();
    console.log(`  [deploy] ${label}: ${addr}`);
    return addr;
  }

  // ── core contracts ────────────────────────────────────────────────
  const verifierAddr = await deployIfMissing(
    "Verifier",
    existing?.contracts.verifier.address,
    async () => {
      const f = contractFactory("Verifier", "HonkVerifier", signer);
      const c = await f.deploy({ nonce: nonces.next() });
      await c.deploymentTransaction()?.wait();
      return c as ethers.Contract;
    },
  );

  const merkleManagerAddr = await deployIfMissing(
    "MerkleManager",
    existing?.contracts.merkleManager.address,
    async () => {
      const f = contractFactory("MerkleManager", "MerkleManager", signer);
      const c = await f.deploy(admin, { nonce: nonces.next() });
      await c.deploymentTransaction()?.wait();
      return c as ethers.Contract;
    },
  );

  const wNativeAddr = await deployIfMissing(
    "wNativeToken",
    existing?.contracts.wNativeToken.address,
    async () => {
      const f = contractFactory("wNativeToken", "wNativeToken", signer);
      const c = await f.deploy(wName, wSym, wDec, { nonce: nonces.next() });
      await c.deploymentTransaction()?.wait();
      return c as ethers.Contract;
    },
  );

  const adManagerAddr = await deployIfMissing(
    "AdManager",
    existing?.contracts.adManager.address,
    async () => {
      const f = contractFactory("AdManager", "AdManager", signer);
      const c = await f.deploy(
        admin,
        verifierAddr,
        merkleManagerAddr,
        wNativeAddr,
        { nonce: nonces.next() },
      );
      await c.deploymentTransaction()?.wait();
      return c as ethers.Contract;
    },
  );

  const orderPortalAddr = await deployIfMissing(
    "OrderPortal",
    existing?.contracts.orderPortal.address,
    async () => {
      const f = contractFactory("OrderPortal", "OrderPortal", signer);
      const c = await f.deploy(
        admin,
        verifierAddr,
        merkleManagerAddr,
        wNativeAddr,
        { nonce: nonces.next() },
      );
      await c.deploymentTransaction()?.wait();
      return c as ethers.Contract;
    },
  );

  // ── grant MANAGER_ROLE to AdManager + OrderPortal ─────────────────
  // Re-granted every run (idempotent); caught in case admin is a multisig that'll grant out of band.
  const merkleManager = attachContract(
    merkleManagerAddr,
    "MerkleManager",
    "MerkleManager",
    signer,
  );
  for (const { name, addr } of [
    { name: "AdManager", addr: adManagerAddr },
    { name: "OrderPortal", addr: orderPortalAddr },
  ]) {
    try {
      const tx = await merkleManager.getFunction("grantRole")(
        MANAGER_ROLE,
        addr,
        { nonce: nonces.next() },
      );
      await tx.wait();
      console.log(`  [grant] MANAGER_ROLE → ${name}`);
    } catch (err) {
      console.warn(
        `  [grant] MANAGER_ROLE → ${name} FAILED (signer may lack DEFAULT_ADMIN_ROLE): ${err}`,
      );
    }
  }

  const manifest = buildManifest({
    chainName,
    chainId,
    env,
    commit,
    deployer,
    contracts: {
      verifier: verifierAddr,
      merkleManager: merkleManagerAddr,
      wNativeToken: wNativeAddr,
      adManager: adManagerAddr,
      orderPortal: orderPortalAddr,
    },
    // Preserve tokens already in the manifest (added by deploy-test-tokens / hand-curation).
    tokens: (existing?.tokens ?? []) as BuildManifestInput["tokens"],
  });

  await writeManifest(outPath, manifest);
  console.log(`[evm-deploy] wrote manifest → ${outPath}`);

  return {
    manifestPath: outPath,
    chainId,
    contracts: {
      verifier: verifierAddr,
      merkleManager: merkleManagerAddr,
      wNativeToken: wNativeAddr,
      adManager: adManagerAddr,
      orderPortal: orderPortalAddr,
    },
  };
}
