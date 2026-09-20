import { ethers } from "ethers";
import { MANAGER_ROLE, connect, envOrDefault, requireEnv } from "./common.js";
import {
  contractFactory,
  contractFactoryLinked,
  linkedLibraryIn,
  attachContract,
} from "./artifacts.js";
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
    poseidon2Yul: string;
    wNativeToken: string;
    adManager: string;
    orderPortal: string;
    sclEip6565: string;
    blsKeyRegistry: string;
    counterpartyVerifier: string;
    rootAnchor: string;
    registrar: string;
    disputeManager: string;
    agentPolicyCodec: string;
    agentPolicy: string;
  };
}

export async function deployCore(
  opts: DeployCoreOptions = {},
): Promise<DeployCoreResult> {
  const rpcUrl = opts.rpcUrl ?? requireEnv("EVM_RPC_URL");
  const privateKey = opts.privateKey ?? requireEnv("EVM_ADMIN_PRIVATE_KEY");

  const {
    signer,
    nonces,
    chainId,
    address: deployer,
  } = await connect(rpcUrl, privateKey);

  const admin = opts.admin ?? envOrDefault("ADMIN", deployer);
  const env = opts.env ?? envOrDefault("DEPLOY_ENV", "local");
  const commit = opts.commit ?? envOrDefault("GIT_COMMIT", "unknown");
  const chainName =
    opts.chainName ?? envOrDefault("CHAIN_NAME", `evm-${chainId}`);
  const wName =
    opts.wNative?.name ?? envOrDefault("WNATIVE_NAME", "Wrapped Native");
  const wSym =
    opts.wNative?.symbol ?? envOrDefault("WNATIVE_SYMBOL", "WNATIVE");
  const wDec =
    opts.wNative?.decimals ?? Number(envOrDefault("WNATIVE_DECIMALS", "18"));

  const outPath = opts.manifestOut ?? manifestPath(chainId);
  const reuse = opts.reuseExisting ?? true;
  const existing = reuse ? await loadOrNull(outPath) : null;

  console.log(`[evm-deploy] chain=${chainName} (id=${chainId}) env=${env}`);
  console.log(`[evm-deploy] deployer=${deployer} admin=${admin}`);
  if (existing) {
    console.log(`[evm-deploy] reusing addresses from ${outPath}`);
  }

  // The manifest is a claim; the chain is the fact. One pointed at the wrong chain, or at a devnet
  // that was reset, would otherwise print [reuse] for every contract and fail on the first read.
  // Checked for all of them at once, before anything is sent.
  if (existing) {
    const provider = signer.provider!;
    const codeless: string[] = [];
    for (const [name, entry] of Object.entries(existing.contracts)) {
      // The one entry the chain can correct: the module's code names its library (see below).
      if (name === "agentPolicyCodec" && existing.contracts.agentPolicy?.address) continue;
      const address = (entry as { address?: string } | undefined)?.address;
      if (address && (await provider.getCode(address)) === "0x") codeless.push(`${name} ${address}`);
    }
    if (codeless.length > 0) {
      throw new Error(
        `${outPath} names ${codeless.length} contract(s) with no code on chain ${chainId}:\n    ${codeless.join("\n    ")}\n` +
          `  Wrong chain, or a devnet that was reset? Delete the manifest (deploy-contracts.sh --fresh does) to deploy afresh.`,
      );
    }
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

  // Poseidon2 (Yul) hasher — deployed before MerkleManager (its constructor takes the address)
  // and recorded in the manifest so the authentic hasher is auditable.
  const poseidon2YulAddr = await deployIfMissing(
    "Poseidon2Yul",
    existing?.contracts.poseidon2Yul?.address,
    async () => {
      const f = contractFactory("Poseidon2Yul", "Poseidon2Yul_BN254", signer);
      const c = await f.deploy({ nonce: nonces.next() });
      await c.deploymentTransaction()?.wait();
      return c as ethers.Contract;
    },
  );

  // The receipt block seeds the ingester's scan start; a reused deployment
  // keeps the manifest's recorded value.
  let merkleManagerDeployBlock = existing?.contracts.merkleManager.deployBlock;
  const merkleManagerAddr = await deployIfMissing(
    "MerkleManager",
    existing?.contracts.merkleManager.address,
    async () => {
      const f = contractFactory("MerkleManager", "MerkleManager", signer);
      const c = await f.deploy(admin, poseidon2YulAddr, { nonce: nonces.next() });
      const receipt = await c.deploymentTransaction()?.wait();
      if (receipt?.blockNumber != null) {
        merkleManagerDeployBlock = receipt.blockNumber.toString();
      }
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

  // ── BLS stack (1.2): SCL library, key registry, module C verifier ──
  const sclAddr = await deployIfMissing(
    "SCL_EIP6565",
    existing?.contracts.sclEip6565?.address,
    async () => {
      const f = contractFactory("libSCL_EIP6565", "SCL_EIP6565", signer);
      const c = await f.deploy({ nonce: nonces.next() });
      await c.deploymentTransaction()?.wait();
      return c as ethers.Contract;
    },
  );

  const blsKeyRegistryAddr = await deployIfMissing(
    "BLSKeyRegistry",
    existing?.contracts.blsKeyRegistry?.address,
    async () => {
      const f = contractFactoryLinked("BLSKeyRegistry", "BLSKeyRegistry", signer, {
        SCL_EIP6565: sclAddr,
      });
      const c = await f.deploy(admin, { nonce: nonces.next() });
      await c.deploymentTransaction()?.wait();
      return c as ethers.Contract;
    },
  );

  const counterpartyVerifierAddr = await deployIfMissing(
    "CounterpartyVerifier",
    existing?.contracts.counterpartyVerifier?.address,
    async () => {
      const f = contractFactory("CounterpartyVerifier", "CounterpartyVerifier", signer);
      const c = await f.deploy(blsKeyRegistryAddr, { nonce: nonces.next() });
      await c.deploymentTransaction()?.wait();
      return c as ethers.Contract;
    },
  );

  // ── RootAnchor (2.3f) + Registrar (2.1b) ───────────────────────────
  // T2 notary: the publisher key(s) in ANCHOR_PUBLISHER (comma-separated, default
  // admin) at ANCHOR_THRESHOLD (default 1); the ladder later swaps the set with
  // setSigners. Per-route delays are set at link time (ANCHOR_DELAY_S).
  const anchorSigners = envOrDefault("ANCHOR_PUBLISHER", admin)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const anchorThreshold = Number(envOrDefault("ANCHOR_THRESHOLD", "1"));
  const rootAnchorAddr = await deployIfMissing(
    "RootAnchor",
    existing?.contracts.rootAnchor?.address,
    async () => {
      const f = contractFactory("RootAnchor", "RootAnchor", signer);
      const c = await f.deploy(admin, anchorSigners, anchorThreshold, {
        nonce: nonces.next(),
      });
      await c.deploymentTransaction()?.wait();
      return c as ethers.Contract;
    },
  );

  // The home-chain REGISTERED-leaf appender; needs MANAGER_ROLE on the MerkleManager (granted
  // below). The registry's proof path stays switched off (2.1b §7); nothing wires it here.
  const registrarAddr = await deployIfMissing(
    "Registrar",
    existing?.contracts.registrar?.address,
    async () => {
      const f = contractFactory("Registrar", "Registrar", signer);
      const c = await f.deploy(merkleManagerAddr, { nonce: nonces.next() });
      await c.deploymentTransaction()?.wait();
      return c as ethers.Contract;
    },
  );

  // The dispute module (2.3g) both escrows share. It holds bonds, never escrow funds, and takes no
  // MerkleManager role — disputes append no leaf. Escrow ↔ module wiring happens at link time.
  const disputeManagerAddr = await deployIfMissing(
    "DisputeManager",
    existing?.contracts.disputeManager?.address,
    async () => {
      const f = contractFactory("DisputeManager", "DisputeManager", signer);
      const c = await f.deploy(admin, wNativeAddr, { nonce: nonces.next() });
      await c.deploymentTransaction()?.wait();
      return c as ethers.Contract;
    },
  );

  // The arbiter and the fee pool, without which the module is deployed but inert: `resolveDispute`
  // reverts for every caller, so every dispute falls to the fallback, and an unset fee pool returns
  // every forfeited bond to the filer. Both are set here rather than left to a follow-up, because a
  // half-wired dispute module is indistinguishable from a working one until someone files.
  //
  // The arbiter must not be the admin (2.3g D6): its whole containment is that it cannot pause an
  // escrow, re-route tokens or re-point the anchor. Outside a local deploy both are explicit.
  {
    const dm = attachContract(disputeManagerAddr, "DisputeManager", "DisputeManager", signer);
    const arbiterAddr = disputeRole("DISPUTE_ARBITER", env, admin);
    const feePoolAddr = disputeRole("DISPUTE_FEE_POOL", env, admin);
    if (env !== "local" && arbiterAddr.toLowerCase() === admin.toLowerCase()) {
      throw new Error(
        "deploy-core: DISPUTE_ARBITER must not be the admin — the arbiter's containment is that it holds no escrow powers",
      );
    }
    for (const [name, fn, value] of [
      ["arbiter", "setArbiter", arbiterAddr],
      ["protocolFeePool", "setProtocolFeePool", feePoolAddr],
    ] as const) {
      const cur = await dm.getFunction(name)();
      if (cur.toLowerCase() === value.toLowerCase()) {
        console.log(`  [skip] DisputeManager.${fn} already ${value}`);
        continue;
      }
      const tx = await dm.getFunction(fn)(value, { nonce: nonces.next() });
      await tx.wait();
      console.log(`  [deploy] DisputeManager.${fn}(${value})`);
    }
  }

  // ── agent policy module (2.1g): the parser library, then the module linked to it ──
  // One shared, ownerless contract per chain that every maker's account installs. Reused only as
  // a pair: a reused module still points at the library it was linked with.
  // The module is the one contract makers install, so its address never moves because the
  // *library's* entry is wrong. Its code says which library it was linked with: read that, and
  // correct the manifest. A module linked to nothing is not something a deploy can repair.
  const reusedAgentPolicy = existing?.contracts.agentPolicy?.address;
  let reusedAgentCodec = existing?.contracts.agentPolicyCodec?.address;
  if (reusedAgentPolicy) {
    const provider = signer.provider!;
    const linked = linkedLibraryIn(
      "ProofBridgeAgentPolicy",
      "ProofBridgeAgentPolicy",
      "AgentPolicyCodec",
      await provider.getCode(reusedAgentPolicy),
    );
    if (!linked || (await provider.getCode(linked)) === "0x") {
      throw new Error(
        `ProofBridgeAgentPolicy at ${reusedAgentPolicy} is not linked to a deployed AgentPolicyCodec (read ${linked ?? "nothing"} from its code). ` +
          `Makers install this address, so it is not replaced automatically: remove agentPolicy and agentPolicyCodec from the manifest to deploy a new pair.`,
      );
    }
    if (linked.toLowerCase() !== reusedAgentCodec?.toLowerCase()) {
      console.warn(
        `  [repair] manifest says AgentPolicyCodec is ${reusedAgentCodec ?? "absent"}; the module's code is linked to ${linked}. Recording ${linked}; the module is untouched.`,
      );
      reusedAgentCodec = linked;
    }
  }
  const agentPolicyCodecAddr = await deployIfMissing(
    "AgentPolicyCodec",
    reusedAgentPolicy ? reusedAgentCodec : undefined,
    async () => {
      const f = contractFactory("AgentPolicyCodec", "AgentPolicyCodec", signer);
      const c = await f.deploy({ nonce: nonces.next() });
      await c.deploymentTransaction()?.wait();
      return c as ethers.Contract;
    },
  );
  const agentPolicyAddr = await deployIfMissing(
    "ProofBridgeAgentPolicy",
    reusedAgentPolicy,
    async () => {
      const f = contractFactoryLinked("ProofBridgeAgentPolicy", "ProofBridgeAgentPolicy", signer, {
        AgentPolicyCodec: agentPolicyCodecAddr,
      });
      const c = await f.deploy({ nonce: nonces.next() });
      await c.deploymentTransaction()?.wait();
      return c as ethers.Contract;
    },
  );

  // ── wire the escrows as the registry's revoke guards ──────────────
  // Re-set every run (idempotent); guards only gate key revocation/rotation.
  {
    const registry = attachContract(
      blsKeyRegistryAddr,
      "BLSKeyRegistry",
      "BLSKeyRegistry",
      signer,
    );
    const setGuards = registry.getFunction("setPositionGuards");
    try {
      // Estimate before taking a nonce: a revert here (signer not the registry admin) must not
      // leave a gap the next tx.wait() hangs on.
      await setGuards.estimateGas([adManagerAddr, orderPortalAddr]);
      const tx = await setGuards([adManagerAddr, orderPortalAddr], { nonce: nonces.next() });
      await tx.wait();
      console.log(`  [wire] BLSKeyRegistry.setPositionGuards([AdManager, OrderPortal])`);
    } catch (err) {
      console.warn(
        `  [wire] setPositionGuards FAILED (signer may not be registry admin): ${err}`,
      );
    }
  }

  // ── point the AdManager at the registry (2.3c) ────────────────────
  // createAd / setSettlementSigner / lockForOrder fail closed until this is set: an ad's
  // settlement signer must hold a live, unexpired key. A fail-closed wire that does not land
  // is a deploy failure, not a warning: nothing else in the run is usable without it.
  {
    const adManager = attachContract(adManagerAddr, "AdManager", "AdManager", signer);
    let cur: string;
    try {
      cur = await adManager.getFunction("keyRegistry")();
    } catch (err) {
      // A reused pre-2.3c AdManager has no `keyRegistry()`: the call lands in its fallback.
      throw new Error(
        `AdManager at ${adManagerAddr} has no keyRegistry() (pre-2.3c bytecode?); redeploy it instead of reusing: ${err}`,
      );
    }
    if (cur.toLowerCase() === blsKeyRegistryAddr.toLowerCase()) {
      console.log(`  [skip] AdManager.setKeyRegistry already set`);
    } else {
      const setKeyRegistry = adManager.getFunction("setKeyRegistry");
      try {
        await setKeyRegistry.estimateGas(blsKeyRegistryAddr);
      } catch (err) {
        throw new Error(
          `AdManager.setKeyRegistry(${blsKeyRegistryAddr}) would revert (signer not the AdManager admin?): ${err}`,
        );
      }
      const tx = await setKeyRegistry(blsKeyRegistryAddr, { nonce: nonces.next() });
      await tx.wait();
      console.log(`  [wire] AdManager.setKeyRegistry(${blsKeyRegistryAddr})`);
    }
  }

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
    { name: "Registrar", addr: registrarAddr },
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
      merkleManagerDeployBlock,
      poseidon2Yul: poseidon2YulAddr,
      wNativeToken: wNativeAddr,
      adManager: adManagerAddr,
      orderPortal: orderPortalAddr,
      sclEip6565: sclAddr,
      blsKeyRegistry: blsKeyRegistryAddr,
      counterpartyVerifier: counterpartyVerifierAddr,
      rootAnchor: rootAnchorAddr,
      registrar: registrarAddr,
      disputeManager: disputeManagerAddr,
      agentPolicyCodec: agentPolicyCodecAddr,
      agentPolicy: agentPolicyAddr,
    },
    // Preserve tokens already in the manifest (added by deploy-test-tokens / hand-curation).
    tokens: (existing?.tokens ?? []) as BuildManifestInput["tokens"],
    // What the anchor was configured with; per-route delays are added by link.
    // The route clocks link set last time; a redeploy keeps them until link runs again.
    routeTiming: existing?.routeTiming,
    // Same rule as the clocks: a redeploy keeps the dispute params until link runs again.
    disputeParams: existing?.disputeParams,
    rootAnchorConfig: existing?.contracts.rootAnchor
      ? existing.rootAnchorConfig
      : { signers: anchorSigners, threshold: anchorThreshold, anchorDelays: {} },
  });

  await writeManifest(outPath, manifest);
  console.log(`[evm-deploy] wrote manifest → ${outPath}`);

  return {
    manifestPath: outPath,
    chainId,
    contracts: {
      verifier: verifierAddr,
      merkleManager: merkleManagerAddr,
      poseidon2Yul: poseidon2YulAddr,
      wNativeToken: wNativeAddr,
      adManager: adManagerAddr,
      orderPortal: orderPortalAddr,
      sclEip6565: sclAddr,
      blsKeyRegistry: blsKeyRegistryAddr,
      counterpartyVerifier: counterpartyVerifierAddr,
      rootAnchor: rootAnchorAddr,
      registrar: registrarAddr,
      disputeManager: disputeManagerAddr,
      agentPolicyCodec: agentPolicyCodecAddr,
      agentPolicy: agentPolicyAddr,
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
