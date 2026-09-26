import * as fs from "fs";
import { assertOneRegistry, checkPeers, switchKeyRegistry, verifierRegistry, type EscrowWiring } from "./one-registry.js";
import { ethers } from "ethers";
import {
  ADMIN_BEARING,
  Acting,
  MANAGER_ROLE,
  adminBlockFromChain,
  adminsOf,
  connect,
  envOrDefault,
  foreignAdmins,
  requireEnv,
  type DescribedCall,
} from "./common.js";
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
  /**
   * Refused unless it is the deployer (#424). Every contract is deployed with the deployer as admin,
   * because deploy and link make admin-only calls from that key; the real admin is nominated
   * afterwards by `handover`. Kept so a caller naming one gets the refusal rather than a silent
   * ignore.
   */
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
  /** Admin-only calls the signer could not make (the admin was handed over); empty when all sent. */
  described: DescribedCall[];
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

/** What a run has put on chain so far, kept so that a failure after the first deploy is not a loss. */
interface RunLog {
  outPath?: string;
  deployed: { label: string; address: string }[];
}

export async function deployCore(
  opts: DeployCoreOptions = {},
): Promise<DeployCoreResult> {
  const run: RunLog = { deployed: [] };
  try {
    return await deployCoreRun(opts, run);
  } catch (err) {
    // The manifest is written once, at the end. What can be refused before sending is (see the
    // top of the run); a transaction can still revert in the middle, and these would be orphans.
    if (run.deployed.length > 0) {
      const lines = run.deployed.map((d) => `${d.label} ${d.address}`);
      console.error(
        `[evm-deploy] FAILED after deploying ${lines.length} contract(s) that are in no manifest:\n    ${lines.join("\n    ")}`,
      );
      if (run.outPath) {
        // Not *.json: deploy-contracts.sh takes the newest .json in this directory as the manifest.
        const side = run.outPath.replace(/\.json$/, "") + ".deployed-this-run.txt";
        fs.writeFileSync(side, lines.join("\n") + "\n");
        console.error(`[evm-deploy] also written to ${side}; add them to the manifest rather than deploying again`);
      }
    }
    throw err;
  }
}

async function deployCoreRun(
  opts: DeployCoreOptions,
  run: RunLog,
): Promise<DeployCoreResult> {
  const rpcUrl = opts.rpcUrl ?? requireEnv("EVM_RPC_URL");
  const privateKey = opts.privateKey ?? requireEnv("EVM_ADMIN_PRIVATE_KEY");

  const {
    signer,
    nonces,
    chainId,
    address: deployer,
  } = await connect(rpcUrl, privateKey);

  // The deployer is the admin at deploy time, always. A named ADMIN used to be the constructor
  // argument, and every admin-only wiring call from the deployer then reverted, twelve contracts in.
  const namedAdmin = opts.admin ?? process.env.ADMIN;
  if (namedAdmin && namedAdmin.toLowerCase() !== deployer.toLowerCase()) {
    throw new Error(
      `deploy-core: ADMIN=${namedAdmin} is not the deployer ${deployer}. Every contract is deployed with the deployer as admin ` +
        `(deploy and link are admin-only); hand over afterwards with \`handover --to ${namedAdmin}\` ` +
        `(deploy-contracts.sh --handover with HANDOVER_ADMIN set). Nothing was sent.`,
    );
  }
  const admin = deployer;
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
  run.outPath = outPath;
  const reuse = opts.reuseExisting ?? true;
  const existing = reuse ? await loadOrNull(outPath) : null;

  console.log(`[evm-deploy] chain=${chainName} (id=${chainId}) env=${env}`);
  console.log(`[evm-deploy] deployer=${deployer} (admin until handover)`);
  if (existing) {
    console.log(`[evm-deploy] reusing addresses from ${outPath}`);
  }

  // ── everything that can be refused before sending, is ─────────────
  // The manifest is written once, at the end, so a run that stops after a contract has gone out
  // leaves it in no manifest. What depends only on the environment is settled here.
  if (!Number.isInteger(wDec) || wDec < 0 || wDec > 255) {
    throw new Error(`deploy-core: WNATIVE_DECIMALS must be an integer 0..255, got ${wDec}`);
  }
  const anchorSigners = envOrDefault("ANCHOR_PUBLISHER", admin)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const anchorThreshold = Number(envOrDefault("ANCHOR_THRESHOLD", "1"));
  for (const a of [admin, ...anchorSigners]) {
    if (!ethers.isAddress(a)) throw new Error(`deploy-core: not an address: ${a} (ADMIN / ANCHOR_PUBLISHER)`);
  }
  if (!Number.isInteger(anchorThreshold) || anchorThreshold < 1 || anchorThreshold > anchorSigners.length) {
    throw new Error(
      `deploy-core: ANCHOR_THRESHOLD must be 1..${anchorSigners.length} (the number of ANCHOR_PUBLISHER signers), got ${anchorThreshold}`,
    );
  }
  // The arbiter must not be the admin (2.3g D6): its whole containment is that it cannot pause an
  // escrow, re-route tokens or re-point the anchor. Outside a local deploy both roles are explicit.
  const arbiterAddr = disputeRole("DISPUTE_ARBITER", env, admin);
  const feePoolAddr = disputeRole("DISPUTE_FEE_POOL", env, admin);
  for (const a of [arbiterAddr, feePoolAddr]) {
    if (!ethers.isAddress(a)) throw new Error(`deploy-core: not an address: ${a} (DISPUTE_ARBITER / DISPUTE_FEE_POOL)`);
  }
  if (env !== "local" && arbiterAddr.toLowerCase() === admin.toLowerCase()) {
    throw new Error(
      "deploy-core: DISPUTE_ARBITER must not be the admin — the arbiter's containment is that it holds no escrow powers",
    );
  }

  // ...and so is what depends on the chain. The manifest is a claim; the chain is the fact.
  const reusedAgentPolicy = existing?.contracts.agentPolicy?.address;
  let reusedAgentCodec = existing?.contracts.agentPolicyCodec?.address;
  let foreign: string[] = [];
  let heldAdmins: Awaited<ReturnType<typeof adminsOf>> = [];
  if (existing) {
    const provider = signer.provider!;
    const entries = Object.entries(existing.contracts)
      .map(([name, entry]) => ({ name, address: (entry as { address?: string } | undefined)?.address }))
      .filter((e): e is { name: string; address: string } => !!e.address)
      // Never taken on the manifest's word: with a module recorded, the module's code names its
      // library (below); without one, the entry is not used at all.
      .filter((e) => e.name !== "agentPolicyCodec");
    const codeless: string[] = [];
    for (const e of entries) {
      if ((await provider.getCode(e.address)) === "0x") codeless.push(`${e.name} ${e.address}`);
    }
    if (codeless.length > 0) {
      const advice =
        codeless.length === entries.length
          ? `None of them has code: the wrong chain, or a devnet that was reset. Delete the manifest (deploy-contracts.sh --fresh does) to deploy afresh.`
          : `The other ${entries.length - codeless.length} are live, so this is a bad entry, not a bad manifest: correct the address. ` +
            `Removing an entry instead deploys a new contract there, and whatever was wired to the old address stays wired to it.`;
      throw new Error(
        `${outPath} names ${codeless.length} of ${entries.length} contract(s) with no code on chain ${chainId}:\n    ${codeless.join("\n    ")}\n  ${advice}`,
      );
    }

    // Who holds admin on what is reused. After a handover the deployer is not the admin, and every
    // admin-only wiring call below is described for the admin instead of sent (#424).
    const reusedAdminBearing = ADMIN_BEARING.flatMap(([key, artifact]) => {
      const address = existing.contracts[key]?.address;
      return address ? [{ label: artifact, artifact, address }] : [];
    });
    heldAdmins = await adminsOf(reusedAdminBearing, (a, f, n) => attachContract(a, f, n, signer));
    foreign = foreignAdmins(deployer, heldAdmins, "evm-deploy");

    // A reused pre-2.3c AdManager has no `keyRegistry()`, and the wiring below cannot do without it.
    try {
      await attachContract(existing.contracts.adManager.address, "AdManager", "AdManager", signer).getFunction("keyRegistry")();
    } catch (err) {
      throw new Error(
        `AdManager at ${existing.contracts.adManager.address} has no keyRegistry() (pre-2.3c bytecode?); redeploy it instead of reusing: ${err}`,
      );
    }

    if (reusedAgentCodec && !reusedAgentPolicy) {
      console.warn(
        `  [ignore] manifest records AgentPolicyCodec ${reusedAgentCodec} and no module; a module is only ever linked to the library deployed with it, so a new pair is deployed`,
      );
    }

    // The agent module is the one contract makers install, so its address never moves because the
    // *library's* entry is wrong. Identity, not presence: the module has to answer as the module,
    // and a library has to decode.
    if (reusedAgentPolicy) {
      if (!(await isAgentPolicyModule(reusedAgentPolicy, signer))) {
        throw new Error(
          `${reusedAgentPolicy} is recorded as ProofBridgeAgentPolicy and does not answer as one (isModuleType). Correct the entry.\n` +
            `  Removing it deploys a new module at a new address; every maker who installed the old one stays on it, so that is a migration, not a repair.`,
        );
      }
      const moduleCode = (await provider.getCode(reusedAgentPolicy)).toLowerCase();
      // At the offset this build's artifact records; or, for a module from a build that laid its
      // code out differently, the manifest's own entry, if the module's code carries it.
      const candidates = [
        linkedLibraryIn("ProofBridgeAgentPolicy", "ProofBridgeAgentPolicy", "AgentPolicyCodec", moduleCode),
        reusedAgentCodec && moduleCode.includes(reusedAgentCodec.slice(2).toLowerCase()) ? reusedAgentCodec : null,
      ];
      let linked: string | null = null;
      for (const c of candidates) {
        if (c && (await isAgentPolicyCodec(c, signer))) {
          linked = c;
          break;
        }
      }
      if (!linked) {
        throw new Error(
          `ProofBridgeAgentPolicy at ${reusedAgentPolicy} cannot be tied to a working AgentPolicyCodec: nothing that decodes at this build's link offset, ` +
            `and the manifest's library (${reusedAgentCodec ?? "absent"}) is not both in the module's code and able to decode. Correct the library entry.\n` +
            `  Removing both entries deploys a new pair at a new address; every maker who installed the old module stays on it, so that is a migration, not a repair.`,
        );
      }
      if (linked.toLowerCase() !== reusedAgentCodec?.toLowerCase()) {
        console.warn(
          `  [repair] manifest says AgentPolicyCodec is ${reusedAgentCodec ?? "absent"}; the module's code is linked to ${linked}. Recording ${linked}; the module is untouched.`,
        );
        reusedAgentCodec = linked;
      }
    }
  }

  // Per contract: what this run deploys has the deployer as admin and is always wired now (H1).
  const acting = new Acting(foreign, nonces, "wire");

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
    run.deployed.push({ label, address: addr });
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
  // #464/#465: a reused verifier must answer registry() and read the registry this deploy wires in.
  const registryOf = async (v: string): Promise<string> =>
    String(await attachContract(v, "CounterpartyVerifier", "CounterpartyVerifier", signer).getFunction("registry")());
  assertOneRegistry(blsKeyRegistryAddr, await verifierRegistry(registryOf, counterpartyVerifierAddr, "deploy"), "deploy");

  // ── RootAnchor (2.3f) + Registrar (2.1b) ───────────────────────────
  // T2 notary: the publisher key(s) in ANCHOR_PUBLISHER (comma-separated, default
  // admin) at ANCHOR_THRESHOLD (default 1); the ladder later swaps the set with
  // setSigners. Per-route delays are set at link time (ANCHOR_DELAY_S).
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
  // Who they are, and that the arbiter is not the admin, was settled before anything was sent.
  {
    const dm = attachContract(disputeManagerAddr, "DisputeManager", "DisputeManager", signer);
    for (const [name, fn, value] of [
      ["arbiter", "setArbiter", arbiterAddr],
      ["protocolFeePool", "setProtocolFeePool", feePoolAddr],
    ] as const) {
      const cur = await dm.getFunction(name)();
      if (cur.toLowerCase() === value.toLowerCase()) {
        console.log(`  [skip] DisputeManager.${fn} already ${value}`);
        continue;
      }
      await acting.call(dm, "DisputeManager", fn, [value], `DisputeManager.${fn}(${value})`);
    }
  }

  // ── agent policy module (2.1g): the parser library, then the module linked to it ──
  // One shared, ownerless contract per chain that every maker's account installs. Reused only as
  // a pair: a reused module still points at the library it was linked with.
  // Whether, and with which library, the recorded module is reused was settled up front.
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
  // Re-set every run (idempotent); guards only gate key revocation/rotation. Whether this can be
  // sent was decided up front; a revert here is a failure, not a warning.
  {
    const registry = attachContract(blsKeyRegistryAddr, "BLSKeyRegistry", "BLSKeyRegistry", signer);
    // `positionGuards` is a public array with no length getter: read by index until it reverts.
    const want = [adManagerAddr, orderPortalAddr].map((a) => a.toLowerCase());
    const have: string[] = [];
    for (let i = 0; ; i++) {
      try {
        have.push(String(await registry.getFunction("positionGuards")(i)).toLowerCase());
      } catch {
        break;
      }
    }
    if (have.length === want.length && have.every((g, i) => g === want[i])) {
      console.log(`  [skip] BLSKeyRegistry.setPositionGuards already [AdManager, OrderPortal]`);
    } else {
      await acting.call(
        registry,
        "BLSKeyRegistry",
        "setPositionGuards",
        [[adManagerAddr, orderPortalAddr]],
        `BLSKeyRegistry.setPositionGuards([AdManager, OrderPortal])`,
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
    // #465 (46-2): the peers this AdManager was linked to, as the manifest recorded them.
    const peers = [
      ...new Set([
        ...Object.keys(existing?.routeTiming ?? {}),
        ...Object.keys(existing?.disputeParams ?? {}),
        ...Object.keys(existing?.rootAnchorConfig?.anchorDelays ?? {}),
      ]),
    ];
    const escrows: EscrowWiring[] = [
      ["AdManager", adManagerAddr],
      ["OrderPortal", orderPortalAddr],
    ].map(([name, addr]) => {
      const c = attachContract(addr, name, name, signer);
      return {
        name,
        rootVerifier: async (peer: string) => String(await c.getFunction("rootVerifier")(peer)),
        setRootVerifier: (peer: string, v: string) =>
          acting.call(c, name, "setRootVerifier", [peer, v], `${name}.setRootVerifier(${peer}, ${v})`),
      };
    });
    if (cur.toLowerCase() === blsKeyRegistryAddr.toLowerCase()) {
      console.log(`  [skip] AdManager.setKeyRegistry already set`);
      await checkPeers({ escrows, peers, escrowRegistry: blsKeyRegistryAddr, registryOf, where: "deploy" });
    } else {
      // #465: the peers move to the verifier on the new registry first, then the registry; never a split.
      await switchKeyRegistry({
        escrows,
        peers,
        newRegistry: blsKeyRegistryAddr,
        newVerifier: counterpartyVerifierAddr,
        registryOf,
        setKeyRegistry: () =>
          acting.call(adManager, "AdManager", "setKeyRegistry", [blsKeyRegistryAddr], `AdManager.setKeyRegistry(${blsKeyRegistryAddr})`),
      });
    }
  }

  // ── grant MANAGER_ROLE to AdManager + OrderPortal + Registrar ─────
  // Check-first, like every other wire: a role already held is not granted again, and whether a
  // grant can be sent at all was decided up front.
  const merkleManager = attachContract(merkleManagerAddr, "MerkleManager", "MerkleManager", signer);
  for (const { name, addr } of [
    { name: "AdManager", addr: adManagerAddr },
    { name: "OrderPortal", addr: orderPortalAddr },
    { name: "Registrar", addr: registrarAddr },
  ]) {
    if (await merkleManager.getFunction("hasRole")(MANAGER_ROLE, addr)) {
      console.log(`  [skip] MANAGER_ROLE → ${name} already granted`);
      continue;
    }
    await acting.call(merkleManager, "MerkleManager", "grantRole", [MANAGER_ROLE, addr], `MANAGER_ROLE → ${name}`);
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
    // Who holds admin, from what the chain answered for the reused contracts; the deployer for a
    // fresh deploy. `handover` moves it.
    admin: adminBlockFromChain(existing?.admin, heldAdmins, deployer, "evm-deploy"),
  });

  await writeManifest(outPath, manifest);
  console.log(`[evm-deploy] wrote manifest → ${outPath}`);
  acting.report();
  if (foreign.length > 0 && run.deployed.length > 0) {
    // Deployed after a handover: wired now, with the deployer as admin, and not yet handed over.
    const holder = heldAdmins.find((h) => h.admin.toLowerCase() !== deployer.toLowerCase())?.admin ?? "<admin>";
    console.warn(
      `[evm-deploy] ${run.deployed.length} contract(s) deployed in this run (${run.deployed.map((d) => d.label).join(", ")}) have the deployer as admin ` +
        `while the rest were handed over; run \`handover --to ${holder}\` to hand them over too.`,
    );
  }

  return {
    manifestPath: outPath,
    described: acting.described,
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

/// Does this address answer as the agent policy module: validator and hook, and not an executor?
async function isAgentPolicyModule(address: string, signer: ethers.Wallet): Promise<boolean> {
  try {
    const isType = attachContract(address, "ProofBridgeAgentPolicy", "ProofBridgeAgentPolicy", signer).getFunction("isModuleType");
    const [validator, executor, hook] = await Promise.all([isType(1), isType(2), isType(4)]);
    return validator === true && hook === true && executor === false;
  } catch {
    return false;
  }
}

/// Does this address decode a policy? `decode` is pure, so the library can be called directly: a
/// minimal policy goes in, and the signer that went in has to come back out.
async function isAgentPolicyCodec(address: string, signer: ethers.Wallet): Promise<boolean> {
  const signerField = ethers.zeroPadValue("0xc0dec0de", 32);
  const word = (n: bigint) => ethers.zeroPadValue(ethers.toBeHex(n), 32);
  const policy = ethers.concat([
    ethers.keccak256(ethers.toUtf8Bytes("ProofBridge.AgentPolicy.v1")),
    "0x01", "0x01", // one action: lock for order
    "0x01", word(1n), word(1n), word(1n), word(1n), // one token row: token, maxPerOrder, capacity, refill
    "0x00", "0x00", // every ad
    ethers.zeroPadValue("0x00", 8), // no expiry
    signerField,
  ]);
  try {
    const decoded = await attachContract(address, "AgentPolicyCodec", "AgentPolicyCodec", signer).getFunction("decode").staticCall(policy);
    return (decoded.settlementSigner as string).toLowerCase() === signerField.toLowerCase();
  } catch {
    return false;
  }
}
