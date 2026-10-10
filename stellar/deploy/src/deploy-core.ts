import * as fs from "fs";
import * as path from "path";
import { assertRegistryEnv, registryInitArgs } from "./keys-env.js";
import { assertOneRegistry, deployRegistryStep, verifierRegistry } from "./one-registry.js";
import { stellarEscrowChain } from "./escrow-chain.js";
import { adminBlockFromChain, adminsOf, foreignAdmins, type HeldAdmin } from "./handover.js";
import {
  envOrDefault,
  requireEnv,
  vkPath,
  wasmDir,
} from "./common.js";
import { namedOutsideLocal, requireDeployEnv, requireStellarChainId } from "./deploy-env.js";
import { assertReusedVk, sha256Hex, vkRecord } from "./vk.js";
import {
  Acting,
  type DescribedCall,
  deployContract,
  deploySAC,
  assertStellarNetworkForEnv,
  getAddress,
  invokeContract,
  latestLedger,
  readView,
  uploadWasm,
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
  /** Admin-only calls the source account could not make (the admin was handed over); empty when all sent. */
  described: DescribedCall[];
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
  const env = requireDeployEnv(opts.env);
  const chainId = requireStellarChainId(opts.chainId, env);
  // A-4: the network the CLI talks to must be the env's, before anything else touches it.
  assertStellarNetworkForEnv(env);
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

  // ── everything that can be refused before sending, is ─────────────
  // T2 notary: the publisher key(s) in ANCHOR_PUBLISHER (comma-separated G-addresses, default admin)
  // at ANCHOR_THRESHOLD (default 1). Outside local the notary is named: after handover the deploy key
  // must not stay the sole anchor signer.
  const anchorSigners = namedOutsideLocal("ANCHOR_PUBLISHER", env, adminStrkey)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  // A-8: naming the deployer as notary outside local is the local default in disguise.
  if (env !== "local" && anchorSigners.includes(adminStrkey)) {
    throw new Error("stellar-deploy: ANCHOR_PUBLISHER names the deployer — outside local the notary must be a separate key (it stays the anchor signer after handover)");
  }
  const anchorThreshold = Number(envOrDefault("ANCHOR_THRESHOLD", "1"));
  // The arbiter must not be the admin (2.3g D6): its containment is that it holds no escrow powers.
  const arbiterAddr = namedOutsideLocal("DISPUTE_ARBITER", env, adminStrkey);
  const feePoolAddr = namedOutsideLocal("DISPUTE_FEE_POOL", env, adminStrkey);
  if (env !== "local" && arbiterAddr === adminStrkey) {
    throw new Error(
      "deploy-core: DISPUTE_ARBITER must not be the admin — the arbiter's containment is that it holds no escrow powers",
    );
  }
  // The bundle's VK; outside local a missing file refuses, so the manifest (and link's A-6 compare) has its hash.
  const vkRec = vkRecord(vk, env);
  // D3: a reused key registry must have been initialized for this environment.
  const reusedRegistry = existing?.contracts.blsKeyRegistry?.address;
  if (reuse && reusedRegistry) {
    assertRegistryEnv("stellar-deploy", env, readView(reusedRegistry, "keys_env"));
  }

  function reused(existingAddr: string | undefined): string | undefined {
    return existingAddr;
  }

  // Who holds admin on what is reused, read before anything is sent. A call to a contract handed
  // over is described, not sent; what this run deploys has the source account as admin and is
  // wired now (#424).
  const heldAdmins: HeldAdmin[] = existing ? adminsOf(existing.contracts) : [];
  const acting = new Acting(foreignAdmins(adminStrkey, heldAdmins, "stellar-deploy"), "wire");
  const deployedNow: string[] = [];

  // C-27: each contract this run creates is written down as it lands, so a run that fails halfway
  // leaves a record of what is on chain and in no manifest (the manifest is written only at the end).
  // Not *.json: deploy-contracts.sh takes the newest .json in the directory as the manifest.
  const sidecar = outPath.replace(/\.json$/, "") + ".deployed-this-run.txt";
  if (fs.existsSync(sidecar)) {
    console.warn(`[stellar-deploy] ${sidecar} is left from a failed run: those contracts are in no manifest. New entries are appended.`);
  }
  fs.appendFileSync(sidecar, `# run ${new Date().toISOString()} chain=${chainId}\n`);
  const tracked = (label: string, id: string): string => {
    fs.appendFileSync(sidecar, `${label} ${id}\n`);
    return id;
  };

  // ── Verifier ────────────────────────────────────────────────────
  let verifier = reused(existing?.contracts.verifier.address);
  if (!verifier) {
    verifier = tracked("Verifier", deployContract(path.join(wasmBase, "verifier.wasm"), [
      "--vk_bytes-file-path",
      vk,
    ]));
    console.log(`  [deploy] Verifier: ${verifier}`);
  } else {
    // The chain answers which VK a reused verifier holds; compare it with this bundle's (C-20).
    const held = readView(verifier, "get_vk");
    const onChain = typeof held === "string" && /^[0-9a-f]+$/i.test(held)
      ? sha256Hex(Buffer.from(held, "hex"))
      : undefined;
    const r = assertReusedVk("stellar-deploy Verifier", vkRec.vkSha256, existing?.meta.vkSha256, onChain);
    console.log(`  [reuse] Verifier: ${verifier} (VK ${r === "match" ? "matches the bundle" : "not checked: no hash to compare"})`);
  }

  // ── MerkleManager ───────────────────────────────────────────────
  let merkleManager = reused(existing?.contracts.merkleManager.address);
  let merkleManagerDeployBlock = existing?.contracts.merkleManager.deployBlock;
  if (!merkleManager) {
    // Pre-deploy ledger: a safe lower bound for the ingester's scan start.
    merkleManagerDeployBlock = latestLedger() ?? merkleManagerDeployBlock;
    merkleManager = tracked("MerkleManager", deployContract(path.join(wasmBase, "merkle_manager.wasm")));
    invokeContract(merkleManager, "initialize", ["--admin", adminStrkey]);
    deployedNow.push("MerkleManager");
    console.log(`  [deploy] MerkleManager: ${merkleManager}`);
  } else {
    console.log(`  [reuse] MerkleManager: ${merkleManager}`);
  }

  // ── wNativeToken (native XLM SAC) ───────────────────────────────
  let wNativeToken = reused(existing?.contracts.wNativeToken.address);
  if (!wNativeToken) {
    wNativeToken = tracked("wNativeToken", deploySAC("native"));
    console.log(`  [deploy] wNativeToken (native XLM SAC): ${wNativeToken}`);
  } else {
    console.log(`  [reuse] wNativeToken: ${wNativeToken}`);
  }

  // ── AdManager ──────────────────────────────────────────────────
  let adManager = reused(existing?.contracts.adManager.address);
  if (!adManager) {
    adManager = tracked("AdManager", deployContract(path.join(wasmBase, "ad_manager.wasm")));
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
    deployedNow.push("AdManager");
    console.log(`  [deploy] AdManager: ${adManager}`);
  } else {
    console.log(`  [reuse] AdManager: ${adManager}`);
  }

  // ── OrderPortal ────────────────────────────────────────────────
  let orderPortal = reused(existing?.contracts.orderPortal.address);
  if (!orderPortal) {
    orderPortal = tracked("OrderPortal", deployContract(path.join(wasmBase, "order_portal.wasm")));
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
    deployedNow.push("OrderPortal");
    console.log(`  [deploy] OrderPortal: ${orderPortal}`);
  } else {
    console.log(`  [reuse] OrderPortal: ${orderPortal}`);
  }

  // ── BLS stack (1.2): key registry + module C verifier ──────────
  let blsKeyRegistry = reused(existing?.contracts.blsKeyRegistry?.address);
  if (!blsKeyRegistry) {
    blsKeyRegistry = tracked("BLSKeyRegistry", deployContract(path.join(wasmBase, "bls_key_registry.wasm")));
    invokeContract(blsKeyRegistry, "initialize", registryInitArgs(adminStrkey, chainId, env));
    deployedNow.push("BLSKeyRegistry");
    console.log(`  [deploy] BLSKeyRegistry: ${blsKeyRegistry}`);
  } else {
    console.log(`  [reuse] BLSKeyRegistry: ${blsKeyRegistry}`);
  }

  let counterpartyVerifier = reused(
    existing?.contracts.counterpartyVerifier?.address,
  );
  if (!counterpartyVerifier) {
    counterpartyVerifier = tracked("CounterpartyVerifier", deployContract(
      path.join(wasmBase, "counterparty_verifier.wasm"),
    ));
    invokeContract(counterpartyVerifier, "initialize", [
      "--registry",
      blsKeyRegistry,
    ]);
    console.log(`  [deploy] CounterpartyVerifier: ${counterpartyVerifier}`);
  } else {
    console.log(`  [reuse] CounterpartyVerifier: ${counterpartyVerifier}`);
  }
  // #464/#465: a reused verifier must answer registry() and read the registry this deploy wires in.
  const registryOf = (v: string): string => readView(v, "registry") as string;
  assertOneRegistry(blsKeyRegistry, verifierRegistry(registryOf, counterpartyVerifier, "deploy"), "deploy");

  // ── Wire the escrows as the registry's revoke guards (check first, then set) ──
  {
    const have = readView(blsKeyRegistry, "position_guards");
    const want = [adManager, orderPortal];
    if (Array.isArray(have) && have.length === want.length && have.every((g, i) => g === want[i])) {
      console.log(`  [skip] BLSKeyRegistry.set_position_guards already [AdManager, OrderPortal]`);
    } else {
      acting.call(blsKeyRegistry, "BLSKeyRegistry", "set_position_guards", ["--guards", JSON.stringify(want)],
        "BLSKeyRegistry.set_position_guards([AdManager, OrderPortal])");
    }
  }

  // ── Point the AdManager at the registry (2.3c; check first, then set) ─────────
  // create_ad / set_settlement_signer / lock_for_order fail closed until this is set: an
  // ad's settlement signer must hold a live, unexpired key.
  {
    // #465 (46-2): the peers this AdManager was linked to, as the manifest recorded them; #466 adds
    // every chain the escrows list.
    const manifestPeers = [
      ...new Set([
        ...Object.keys(existing?.routeTiming ?? {}),
        ...Object.keys(existing?.disputeParams ?? {}),
        ...Object.keys(existing?.rootAnchorConfig?.anchorDelays ?? {}),
      ]),
    ];
    // #467 (47-2): the specs test the step, not this call (no Stellar end-to-end harness); keep it.
    deployRegistryStep(stellarEscrowChain(acting, readView), { adManager, orderPortal }, {
      registry: blsKeyRegistry,
      verifier: counterpartyVerifier,
      manifestPeers,
    });
  }

  // ── RootAnchor (2.3f) + Registrar (2.1b) ───────────────────────────
  // T2 notary: the publisher key(s) in ANCHOR_PUBLISHER at ANCHOR_THRESHOLD, settled up front.
  // Per-route delays are set at link time.
  let rootAnchor = reused(existing?.contracts.rootAnchor?.address);
  if (!rootAnchor) {
    rootAnchor = tracked("RootAnchor", deployContract(path.join(wasmBase, "root_anchor.wasm")));
    invokeContract(rootAnchor, "initialize", [
      "--admin",
      adminStrkey,
      "--signers",
      JSON.stringify(anchorSigners),
      "--threshold",
      String(anchorThreshold),
    ]);
    deployedNow.push("RootAnchor");
    console.log(`  [deploy] RootAnchor: ${rootAnchor}`);
  } else {
    console.log(`  [reuse] RootAnchor: ${rootAnchor}`);
  }

  // The home-chain REGISTERED-leaf appender; a manager on the MerkleManager (set below). The
  // registry's proof path stays switched off (2.1b §7); nothing wires it here.
  let registrar = reused(existing?.contracts.registrar?.address);
  if (!registrar) {
    registrar = tracked("Registrar", deployContract(path.join(wasmBase, "registrar.wasm")));
    invokeContract(registrar, "initialize", ["--merkle_manager", merkleManager]);
    console.log(`  [deploy] Registrar: ${registrar}`);
  } else {
    console.log(`  [reuse] Registrar: ${registrar}`);
  }

  // The dispute module (2.3g) both escrows share. Holds bonds, never escrow funds, and takes no
  // MerkleManager role — disputes append no leaf. Escrow ↔ module wiring happens at link time.
  let disputeManager = reused(existing?.contracts.disputeManager?.address);
  if (!disputeManager) {
    disputeManager = tracked("DisputeManager", deployContract(path.join(wasmBase, "dispute_manager.wasm")));
    invokeContract(disputeManager, "initialize", [
      "--admin",
      adminStrkey,
      "--w_native",
      wNativeToken,
    ]);
    deployedNow.push("DisputeManager");
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
    if (readView(disputeManager, "get_arbiter") === arbiterAddr) {
      console.log(`  [skip] DisputeManager.set_arbiter already ${arbiterAddr}`);
    } else {
      acting.call(disputeManager, "DisputeManager", "set_arbiter", ["--arbiter", arbiterAddr], `DisputeManager.set_arbiter(${arbiterAddr})`);
    }
    if (readView(disputeManager, "get_protocol_fee_pool") === feePoolAddr) {
      console.log(`  [skip] DisputeManager.set_protocol_fee_pool already ${feePoolAddr}`);
    } else {
      acting.call(disputeManager, "DisputeManager", "set_protocol_fee_pool", ["--pool", feePoolAddr], `DisputeManager.set_protocol_fee_pool(${feePoolAddr})`);
    }
  }

  // ── MerkleManager managers: the escrows (check first, then set) ─────
  // The Registrar is deployed but made a manager only at proof registration's T3 flip.
  for (const manager of appendersAtDeploy({ adManager, orderPortal, registrar })) {
    if (readView(merkleManager, "is_manager", ["--addr", manager]) === true) {
      console.log(`  [skip] MerkleManager.set_manager(${manager}) already true`);
      continue;
    }
    acting.call(merkleManager, "MerkleManager", "set_manager", ["--manager", manager, "--status", "true"], `MerkleManager.set_manager(${manager}, true)`);
  }

  // ── agent account wasm (2.1, C-4) ───────────────────────────────
  // Installed, not instantiated: each operator creates their own account from this hash (the owner
  // must not be the deployer). Recorded so the runbook and the pod provisioner have one to use.
  const agentWasm = path.join(wasmBase, "agent_account.wasm");
  let agentAccountWasmHash = existing?.wasmHashes?.agentAccount;
  const localAgentHash = sha256Hex(fs.readFileSync(agentWasm)).slice(2);
  if (agentAccountWasmHash === localAgentHash) {
    console.log(`  [reuse] agent-account wasm: ${agentAccountWasmHash}`);
  } else {
    const uploaded = uploadWasm(agentWasm);
    if (uploaded !== localAgentHash) {
      throw new Error(`deploy-core: agent-account upload returned ${uploaded}, the file hashes to ${localAgentHash}`);
    }
    agentAccountWasmHash = uploaded;
    console.log(`  [install] agent-account wasm: ${agentAccountWasmHash}`);
  }

  // ── manifest ───────────────────────────────────────────────────
  const manifest = buildManifest({
    wasmHashes: { agentAccount: agentAccountWasmHash },
    vk: vkRec,
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
    // Who holds admin, from what the chain answered for the reused contracts; the source account
    // for a fresh deploy. `handover` moves it.
    admin: adminBlockFromChain(existing?.admin, heldAdmins, adminStrkey, "stellar-deploy"),
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
  // Everything this run created is in the manifest now.
  fs.rmSync(sidecar, { force: true });
  acting.report();
  if (!acting.allMine && deployedNow.length > 0) {
    // Deployed after a handover: wired now, with the source account as admin, not yet handed over.
    const holder = heldAdmins.find((h) => h.admin !== adminStrkey)?.admin ?? "<admin>";
    console.warn(
      `[stellar-deploy] ${deployedNow.length} contract(s) deployed in this run (${deployedNow.join(", ")}) have the source account as admin ` +
        `while the rest were handed over; run \`handover --to ${holder}\` to hand them over too.`,
    );
  }

  return {
    manifestPath: outPath,
    described: acting.described,
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

/** Who the deploy makes a MerkleManager manager: the escrows. The Registrar waits for the T3 flip. */
export function appendersAtDeploy(c: { adManager: string; orderPortal: string; registrar: string }): string[] {
  return [c.adManager, c.orderPortal];
}
