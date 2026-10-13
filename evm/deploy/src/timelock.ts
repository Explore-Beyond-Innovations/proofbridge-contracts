import { ethers } from "ethers";
import { readManifest, type ChainDeploymentManifest } from "@proofbridge/deployment-manifest";
import { connect, requireEnv } from "./common.js";
import { attachContract } from "./artifacts.js";
import { manifestPath, writeManifest } from "./manifest.js";

/**
 * The 24-hour admin delay (#586), operated by hand.
 *
 * Every escrow, the MerkleManager, the DisputeManager, the RootAnchor and the BLSKeyRegistry carry
 * it (on the last two only the trust-granting setters wait; revocations stay instant). Before `activate` their setters are
 * the admin's, instantly: that is how `deploy` and `link` configure a fresh chain. `activate` closes
 * that setup window for good, on every one of them. After it, a change is `propose`d (admin), waits
 * 24 hours, and is `execute`d by anyone with exactly the proposed arguments; the admin may `cancel` it
 * before then. A proposal expires 14 days after it ripens, and an admin handover voids the old
 * admin's pending proposals; either way, propose again. `deploy` and `link` already do this on their
 * own for what they wire: on a contract whose delay is on they propose, and a re-run after the delay
 * executes. A contract `deploy` adds to a chain already activated is activated in the same run.
 */

/** The contracts with the delay, by the name the commands take, and their manifest key. */
export const TIMELOCK_CONTRACTS = {
  AdManager: "adManager",
  OrderPortal: "orderPortal",
  MerkleManager: "merkleManager",
  DisputeManager: "disputeManager",
  RootAnchor: "rootAnchor",
  BLSKeyRegistry: "blsKeyRegistry",
} as const;
export type TimelockContract = keyof typeof TIMELOCK_CONTRACTS;

export interface TimelockOptions {
  rpcUrl?: string;
  privateKey?: string;
  /** Path to this chain's manifest. Defaults to deployments/<chainId>.json. */
  manifest?: string;
}

/** One call under the delay: the contract by name, the setter, and its arguments as ethers takes them. */
export interface TimelockCall {
  contract: TimelockContract;
  fn: string;
  args: unknown[];
}

async function open(opts: TimelockOptions) {
  const rpcUrl = opts.rpcUrl ?? requireEnv("EVM_RPC_URL");
  const privateKey = opts.privateKey ?? requireEnv("EVM_ADMIN_PRIVATE_KEY");
  const { signer, nonces, chainId, provider } = await connect(rpcUrl, privateKey);
  const path = opts.manifest ?? manifestPath(chainId);
  const manifest = await readManifest(path);
  if (manifest.chain.kind !== "EVM" || BigInt(manifest.chain.chainId) !== chainId) {
    throw new Error(`timelock: ${path} is for ${manifest.chain.kind} chain ${manifest.chain.chainId}, connected to ${chainId}`);
  }
  const contractOf = (name: TimelockContract): ethers.Contract => {
    const entry = manifest.contracts[TIMELOCK_CONTRACTS[name]];
    if (!entry) throw new Error(`timelock: the manifest has no ${name}`);
    return attachContract(entry.address, name, name, signer);
  };
  return { signer, nonces, provider, path, manifest, contractOf };
}

function assertName(name: string): asserts name is TimelockContract {
  if (!(name in TIMELOCK_CONTRACTS)) {
    throw new Error(`timelock: unknown contract "${name}"; one of ${Object.keys(TIMELOCK_CONTRACTS).join(", ")}`);
  }
}

/** The proposal id of a call: `keccak256` of its calldata, as the contract keys it. */
export function proposalId(contract: ethers.Contract, fn: string, args: unknown[]): { data: string; id: string } {
  const data = contract.interface.encodeFunctionData(fn, args);
  return { data, id: ethers.keccak256(data) };
}

/**
 * Whether each contract's delay is on. A contract still in setup on a chain the manifest records as
 * activated (a later deploy added it and it was never switched on) is flagged.
 */
export async function timelockStatus(opts: TimelockOptions): Promise<Record<string, boolean>> {
  const { manifest, contractOf } = await open(opts);
  const out: Record<string, boolean> = {};
  for (const name of Object.keys(TIMELOCK_CONTRACTS) as TimelockContract[]) {
    if (!manifest.contracts[TIMELOCK_CONTRACTS[name]]) continue;
    out[name] = Boolean(await contractOf(name).getFunction("timelockActive")());
    const flag = !out[name] && manifest.timelock ? "  <-- the chain is activated; run `timelock activate --confirm`" : "";
    console.log(`  ${name}: ${out[name] ? "delay on" : "setup (no delay)"}${flag}`);
  }
  return out;
}

/** The manifest keys every non-local chain must carry before it can be activated. */
function missingOutsideLocal(manifest: ChainDeploymentManifest): string[] {
  if (manifest.meta.env === "local") return [];
  return (Object.keys(TIMELOCK_CONTRACTS) as TimelockContract[]).filter((n) => !manifest.contracts[TIMELOCK_CONTRACTS[n]]);
}

/**
 * Switch the delay on, for good, on every contract that carries it (admin). Idempotent: a contract
 * already on is skipped. Outside local, a manifest missing any of them is refused before anything is
 * sent. Throws (the CLI exits non-zero) naming every contract that failed to activate; the manifest
 * records the time only once every one of them is on.
 */
export async function timelockActivate(opts: TimelockOptions): Promise<{ activated: string[] }> {
  const { nonces, manifest, path, contractOf } = await open(opts);
  const missing = missingOutsideLocal(manifest);
  if (missing.length > 0) {
    throw new Error(`timelock activate: the ${manifest.meta.env} manifest ${path} has no ${missing.join(", ")}; nothing was sent`);
  }
  const activated: string[] = [];
  const failed: string[] = [];
  for (const name of Object.keys(TIMELOCK_CONTRACTS) as TimelockContract[]) {
    if (!manifest.contracts[TIMELOCK_CONTRACTS[name]]) continue;
    const c = contractOf(name);
    if (await c.getFunction("timelockActive")()) {
      console.log(`  [skip] ${name}: delay already on`);
      continue;
    }
    try {
      await (await c.getFunction("activateTimelock")({ nonce: nonces.next() })).wait();
      activated.push(name);
      console.log(`  [timelock] ${name}.activateTimelock()`);
    } catch (err) {
      failed.push(name);
      console.error(`  [timelock] ${name}.activateTimelock() failed: ${err}`);
    }
  }
  if (failed.length > 0) {
    throw new Error(`timelock activate: ${failed.join(", ")} failed to activate and keep instant setters; fix and re-run`);
  }
  if (!manifest.timelock) {
    (manifest as ChainDeploymentManifest).timelock = { activatedAt: new Date().toISOString() };
    await writeManifest(path, manifest);
  }
  return { activated };
}

/** Propose a call (admin). Returns its id and the earliest time anyone may execute it. */
export async function timelockPropose(opts: TimelockOptions & TimelockCall): Promise<{ id: string; eta: bigint }> {
  assertName(opts.contract);
  const { nonces, provider, contractOf } = await open(opts);
  const c = contractOf(opts.contract);
  const { data, id } = proposalId(c, opts.fn, opts.args);
  const receipt = await (await c.getFunction("proposeAction")(data, { nonce: nonces.next() })).wait();
  const eta = BigInt(await c.getFunction("timelockEta")(id));
  console.log(
    `  [propose] ${opts.contract}.${opts.fn}(${opts.args.map(String).join(", ")})  id ${id}  from ${new Date(Number(eta) * 1000).toISOString()} (block ${receipt?.blockNumber}, ${(await provider.getBlock(receipt!.blockNumber))?.timestamp})`,
  );
  return { id, eta };
}

/** Execute a ripe proposal (anyone): the setter itself, with exactly the proposed arguments. */
export async function timelockExecute(opts: TimelockOptions & TimelockCall): Promise<{ id: string }> {
  assertName(opts.contract);
  const { nonces, provider, contractOf } = await open(opts);
  const c = contractOf(opts.contract);
  const { id } = proposalId(c, opts.fn, opts.args);
  const eta = BigInt(await c.getFunction("timelockEta")(id));
  if (eta === 0n) throw new Error(`timelock: no pending proposal ${id} for ${opts.contract}.${opts.fn}; propose it first`);
  const now = BigInt((await provider.getBlock("latest"))!.timestamp);
  if (now < eta) {
    throw new Error(`timelock: ${opts.contract}.${opts.fn} is executable from ${new Date(Number(eta) * 1000).toISOString()}; nothing was sent`);
  }
  await (await c.getFunction(opts.fn)(...opts.args, { nonce: nonces.next() })).wait();
  console.log(`  [execute] ${opts.contract}.${opts.fn}(${opts.args.map(String).join(", ")})  id ${id}`);
  return { id };
}

/** Cancel a pending proposal (admin). */
export async function timelockCancel(opts: TimelockOptions & TimelockCall): Promise<{ id: string }> {
  assertName(opts.contract);
  const { nonces, contractOf } = await open(opts);
  const c = contractOf(opts.contract);
  const { id } = proposalId(c, opts.fn, opts.args);
  await (await c.getFunction("cancelAction")(id, { nonce: nonces.next() })).wait();
  console.log(`  [cancel] ${opts.contract}.${opts.fn}  id ${id}`);
  return { id };
}
