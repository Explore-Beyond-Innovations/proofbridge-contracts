/** Shell wrappers around the `stellar` CLI — canonical path for contract deploy / invoke / asset deploy. */

import { execFileSync } from "child_process";
import { StrKey } from "@stellar/stellar-sdk";
import { encodeCall, flagsToNamed } from "./timelock.js";
import type { DeployEnv } from "./deploy-env.js";

/** The passphrase each environment's network answers with (RPC `getNetwork`). */
export const NETWORK_PASSPHRASES: Record<DeployEnv, string> = {
  local: "Standalone Network ; February 2017",
  testnet: "Test SDF Network ; September 2015",
  mainnet: "Public Global Stellar Network ; September 2015",
};

// Set once `assertStellarNetworkForEnv` has checked it; before that, STELLAR_NETWORK as given.
let checkedNetwork: string | undefined;

/** The `stellar network` profile every call uses. There is no default: a wrong guess is a real network. */
export function network(): string {
  const n = checkedNetwork ?? process.env.STELLAR_NETWORK;
  if (!n) throw new Error("STELLAR_NETWORK is unset; name the `stellar network` profile to use");
  return n;
}

/**
 * A-4: the stated environment must be the network the RPC is on. STELLAR_NETWORK is required outside
 * local (it defaults to the `local` profile only there), and the RPC's own passphrase must be the
 * env's: `DEPLOY_ENV=local` against testnet would bring every local default to a real network.
 * Runs before any transaction.
 */
export function assertStellarNetworkForEnv(deployEnv: DeployEnv, env: NodeJS.ProcessEnv = process.env): string {
  const name = env.STELLAR_NETWORK || (deployEnv === "local" ? "local" : undefined);
  if (!name) {
    throw new Error(`STELLAR_NETWORK is unset for DEPLOY_ENV=${deployEnv}; name the \`stellar network\` profile for ${deployEnv}`);
  }
  let out: string;
  try {
    out = exec(["network", "info", "--network", name, "--output", "json"]);
  } catch (err) {
    throw new Error(`could not ask the RPC of STELLAR_NETWORK=${name} for its network (stellar network info): ${err instanceof Error ? err.message : err}`);
  }
  let passphrase: unknown;
  try {
    passphrase = (JSON.parse(out.split("\n").filter(Boolean).pop() ?? "null") as { passphrase?: unknown } | null)?.passphrase;
  } catch {
    passphrase = undefined;
  }
  if (typeof passphrase !== "string") {
    throw new Error(`the RPC of STELLAR_NETWORK=${name} gave no network passphrase: ${out}`);
  }
  const want = NETWORK_PASSPHRASES[deployEnv];
  if (passphrase !== want) {
    const is = (Object.entries(NETWORK_PASSPHRASES).find(([, p]) => p === passphrase)?.[0]) ?? "an unknown network";
    throw new Error(
      `DEPLOY_ENV=${deployEnv} but STELLAR_NETWORK=${name} is on ${is}, not the ${deployEnv} network. ` +
        `Point STELLAR_NETWORK at the ${deployEnv} network, or set DEPLOY_ENV to the network's environment.`,
    );
  }
  checkedNetwork = name;
  return name;
}

/** Single-quote a shell argument; a bare flag or plain word is left as is. */
export function shellQuote(arg: string): string {
  return /^[A-Za-z0-9_\-=.:/]+$/.test(arg) ? arg : `'${arg.replace(/'/g, `'\\''`)}'`;
}
const source = (): string => process.env.STELLAR_SOURCE_ACCOUNT ?? "admin";

/** A secret seed in any argument (e.g. `--source S...` from STELLAR_SOURCE_ACCOUNT) never reaches a log. */
export function redact(text: string): string {
  return text.replace(/\bS[A-Z2-7]{55}\b/g, (m) => (StrKey.isValidEd25519SecretSeed(m) ? "S…[redacted]" : m));
}

/** A fresh localnet's RPC can simulate before its ledger snapshot is complete; the same call passes a moment later. */
export const isSnapshotRace = (text: string): boolean => /not present in the snapshot/i.test(text);

/**
 * Runs `run`, again up to `attempts` times while it fails with the snapshot race. The simulation failed before
 * anything was sent, so a retry can't submit twice. Any other failure is thrown at once.
 */
export function withSnapshotRetry<T>(run: () => T, sleep: (ms: number) => void, attempts = 5): T {
  for (let i = 1; ; i++) {
    try {
      return run();
    } catch (err) {
      const e = err as { message?: string; stderr?: unknown };
      const text = `${e.message ?? ""} ${typeof e.stderr === "string" ? e.stderr : ""}`;
      if (i >= attempts || !isSnapshotRace(text)) throw err;
      sleep(1_000 * i);
    }
  }
}

const sleepSync = (ms: number) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

function exec(args: string[]): string {
  return withSnapshotRetry(() => execOnce(args), sleepSync);
}

function execOnce(args: string[]): string {
  try {
    return execFileSync("stellar", args, {
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 180_000,
    }).trim();
  } catch (err) {
    // execFileSync's message and stderr carry the full command line; rethrow them redacted.
    const e = err as Error & { stderr?: unknown; stdout?: unknown };
    const out = new Error(redact(e.message ?? String(err)));
    Object.assign(out, {
      status: (err as { status?: unknown }).status,
      stderr: typeof e.stderr === "string" ? redact(e.stderr) : e.stderr,
    });
    throw out;
  }
}

/** Run `stellar <args>`, echoing the command (secrets redacted) for debug visibility. */
export function stellar(args: string[]): string {
  console.log(`  [stellar] stellar ${redact(args.join(" "))}`);
  return exec(args);
}

/** Latest ledger sequence (verified on the pinned v23.3.0), or undefined without `ledger latest`. */
export function latestLedger(): string | undefined {
  try {
    const out = exec(["ledger", "latest", "--network", network(), "--output", "json"]);
    const seq = (JSON.parse(out) as { sequence?: number }).sequence;
    return seq != null ? String(seq) : undefined;
  } catch {
    return undefined;
  }
}

/** Deploy a contract WASM. Returns the contract id (C...). */
export function deployContract(
  wasmPath: string,
  constructorArgs: string[] = [],
): string {
  const args = [
    "contract",
    "deploy",
    "--wasm",
    wasmPath,
    "--source",
    source(),
    "--network",
    network(),
  ];
  if (constructorArgs.length > 0) args.push("--", ...constructorArgs);
  const out = stellar(args);
  const lines = out.split("\n").filter((l) => l.trim());
  const id = lines[lines.length - 1].trim();
  if (!id.startsWith("C")) {
    throw new Error(`unexpected deploy output:\n${out}`);
  }
  return id;
}

/**
 * Install a wasm on the network without instantiating it; returns its hash (hex, no 0x). For
 * contracts operators instantiate themselves, like the agent account (C-4).
 */
export function uploadWasm(wasmPath: string): string {
  const out = stellar(["contract", "upload", "--wasm", wasmPath, "--source", source(), "--network", network()]);
  const hash = out.split("\n").filter((l) => l.trim()).pop()?.trim() ?? "";
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error(`unexpected upload output:\n${out}`);
  return hash;
}

/** Invoke a contract function. Returns stdout. */
export function invokeContract(
  contractId: string,
  fn: string,
  args: string[] = [],
  options: { send?: boolean; source?: string } = {},
): string {
  const src = options.source ?? source();
  const cli = [
    "contract",
    "invoke",
    "--id",
    contractId,
    "--source-account",
    src,
    "--network",
    network(),
    "--send",
    options.send === false ? "no" : "yes",
    "--",
    fn,
    ...args,
  ];
  return stellar(cli);
}

export function getAddress(name: string = source()): string {
  return stellar(["keys", "address", name]);
}

export function getSecret(name: string = source()): string {
  return stellar(["keys", "secret", name]);
}

/**
 * "Asset already deployed" / already-initialized detection for `stellar contract asset deploy`.
 * Update the pattern if you bump the Stellar CLI version and the wording shifts.
 */
function isAlreadyDeployedSacError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return /already\s*(deployed|initialized|exists)|AlreadyInitializedError|error\s*code\s*3\b/i.test(
    msg,
  );
}

/** Deploy or look up a SAC (native XLM via `asset=native`); only falls back to `contract id asset` when the deploy failed with "already deployed". */
export function deploySAC(asset: string = "native"): string {
  try {
    return stellar([
      "contract",
      "asset",
      "deploy",
      "--asset",
      asset,
      "--source",
      source(),
      "--network",
      network(),
    ]);
  } catch (err) {
    if (!isAlreadyDeployedSacError(err)) throw err;
    // `contract id asset` is a pure passphrase-based derivation — no --source.
    return stellar([
      "contract",
      "id",
      "asset",
      "--asset",
      asset,
      "--network",
      network(),
    ]);
  }
}

// ── address encoding ────────────────────────────────────────────────

/** Decode a Stellar strkey (C.../G...) to `0x` + 64-hex (32 bytes). Throws on bad checksum / wrong version. */
export function strkeyToHex(strkey: string): string {
  let payload: Buffer;
  if (StrKey.isValidContract(strkey)) {
    payload = StrKey.decodeContract(strkey);
  } else if (StrKey.isValidEd25519PublicKey(strkey)) {
    payload = StrKey.decodeEd25519PublicKey(strkey);
  } else {
    throw new Error(`invalid Stellar strkey: ${strkey}`);
  }
  if (payload.length !== 32) {
    throw new Error(`expected 32-byte strkey payload, got ${payload.length}`);
  }
  return "0x" + payload.toString("hex");
}

/** Decode a Stellar ed25519 secret seed (S...) to its raw 32-byte seed. Throws on invalid. */
export function decodeEd25519Secret(secret: string): Buffer {
  if (!StrKey.isValidEd25519SecretSeed(secret)) {
    throw new Error("invalid Stellar ed25519 secret seed");
  }
  return StrKey.decodeEd25519SecretSeed(secret);
}

/** One call the CLI would have made, for the admin to make instead (#424). */
export interface DescribedCall {
  label: string;
  contractId: string;
  fn: string;
  args: string[];
}

/**
 * The CLI acts while it is the admin and describes when it is not (#424): see the EVM twin in
 * evm/deploy/src/common.ts. Decided up front from each contract's admin view, before anything is
 * sent; in describe mode every call is printed as the `stellar contract invoke` the admin has to
 * make, and the command exits 2.
 */
/** The last line of a read-only invoke, parsed: the CLI prints the return value as JSON. */
export function readView(contractId: string, fn: string, args: string[] = []): unknown {
  const out = invokeContract(contractId, fn, args, { send: false });
  const last = out.split("\n").filter(Boolean).pop() ?? "null";
  return JSON.parse(last);
}

/** #586: a call under the 24-hour delay: proposed by this run, or waiting out an earlier proposal. */
export interface PendingCall {
  label: string;
  contractId: string;
  fn: string;
  args: string[];
  /** The proposal id (hex). */
  id: string;
  proposedNow: boolean;
}

export class Acting {
  readonly described: DescribedCall[] = [];
  /** #586: calls on a timelocked contract that were proposed, or are waiting out their delay. */
  readonly pending: PendingCall[] = [];
  private readonly foreign: Set<string>;
  private readonly timelocked: Set<string>;

  /**
   * @param foreign contract ids whose admin is not the source account. The decision is per
   * contract: a call to one of these is described, a call to any other contract is sent, so a
   * contract deployed in this run (its admin is the source account) is wired whatever happened to
   * the rest (#424 H1).
   */
  constructor(foreign: Iterable<string>, private readonly tag: string, timelocked: Iterable<string> = []) {
    this.foreign = new Set(foreign);
    this.timelocked = new Set(timelocked);
  }

  canSendTo(contractId: string): boolean {
    return !this.foreign.has(contractId);
  }

  /** True when every contract this command touches is the source account's. */
  get allMine(): boolean {
    return this.foreign.size === 0;
  }

  /**
   * Send `fn(args)` on `contractId`, or describe it. Returns whether it was sent. `instant` marks a
   * brake (a call the contract runs without the delay, such as a tightening): never proposed.
   */
  call(contractId: string, label: string, fn: string, args: string[], line: string, instant = false): boolean {
    if (!instant && this.timelocked.has(contractId)) return this.callTimelocked(contractId, label, fn, args, line);
    if (!this.canSendTo(contractId)) {
      this.described.push({ label, contractId, fn, args });
      console.log(`  [describe] ${line}`);
      return false;
    }
    invokeContract(contractId, fn, args);
    console.log(`  [${this.tag}] ${line}`);
    return true;
  }

  /**
   * #586: the delay is on for `contractId`. A pending proposal for this exact call is executed if its
   * delay is over (the setter's own simulation says so), else reported; none is proposed (or, when
   * the source account is not the admin, the `propose_action` is described). Returns whether the
   * setter itself ran.
   */
  private callTimelocked(contractId: string, label: string, fn: string, args: string[], line: string): boolean {
    const enc = encodeCall(label, fn, flagsToNamed(args));
    if (Number(readView(contractId, "timelock_eta", ["--id", enc.id])) !== 0) {
      try {
        invokeContract(contractId, fn, args, { send: false });
      } catch {
        this.pending.push({ label, contractId, fn, args, id: enc.id, proposedNow: false });
        console.log(`  [pending] ${line} - proposal ${enc.id} is not executable yet`);
        return false;
      }
      invokeContract(contractId, fn, args);
      console.log(`  [execute] ${line}`);
      return true;
    }
    const proposeArgs = ["--fn_name", fn, "--args", enc.argsXdr];
    if (!this.canSendTo(contractId)) {
      this.described.push({ label, contractId, fn: "propose_action", args: proposeArgs });
      console.log(`  [describe] propose ${line}`);
      return false;
    }
    invokeContract(contractId, "propose_action", proposeArgs);
    this.pending.push({ label, contractId, fn, args, id: enc.id, proposedNow: true });
    console.log(`  [propose] ${line} - proposal ${enc.id}, executable in 24 hours`);
    return false;
  }

  report(): void {
    if (this.pending.length > 0) {
      console.log(
        `\n[${this.tag}] ${this.pending.length} call(s) are under the 24-hour delay; re-run this command after it to execute them:`,
      );
      for (const p of this.pending) console.log(`  ${p.label}.${p.fn}  proposal ${p.id}`);
    }
    if (this.described.length === 0) return;
    console.log(
      `\n[${this.tag}] the source account is not the admin of every contract, so these ${this.described.length} call(s) were not sent. The admin has to make them:`,
    );
    for (const d of this.described) {
      // Args are quoted for a shell: JSON values (`--guards '[...]'`, `--timing '{...}'`) carry
      // characters the shell would otherwise split or expand.
      console.log(
        `  ${d.label}.${d.fn}\n    stellar contract invoke --id ${d.contractId} --source-account <admin> --network ${network()} -- ${d.fn} ${d.args.map(shellQuote).join(" ")}`,
      );
    }
  }
}
