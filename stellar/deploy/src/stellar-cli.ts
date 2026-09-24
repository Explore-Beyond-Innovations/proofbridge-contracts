/** Shell wrappers around the `stellar` CLI — canonical path for contract deploy / invoke / asset deploy. */

import { execFileSync } from "child_process";
import { StrKey } from "@stellar/stellar-sdk";

const NETWORK = process.env.STELLAR_NETWORK ?? "testnet";

/** Single-quote a shell argument; a bare flag or plain word is left as is. */
export function shellQuote(arg: string): string {
  return /^[A-Za-z0-9_\-=.:/]+$/.test(arg) ? arg : `'${arg.replace(/'/g, `'\\''`)}'`;
}
const SOURCE = process.env.STELLAR_SOURCE_ACCOUNT ?? "admin";

function exec(args: string[]): string {
  return execFileSync("stellar", args, {
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"],
    timeout: 180_000,
  }).trim();
}

/** Run `stellar <args>`, echoing the command for debug visibility. */
export function stellar(args: string[]): string {
  console.log(`  [stellar] stellar ${args.join(" ")}`);
  return exec(args);
}

/** Latest ledger sequence (verified on the pinned v23.3.0), or undefined without `ledger latest`. */
export function latestLedger(): string | undefined {
  try {
    const out = exec(["ledger", "latest", "--network", NETWORK, "--output", "json"]);
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
    SOURCE,
    "--network",
    NETWORK,
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

/** Invoke a contract function. Returns stdout. */
export function invokeContract(
  contractId: string,
  fn: string,
  args: string[] = [],
  options: { send?: boolean; source?: string } = {},
): string {
  const source = options.source ?? SOURCE;
  const cli = [
    "contract",
    "invoke",
    "--id",
    contractId,
    "--source-account",
    source,
    "--network",
    NETWORK,
    "--send",
    options.send === false ? "no" : "yes",
    "--",
    fn,
    ...args,
  ];
  return stellar(cli);
}

export function getAddress(name: string = SOURCE): string {
  return stellar(["keys", "address", name]);
}

export function getSecret(name: string = SOURCE): string {
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
      SOURCE,
      "--network",
      NETWORK,
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
      NETWORK,
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

export class Acting {
  readonly described: DescribedCall[] = [];
  private readonly foreign: Set<string>;

  /**
   * @param foreign contract ids whose admin is not the source account. The decision is per
   * contract: a call to one of these is described, a call to any other contract is sent, so a
   * contract deployed in this run (its admin is the source account) is wired whatever happened to
   * the rest (#424 H1).
   */
  constructor(foreign: Iterable<string>, private readonly tag: string) {
    this.foreign = new Set(foreign);
  }

  canSendTo(contractId: string): boolean {
    return !this.foreign.has(contractId);
  }

  /** True when every contract this command touches is the source account's. */
  get allMine(): boolean {
    return this.foreign.size === 0;
  }

  /** Send `fn(args)` on `contractId`, or describe it. Returns whether it was sent. */
  call(contractId: string, label: string, fn: string, args: string[], line: string): boolean {
    if (!this.canSendTo(contractId)) {
      this.described.push({ label, contractId, fn, args });
      console.log(`  [describe] ${line}`);
      return false;
    }
    invokeContract(contractId, fn, args);
    console.log(`  [${this.tag}] ${line}`);
    return true;
  }

  report(): void {
    if (this.described.length === 0) return;
    console.log(
      `\n[${this.tag}] the source account is not the admin of every contract, so these ${this.described.length} call(s) were not sent. The admin has to make them:`,
    );
    for (const d of this.described) {
      // Args are quoted for a shell: JSON values (`--guards '[...]'`, `--timing '{...}'`) carry
      // characters the shell would otherwise split or expand.
      console.log(
        `  ${d.label}.${d.fn}\n    stellar contract invoke --id ${d.contractId} --source-account <admin> --network ${NETWORK} -- ${d.fn} ${d.args.map(shellQuote).join(" ")}`,
      );
    }
  }
}
