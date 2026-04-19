/** Shell wrappers around the `stellar` CLI — canonical path for contract deploy / invoke / asset deploy. */

import { execSync } from "child_process";

const NETWORK = process.env.STELLAR_NETWORK ?? "testnet";
const SOURCE = process.env.STELLAR_SOURCE_ACCOUNT ?? "admin";

/** Quote a single positional/value arg for POSIX sh, leaving flags untouched. */
function shQuote(arg: string): string {
  if (arg.startsWith("--")) return arg;
  return `'${arg.replace(/'/g, `'\\''`)}'`;
}

function joinArgs(args: string[]): string {
  return args.map(shQuote).join(" ");
}

function exec(cmd: string): string {
  return execSync(cmd, {
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"],
    timeout: 180_000,
  }).trim();
}

/** Run `stellar <args>`, echoing the command for debug visibility. */
export function stellar(args: string): string {
  const cmd = `stellar ${args}`;
  console.log(`  [stellar] ${cmd}`);
  return exec(cmd);
}

/** Deploy a contract WASM. Returns the contract id (C...). */
export function deployContract(
  wasmPath: string,
  constructorArgs: string[] = [],
): string {
  const ctor =
    constructorArgs.length > 0 ? `-- ${joinArgs(constructorArgs)}` : "";
  const out = stellar(
    `contract deploy --wasm "${wasmPath}" --source "${SOURCE}" --network "${NETWORK}" ${ctor}`,
  );
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
  const send = options.send === false ? "--send no" : "--send yes";
  const source = options.source ?? SOURCE;
  const argsStr = args.length > 0 ? joinArgs(args) : "";
  return stellar(
    `contract invoke --id "${contractId}" --source-account "${source}" --network "${NETWORK}" ${send} -- ${fn} ${argsStr}`,
  );
}

export function getAddress(name: string = SOURCE): string {
  return stellar(`keys address "${name}"`);
}

export function getSecret(name: string = SOURCE): string {
  return stellar(`keys secret "${name}"`);
}

/** Deploy or look up a SAC (native XLM via `asset=native`); falls back to `contract id asset` if already deployed. */
export function deploySAC(asset: string = "native"): string {
  try {
    return stellar(
      `contract asset deploy --asset "${asset}" --source "${SOURCE}" --network "${NETWORK}"`,
    );
  } catch {
    return stellar(
      `contract id asset --asset "${asset}" --source "${SOURCE}" --network "${NETWORK}"`,
    );
  }
}

// ── address encoding ────────────────────────────────────────────────

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Decode(str: string): Uint8Array {
  const lookup: Record<string, number> = {};
  for (let i = 0; i < BASE32_ALPHABET.length; i++) {
    lookup[BASE32_ALPHABET[i]] = i;
  }
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const ch of str) {
    value = (value << 5) | (lookup[ch] ?? 0);
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(bytes);
}

/** Decode a Stellar strkey (C.../G...) to `0x` + 64-hex (32 bytes). */
export function strkeyToHex(strkey: string): string {
  const decoded = base32Decode(strkey);
  const payload = decoded.slice(1, 33); // skip 1-byte version, drop 2-byte checksum
  return "0x" + Buffer.from(payload).toString("hex");
}
