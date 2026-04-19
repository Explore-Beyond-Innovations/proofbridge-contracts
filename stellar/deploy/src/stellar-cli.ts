/** Shell wrappers around the `stellar` CLI — canonical path for contract deploy / invoke / asset deploy. */

import { execFileSync } from "child_process";
import { StrKey } from "@stellar/stellar-sdk";

const NETWORK = process.env.STELLAR_NETWORK ?? "testnet";
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

/** Deploy or look up a SAC (native XLM via `asset=native`); falls back to `contract id asset` if already deployed. */
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
  } catch {
    return stellar([
      "contract",
      "id",
      "asset",
      "--asset",
      asset,
      "--source",
      SOURCE,
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
