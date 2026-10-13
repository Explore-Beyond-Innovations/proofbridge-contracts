import { createHash } from "crypto";
import { Address, nativeToScVal, xdr } from "@stellar/stellar-sdk";
import { readManifest, writeManifest, type ChainDeploymentManifest } from "@proofbridge/deployment-manifest";
import { invokeContract, readView } from "./stellar-cli.js";

/**
 * The 24-hour admin delay (#586) on the Soroban side.
 *
 * A proposal is `propose_action(fn_name, args)` where `args` is the XDR of the call's argument list
 * (an `ScVal::Vec`, each argument with the setter's own type); the contract keys it by
 * `sha256(xdr((fn_name, args)))` and the setter, called later with exactly those arguments by anyone,
 * consumes it. This file is the encoder (which setter takes which types) and the commands
 * (`status`, `activate`, `propose`, `execute`, `cancel`). `deploy` and `link` use the encoder through
 * `Acting` to propose instead of send once a contract's delay is on.
 */

type ArgType = "u128" | "u64" | "u32" | "bool" | "bytes32" | "address" | { struct: Record<string, ArgType> };

const TIMING: ArgType = { struct: { min_window: "u64", buffer: "u64", margin: "u64", claim_stagger: "u64" } };

/** Every timelocked setter, by contract label, with its arguments in order. */
export const TIMELOCKED_SETTERS: Record<string, Record<string, [string, ArgType][]>> = {
  AdManager: {
    set_chain: [["order_chain_id", "u128"], ["order_portal", "bytes32"]],
    remove_chain: [["order_chain_id", "u128"]],
    set_root_verifier: [["chain_id", "u128"], ["module", "address"]],
    set_key_registry: [["registry", "address"]],
    set_route_timing: [["chain_id", "u128"], ["timing", TIMING]],
    set_dispute_manager: [["manager", "address"]],
    set_root_anchor: [["anchor", "address"]],
    set_token_route: [["ad_token", "bytes32"], ["order_token", "bytes32"], ["order_chain_id", "u128"]],
    remove_token_route: [["ad_token", "bytes32"], ["order_chain_id", "u128"]],
    set_protocol_fee_pool: [["pool", "bytes32"]],
    set_fee_bps: [["lp_bps", "u32"], ["protocol_bps", "u32"]],
  },
  OrderPortal: {
    set_chain: [["ad_chain_id", "u128"], ["ad_manager", "bytes32"]],
    remove_chain: [["ad_chain_id", "u128"]],
    set_root_verifier: [["chain_id", "u128"], ["module", "address"]],
    set_route_timing: [["chain_id", "u128"], ["timing", TIMING]],
    set_root_anchor: [["anchor", "address"]],
    set_token_route: [["order_token", "bytes32"], ["ad_chain_id", "u128"], ["ad_token", "bytes32"]],
    remove_token_route: [["order_token", "bytes32"], ["ad_chain_id", "u128"]],
  },
  MerkleManager: {
    set_manager: [["manager", "address"], ["status", "bool"]],
  },
  DisputeManager: {
    set_escrow: [["escrow", "address"], ["allowed", "bool"]],
    set_dispute_params: [["chain_id", "u128"], ["params", { struct: { challenge_period: "u64", bond_floor: "u128" } }]],
    set_arbiter: [["arbiter", "address"]],
    set_protocol_fee_pool: [["pool", "address"]],
    set_bond_config: [["token", "address"], ["peer_chain_id", "u128"], ["config", { struct: { min_bond: "u128", bond_bps: "u32" } }]],
  },
};

/** The manifest key of each contract with the delay. */
export const TIMELOCK_CONTRACTS = {
  AdManager: "adManager",
  OrderPortal: "orderPortal",
  MerkleManager: "merkleManager",
  DisputeManager: "disputeManager",
} as const;

function toScVal(v: unknown, t: ArgType, where: string): xdr.ScVal {
  if (typeof t === "object") {
    const obj = (typeof v === "string" ? JSON.parse(v) : v) as Record<string, unknown>;
    // A #[contracttype] struct is an ScMap keyed by field name, keys in order.
    const keys = Object.keys(t.struct).sort();
    return xdr.ScVal.scvMap(
      keys.map((k) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(k), val: toScVal(obj[k], t.struct[k]!, `${where}.${k}`) })),
    );
  }
  switch (t) {
    case "u128":
    case "u64":
      return nativeToScVal(BigInt(String(v)), { type: t });
    case "u32":
      return xdr.ScVal.scvU32(Number(v));
    case "bool":
      return xdr.ScVal.scvBool(v === true || v === "true");
    case "bytes32": {
      const hex = String(v).replace(/^0x/, "");
      if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error(`timelock: ${where} must be 32 bytes of hex, got ${v}`);
      return xdr.ScVal.scvBytes(Buffer.from(hex, "hex"));
    }
    case "address":
      return new Address(String(v)).toScVal();
  }
}

/** A setter call encoded as the contract keys it: its id, and the argument list's XDR to propose. */
export interface EncodedCall {
  /** `sha256(xdr((fn_name, args)))`, hex: the proposal id `timelock_eta` / `cancel_action` take. */
  id: string;
  /** The XDR of the argument list (`ScVal::Vec`), hex: `propose_action`'s `args`. */
  argsXdr: string;
}

/** Encode `label.fn(named)`, where `named` maps each argument name to its value (struct fields as an object or JSON). */
export function encodeCall(label: string, fn: string, named: Record<string, unknown>): EncodedCall {
  const spec = TIMELOCKED_SETTERS[label]?.[fn];
  if (!spec) throw new Error(`timelock: ${label}.${fn} is not a timelocked setter`);
  const args = spec.map(([name, t]) => {
    if (!(name in named)) throw new Error(`timelock: ${label}.${fn} needs --${name}`);
    return toScVal(named[name], t, `${label}.${fn} ${name}`);
  });
  const list = xdr.ScVal.scvVec(args);
  const keyed = xdr.ScVal.scvVec([xdr.ScVal.scvSymbol(fn), list]);
  return {
    id: createHash("sha256").update(keyed.toXDR()).digest("hex"),
    argsXdr: list.toXDR().toString("hex"),
  };
}

/** `["--chain_id", "7", "--timing", "{...}"]` (the CLI's flag form) as `{ chain_id: "7", timing: "{...}" }`. */
export function flagsToNamed(args: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (let i = 0; i < args.length; i += 2) {
    const k = args[i]!;
    if (!k.startsWith("--")) throw new Error(`timelock: expected a --flag, got ${k}`);
    out[k.slice(2)] = args[i + 1] ?? "";
  }
  return out;
}

/** The inverse: `{ chain_id: "7" }` as `["--chain_id", "7"]`, objects as JSON. */
export function namedToFlags(named: Record<string, unknown>): string[] {
  return Object.entries(named).flatMap(([k, v]) => [`--${k}`, typeof v === "string" ? v : JSON.stringify(v)]);
}

/** The contract ids among `contracts` whose delay is on. A pre-#586 contract has no view: not timelocked. */
export function timelockedOf(contracts: ChainDeploymentManifest["contracts"]): string[] {
  const out: string[] = [];
  for (const key of Object.values(TIMELOCK_CONTRACTS)) {
    const id = contracts[key]?.address;
    if (!id) continue;
    try {
      if (readView(id, "timelock_active") === true) out.push(id);
    } catch {
      // pre-#586 wasm
    }
  }
  return out;
}

export interface TimelockOptions {
  manifest: string;
}

export interface TimelockCallOptions extends TimelockOptions {
  contract: keyof typeof TIMELOCK_CONTRACTS;
  fn: string;
  /** Arguments by name, e.g. `{ "lp_bps": 30, "protocol_bps": 20 }`. */
  named: Record<string, unknown>;
}

async function contractId(manifest: string, label: keyof typeof TIMELOCK_CONTRACTS): Promise<{ m: ChainDeploymentManifest; id: string }> {
  const m = await readManifest(manifest);
  if (m.chain.kind !== "STELLAR") throw new Error(`timelock: ${manifest} is not a Stellar manifest`);
  const id = m.contracts[TIMELOCK_CONTRACTS[label]]?.address;
  if (!id) throw new Error(`timelock: the manifest has no ${label}`);
  return { m, id };
}

export async function timelockStatus(opts: TimelockOptions): Promise<Record<string, boolean>> {
  const m = await readManifest(opts.manifest);
  const out: Record<string, boolean> = {};
  for (const [label, key] of Object.entries(TIMELOCK_CONTRACTS)) {
    const id = m.contracts[key]?.address;
    if (!id) continue;
    out[label] = readView(id, "timelock_active") === true;
    console.log(`  ${label}: ${out[label] ? "delay on" : "setup (no delay)"}`);
  }
  return out;
}

/** Switch the delay on, for good, on every contract that carries it (admin). Idempotent. */
export async function timelockActivate(opts: TimelockOptions): Promise<{ activated: string[] }> {
  const m = await readManifest(opts.manifest);
  const activated: string[] = [];
  let allOn = true;
  for (const [label, key] of Object.entries(TIMELOCK_CONTRACTS)) {
    const id = m.contracts[key]?.address;
    if (!id) continue;
    if (readView(id, "timelock_active") === true) {
      console.log(`  [skip] ${label}: delay already on`);
      continue;
    }
    try {
      invokeContract(id, "activate_timelock");
      activated.push(label);
      console.log(`  [timelock] ${label}.activate_timelock()`);
    } catch (err) {
      allOn = false;
      console.error(`  [timelock] ${label}.activate_timelock() failed: ${err}`);
    }
  }
  if (allOn && !m.timelock) {
    m.timelock = { activatedAt: new Date().toISOString() };
    await writeManifest(opts.manifest, m);
  }
  return { activated };
}

export async function timelockPropose(opts: TimelockCallOptions): Promise<EncodedCall & { eta: number }> {
  const { id } = await contractId(opts.manifest, opts.contract);
  const enc = encodeCall(opts.contract, opts.fn, opts.named);
  invokeContract(id, "propose_action", ["--fn_name", opts.fn, "--args", enc.argsXdr]);
  const eta = Number(readView(id, "timelock_eta", ["--id", enc.id]));
  console.log(`  [propose] ${opts.contract}.${opts.fn}  id ${enc.id}  from ${new Date(eta * 1000).toISOString()}`);
  return { ...enc, eta };
}

/** Execute a ripe proposal (any source account): the setter itself, with exactly the proposed arguments. */
export async function timelockExecute(opts: TimelockCallOptions): Promise<EncodedCall> {
  const { id } = await contractId(opts.manifest, opts.contract);
  const enc = encodeCall(opts.contract, opts.fn, opts.named);
  if (Number(readView(id, "timelock_eta", ["--id", enc.id])) === 0) {
    throw new Error(`timelock: no pending proposal ${enc.id} for ${opts.contract}.${opts.fn}; propose it first`);
  }
  invokeContract(id, opts.fn, namedToFlags(opts.named));
  console.log(`  [execute] ${opts.contract}.${opts.fn}  id ${enc.id}`);
  return enc;
}

export async function timelockCancel(opts: TimelockCallOptions): Promise<EncodedCall> {
  const { id } = await contractId(opts.manifest, opts.contract);
  const enc = encodeCall(opts.contract, opts.fn, opts.named);
  invokeContract(id, "cancel_action", ["--id", enc.id]);
  console.log(`  [cancel] ${opts.contract}.${opts.fn}  id ${enc.id}`);
  return enc;
}
