// 2.6 review D3 / 50-4: the key registry is initialized for one environment (its messages' domain
// salt and Network line), and pre-signed retirements under an older message format are listed.

import * as fs from "fs";
import { invokeContract, shellQuote } from "./stellar-cli.js";

/** `initialize`'s arguments: the environment goes in, so a signature for another never applies. */
export function registryInitArgs(adminStrkey: string, chainId: bigint, env: string): string[] {
  return ["--admin", adminStrkey, "--chain_id", chainId.toString(), "--deploy_env", env];
}

/** A reused registry must be the deploy's environment; refused before anything is sent. */
export function assertRegistryEnv(where: string, want: string, held: unknown): void {
  if (held !== want) {
    throw new Error(
      `${where}: the reused BLSKeyRegistry was initialized for ${JSON.stringify(held)}, not DEPLOY_ENV=${want}; ` +
        `its key messages would carry the wrong Network line and salt — deploy a fresh registry`,
    );
  }
}

/** One pre-signed retirement as the relayer's vault holds it. */
export interface StoredRetirement {
  account: string;
  keyCommitment: string;
  validUntil: string;
  scheme: "secp256k1" | "sep53";
  sig: string;
}

export type RetirementStatus = "current" | "stale-format" | "no-slot" | "already-shorter" | "error";

/**
 * What a simulated `set_valid_until` says about a stored retirement: it would apply (current), its
 * signature is refused (stale-format: OwnerMismatch #6, or the host's ed25519 check trapping), the key
 * holds no slot here (NoSuchSlot #12), or the slot is already at least as short (BadValidUntil #15).
 */
export function classifyRetirement(outcome: { ok: true } | { ok: false; message: string }): RetirementStatus {
  if (outcome.ok) return "current";
  const m = outcome.message;
  if (/Error\(Contract, #6\)/.test(m) || /Error\(Crypto,/.test(m)) return "stale-format";
  if (/Error\(Contract, #12\)/.test(m)) return "no-slot";
  if (/Error\(Contract, #15\)/.test(m)) return "already-shorter";
  return "error";
}

const strip0x = (h: string) => h.replace(/^0x/, "");

/** The `--owner` JSON for a retirement: OwnerAuth::Signed with no legs and the bare signature. */
export function retirementOwnerJson(r: StoredRetirement): string {
  const sig = strip0x(r.sig);
  return JSON.stringify({
    Signed: { legs: [], sig: r.scheme === "secp256k1" ? { Secp256k1: sig } : { Sep53: sig } },
  });
}

export interface AuditRow extends StoredRetirement {
  status: RetirementStatus;
  detail?: string;
}

/**
 * 50-4: simulate each stored retirement on this chain's registry (nothing is sent) and list the ones
 * the registry refuses as signed under an old message format: those must be collected again.
 */
export function retirementsAudit(
  registry: string,
  file: string,
  simulate: (args: string[]) => void = (args) => void invokeContract(registry, "set_valid_until", args, { send: false }),
): AuditRow[] {
  const entries = JSON.parse(fs.readFileSync(file, "utf8")) as StoredRetirement[];
  if (!Array.isArray(entries)) throw new Error(`retirements-audit: ${file} is not a JSON array`);
  const rows: AuditRow[] = [];
  for (const r of entries) {
    const args = [
      "--account",
      strip0x(r.account),
      "--owner",
      retirementOwnerJson(r),
      "--key_commitment",
      strip0x(r.keyCommitment),
      "--valid_until",
      BigInt(r.validUntil).toString(),
    ];
    let outcome: { ok: true } | { ok: false; message: string };
    try {
      simulate(args);
      outcome = { ok: true };
    } catch (err) {
      const e = err as { stderr?: unknown; message?: string };
      outcome = { ok: false, message: `${String(e.stderr ?? "")}\n${e.message ?? String(err)}` };
    }
    const status = classifyRetirement(outcome);
    rows.push({ ...r, status, ...(status === "error" && !outcome.ok ? { detail: outcome.message.trim().split("\n")[0] } : {}) });
  }
  return rows;
}

/** The table the CLI prints; the caller exits non-zero when any row is stale-format (or unreadable). */
export function formatAudit(rows: AuditRow[]): string {
  const lines = rows.map(
    (r) => `${r.status.padEnd(15)} ${r.account} key ${r.keyCommitment} until ${r.validUntil}${r.detail ? `  (${shellQuote(r.detail)})` : ""}`,
  );
  const stale = rows.filter((r) => r.status === "stale-format").length;
  lines.push(`${rows.length} retirement(s); ${stale} stale-format (collect them again under the current message)`);
  return lines.join("\n");
}
