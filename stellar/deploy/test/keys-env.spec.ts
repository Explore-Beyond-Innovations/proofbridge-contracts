import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  assertRegistryEnv,
  classifyRetirement,
  formatAudit,
  registryInitArgs,
  retirementOwnerJson,
  retirementsAudit,
  type StoredRetirement,
} from "../src/keys-env.js";

test("D3: initialize names the deploy's environment", () => {
  const args = registryInitArgs("GADMIN", 1000002n, "testnet");
  assert.deepEqual(args, ["--admin", "GADMIN", "--chain_id", "1000002", "--deploy_env", "testnet"]);
});

test("D3: a reused registry must answer this environment", () => {
  assertRegistryEnv("x", "local", "local");
  assert.throws(() => assertRegistryEnv("x", "local", "testnet"), /initialized for "testnet", not DEPLOY_ENV=local/);
  assert.throws(() => assertRegistryEnv("x", "mainnet", undefined), /not DEPLOY_ENV=mainnet/);
});

test("50-4: a simulated set_valid_until classifies each stored retirement", () => {
  assert.equal(classifyRetirement({ ok: true }), "current");
  assert.equal(classifyRetirement({ ok: false, message: "HostError: Error(Contract, #6)" }), "stale-format");
  assert.equal(classifyRetirement({ ok: false, message: "HostError: Error(Crypto, InvalidInput)" }), "stale-format");
  assert.equal(classifyRetirement({ ok: false, message: "HostError: Error(Contract, #12)" }), "no-slot");
  assert.equal(classifyRetirement({ ok: false, message: "HostError: Error(Contract, #15)" }), "already-shorter");
  assert.equal(classifyRetirement({ ok: false, message: "HostError: Error(Contract, #16)" }), "error");
  assert.equal(classifyRetirement({ ok: false, message: "connection refused" }), "error");
});

test("50-4: the audit simulates every entry with a leg-less signed owner and lists the stale ones", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "audit-"));
  const entry = (i: number, scheme: StoredRetirement["scheme"]): StoredRetirement => ({
    account: "0x" + String(i).repeat(64),
    keyCommitment: "0x" + "ab".repeat(32),
    validUntil: "1",
    scheme,
    sig: "0x" + "cd".repeat(scheme === "secp256k1" ? 65 : 64),
  });
  const entries = [entry(1, "secp256k1"), entry(2, "sep53"), entry(3, "secp256k1"), entry(4, "secp256k1")];
  const file = path.join(tmp, "vault.json");
  fs.writeFileSync(file, JSON.stringify(entries));
  const seen: string[][] = [];
  const answers = [undefined, "Error(Crypto, InvalidInput)", "Error(Contract, #6)", "Error(Contract, #12)"];
  const rows = retirementsAudit("CREG", file, (args) => {
    const a = answers[seen.length];
    seen.push(args);
    if (a) throw Object.assign(new Error("invoke failed"), { stderr: `HostError: ${a}` });
  });
  assert.deepEqual(rows.map((r) => r.status), ["current", "stale-format", "stale-format", "no-slot"]);
  assert.deepEqual(seen[0], [
    "--account",
    "1".repeat(64),
    "--owner",
    JSON.stringify({ Signed: { legs: [], sig: { Secp256k1: "cd".repeat(65) } } }),
    "--key_commitment",
    "ab".repeat(32),
    "--valid_until",
    "1",
  ]);
  assert.equal(retirementOwnerJson(entries[1]), JSON.stringify({ Signed: { legs: [], sig: { Sep53: "cd".repeat(64) } } }));
  assert.match(formatAudit(rows), /4 retirement\(s\); 2 stale-format/);
  fs.rmSync(tmp, { recursive: true, force: true });
});
