import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { assertReusableWasm, wasmMismatchOverride, wasmSha256 } from "../src/wasm-reuse.js";
import { sha256Hex } from "../src/vk.js";

// A key registry or counterparty verifier reused under code with another storage shape would hold
// slots the new code cannot decode; the admin `upgrade` keeps storage, so reuse is refused unless
// the recorded wasm hash is this bundle's.
test("a reused contract deployed from other wasm is refused; the same wasm passes; no record refuses", () => {
  const a = "a".repeat(64);
  const b = "b".repeat(64);
  assert.throws(() => assertReusableWasm("BLSKeyRegistry", b, () => a, false), /deployed from wasm b{64}, but this bundle's wasm hashes to a{64}/);
  assert.equal(assertReusableWasm("BLSKeyRegistry", a, () => a, false), "match");
  assert.equal(assertReusableWasm("BLSKeyRegistry", a.toUpperCase(), () => a, false), "match", "case does not matter");
  assert.throws(() => assertReusableWasm("CounterpartyVerifier", undefined, () => a, false), /records no wasm hash for the reused contract.*a{64}/);
  // the refusal names the one-run flag as the override, and the env variable as local-only
  assert.throws(() => assertReusableWasm("CounterpartyVerifier", undefined, () => a, false), /pass --allow-wasm-mismatch to this one run.*on a local stack STELLAR_ALLOW_WASM_MISMATCH=1 also counts/);
});

// The deploy orchestrator sources env files with `set -a`, so a variable left in one would apply to
// every later run: outside local only the flag (the option) overrides, and the variable is exactly `1`.
test("the override: the option counts everywhere; the env variable only on local, only as exactly \"1\"", () => {
  const on = { STELLAR_ALLOW_WASM_MISMATCH: "1" };
  assert.deepEqual(wasmMismatchOverride("local", undefined, on), { allow: true, ignoredEnv: false });
  for (const v of ["true", "yes", "0", "TRUE", " 1"]) {
    assert.deepEqual(wasmMismatchOverride("local", undefined, { STELLAR_ALLOW_WASM_MISMATCH: v }), { allow: false, ignoredEnv: false }, `value ${JSON.stringify(v)}`);
  }
  assert.deepEqual(wasmMismatchOverride("local", undefined, {}), { allow: false, ignoredEnv: false });
  for (const e of ["testnet", "mainnet"] as const) {
    assert.deepEqual(wasmMismatchOverride(e, undefined, on), { allow: false, ignoredEnv: true }, `${e}: the variable is ignored and said so`);
    assert.deepEqual(wasmMismatchOverride(e, undefined, {}), { allow: false, ignoredEnv: false }, e);
    assert.deepEqual(wasmMismatchOverride(e, true, {}), { allow: true, ignoredEnv: false }, `${e}: the flag`);
    assert.deepEqual(wasmMismatchOverride(e, true, on), { allow: true, ignoredEnv: false }, `${e}: the flag, variable beside it`);
  }
  // an explicit option is the answer either way; the variable is not consulted
  assert.deepEqual(wasmMismatchOverride("local", false, on), { allow: false, ignoredEnv: false });
});

test("the override reuses either way, and never reads the bundle's wasm", () => {
  let read = 0;
  const local = () => {
    read++;
    return "a".repeat(64);
  };
  assert.equal(assertReusableWasm("BLSKeyRegistry", "b".repeat(64), local, true), "overridden");
  assert.equal(assertReusableWasm("BLSKeyRegistry", undefined, local, true), "overridden");
  assert.equal(read, 0);
});

test("wasmSha256 is the install hash (hex sha256, no 0x) and names a missing file", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "wasm-"));
  const f = path.join(dir, "x.wasm");
  fs.writeFileSync(f, "wasm-bytes");
  assert.equal(wasmSha256(f), sha256Hex(Buffer.from("wasm-bytes")).slice(2));
  assert.match(wasmSha256(f), /^[0-9a-f]{64}$/);
  assert.throws(() => wasmSha256(path.join(dir, "missing.wasm"), "stellar-deploy BLSKeyRegistry"), /wasm file .*missing\.wasm is missing, so the reused contract cannot be compared/);
  fs.rmSync(dir, { recursive: true });
});
