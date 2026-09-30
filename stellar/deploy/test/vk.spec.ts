import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { assertReusedVk, sha256Hex, vkRecord } from "../src/vk.js";

// C-20: a reused verifier checking proofs against another VK makes one chain refuse every proof.
test("a reused verifier with another VK is refused; the same VK, or nothing to compare, passes", () => {
  const a = sha256Hex(Buffer.from("vk-a"));
  const b = sha256Hex(Buffer.from("vk-b"));
  assert.throws(() => assertReusedVk("Verifier", a, b), /checks proofs against VK/);
  assert.throws(() => assertReusedVk("Verifier", a, a, b), /checks proofs against VK/, "the chain's answer wins over the manifest");
  assert.equal(assertReusedVk("Verifier", a, b, a), "match", "the chain's answer wins over a stale record");
  assert.equal(assertReusedVk("Verifier", a, a), "match");
  assert.equal(assertReusedVk("Verifier", a, undefined), "unknown");
  assert.equal(assertReusedVk("Verifier", undefined, a), "unknown");
});

test("the record hashes the VK file and takes a well-formed CIRCUITS_COMMIT", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vk-"));
  const f = path.join(dir, "vk");
  fs.writeFileSync(f, "vk-bytes");
  assert.deepEqual(vkRecord(f, "testnet", { CIRCUITS_COMMIT: "2d9791e6" }), {
    vkSha256: sha256Hex(Buffer.from("vk-bytes")),
    circuitsCommit: "2d9791e6",
  });
  assert.equal(vkRecord(f, "testnet", { CIRCUITS_COMMIT: "not a sha" }).circuitsCommit, undefined, "a malformed commit is dropped");
  // Outside local a missing VK refuses: the manifest would record no hash and A-6's compare would skip.
  assert.throws(() => vkRecord(path.join(dir, "missing"), "testnet", {}), /VK file is missing/);
  assert.throws(() => vkRecord(path.join(dir, "missing"), "mainnet", { DEPLOY_ENV: "local" }), /VK file is missing/, "the resolved env decides");
  assert.deepEqual(vkRecord(path.join(dir, "missing"), "local", {}), {}, "a local stack may run without built circuits");
  fs.rmSync(dir, { recursive: true });
});
