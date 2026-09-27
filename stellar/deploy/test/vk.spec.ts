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
  assert.deepEqual(vkRecord(f, { CIRCUITS_COMMIT: "2d9791e6" }), {
    vkSha256: sha256Hex(Buffer.from("vk-bytes")),
    circuitsCommit: "2d9791e6",
  });
  assert.deepEqual(vkRecord(path.join(dir, "missing"), { CIRCUITS_COMMIT: "not a sha" }), {});
  fs.rmSync(dir, { recursive: true });
});
