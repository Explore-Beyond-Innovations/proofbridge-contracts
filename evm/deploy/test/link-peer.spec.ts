import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { assertPeerCompatible, readEnvFile } from "../src/link.js";

const manifest = (over: Record<string, unknown> = {}) =>
  ({ meta: { env: "testnet", vkSha256: "0x" + "ab".repeat(32), ...over } }) as never;

// A-6: one route, one environment, one VK.
test("link refuses a peer deployed for another env or against another VK", () => {
  assertPeerCompatible(manifest(), manifest());
  assert.throws(() => assertPeerCompatible(manifest(), manifest({ env: "local" })), /cannot span environments/);
  assert.throws(() => assertPeerCompatible(manifest(), manifest({ vkSha256: "0x" + "cd".repeat(32) })), /refuse each other's proofs/);
  // A side with no recorded hash is not a mismatch (the deploy itself refuses a missing VK now).
  assertPeerCompatible(manifest({ vkSha256: undefined }), manifest());
});

// A-5: the peer's planned clocks come from its env file when its manifest has not recorded them.
test("readEnvFile reads KEY=VALUE, skips comments, strips quotes and `export`", () => {
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "env-")), "peer.env");
  fs.writeFileSync(f, ["# clocks", "DEPLOY_ENV=testnet", "export ROUTE_BUFFER_S=1800", 'ROUTE_LONG_BACKSTOP_S="172800"', "", "BROKEN LINE"].join("\n"));
  assert.deepEqual(readEnvFile(f), { DEPLOY_ENV: "testnet", ROUTE_BUFFER_S: "1800", ROUTE_LONG_BACKSTOP_S: "172800" });
});
