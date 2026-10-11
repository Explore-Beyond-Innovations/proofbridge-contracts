import { test } from "node:test";
import assert from "node:assert/strict";
import { assertPeerCompatible } from "../src/link.js";

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
