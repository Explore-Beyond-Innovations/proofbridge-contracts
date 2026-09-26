// #464: the deploy CLI refuses to wire an escrow and a verifier that read different key registries.
import { test } from "node:test";
import assert from "node:assert/strict";
import { assertOneRegistry } from "../src/one-registry.ts";

test("one registry passes, whatever the letter case", () => {
  assertOneRegistry("0xAbC0000000000000000000000000000000000001", "0xabc0000000000000000000000000000000000001", "deploy");
});

test("a split throws and names both registries", () => {
  assert.throws(
    () => assertOneRegistry("0x1111111111111111111111111111111111111111", "0x2222222222222222222222222222222222222222", "link"),
    /link: registry split .*0x1111111111111111111111111111111111111111.*0x2222222222222222222222222222222222222222/,
  );
});
