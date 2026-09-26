// #464/#465: the deploy CLI never leaves an escrow and a peer's verifier on different key registries,
// and a switch to a new registry moves the verifiers first. Driven with a fake chain.
import { test } from "node:test";
import assert from "node:assert/strict";
import { assertOneRegistry, checkPeers, switchKeyRegistry, verifierRegistry, type EscrowWiring } from "../src/one-registry.ts";

const A = "0x1111111111111111111111111111111111111111";
const B = "0x2222222222222222222222222222222222222222";
const V_A = "0xaaaa00000000000000000000000000000000000a";
const V_B = "0xbbbb00000000000000000000000000000000000b";
const ZERO = "0x0000000000000000000000000000000000000000";

/** A fake chain: verifiers → registries, escrows' per-peer wiring, and a log of every write. */
function chain(opts: { wired: Record<string, string>; registries: Record<string, string>; sticky?: boolean; described?: boolean }) {
  const log: string[] = [];
  const escrows: EscrowWiring[] = ["AdManager", "OrderPortal"].map((name) => ({
    name,
    rootVerifier: async (peer: string) => opts.wired[`${name}:${peer}`] ?? ZERO,
    setRootVerifier: async (peer: string, v: string) => {
      log.push(`${name}.setRootVerifier(${peer})`);
      if (opts.described) return false;
      if (!opts.sticky) opts.wired[`${name}:${peer}`] = v; // sticky: the write "succeeds" but nothing changes
      return true;
    },
  }));
  const registryOf = async (v: string) => {
    const r = opts.registries[v.toLowerCase()];
    if (!r) throw new Error("execution reverted"); // does not answer registry()
    return r;
  };
  return { escrows, registryOf, log };
}

test("one registry passes, whatever the letter case", () => {
  assertOneRegistry("0xAbC0000000000000000000000000000000000001", "0xabc0000000000000000000000000000000000001", "deploy");
});

test("46-4: a verifier that does not answer registry() is named", async () => {
  const c = chain({ wired: {}, registries: {} });
  await assert.rejects(verifierRegistry(c.registryOf, V_A, "link"), /link: the verifier 0xaaaa.* does not answer registry\(\)/);
});

test("46-2: a peer whose verifier reads another registry fails the run, naming the escrow and the peer", async () => {
  const c = chain({ wired: { "AdManager:31337": V_A }, registries: { [V_A]: A } });
  await assert.rejects(
    checkPeers({ escrows: c.escrows, peers: ["31337"], escrowRegistry: B, registryOf: c.registryOf, where: "link" }),
    /link: AdManager peer 31337: registry split/,
  );
});

test("46-2: an unwired peer is not a split", async () => {
  const c = chain({ wired: {}, registries: {} });
  await checkPeers({ escrows: c.escrows, peers: ["31337"], escrowRegistry: B, registryOf: c.registryOf, where: "link" });
});

test("a switch moves every wired peer to the new verifier before the registry, and leaves no split", async () => {
  const c = chain({
    wired: { "AdManager:31337": V_A, "OrderPortal:31337": V_A, "AdManager:1000001": ZERO },
    registries: { [V_A]: A, [V_B]: B },
  });
  await switchKeyRegistry({
    escrows: c.escrows,
    peers: ["31337", "1000001"],
    newRegistry: B,
    newVerifier: V_B,
    registryOf: c.registryOf,
    setKeyRegistry: async () => {
      c.log.push("setKeyRegistry");
      return true;
    },
  });
  assert.deepEqual(c.log, ["AdManager.setRootVerifier(31337)", "OrderPortal.setRootVerifier(31337)", "setKeyRegistry"]);
});

test("a switch whose re-point did not take is caught by the read-back", async () => {
  const c = chain({ wired: { "AdManager:31337": V_A }, registries: { [V_A]: A, [V_B]: B }, sticky: true });
  await assert.rejects(
    switchKeyRegistry({
      escrows: c.escrows,
      peers: ["31337"],
      newRegistry: B,
      newVerifier: V_B,
      registryOf: c.registryOf,
      setKeyRegistry: async () => true,
    }),
    /deploy: AdManager peer 31337: registry split/,
  );
});

test("a switch to a verifier on another registry writes nothing", async () => {
  const c = chain({ wired: { "AdManager:31337": V_A }, registries: { [V_A]: A, [V_B]: A } });
  await assert.rejects(
    switchKeyRegistry({
      escrows: c.escrows,
      peers: ["31337"],
      newRegistry: B,
      newVerifier: V_B,
      registryOf: c.registryOf,
      setKeyRegistry: async () => true,
    }),
    /deploy: registry split/,
  );
  assert.deepEqual(c.log, []);
});

test("a switch the admin has to send is described, not read back", async () => {
  const c = chain({ wired: { "AdManager:31337": V_A }, registries: { [V_A]: A, [V_B]: B }, described: true });
  await switchKeyRegistry({
    escrows: c.escrows,
    peers: ["31337"],
    newRegistry: B,
    newVerifier: V_B,
    registryOf: c.registryOf,
    setKeyRegistry: async () => false,
  });
});
