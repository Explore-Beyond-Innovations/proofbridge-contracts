// #464/#465: the deploy CLI never leaves an escrow and a peer's verifier on different key registries,
// and a switch to a new registry moves the verifiers first. Driven with a fake chain, Stellar ids.
import { test } from "node:test";
import assert from "node:assert/strict";
import { assertOneRegistry, checkPeers, switchKeyRegistry, verifierRegistry, type EscrowWiring } from "../src/one-registry.ts";

const A = "CAREGISTRYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const B = "CBREGISTRYBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const V_A = "CAVERIFIERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const V_B = "CBVERIFIERBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

/** A fake chain: verifiers → registries, escrows' per-peer wiring, and a log of every write. */
function chain(opts: { wired: Record<string, string>; registries: Record<string, string>; sticky?: boolean; described?: boolean }) {
  const log: string[] = [];
  const escrows: EscrowWiring[] = ["AdManager", "OrderPortal"].map((name) => ({
    name,
    rootVerifier: (peer: string) => opts.wired[`${name}:${peer}`] ?? null,
    setRootVerifier: (peer: string, v: string) => {
      log.push(`${name}.set_root_verifier(${peer})`);
      if (opts.described) return false;
      if (!opts.sticky) opts.wired[`${name}:${peer}`] = v;
      return true;
    },
  }));
  const registryOf = (v: string): string => {
    const r = opts.registries[v];
    if (!r) throw new Error("HostError: Error(WasmVm, InvalidAction)"); // an uninitialized verifier panics
    return r;
  };
  return { escrows, registryOf, log };
}

test("a Stellar contract id is compared exactly", () => {
  assertOneRegistry(A, A, "deploy");
  assert.throws(() => assertOneRegistry(A, A.toLowerCase(), "deploy"), /registry split/);
});

test("46-4: a verifier that panics in registry() (wired before initialize) is named", () => {
  const c = chain({ wired: {}, registries: {} });
  assert.throws(() => verifierRegistry(c.registryOf, V_A, "link"), /link: the verifier CAVERIFIER.* does not answer registry\(\)/);
});

test("46-2: a peer whose verifier reads another registry fails the run, naming the escrow and the peer", () => {
  const c = chain({ wired: { "OrderPortal:31337": V_A }, registries: { [V_A]: A } });
  assert.throws(
    () => checkPeers({ escrows: c.escrows, peers: ["31337"], escrowRegistry: B, registryOf: c.registryOf, where: "link" }),
    /link: OrderPortal peer 31337: registry split/,
  );
});

test("a switch moves every wired peer to the new verifier before the registry, and leaves no split", () => {
  const c = chain({ wired: { "AdManager:31337": V_A, "OrderPortal:31337": V_A }, registries: { [V_A]: A, [V_B]: B } });
  switchKeyRegistry({
    escrows: c.escrows,
    peers: ["31337", "11155111"],
    newRegistry: B,
    newVerifier: V_B,
    registryOf: c.registryOf,
    setKeyRegistry: () => {
      c.log.push("set_key_registry");
      return true;
    },
  });
  assert.deepEqual(c.log, ["AdManager.set_root_verifier(31337)", "OrderPortal.set_root_verifier(31337)", "set_key_registry"]);
});

test("a switch whose re-point did not take is caught by the read-back", () => {
  const c = chain({ wired: { "AdManager:31337": V_A }, registries: { [V_A]: A, [V_B]: B }, sticky: true });
  assert.throws(
    () =>
      switchKeyRegistry({
        escrows: c.escrows,
        peers: ["31337"],
        newRegistry: B,
        newVerifier: V_B,
        registryOf: c.registryOf,
        setKeyRegistry: () => true,
      }),
    /deploy: AdManager peer 31337: registry split/,
  );
});

test("a switch to a verifier on another registry writes nothing", () => {
  const c = chain({ wired: { "AdManager:31337": V_A }, registries: { [V_A]: A, [V_B]: A } });
  assert.throws(
    () =>
      switchKeyRegistry({
        escrows: c.escrows,
        peers: ["31337"],
        newRegistry: B,
        newVerifier: V_B,
        registryOf: c.registryOf,
        setKeyRegistry: () => true,
      }),
    /deploy: registry split/,
  );
  assert.deepEqual(c.log, []);
});
