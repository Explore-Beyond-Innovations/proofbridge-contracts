// #464/#465: the deploy CLI never leaves an escrow and a peer's verifier on different key registries,
// and a switch to a new registry moves the verifiers first. Driven with a fake chain, Stellar ids.
import { test } from "node:test";
import assert from "node:assert/strict";
import { assertOneRegistry, checkPeers, deployRegistryStep, linkCheckStep, switchKeyRegistry, verifierRegistry, type EscrowChain, type EscrowWiring } from "../src/one-registry.ts";

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

// #466: the steps `link` and `deploy-core` call, driven with a fake chain whose escrows list their
// wired chains, as `wired_chains()` reports them.
const AM = "CADMANAGERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const OP = "CORDERPORTALAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const ids = { adManager: AM, orderPortal: OP };

function escrowChain(o: { wired: Record<string, string>; registries: Record<string, string>; keyRegistry: string; unlisted?: boolean }) {
  const log: string[] = [];
  const c: EscrowChain = {
    rootVerifier: (escrow, peer) => o.wired[`${escrow}:${peer}`] ?? null,
    wiredChains: (escrow) => {
      if (o.unlisted) throw new Error("HostError: Error(WasmVm, MissingValue)"); // pre-#466 wasm
      return Object.keys(o.wired).filter((k) => k.startsWith(`${escrow}:`)).map((k) => k.split(":")[1]);
    },
    registryOf: (v) => {
      const r = o.registries[v];
      if (!r) throw new Error("HostError: Error(WasmVm, InvalidAction)");
      return r;
    },
    keyRegistry: () => o.keyRegistry,
    setRootVerifier: (escrow, name, peer, v) => {
      log.push(`${name}.set_root_verifier(${peer})`);
      o.wired[`${escrow}:${peer}`] = v;
      return true;
    },
    setKeyRegistry: (_am, r) => {
      log.push("AdManager.set_key_registry");
      o.keyRegistry = r;
      return true;
    },
  };
  return { c, log };
}

test("466: link finds a peer wired by hand outside the one it links, and refuses its split", () => {
  const { c } = escrowChain({ wired: { [`${AM}:31337`]: V_A, [`${AM}:999`]: V_B }, registries: { [V_A]: A, [V_B]: B }, keyRegistry: A });
  assert.throws(() => linkCheckStep(c, ids, "31337"), /link: AdManager peer 999: registry split/);
});

test("466: link passes when every listed peer reads the escrow's registry", () => {
  const { c } = escrowChain({ wired: { [`${AM}:31337`]: V_A, [`${OP}:999`]: V_A }, registries: { [V_A]: A }, keyRegistry: A });
  linkCheckStep(c, ids, "31337");
});

test("466: deploy with the registry unchanged checks a hand-wired peer the manifest never recorded", () => {
  const { c, log } = escrowChain({ wired: { [`${OP}:999`]: V_B }, registries: { [V_A]: A, [V_B]: B }, keyRegistry: A });
  assert.throws(
    () => deployRegistryStep(c, ids, { registry: A, verifier: V_A, manifestPeers: ["31337"] }),
    /deploy: OrderPortal peer 999: registry split/,
  );
  assert.deepEqual(log, []);
});

test("466: deploy switching the registry also re-points a hand-wired peer, before the registry", () => {
  const { c, log } = escrowChain({ wired: { [`${AM}:31337`]: V_A, [`${AM}:999`]: V_A }, registries: { [V_A]: A, [V_B]: B }, keyRegistry: A });
  deployRegistryStep(c, ids, { registry: B, verifier: V_B, manifestPeers: ["31337"] });
  assert.equal(log[log.length - 1], "AdManager.set_key_registry");
  assert.ok(log.includes("AdManager.set_root_verifier(999)"), `the hand-wired peer moved: ${log.join(", ")}`);
});

test("466: an escrow that cannot list its chains falls back to the manifest's peers", () => {
  const { c } = escrowChain({ wired: { [`${AM}:999`]: V_B }, registries: { [V_B]: B }, keyRegistry: A, unlisted: true });
  deployRegistryStep(c, ids, { registry: A, verifier: V_A, manifestPeers: ["31337"] });
});
