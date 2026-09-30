import { test, after } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { randomBytes } from "crypto";
import { Keypair, StrKey } from "@stellar/stellar-sdk";
import { deployCore } from "../src/deploy-core.js";
import { link } from "../src/link.js";
import { buildManifest } from "../src/manifest.js";
import { NETWORK_PASSPHRASES } from "../src/stellar-cli.js";

// The checks are pinned as pure functions elsewhere; these drive `deployCore` and `link` with a fake
// `stellar` on PATH (test/helpers/fake-stellar), so removing a call from either path turns them red.
// The fake answers `network info` and `keys address` only: any other call is how far a run got.

const FAKE_DIR = path.join(path.dirname(new URL(import.meta.url).pathname), "helpers", "fake-stellar");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "stellar-callsites-"));
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

const DEPLOYER = Keypair.random().publicKey();
const OTHER = Keypair.random().publicKey();
const contractId = () => StrKey.encodeContract(randomBytes(32));
const vkFile = path.join(tmp, "vk");
fs.writeFileSync(vkFile, "a vk");

const CLOCKS = {
  ROUTE_MIN_WINDOW_S: "0",
  ROUTE_BUFFER_S: "1800",
  ROUTE_MARGIN_S: "0",
  ROUTE_LONG_BACKSTOP_S: "86400",
  ROUTE_CLAIM_STAGGER_S: "0",
  DISPUTE_CHALLENGE_PERIOD_S: "3600",
  DISPUTE_BOND_FLOOR: "1",
  DISPUTE_BOND_BPS: "0",
  ANCHOR_DELAY_S: "60",
};
const CLEAN: Record<string, string | undefined> = {
  DEPLOY_ENV: undefined,
  STELLAR_NETWORK: undefined,
  STELLAR_CHAIN_ID: undefined,
  STELLAR_EVENT_VK: undefined,
  ANCHOR_PUBLISHER: undefined,
  DISPUTE_ARBITER: undefined,
  DISPUTE_FEE_POOL: undefined,
  FAKE_STELLAR_PASSPHRASE: undefined,
  ...Object.fromEntries(Object.keys(CLOCKS).map((k) => [k, undefined])),
};

let n = 0;
/** Run `fn` with the fake CLI on PATH and these env entries; returns the CLI calls it made. */
async function withFake(vars: Record<string, string | undefined>, fn: () => Promise<unknown>): Promise<string[]> {
  const log = path.join(tmp, `calls-${n++}.log`);
  fs.writeFileSync(log, "");
  const all = { ...CLEAN, ...vars, FAKE_STELLAR_LOG: log, FAKE_STELLAR_ADDRESS: DEPLOYER, PATH: `${FAKE_DIR}:${process.env.PATH}` };
  const saved: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(all)) {
    saved[k] = process.env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    await fn();
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
  return fs.readFileSync(log, "utf8").split("\n").filter(Boolean);
}
const sent = (calls: string[]) => calls.filter((c) => /^contract (deploy|upload|asset)|--send yes/.test(c));
const deploy = (env: string, out: string) =>
  deployCore({ env, manifestOut: path.join(tmp, out), wasmDir: path.join(tmp, "no-wasm") });
const NAMED = { ANCHOR_PUBLISHER: OTHER, DISPUTE_ARBITER: OTHER, DISPUTE_FEE_POOL: OTHER, STELLAR_EVENT_VK: vkFile };

// ── deploy ─────────────────────────────────────────────────────────────

test("A-4: a local deploy asks the `local` profile's RPC for its passphrase first, then goes on", async () => {
  const calls = await withFake({ FAKE_STELLAR_PASSPHRASE: NETWORK_PASSPHRASES.local, STELLAR_EVENT_VK: vkFile }, () =>
    assert.rejects(deploy("local", "l.json"), /fake stellar: no answer for contract deploy/),
  );
  assert.equal(calls[0], "network info --network local --output json");
});

test("A-4: STELLAR_NETWORK is required outside local (no testnet default)", async () => {
  const calls = await withFake({ ...NAMED, STELLAR_CHAIN_ID: "1000002", FAKE_STELLAR_PASSPHRASE: NETWORK_PASSPHRASES.testnet }, () =>
    assert.rejects(deploy("testnet", "t.json"), /STELLAR_NETWORK is unset for DEPLOY_ENV=testnet/),
  );
  assert.deepEqual(calls, []);
});

test("A-4: DEPLOY_ENV=local against a testnet RPC is refused before anything is sent", async () => {
  const calls = await withFake({ STELLAR_NETWORK: "testnet", FAKE_STELLAR_PASSPHRASE: NETWORK_PASSPHRASES.testnet, STELLAR_EVENT_VK: vkFile }, () =>
    assert.rejects(deploy("local", "l2.json"), /DEPLOY_ENV=local but STELLAR_NETWORK=testnet is on "Test SDF Network ; September 2015" \(testnet\)/),
  );
  assert.deepEqual(calls, ["network info --network testnet --output json"]);
});

test("A-4: DEPLOY_ENV=testnet against a mainnet RPC, or one that does not answer, is refused", async () => {
  const env = { ...NAMED, STELLAR_NETWORK: "pubnet", STELLAR_CHAIN_ID: "1000002" };
  let calls = await withFake({ ...env, FAKE_STELLAR_PASSPHRASE: NETWORK_PASSPHRASES.mainnet }, () =>
    assert.rejects(deploy("testnet", "t2.json"), /is on "Public Global Stellar Network ; September 2015" \(mainnet\)/),
  );
  assert.deepEqual(sent(calls), []);
  calls = await withFake(env, () => assert.rejects(deploy("testnet", "t3.json"), /could not ask the RPC of STELLAR_NETWORK=pubnet/));
  assert.deepEqual(sent(calls), []);
});

test("A-7: the chain id is checked at the deploy entry point", async () => {
  await withFake({ ...NAMED, STELLAR_NETWORK: "testnet", STELLAR_CHAIN_ID: "1000001", FAKE_STELLAR_PASSPHRASE: NETWORK_PASSPHRASES.testnet }, () =>
    assert.rejects(deploy("testnet", "c.json"), /DEPLOY_ENV=testnet uses STELLAR_CHAIN_ID 1000002/),
  );
});

test("A-8: outside local the deployer may not be the anchor notary, refused before anything is sent", async () => {
  const calls = await withFake(
    { ...NAMED, ANCHOR_PUBLISHER: `${OTHER},${DEPLOYER}`, STELLAR_NETWORK: "testnet", STELLAR_CHAIN_ID: "1000002", FAKE_STELLAR_PASSPHRASE: NETWORK_PASSPHRASES.testnet },
    () => assert.rejects(deploy("testnet", "a8.json"), /ANCHOR_PUBLISHER names the deployer/),
  );
  assert.deepEqual(sent(calls), []);
});

test("vkRecord: outside local a missing VK is refused before anything is sent", async () => {
  const calls = await withFake(
    { ...NAMED, STELLAR_EVENT_VK: path.join(tmp, "no-vk"), STELLAR_NETWORK: "testnet", STELLAR_CHAIN_ID: "1000002", FAKE_STELLAR_PASSPHRASE: NETWORK_PASSPHRASES.testnet },
    () => assert.rejects(deploy("testnet", "vk.json"), /VK file is missing/),
  );
  assert.deepEqual(sent(calls), []);
});

// ── link ───────────────────────────────────────────────────────────────

function manifest(file: string, chainId: bigint, env: string, opts: { disputeManager?: boolean; vk?: string } = {}): string {
  const m = buildManifest({
    chainName: `c-${chainId}`,
    chainId,
    env,
    commit: "unknown",
    deployer: DEPLOYER,
    vk: opts.vk ? { vkSha256: opts.vk } : undefined,
    contracts: {
      verifier: contractId(),
      merkleManager: contractId(),
      wNativeToken: contractId(),
      adManager: contractId(),
      orderPortal: contractId(),
      blsKeyRegistry: contractId(),
      counterpartyVerifier: contractId(),
      rootAnchor: contractId(),
      registrar: contractId(),
      ...(opts.disputeManager === false ? {} : { disputeManager: contractId() }),
    },
    tokens: [],
  });
  const out = path.join(tmp, file);
  fs.writeFileSync(out, JSON.stringify(m, null, 2));
  return out;
}
const peerEnv = (env: string) => {
  const f = path.join(tmp, `peer-${env}.env`);
  fs.writeFileSync(f, [`DEPLOY_ENV=${env}`, ...Object.entries(CLOCKS).map(([k, v]) => `${k}=${v}`)].join("\n"));
  return f;
};
const TESTNET = { ...CLOCKS, STELLAR_NETWORK: "testnet", FAKE_STELLAR_PASSPHRASE: NETWORK_PASSPHRASES.testnet };
const linkT = (localManifest: string, peerManifest: string, peerEnvFile?: string) =>
  link({ localManifest, peerManifest, peerEnvFile, localChainId: 1000002n });
// Past every route check, the first thing link does is read the chain; the fake has no answer.
const PAST_CHECKS = /fake stellar: no answer for contract invoke/;

test("A-4: link checks the network against the manifest's env before any call", async () => {
  const local = manifest("lnk-l.json", 1000002n, "testnet");
  const calls = await withFake({ ...CLOCKS, STELLAR_NETWORK: "testnet", FAKE_STELLAR_PASSPHRASE: NETWORK_PASSPHRASES.local }, () =>
    assert.rejects(linkT(local, manifest("lnk-p.json", 11155111n, "testnet")), /DEPLOY_ENV=testnet but STELLAR_NETWORK=testnet is on "Standalone Network/),
  );
  assert.deepEqual(calls, ["network info --network testnet --output json"]);
});

test("A-5: a real-network route whose peer has not linked, with no --peer-env, is refused", async () => {
  const local = manifest("u-l.json", 1000002n, "testnet");
  const peer = manifest("u-p.json", 11155111n, "testnet");
  let calls = await withFake(TESTNET, () => assert.rejects(linkT(local, peer), /could not be checked in both directions/));
  assert.deepEqual(sent(calls), []);
  calls = await withFake(TESTNET, () => assert.rejects(linkT(local, peer, peerEnv("testnet")), PAST_CHECKS));
  assert.deepEqual(sent(calls), []);
});

test("A-6: link refuses a peer deployed for another env, or against another VK", async () => {
  const local = manifest("c-l.json", 1000002n, "testnet", { vk: "0x" + "ab".repeat(32) });
  await withFake(TESTNET, () =>
    assert.rejects(linkT(local, manifest("c-p1.json", 11155111n, "mainnet"), peerEnv("mainnet")), /cannot span environments/),
  );
  await withFake(TESTNET, () =>
    assert.rejects(
      linkT(local, manifest("c-p2.json", 11155111n, "testnet", { vk: "0x" + "cd".repeat(32) }), peerEnv("testnet")),
      /refuse each other's proofs/,
    ),
  );
});

test("A-5: no DisputeManager on either side links on the clocks alone; a mixed route is refused", async () => {
  const bareLocal = manifest("d-l0.json", 1000002n, "testnet", { disputeManager: false });
  const barePeer = manifest("d-p0.json", 11155111n, "testnet", { disputeManager: false });
  await withFake(TESTNET, () => assert.rejects(linkT(bareLocal, barePeer, peerEnv("testnet")), PAST_CHECKS));
  const fullLocal = manifest("d-l1.json", 1000002n, "testnet");
  const fullPeer = manifest("d-p1.json", 11155111n, "testnet");
  await withFake(TESTNET, () => assert.rejects(linkT(fullLocal, barePeer, peerEnv("testnet")), /only this chain has a DisputeManager/));
  await withFake(TESTNET, () => assert.rejects(linkT(bareLocal, fullPeer, peerEnv("testnet")), /only the peer has a DisputeManager/));
});
