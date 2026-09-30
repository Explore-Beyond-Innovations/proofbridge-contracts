import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { deployCore } from "../src/deploy-core.js";
import { link } from "../src/link.js";
import { K0, startAnvil, withEnv, type Anvil } from "./helpers/anvil.js";

// `link` itself, on two real Anvils with real deploys: removing a route check from the link path
// turns these red. The checks run before anything is sent, so a refusal must leave the nonce alone.

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
  ANCHOR_PUBLISHER: undefined,
  DISPUTE_ARBITER: undefined,
  DISPUTE_FEE_POOL: undefined,
  EVENT_VK: undefined,
  STELLAR_EVENT_VK: undefined,
  LOCAL_EVM_CHAIN_IDS: undefined,
  ...Object.fromEntries(Object.keys(CLOCKS).map((k) => [k, undefined])),
};

let a: Anvil; // 31337
let b: Anvil; // 1337
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "evm-link-callsites-"));
let MA = "";
let MB = "";

before(async () => {
  [a, b] = await Promise.all([startAnvil(31337), startAnvil(1337)]);
  await withEnv({ ...CLEAN, EVENT_VK: path.join(tmp, "no-vk") }, async () => {
    MA = (await deployCore({ rpcUrl: a.url, privateKey: K0, env: "local", manifestOut: path.join(tmp, "a.json") })).manifestPath;
    MB = (await deployCore({ rpcUrl: b.url, privateKey: K0, env: "local", manifestOut: path.join(tmp, "b.json") })).manifestPath;
  });
});
after(() => {
  a?.stop();
  b?.stop();
  fs.rmSync(tmp, { recursive: true, force: true });
});

/** A copy of a manifest with `edit` applied, so each case starts from the real deploy. */
function variant(src: string, name: string, edit: (m: any) => void): string {
  const m = JSON.parse(fs.readFileSync(src, "utf8"));
  edit(m);
  const out = path.join(tmp, name);
  fs.writeFileSync(out, JSON.stringify(m, null, 2));
  return out;
}
const linkA = (localManifest: string, peerManifest: string, peerEnvFile?: string) =>
  link({ rpcUrl: a.url, privateKey: K0, localManifest, peerManifest, peerEnvFile });
async function refusesWithNoTx(run: () => Promise<unknown>, re: RegExp) {
  const n0 = await a.nonce();
  await assert.rejects(run, re);
  assert.equal(await a.nonce(), n0, "nothing was sent");
}
const testnet = (m: any) => {
  m.meta.env = "testnet";
};

test("A-5: a real-network route whose peer has not linked, with no --peer-env, is refused", async () => {
  const localT = variant(MA, "a-testnet.json", testnet);
  const peerT = variant(MB, "b-testnet.json", testnet);
  await withEnv({ ...CLEAN, ...CLOCKS }, async () => {
    await refusesWithNoTx(() => linkA(localT, peerT), /could not be checked in both directions/);
    // The peer's env file describes its side: now both directions are checked and the link runs.
    const envFile = path.join(tmp, "peer.env");
    fs.writeFileSync(envFile, ["DEPLOY_ENV=testnet", ...Object.entries(CLOCKS).map(([k, v]) => `${k}=${v}`)].join("\n"));
    const r = await linkA(localT, peerT, envFile);
    assert.ok(r.chainTxs > 0);
  });
});

test("A-6: link refuses a peer deployed for another env, or against another VK", async () => {
  await withEnv({ ...CLEAN }, async () => {
    // The peer's side is described (its env file), so the route check passes and this one decides.
    const envFile = path.join(tmp, "peer-a6.env");
    fs.writeFileSync(envFile, ["DEPLOY_ENV=testnet", ...Object.entries(CLOCKS).map(([k, v]) => `${k}=${v}`)].join("\n"));
    const peerEnv = variant(MB, "b-env.json", testnet);
    await refusesWithNoTx(() => linkA(MA, peerEnv, envFile), /cannot span environments/);
    const localVk = variant(MA, "a-vk.json", (m) => (m.meta.vkSha256 = "0x" + "ab".repeat(32)));
    const peerVk = variant(MB, "b-vk.json", (m) => (m.meta.vkSha256 = "0x" + "cd".repeat(32)));
    await refusesWithNoTx(() => linkA(localVk, peerVk), /refuse each other's proofs/);
  });
});

const noModule = (m: any) => {
  delete m.contracts.disputeManager;
  m.disputeParams = {};
};

test("A-5: a route with no DisputeManager on either side links (older manifests); the clocks are still set", async () => {
  await withEnv({ ...CLEAN }, async () => {
    const r = await linkA(variant(MA, "a-nodm.json", noModule), variant(MB, "b-nodm.json", noModule));
    assert.equal(r.peerChainId, "1337");
  });
});

test("A-5: a mixed route (a module on one side only) is refused, either way round", async () => {
  await withEnv({ ...CLEAN }, async () => {
    await refusesWithNoTx(() => linkA(MA, variant(MB, "b-mixed.json", noModule)), /only this chain has a DisputeManager/);
    await refusesWithNoTx(() => linkA(variant(MA, "a-mixed.json", noModule), MB), /only the peer has a DisputeManager/);
  });
});
