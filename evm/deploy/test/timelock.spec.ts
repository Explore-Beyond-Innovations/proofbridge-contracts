import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { ethers } from "ethers";
import { readManifest } from "@proofbridge/deployment-manifest";
import { deployCore, feeConfigFromEnv } from "../src/deploy-core.js";
import { tokenBondsFromEnv } from "../src/link.js";
import { timelockActivate, timelockCancel, timelockExecute, timelockPropose, timelockStatus } from "../src/timelock.js";
import { attachContract } from "../src/artifacts.js";
import { A0, A1, K0, startAnvil, withEnv, type Anvil } from "./helpers/anvil.js";

// #586: the fee at deploy, and the 24-hour delay as the CLI drives it, on a real Anvil.

const CLEAN: Record<string, string | undefined> = {
  DEPLOY_ENV: undefined,
  ANCHOR_PUBLISHER: undefined,
  DISPUTE_ARBITER: undefined,
  DISPUTE_FEE_POOL: undefined,
  PROTOCOL_FEE_POOL: undefined,
  LP_FEE_BPS: undefined,
  PROTOCOL_FEE_BPS: undefined,
  STELLAR_EVENT_VK: undefined,
  LOCAL_EVM_CHAIN_IDS: undefined,
};

let a: Anvil;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "evm-timelock-"));
let M = "";

before(async () => {
  a = await startAnvil(31337);
  await withEnv({ ...CLEAN, EVENT_VK: path.join(tmp, "no-vk") }, async () => {
    M = (await deployCore({ rpcUrl: a.url, privateKey: K0, env: "local", manifestOut: path.join(tmp, "a.json") })).manifestPath;
  });
});
after(() => {
  a?.stop();
  fs.rmSync(tmp, { recursive: true, force: true });
});

const adManager = async () => {
  const m = await readManifest(M);
  return attachContract(m.contracts.adManager.address, "AdManager", "AdManager", new ethers.Wallet(K0, a.provider));
};
const opts = () => ({ rpcUrl: a.url, privateKey: K0, manifest: M });
const warpDay = async (extra = 0) => {
  await a.provider.send("evm_increaseTime", [86_400 + extra]);
  await a.provider.send("evm_mine", []);
};

test("a local deploy sets the launch fee, paid to the deployer, and records it", async () => {
  const [pool, lp, protocol] = await (await adManager()).getFunction("feeConfig")();
  assert.equal(String(pool).toLowerCase(), A0.toLowerCase());
  assert.equal(Number(lp), 30);
  assert.equal(Number(protocol), 20);
  assert.deepEqual((await readManifest(M)).feeConfig, { pool: A0, lpBps: 30, protocolBps: 20 });
});

test("outside local every fee value is required, and each is capped at 1%", () => {
  assert.throws(() => feeConfigFromEnv("testnet", A0, {}), /PROTOCOL_FEE_POOL is unset/);
  assert.throws(() => feeConfigFromEnv("testnet", A0, { PROTOCOL_FEE_POOL: A1, PROTOCOL_FEE_BPS: "20" }), /LP_FEE_BPS is unset/);
  assert.throws(() => feeConfigFromEnv("local", A0, { LP_FEE_BPS: "101" }), /at most 100/);
  assert.deepEqual(feeConfigFromEnv("testnet", A0, { PROTOCOL_FEE_POOL: A1, LP_FEE_BPS: "30", PROTOCOL_FEE_BPS: "0" }), {
    pool: A1,
    lpBps: 30,
    protocolBps: 0,
  });
});

test("DISPUTE_TOKEN_BONDS is checked with the contract's rules before anything is sent", () => {
  assert.deepEqual(tokenBondsFromEnv({}), {});
  assert.deepEqual(tokenBondsFromEnv({ DISPUTE_TOKEN_BONDS: '{"usdc":{"minBond":"1000000","bondBps":50}}' }), {
    usdc: { minBond: "1000000", bondBps: 50 },
  });
  assert.throws(() => tokenBondsFromEnv({ DISPUTE_TOKEN_BONDS: "{" }), /not JSON/);
  assert.throws(() => tokenBondsFromEnv({ DISPUTE_TOKEN_BONDS: '{"usdc":{"minBond":"0","bondBps":50}}' }), /at least 1/);
  assert.throws(() => tokenBondsFromEnv({ DISPUTE_TOKEN_BONDS: '{"usdc":{"minBond":"1","bondBps":501}}' }), /0\.\.500/);
});

test("once the delay is on, a re-run proposes; after 24 hours a re-run executes", async () => {
  await timelockActivate(opts());
  const status = await timelockStatus(opts());
  for (const on of Object.values(status)) assert.equal(on, true, "every contract with the delay is on");
  assert.ok((await readManifest(M)).timelock?.activatedAt, "the manifest records the activation");

  const redeploy = () =>
    withEnv({ ...CLEAN, EVENT_VK: path.join(tmp, "no-vk"), LP_FEE_BPS: "10" }, () =>
      deployCore({ rpcUrl: a.url, privateKey: K0, env: "local", manifestOut: M }),
    );
  const first = await redeploy();
  assert.equal(first.pending.length, 1, "the fee change is proposed, not sent");
  assert.equal(first.pending[0]!.fn, "setFeeBps");
  assert.equal(Number((await (await adManager()).getFunction("feeConfig")())[1]), 30, "nothing changed yet");

  const early = await redeploy();
  assert.equal(early.pending.length, 1, "still waiting: re-proposing is not attempted");
  assert.equal(early.pending[0]!.proposedNow, false);

  await warpDay();
  const later = await redeploy();
  assert.equal(later.pending.length, 0, "the ripe proposal ran");
  assert.equal(Number((await (await adManager()).getFunction("feeConfig")())[1]), 10);
  assert.equal((await readManifest(M)).feeConfig?.lpBps, 10);
});

test("propose, early execute refused, cancel, and execute after the delay", async () => {
  const call = { ...opts(), contract: "AdManager" as const, fn: "setFeeBps", args: [5, 5] };
  const { id } = await timelockPropose(call);
  await assert.rejects(() => timelockExecute(call), /executable from/);
  await timelockCancel(call);
  assert.equal(BigInt(await (await adManager()).getFunction("timelockEta")(id)), 0n);
  await warpDay();
  await assert.rejects(() => timelockExecute(call), /no pending proposal/);

  await timelockPropose(call);
  await warpDay();
  // Anyone may execute: the stranger's key runs it.
  await timelockExecute({ ...call, privateKey: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" });
  const [, lp, protocol] = await (await adManager()).getFunction("feeConfig")();
  assert.equal(Number(lp), 5);
  assert.equal(Number(protocol), 5);
});
