// The AdManager / DisputeManager `settleBond` pair: the escrow must call the selector the module
// dispatches, so both must come from one build. Pure checks on this build's artifacts first, then
// `deployCore` and `link` on a real Anvil, so removing the check from either path turns a case red.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { ethers } from "ethers";
import { deployedCode } from "../src/artifacts.ts";
import { assertSettleBondPair, carriesSelector, settleBondSelector } from "../src/settle-bond-pair.ts";
import { deployCore } from "../src/deploy-core.ts";
import { link } from "../src/link.ts";
import { K0, startAnvil, withEnv, type Anvil } from "./helpers/anvil.ts";

const AD = deployedCode("AdManager", "AdManager");
const DM = deployedCode("DisputeManager", "DisputeManager");
const OP = deployedCode("OrderPortal", "OrderPortal");
const AT = { address: "0x" + "a".repeat(40), code: AD };
const MT = { address: "0x" + "d".repeat(40), code: DM };

/** The code with every `PUSH4 <selector>` turned into another selector: a contract built with a different shape. */
function withOtherSelector(code: string, selector: string): string {
  const other = (BigInt("0x" + selector) ^ 1n).toString(16).padStart(8, "0");
  return code.toLowerCase().split("63" + selector).join("63" + other);
}

test("settleBondSelector is the four-arg signature's keccak, read from this build's artifact", () => {
  const { signature, selector } = settleBondSelector();
  assert.equal(signature, "settleBond(bytes32,uint8,bool,bool)");
  assert.equal("0x" + selector, ethers.id(signature).slice(0, 10));
});

test("this build's AdManager calls, and its DisputeManager dispatches, the selector; the OrderPortal never calls it", () => {
  const { selector } = settleBondSelector();
  assert.equal(carriesSelector(AD, selector), true, "AdManager");
  assert.equal(carriesSelector(DM, selector), true, "DisputeManager");
  assert.equal(carriesSelector(OP, selector), false, "OrderPortal");
  assert.doesNotThrow(() => assertSettleBondPair({ adManager: AT, disputeManager: MT, where: "t" }));
});

test("a module from another build is refused by name; so is an escrow from another build; so are both", () => {
  const { selector } = settleBondSelector();
  const oldModule = { ...MT, code: withOtherSelector(DM, selector) };
  const oldEscrow = { ...AT, code: withOtherSelector(AD, selector) };
  assert.throws(
    () => assertSettleBondPair({ adManager: AT, disputeManager: oldModule, where: "t" }),
    /t: settleBond pair — DisputeManager at 0xd+ does not dispatch this build's settleBond\(bytes32,uint8,bool,bool\)/,
  );
  assert.throws(
    () => assertSettleBondPair({ adManager: oldEscrow, disputeManager: MT, where: "t" }),
    /AdManager at 0xa+ does not call this build's settleBond/,
  );
  assert.throws(
    () => assertSettleBondPair({ adManager: oldEscrow, disputeManager: oldModule, where: "t" }),
    /DisputeManager at .* does not dispatch .*; AdManager at .* does not call/,
  );
  // Another contract altogether at the module's address.
  assert.throws(() => assertSettleBondPair({ adManager: AT, disputeManager: { ...MT, code: OP }, where: "t" }), /does not dispatch/);
  assert.throws(() => assertSettleBondPair({ adManager: AT, disputeManager: { ...MT, code: "0x" }, where: "t" }), /does not dispatch/);
});

test("carriesSelector wants a 4-byte selector and matches only PUSH4", () => {
  assert.throws(() => carriesSelector("0x", "0x1234"), /not a 4-byte selector/);
  assert.equal(carriesSelector("0x639ae9eac160e01b", "9ae9eac1"), true);
  assert.equal(carriesSelector("0x9ae9eac1", "0x9ae9eac1"), false, "the bytes without the PUSH4 are not a call or a dispatch");
});

// ── on real Anvils: the deploy and the link refuse a mixed pair before anything is sent ──────────

const CLEAN: Record<string, string | undefined> = {
  DEPLOY_ENV: undefined,
  ANCHOR_PUBLISHER: undefined,
  DISPUTE_ARBITER: undefined,
  DISPUTE_FEE_POOL: undefined,
  EVENT_VK: undefined,
  STELLAR_EVENT_VK: undefined,
  LOCAL_EVM_CHAIN_IDS: undefined,
};
let a: Anvil; // 31337
let b: Anvil; // 1337, the link's peer
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "evm-settle-bond-pair-"));
let MA = "";
let MB = "";
let contracts: { adManager: string; disputeManager: string };

before(async () => {
  [a, b] = await Promise.all([startAnvil(31337), startAnvil(1337)]);
  await withEnv({ ...CLEAN, EVENT_VK: path.join(tmp, "no-vk") }, async () => {
    const ra = await deployCore({ rpcUrl: a.url, privateKey: K0, env: "local", manifestOut: path.join(tmp, "a.json") });
    MA = ra.manifestPath;
    contracts = ra.contracts;
    MB = (await deployCore({ rpcUrl: b.url, privateKey: K0, env: "local", manifestOut: path.join(tmp, "b.json") })).manifestPath;
  });
});
after(() => {
  a?.stop();
  b?.stop();
  fs.rmSync(tmp, { recursive: true, force: true });
});

const redeployA = () => deployCore({ rpcUrl: a.url, privateKey: K0, env: "local", manifestOut: MA });
const linkA = () => link({ rpcUrl: a.url, privateKey: K0, localManifest: MA, peerManifest: MB });

async function refusesWithNoTx(run: () => Promise<unknown>, re: RegExp) {
  const n0 = await a.nonce();
  await assert.rejects(run, re);
  assert.equal(await a.nonce(), n0, "nothing was sent");
}

/** Put `code` at `address` for the duration of `fn`, then restore what was there. */
async function withCodeAt(address: string, code: string, fn: () => Promise<void>) {
  const original = await a.provider.getCode(address);
  await a.provider.send("anvil_setCode", [address, code]);
  try {
    await fn();
  } finally {
    await a.provider.send("anvil_setCode", [address, original]);
  }
}

test("the same bundle redeploys and links the pair it deployed", async () => {
  await withEnv({ ...CLEAN, EVENT_VK: path.join(tmp, "no-vk") }, async () => {
    await redeployA();
    await linkA();
  });
});

test("a reused DisputeManager from another build is refused by deploy and by link, nothing sent", async () => {
  const { selector } = settleBondSelector();
  const older = withOtherSelector(await a.provider.getCode(contracts.disputeManager), selector);
  await withCodeAt(contracts.disputeManager, "0x" + older.replace(/^0x/, ""), async () => {
    await withEnv({ ...CLEAN, EVENT_VK: path.join(tmp, "no-vk") }, async () => {
      await refusesWithNoTx(redeployA, /deploy: settleBond pair — DisputeManager at 0x[0-9a-fA-F]{40} does not dispatch this build's settleBond/);
      await refusesWithNoTx(linkA, /link: settleBond pair — DisputeManager at 0x[0-9a-fA-F]{40} does not dispatch/);
    });
  });
});

test("a reused AdManager from another build is refused by deploy and by link, nothing sent", async () => {
  const { selector } = settleBondSelector();
  const older = withOtherSelector(await a.provider.getCode(contracts.adManager), selector);
  await withCodeAt(contracts.adManager, "0x" + older.replace(/^0x/, ""), async () => {
    await withEnv({ ...CLEAN, EVENT_VK: path.join(tmp, "no-vk") }, async () => {
      await refusesWithNoTx(redeployA, /deploy: settleBond pair — AdManager at 0x[0-9a-fA-F]{40} does not call this build's settleBond/);
      await refusesWithNoTx(linkA, /link: settleBond pair — AdManager at 0x[0-9a-fA-F]{40} does not call/);
    });
  });
});

// A manifest with the escrow and no module: the module this run deploys is this build's, so the
// reused escrow is checked against the bundle, and an escrow from another build is refused up front.
test("a reused AdManager with a module still to deploy is checked against the bundle", async () => {
  const { selector } = settleBondSelector();
  const noModule = path.join(tmp, "a-nodm.json");
  const m = JSON.parse(fs.readFileSync(MA, "utf8"));
  delete m.contracts.disputeManager;
  m.disputeParams = {};
  fs.writeFileSync(noModule, JSON.stringify(m, null, 2));
  const older = withOtherSelector(await a.provider.getCode(contracts.adManager), selector);
  await withCodeAt(contracts.adManager, "0x" + older.replace(/^0x/, ""), async () => {
    await withEnv({ ...CLEAN, EVENT_VK: path.join(tmp, "no-vk") }, async () => {
      await refusesWithNoTx(
        () => deployCore({ rpcUrl: a.url, privateKey: K0, env: "local", manifestOut: noModule }),
        /deploy: settleBond pair — AdManager at 0x[0-9a-fA-F]{40} does not call this build's settleBond/,
      );
    });
  });
});
