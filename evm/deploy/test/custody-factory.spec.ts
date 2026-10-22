// Plan 46 B1: the custody account factory is deployed beside the policy module and recorded in the manifest,
// and reused only while it was made for that module.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { ethers } from "ethers";
import { attachContract } from "../src/artifacts.ts";
import { deployCore } from "../src/deploy-core.ts";
import { K0, startAnvil, withEnv, type Anvil } from "./helpers/anvil.ts";

let a: Anvil;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "evm-custody-factory-"));
before(async () => {
  a = await startAnvil(31337);
});
after(() => {
  a?.stop();
  fs.rmSync(tmp, { recursive: true, force: true });
});
const CLEAN = { DEPLOY_ENV: undefined, EVENT_VK: undefined, ADMIN: undefined, ANCHOR_PUBLISHER: undefined, DISPUTE_ARBITER: undefined, DISPUTE_FEE_POOL: undefined };
const deploy = (out: string) => withEnv(CLEAN, () => deployCore({ rpcUrl: a.url, privateKey: K0, env: "local", manifestOut: path.join(tmp, out) }));
const manifest = (out: string) => JSON.parse(fs.readFileSync(path.join(tmp, out), "utf8"));

async function moduleOf(factory: string): Promise<string> {
  const p = new ethers.JsonRpcProvider(a.url, undefined, { staticNetwork: true, cacheTimeout: -1 });
  const f = attachContract(factory, "CustodyAccountFactory", "CustodyAccountFactory", p);
  const impl = attachContract(await f.implementation(), "ProofBridgeCustodyAccount", "ProofBridgeCustodyAccount", p);
  const m = (await impl.module()) as string;
  p.destroy();
  return m;
}

test("deploy: the factory is recorded, bound to the deployed module, and reused on a rerun", async () => {
  const r = await deploy("fresh.json");
  assert.ok(r.contracts.custodyAccountFactory, "deployed");
  assert.equal(manifest("fresh.json").contracts.custodyAccountFactory.address, r.contracts.custodyAccountFactory, "recorded");
  assert.equal((await moduleOf(r.contracts.custodyAccountFactory)).toLowerCase(), r.contracts.agentPolicy.toLowerCase());
  const again = await deploy("fresh.json");
  assert.equal(again.contracts.custodyAccountFactory, r.contracts.custodyAccountFactory, "reused");
});

test("deploy: a recorded factory made for another module is replaced, not reused", async () => {
  const r = await deploy("moved.json");
  // Drop the module from the record: the rerun deploys a new one, and the old factory mounts the old module.
  const m = manifest("moved.json");
  delete m.contracts.agentPolicy;
  delete m.contracts.agentPolicyCodec;
  fs.writeFileSync(path.join(tmp, "moved.json"), JSON.stringify(m, null, 2));
  const again = await deploy("moved.json");
  assert.notEqual(again.contracts.agentPolicy, r.contracts.agentPolicy, "a new module");
  assert.notEqual(again.contracts.custodyAccountFactory, r.contracts.custodyAccountFactory, "so a new factory");
  assert.equal((await moduleOf(again.contracts.custodyAccountFactory)).toLowerCase(), again.contracts.agentPolicy.toLowerCase());
});

test("deploy: a recorded factory that isn't one is refused up front, before anything is sent (81-10)", async () => {
  const r = await deploy("wrong.json");
  // Point the record at a live contract that is no factory: the escrow.
  const m = manifest("wrong.json");
  m.contracts.custodyAccountFactory = { ...m.contracts.custodyAccountFactory, address: m.contracts.adManager.address, addressBytes32: m.contracts.adManager.addressBytes32 };
  fs.writeFileSync(path.join(tmp, "wrong.json"), JSON.stringify(m, null, 2));
  const p = new ethers.JsonRpcProvider(a.url, undefined, { staticNetwork: true, cacheTimeout: -1 });
  const nonceBefore = await p.getTransactionCount(new ethers.Wallet(K0).address);
  await assert.rejects(deploy("wrong.json"), /custodyAccountFactory .* does not answer as a CustodyAccountFactory/);
  assert.equal(await p.getTransactionCount(new ethers.Wallet(K0).address), nonceBefore, "nothing was sent");
  p.destroy();
});
