import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { deployCore } from "../src/deploy-core.js";
import { contractFactory, runtimeCodeOf } from "../src/artifacts.js";
import { assertVerifierCode } from "../src/vk.js";
import { ethers } from "ethers";
import { artifactsDir } from "../src/common.js";
import { A0, A1, K0, startAnvil, withEnv, type Anvil } from "./helpers/anvil.js";

// The checks are pinned as pure functions elsewhere; these drive `deployCore` itself on a real
// Anvil, so removing a call from the deploy path turns them red.

// Every variable deployCore reads that could leak in from the shell, cleared per test.
const CLEAN: Record<string, string | undefined> = {
  DEPLOY_ENV: undefined,
  ADMIN: undefined,
  ANCHOR_PUBLISHER: undefined,
  ANCHOR_THRESHOLD: undefined,
  DISPUTE_ARBITER: undefined,
  DISPUTE_FEE_POOL: undefined,
  EVENT_VK: undefined,
  STELLAR_EVENT_VK: undefined,
  LOCAL_EVM_CHAIN_IDS: undefined,
  TESTNET_EVM_CHAIN_IDS: undefined,
  MAINNET_EVM_CHAIN_IDS: undefined,
};

let local: Anvil; // 31337
let sepolia: Anvil; // Sepolia's id, so a testnet env passes the chain-id check
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "evm-callsites-"));
const vkFile = path.join(tmp, "vk");
fs.writeFileSync(vkFile, "a vk");

before(async () => {
  [local, sepolia] = await Promise.all([startAnvil(31337), startAnvil(11155111)]);
});
after(() => {
  local?.stop();
  sepolia?.stop();
  fs.rmSync(tmp, { recursive: true, force: true });
});

const deploy = (a: Anvil, env: string, out: string) =>
  deployCore({ rpcUrl: a.url, privateKey: K0, env, manifestOut: path.join(tmp, out) });

async function refusesWithNoTx(a: Anvil, run: () => Promise<unknown>, re: RegExp) {
  const n0 = await a.nonce();
  await assert.rejects(run, re);
  assert.equal(await a.nonce(), n0, "nothing was sent");
}

test("A-4: DEPLOY_ENV=testnet on a local chain is refused before anything is sent", async () => {
  await withEnv({ ...CLEAN, ANCHOR_PUBLISHER: A1, DISPUTE_ARBITER: A1, DISPUTE_FEE_POOL: A1, EVENT_VK: vkFile }, () =>
    refusesWithNoTx(local, () => deploy(local, "testnet", "a4.json"), /DEPLOY_ENV=testnet but the RPC is chain 31337, which is a local chain/),
  );
});

test("A-4: DEPLOY_ENV=local on a testnet chain id is refused before anything is sent", async () => {
  await withEnv({ ...CLEAN, EVENT_VK: vkFile }, () =>
    refusesWithNoTx(sepolia, () => deploy(sepolia, "local", "a4l.json"), /DEPLOY_ENV=local but the RPC is chain 11155111, which is a testnet chain/),
  );
});

test("A-8: outside local the deployer may not be the anchor notary", async () => {
  await withEnv({ ...CLEAN, ANCHOR_PUBLISHER: `${A1},${A0}`, DISPUTE_ARBITER: A1, DISPUTE_FEE_POOL: A1, EVENT_VK: vkFile }, () =>
    refusesWithNoTx(sepolia, () => deploy(sepolia, "testnet", "a8.json"), /ANCHOR_PUBLISHER names the deployer/),
  );
});

test("vkRecord: a testnet deploy without the VK file is refused before the first contract", async () => {
  await withEnv(
    { ...CLEAN, ANCHOR_PUBLISHER: A1, DISPUTE_ARBITER: A1, DISPUTE_FEE_POOL: A1, EVENT_VK: path.join(tmp, "no-vk") },
    () => refusesWithNoTx(sepolia, () => deploy(sepolia, "testnet", "vk.json"), /VK file is missing/),
  );
});

// The env comes from the option, not only from DEPLOY_ENV: vkRecord must be handed the resolved one.
test("vkRecord: the resolved env decides, not process.env (local via the option, DEPLOY_ENV unset)", async () => {
  await withEnv({ ...CLEAN, DEPLOY_ENV: undefined, EVENT_VK: path.join(tmp, "no-vk") }, async () => {
    const r = await deploy(local, "local", "vk-local.json");
    assert.ok(fs.existsSync(r.manifestPath));
  });
});

// A-3: the reused Verifier's code is compared with what the bundle's creation code yields.
test("a reused Verifier is compared with the chain, byte for byte, immutables included", async () => {
  await withEnv({ ...CLEAN, EVENT_VK: vkFile }, async () => {
    const r = await deploy(local, "local", "reuse.json");
    const verifier = r.contracts.verifier;
    // Same bundle: the rerun reuses it.
    await deploy(local, "local", "reuse.json");

    // The same runtime with one immutable (`n`) changed: what a masked compare let through.
    const code = await local.provider.getCode(verifier);
    const tampered = withImmutableChanged(code);
    await local.provider.send("anvil_setCode", [verifier, tampered]);
    await refusesWithNoTx(local, () => deploy(local, "local", "reuse.json"), /not this bundle's Verifier/);

    // Another contract altogether at the recorded address.
    await local.provider.send("anvil_setCode", [verifier, await local.provider.getCode(r.contracts.poseidon2Yul)]);
    await refusesWithNoTx(local, () => deploy(local, "local", "reuse.json"), /not this bundle's Verifier/);
  });
});

test("runtimeCodeOf matches a real Verifier deploy, and not one with an altered immutable", async () => {
  const signer = new ethers.Wallet(K0, local.provider);
  const c = await contractFactory("Verifier", "HonkVerifier", signer).deploy();
  await c.waitForDeployment();
  const onChain = await local.provider.getCode(await c.getAddress());
  const expected = await runtimeCodeOf(local.provider, "Verifier", "HonkVerifier");
  assert.equal(onChain, expected);
  assertVerifierCode("t", onChain, expected);
  assert.throws(() => assertVerifierCode("t", withImmutableChanged(onChain), expected), /not this bundle's Verifier/);
  assert.throws(() => assertVerifierCode("t", "0x", expected), /no code at the reused verifier address/);
});

// The artifact records where the immutables sit; flip the low byte of the first.
function withImmutableChanged(code: string): string {
  const art = JSON.parse(fs.readFileSync(path.join(artifactsDir(), "Verifier.sol", "HonkVerifier.json"), "utf8"));
  const refs = Object.values(art.deployedBytecode.immutableReferences as Record<string, { start: number }[]>)[0];
  const at = 2 + (refs[0].start + 31) * 2;
  const b = parseInt(code.slice(at, at + 2), 16) ^ 1;
  return code.slice(0, at) + b.toString(16).padStart(2, "0") + code.slice(at + 2);
}
