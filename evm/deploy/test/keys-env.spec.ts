import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { ethers } from "ethers";
import { deployCore } from "../src/deploy-core.js";
import { attachContract, contractFactory, contractFactoryLinked, getAbi } from "../src/artifacts.js";
import { assertRegistryEnv, registryEnvOf } from "../src/keys-env.js";
import { auditRetirements, classifyRetirement, type StoredRetirement } from "../src/retirements-audit.js";
import { A1, K0, startAnvil, withEnv, type Anvil } from "./helpers/anvil.js";

// Review D3 (the registry holds the deploy's environment) and 50-4 (the stale-retirement audit).

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

const V = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, "../../../test-vectors/bls-encodings.json"), "utf8"));
const VECTOR_REGISTRY = "0x1111111111111111111111111111111111111111";

let local: Anvil;
let sepolia: Anvil; // the vectors' chain, at the clock their registrations are signed for
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "evm-keys-env-"));
const vkFile = path.join(tmp, "vk");
fs.writeFileSync(vkFile, "a vk");

before(async () => {
  [local, sepolia] = await Promise.all([
    startAnvil(31337),
    startAnvil(11155111, ["--timestamp", V.ownerAuth._meta.deadline.registerChainTime]),
  ]);
});
after(() => {
  local?.stop();
  sepolia?.stop();
  fs.rmSync(tmp, { recursive: true, force: true });
});

const deploy = (out: string) =>
  deployCore({ rpcUrl: local.url, privateKey: K0, env: "local", manifestOut: path.join(tmp, out) });

async function refusesWithNoTx(run: () => Promise<unknown>, re: RegExp) {
  const n0 = await local.nonce();
  await assert.rejects(run, re);
  assert.equal(await local.nonce(), n0, "nothing was sent");
}

test("assertRegistryEnv: only the deploy's own environment passes", () => {
  assertRegistryEnv("0xR", "testnet", "testnet");
  assert.throws(() => assertRegistryEnv("0xR", "local", "testnet"), /was deployed for env=local, but DEPLOY_ENV=testnet/);
  assert.throws(() => assertRegistryEnv("0xR", null, "local"), /predates the environment binding/);
});

test("deploy: the registry is deployed for DEPLOY_ENV, and a reused one for another env is refused", async () => {
  await withEnv({ ...CLEAN, EVENT_VK: vkFile }, async () => {
    const r = await deploy("env.json");
    const registry = r.contracts.blsKeyRegistry;
    const signer = new ethers.Wallet(K0, local.provider);
    assert.equal(await registryEnvOf(registry, signer), "local");
    assert.equal(
      await attachContract(registry, "BLSKeyRegistry", "BLSKeyRegistry", signer).getFunction("domainSeparator")(),
      V.ownerAuth._meta.envs.local.domainSeparator,
    );

    // The same registry code built for testnet, at the recorded address.
    const other = await contractFactoryLinked("BLSKeyRegistry", "BLSKeyRegistry", signer, {
      SCL_EIP6565: r.contracts.sclEip6565,
    }).deploy(A1, "testnet");
    await other.waitForDeployment();
    await local.provider.send("anvil_setCode", [registry, await local.provider.getCode(await other.getAddress())]);
    await refusesWithNoTx(() => deploy("env.json"), /was deployed for env=testnet, but DEPLOY_ENV=local/);

    // A contract with an admin() but no keysEnv(), as a registry from before the binding.
    await local.provider.send("anvil_setCode", [registry, await local.provider.getCode(r.contracts.rootAnchor)]);
    await refusesWithNoTx(() => deploy("env.json"), /predates the environment binding/);
  });
});

test("classifyRetirement: the registry's refusal decides", () => {
  assert.equal(classifyRetirement(null), "current");
  assert.equal(classifyRetirement("OwnerMismatch"), "stale-format");
  assert.equal(classifyRetirement("BadLength"), "stale-format");
  assert.equal(classifyRetirement("NoSuchSlot"), "no-slot");
  assert.equal(classifyRetirement("BadValidUntil"), "already-shorter");
  assert.equal(classifyRetirement("Something"), "unchecked");
});

test("retirements-audit: current, stale-format (old digest, altered), no-slot and unchecked rows", async () => {
  const signer = new ethers.Wallet(K0, sepolia.provider);
  // Explicit nonces: the provider caches the account nonce between back-to-back sends.
  let nonce = await sepolia.nonce();
  const scl = await contractFactory("libSCL_EIP6565", "SCL_EIP6565", signer).deploy({ nonce: nonce++ });
  await scl.waitForDeployment();
  const impl = await contractFactoryLinked("BLSKeyRegistry", "BLSKeyRegistry", signer, {
    SCL_EIP6565: await scl.getAddress(),
  }).deploy(A1, "testnet", { nonce: nonce++ });
  await impl.waitForDeployment();
  await sepolia.provider.send("anvil_setCode", [VECTOR_REGISTRY, await sepolia.provider.getCode(await impl.getAddress())]);
  const registry = new ethers.Contract(VECTOR_REGISTRY, getAbi("BLSKeyRegistry", "BLSKeyRegistry"), signer);

  const leg = (l: any) => [l.chainId, l.registry, l.nonce];
  for (const who of ["bridger", "maker"] as const) {
    const e = V.ownerAuth[who].register[0];
    const reg = V.registration[who === "maker" ? "makerOnSepolia" : "bridgerOnSepolia"];
    const owner = { scheme: who === "maker" ? 1 : 0, legs: e.legs.map(leg), sig: who === "maker" ? e.evmSig : e.sig };
    await (await registry.getFunction("register")(e.account, owner, reg.pkNative, reg.pop, 0, e.deadline, { nonce: nonce++ })).wait();
  }

  const row = (who: "maker" | "bridger", k: number): StoredRetirement => {
    const e = V.ownerAuth[who].retire[k];
    return { account: e.account, keyCommitment: e.keyCommitment, validUntil: e.validUntil, scheme: e.scheme, sig: e.sig, evmSig: e.evmSig };
  };
  // The same RetireKey signed under the domain before the environment salt (a pre-review filing).
  const b0 = row("bridger", 0);
  const oldDomainSig = ethers.Signature.from(
    new ethers.SigningKey(V.keys.bridgerWallet.sk).sign(
      ethers.TypedDataEncoder.hash(
        { name: "ProofBridge Keys", version: "2" },
        { RetireKey: [{ name: "account", type: "bytes32" }, { name: "keyCommitment", type: "bytes32" }, { name: "validUntil", type: "uint64" }] },
        { account: b0.account, keyCommitment: b0.keyCommitment, validUntil: b0.validUntil },
      ),
    ),
  ).serialized;
  const altered = { ...row("maker", 0), evmSig: row("maker", 0).evmSig!.slice(0, -2) + "00" };

  const rows = await auditRetirements(registry, [
    b0,
    row("maker", 0),
    { ...b0, sig: oldDomainSig },
    altered,
    row("bridger", 2), // key 1: never registered here
    { ...row("maker", 0), evmSig: undefined },
  ]);
  assert.deepEqual(
    rows.map((r) => r.status),
    ["current", "current", "stale-format", "stale-format", "no-slot", "unchecked"],
  );
});
