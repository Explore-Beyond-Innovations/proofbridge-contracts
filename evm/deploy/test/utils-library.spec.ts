// The deployed-library probe: the frozen vector is the one the parity suite freezes, and the code
// comparison accepts exactly this build's bytes (with or without solc's own-address stamp).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ORDER_VECTOR_0, libraryCodeMatches } from "../src/utils-library.ts";

const VECTORS = join(dirname(fileURLToPath(import.meta.url)), "../../../test-vectors/order-hash-v2.json");

test("ORDER_VECTOR_0 is .vectors[0] of order-hash-v2.json, field for field", () => {
  const v0 = JSON.parse(readFileSync(VECTORS, "utf8")).vectors[0];
  assert.equal(v0.name, "canonical-equal");
  for (const [k, want] of Object.entries(v0.order)) {
    if (k === "saltHex") continue;
    const have = (ORDER_VECTOR_0.order as Record<string, unknown>)[k];
    assert.notEqual(have, undefined, `missing field ${k}`);
    assert.equal(String(have), String(want), `field ${k}`);
  }
  // Encoded positionally, so the order of the keys is part of the vector, not just their names.
  assert.deepEqual(Object.keys(ORDER_VECTOR_0.order), Object.keys(v0.order).filter((k) => k !== "saltHex"), "same fields, same order");
  assert.equal(ORDER_VECTOR_0.orderHash, v0.expected.orderHash);
});

const ADDR = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd";
const BODY = "3014" + "60806040" + "fe";

test("libraryCodeMatches: byte-equal code matches", () => {
  assert.equal(libraryCodeMatches("0x" + BODY, "0x" + BODY, ADDR), true);
});

test("libraryCodeMatches: the own-address stamp is accepted only at the artifact's zero slot", () => {
  const artifact = "0x73" + "0".repeat(40) + BODY;
  assert.equal(libraryCodeMatches(artifact, "0x73" + ADDR.slice(2) + BODY, ADDR), true);
  assert.equal(libraryCodeMatches(artifact, "0x73" + "1".repeat(40) + BODY, ADDR), false, "another address");
  assert.equal(libraryCodeMatches("0x" + BODY, "0x73" + ADDR.slice(2) + BODY, ADDR), false, "stamp the artifact lacks");
});

test("libraryCodeMatches: different code, empty code and a different body are refused", () => {
  assert.equal(libraryCodeMatches("0x" + BODY, "0x" + BODY + "00", ADDR), false);
  assert.equal(libraryCodeMatches("0x" + BODY, "0x", ADDR), false);
  assert.equal(libraryCodeMatches("0x", "0x", ADDR), false);
});

// ── on a real Anvil: the probe and the deploy's refusal ──────────────────────────────────────────
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { before, after } from "node:test";
import { ethers } from "ethers";
import { contractFactory } from "../src/artifacts.ts";
import { deployCore } from "../src/deploy-core.ts";
import { probeUtilsLibrary, verifyUtilsLibrary, UTILS_LIBRARY } from "../src/utils-library.ts";
import { K0, startAnvil, withEnv, type Anvil } from "./helpers/anvil.ts";
import { artifactsDir } from "../src/common.ts";

let a: Anvil;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "evm-utils-library-"));
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

test("probe: a fresh library answers; another contract at the address does not, and the mismatch is named", async () => {
  // Its own provider with ethers' request cache off: `getCode` right after `anvil_setCode` must see
  // the new code, and the helper's provider keeps answers for 250ms.
  const signer = new ethers.Wallet(K0, new ethers.JsonRpcProvider(a.url, undefined, { staticNetwork: true, cacheTimeout: -1 }));
  let nonce = await a.nonce();
  const lib = await contractFactory(UTILS_LIBRARY, UTILS_LIBRARY, signer).deploy({ nonce: nonce++ });
  await lib.deploymentTransaction()?.wait();
  const at = await lib.getAddress();
  assert.equal(await probeUtilsLibrary(at, signer), null);
  assert.deepEqual(await verifyUtilsLibrary(at, signer), { ok: true, sameBuild: true });

  const other = await contractFactory("AgentPolicyCodec", "AgentPolicyCodec", signer).deploy({ nonce: nonce++ });
  await other.deploymentTransaction()?.wait();
  const why = await probeUtilsLibrary(await other.getAddress(), signer);
  assert.match(String(why), /does not answer as ProofBridgeUtils/);
  const v = await verifyUtilsLibrary(await other.getAddress(), signer);
  assert.equal(v.ok, false);
  assert.match((v as { why: string }).why, /code differs from this build's ProofBridgeUtils and does not answer/);

  // The library's code with one trailing byte changed: not this build's bytes, but it still answers
  // the probe — the "earlier build's copy" verdict, kept with a note rather than refused.
  const code = await signer.provider!.getCode(at);
  const tampered = code.slice(0, -4) + (code.slice(-4, -2) === "00" ? "01" : "00") + code.slice(-2);
  assert.notEqual(tampered, code);
  await a.provider.send("anvil_setCode", [at, tampered]);
  assert.deepEqual(await verifyUtilsLibrary(at, signer), { ok: true, sameBuild: false });

  // L4: a failure that is not the library's answer is rethrown as itself, never "does not answer".
  await withEnv({ EVM_OUT_DIR: strippedOut() }, () =>
    assert.rejects(probeUtilsLibrary(at, signer), /records no selector for digest\(OrderHash\.Order\)/),
  );
  (signer.provider as ethers.JsonRpcProvider).destroy();
});

/** This build's `out/`, every artifact linked in, except a ProofBridgeUtils artifact with its runtime code and selectors stripped. */
function strippedOut(): string {
  const src = artifactsDir();
  const out = fs.mkdtempSync(path.join(tmp, "out-"));
  for (const entry of fs.readdirSync(src)) {
    if (entry === "ProofBridgeUtils.sol") continue;
    fs.symlinkSync(path.join(src, entry), path.join(out, entry));
  }
  fs.mkdirSync(path.join(out, "ProofBridgeUtils.sol"));
  const a = JSON.parse(fs.readFileSync(path.join(src, "ProofBridgeUtils.sol", "ProofBridgeUtils.json"), "utf8"));
  delete a.deployedBytecode;
  delete a.methodIdentifiers;
  fs.writeFileSync(path.join(out, "ProofBridgeUtils.sol", "ProofBridgeUtils.json"), JSON.stringify(a));
  return out;
}

test("deploy: a stripped library artifact is refused before anything is sent (L5)", async () => {
  const n0 = await a.nonce();
  await withEnv({ EVM_OUT_DIR: strippedOut() }, () =>
    assert.rejects(deploy("stripped.json"), /ProofBridgeUtils\.json records no deployedBytecode/),
  );
  assert.equal(await a.nonce(), n0, "nothing was sent");
});

test("deploy: a reused escrow is refused when its linked library no longer answers, with nothing sent", async () => {
  const r = await deploy("reuse.json");
  const lib = r.contracts.proofBridgeUtils;
  assert.equal(manifest("reuse.json").contracts.proofBridgeUtils.address, lib, "recorded");
  // Same bundle: the rerun reuses the library and both escrows.
  const again = await deploy("reuse.json");
  assert.equal(again.contracts.proofBridgeUtils, lib);
  assert.equal(again.contracts.adManager, r.contracts.adManager);

  // Another contract altogether where the escrows' code points.
  await a.provider.send("anvil_setCode", [lib, await a.provider.getCode(r.contracts.agentPolicyCodec)]);
  const n0 = await a.nonce();
  await assert.rejects(() => deploy("reuse.json"), /AdManager at .* links no working ProofBridgeUtils/);
  assert.equal(await a.nonce(), n0, "nothing was sent");
});

test("deploy: the manifest's library entry is a claim — a wrong one is repaired from the escrow's code", async () => {
  const r = await deploy("repair.json");
  const m = manifest("repair.json");
  m.contracts.proofBridgeUtils = { ...m.contracts.proofBridgeUtils, ...m.contracts.agentPolicyCodec }; // wrong on purpose
  fs.writeFileSync(path.join(tmp, "repair.json"), JSON.stringify(m, null, 2));
  const again = await deploy("repair.json");
  assert.equal(again.contracts.proofBridgeUtils, r.contracts.proofBridgeUtils, "what the escrows link, not what the entry said");
  assert.equal(manifest("repair.json").contracts.proofBridgeUtils.address, r.contracts.proofBridgeUtils, "repaired on disk");
});
