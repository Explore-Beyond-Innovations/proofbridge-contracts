import { test, after } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { randomBytes } from "crypto";
import { spawnSync } from "child_process";
import { createRequire } from "module";
import { Keypair, StrKey } from "@stellar/stellar-sdk";
import { appendersAtDeploy, deployCore } from "../src/deploy-core.js";
import { link } from "../src/link.js";
import { buildManifest } from "../src/manifest.js";
import { NETWORK_PASSPHRASES } from "../src/stellar-cli.js";
import { wasmSha256 } from "../src/wasm-reuse.js";

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
// the bundle's wasm: the two contracts whose reuse is hash-checked, and the rest for the one case
// that drives a fresh deploy to its manifest (every other case stops before they are reached)
const wasmDirPath = path.join(tmp, "wasm");
fs.mkdirSync(wasmDirPath);
const BUNDLE_WASM = [
  "verifier.wasm",
  "merkle_manager.wasm",
  "ad_manager.wasm",
  "order_portal.wasm",
  "bls_key_registry.wasm",
  "counterparty_verifier.wasm",
  "root_anchor.wasm",
  "registrar.wasm",
  "dispute_manager.wasm",
  "agent_account.wasm",
];
for (const w of BUNDLE_WASM) fs.writeFileSync(path.join(wasmDirPath, w), `${w} v2`);
const BUNDLE_HASHES = {
  blsKeyRegistry: wasmSha256(path.join(wasmDirPath, "bls_key_registry.wasm")),
  counterpartyVerifier: wasmSha256(path.join(wasmDirPath, "counterparty_verifier.wasm")),
};

const CLOCKS = {
  ROUTE_MIN_WINDOW_S: "0",
  ROUTE_BUFFER_S: "1800",
  ROUTE_MARGIN_S: "0",
  ROUTE_CLAIM_STAGGER_S: "0",
  DISPUTE_CHALLENGE_PERIOD_S: "3600",
  DISPUTE_BOND_FLOOR: "10000000", // the minimum outside local (1 XLM)
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
  PROTOCOL_FEE_POOL: undefined,
  LP_FEE_BPS: undefined,
  PROTOCOL_FEE_BPS: undefined,
  FAKE_STELLAR_PASSPHRASE: undefined,
  FAKE_STELLAR_KEYS_ENV: undefined,
  FAKE_STELLAR_IDS: undefined,
  STELLAR_ALLOW_WASM_MISMATCH: undefined,
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
const deploy = (env: string, out: string, extra: { allowWasmMismatch?: boolean } = {}) =>
  deployCore({ env, manifestOut: path.join(tmp, out), wasmDir: wasmDirPath, ...extra });
const NAMED = {
  ANCHOR_PUBLISHER: OTHER,
  DISPUTE_ARBITER: OTHER,
  DISPUTE_FEE_POOL: OTHER,
  STELLAR_EVENT_VK: vkFile,
  // #586: the fee values a non-local deploy must name.
  PROTOCOL_FEE_POOL: OTHER,
  LP_FEE_BPS: "30",
  PROTOCOL_FEE_BPS: "20",
};
/** What `console.warn` printed while `fn` ran. */
async function warnedDuring(fn: () => Promise<unknown>): Promise<string[]> {
  const lines: string[] = [];
  const orig = console.warn;
  console.warn = (...a: unknown[]) => {
    lines.push(a.map(String).join(" "));
  };
  try {
    await fn();
  } finally {
    console.warn = orig;
  }
  return lines;
}
// Past the registry-env and wasm checks on a reused manifest, the deploy's next read is who holds admin.
const PAST_WASM_CHECKS = /fake stellar: no answer for contract invoke .* -- get_admin/;

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
    assert.rejects(deploy("local", "l2.json"), /DEPLOY_ENV=local but STELLAR_NETWORK=testnet is on testnet, not the local network/),
  );
  assert.deepEqual(calls, ["network info --network testnet --output json"]);
});

test("A-4: DEPLOY_ENV=testnet against a mainnet RPC, or one that does not answer, is refused", async () => {
  const env = { ...NAMED, STELLAR_NETWORK: "pubnet", STELLAR_CHAIN_ID: "1000002" };
  let calls = await withFake({ ...env, FAKE_STELLAR_PASSPHRASE: NETWORK_PASSPHRASES.mainnet }, () =>
    assert.rejects(deploy("testnet", "t2.json"), /is on mainnet, not the testnet network/),
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

test("D3: a reused key registry initialized for another env is refused before anything is sent", async () => {
  const out = "reuse-env.json";
  manifest(out, 1000003n, "local");
  const LOCAL = { FAKE_STELLAR_PASSPHRASE: NETWORK_PASSPHRASES.local, STELLAR_EVENT_VK: vkFile };
  let calls = await withFake({ ...LOCAL, FAKE_STELLAR_KEYS_ENV: "testnet" }, () =>
    assert.rejects(deploy("local", out), /reused BLSKeyRegistry was initialized for "testnet", not DEPLOY_ENV=local/),
  );
  assert.deepEqual(sent(calls), []);
  assert.ok(calls.some((c) => / -- keys_env$/.test(c)), "the registry was asked");
  // the same registry, initialized for local: the deploy goes past the check (to the next read)
  calls = await withFake({ ...LOCAL, FAKE_STELLAR_KEYS_ENV: "local" }, () =>
    assert.rejects(deploy("local", out), /fake stellar: no answer for contract invoke .* -- (?!keys_env)/),
  );
  assert.deepEqual(sent(calls), []);
});

// A reused key registry or counterparty verifier is compared with the bundle's wasm before anything
// is sent: a storage-shape change leaves old slots undecodable, and the admin upgrade keeps storage.
test("a reused key registry deployed from other wasm is refused before anything is sent", async () => {
  const out = "reuse-wasm.json";
  manifest(out, 1000003n, "local", { wasmHashes: { blsKeyRegistry: "1".repeat(64) } });
  const LOCAL = { FAKE_STELLAR_PASSPHRASE: NETWORK_PASSPHRASES.local, STELLAR_EVENT_VK: vkFile, FAKE_STELLAR_KEYS_ENV: "local" };
  const calls = await withFake(LOCAL, () =>
    assert.rejects(deploy("local", out), new RegExp(`BLSKeyRegistry: the reused contract was deployed from wasm 1{64}, but this bundle's wasm hashes to ${BUNDLE_HASHES.blsKeyRegistry}`)),
  );
  assert.deepEqual(sent(calls), []);
});

test("a reused counterparty verifier deployed from other wasm is refused before anything is sent", async () => {
  const out = "reuse-wasm-v.json";
  manifest(out, 1000003n, "local", { wasmHashes: { counterpartyVerifier: "2".repeat(64) } });
  const LOCAL = { FAKE_STELLAR_PASSPHRASE: NETWORK_PASSPHRASES.local, STELLAR_EVENT_VK: vkFile, FAKE_STELLAR_KEYS_ENV: "local" };
  const calls = await withFake(LOCAL, () =>
    assert.rejects(deploy("local", out), /CounterpartyVerifier: the reused contract was deployed from wasm 2{64}/),
  );
  assert.deepEqual(sent(calls), []);
});

test("a manifest from before the wasm hash was recorded refuses to reuse, saying why", async () => {
  const out = "reuse-wasm-old.json";
  manifest(out, 1000003n, "local", { wasmHashes: null });
  const LOCAL = { FAKE_STELLAR_PASSPHRASE: NETWORK_PASSPHRASES.local, STELLAR_EVENT_VK: vkFile, FAKE_STELLAR_KEYS_ENV: "local" };
  const calls = await withFake(LOCAL, () =>
    assert.rejects(deploy("local", out), /BLSKeyRegistry: the manifest records no wasm hash for the reused contract.*manifests from before the hash was recorded.*pass --allow-wasm-mismatch to this one run/),
  );
  assert.deepEqual(sent(calls), []);
});

test("on local, STELLAR_ALLOW_WASM_MISMATCH=1 (or the option) reuses past a mismatch or a missing record, as a warning; a matching record passes on its own", async () => {
  const out = "reuse-wasm-ok.json";
  manifest(out, 1000003n, "local", { wasmHashes: { blsKeyRegistry: "1".repeat(64), counterpartyVerifier: undefined } });
  const LOCAL = { FAKE_STELLAR_PASSPHRASE: NETWORK_PASSPHRASES.local, STELLAR_EVENT_VK: vkFile, FAKE_STELLAR_KEYS_ENV: "local" };
  let calls: string[] = [];
  const warned = await warnedDuring(async () => {
    calls = await withFake({ ...LOCAL, STELLAR_ALLOW_WASM_MISMATCH: "1" }, () => assert.rejects(deploy("local", out), PAST_WASM_CHECKS));
  });
  assert.deepEqual(sent(calls), []);
  // the override is announced as a warning, once up front and once per contract it skipped
  assert.ok(warned.some((l) => /WASM MISMATCH OVERRIDE ON/.test(l)), `banner in ${JSON.stringify(warned)}`);
  assert.ok(warned.some((l) => /BLSKeyRegistry wasm NOT CHECKED: override on \(recorded 1{64}\)/.test(l)), `registry line in ${JSON.stringify(warned)}`);
  assert.ok(warned.some((l) => /CounterpartyVerifier wasm NOT CHECKED: override on \(recorded none\)/.test(l)), `verifier line in ${JSON.stringify(warned)}`);
  calls = await withFake(LOCAL, () => assert.rejects(deploy("local", out, { allowWasmMismatch: true }), PAST_WASM_CHECKS));
  assert.deepEqual(sent(calls), []);
  // the bundle's own hashes recorded: no override needed, and nothing warned
  const ok = "reuse-wasm-match.json";
  manifest(ok, 1000003n, "local");
  const quiet = await warnedDuring(async () => {
    calls = await withFake(LOCAL, () => assert.rejects(deploy("local", ok), PAST_WASM_CHECKS));
  });
  assert.deepEqual(sent(calls), []);
  assert.ok(!quiet.some((l) => /WASM MISMATCH|NOT CHECKED/.test(l)), `no override warning in ${JSON.stringify(quiet)}`);
  // the manifest round-trips the two hashes through the schema (a stripped field would read as "no record")
  const back = JSON.parse(fs.readFileSync(path.join(tmp, ok), "utf8")) as { wasmHashes?: Record<string, string> };
  assert.deepEqual(back.wasmHashes, BUNDLE_HASHES);
});

test("the env override is exactly \"1\": \"true\", \"yes\" and \"0\" still refuse a mismatch", async () => {
  const out = "reuse-wasm-not-one.json";
  manifest(out, 1000003n, "local", { wasmHashes: { blsKeyRegistry: "1".repeat(64) } });
  const LOCAL = { FAKE_STELLAR_PASSPHRASE: NETWORK_PASSPHRASES.local, STELLAR_EVENT_VK: vkFile, FAKE_STELLAR_KEYS_ENV: "local" };
  for (const v of ["true", "yes", "0"]) {
    const calls = await withFake({ ...LOCAL, STELLAR_ALLOW_WASM_MISMATCH: v }, () =>
      assert.rejects(deploy("local", out), /BLSKeyRegistry: the reused contract was deployed from wasm 1{64}/, `STELLAR_ALLOW_WASM_MISMATCH=${v}`),
    );
    assert.deepEqual(sent(calls), []);
  }
});

// Env files are sourced with `set -a` by the deploy orchestrator, so a variable left in one would
// carry into every later run on a real network: outside local the override is the flag of one run.
test("outside local STELLAR_ALLOW_WASM_MISMATCH is ignored and said so; the flag (the option) is the override there", async () => {
  const out = "reuse-wasm-testnet.json";
  manifest(out, 1000002n, "testnet", { wasmHashes: { blsKeyRegistry: "1".repeat(64) } });
  const T = { ...NAMED, STELLAR_NETWORK: "testnet", STELLAR_CHAIN_ID: "1000002", FAKE_STELLAR_PASSPHRASE: NETWORK_PASSPHRASES.testnet, FAKE_STELLAR_KEYS_ENV: "testnet" };
  let calls: string[] = [];
  let warned = await warnedDuring(async () => {
    calls = await withFake({ ...T, STELLAR_ALLOW_WASM_MISMATCH: "1" }, () =>
      assert.rejects(deploy("testnet", out), /BLSKeyRegistry: the reused contract was deployed from wasm 1{64}.*pass --allow-wasm-mismatch to this one run/),
    );
  });
  assert.deepEqual(sent(calls), []);
  assert.ok(warned.some((l) => /STELLAR_ALLOW_WASM_MISMATCH is set but ignored for DEPLOY_ENV=testnet.*--allow-wasm-mismatch/.test(l)), `ignored line in ${JSON.stringify(warned)}`);
  assert.ok(!warned.some((l) => /OVERRIDE ON/.test(l)), "no override banner: the variable did not count");
  // the flag's option: past the check to the next read, with the banner
  warned = await warnedDuring(async () => {
    calls = await withFake(T, () => assert.rejects(deploy("testnet", out, { allowWasmMismatch: true }), PAST_WASM_CHECKS));
  });
  assert.deepEqual(sent(calls), []);
  assert.ok(warned.some((l) => /WASM MISMATCH OVERRIDE ON/.test(l)), `banner in ${JSON.stringify(warned)}`);
  assert.ok(warned.some((l) => /BLSKeyRegistry wasm NOT CHECKED: override on/.test(l)), `registry line in ${JSON.stringify(warned)}`);
});

// The flag itself, through bin/cli.ts: the one override an operator has on a real network.
test("`deploy --allow-wasm-mismatch` is the CLI's override; the env variable on the command's environment is not", () => {
  const out = "reuse-wasm-cli.json";
  manifest(out, 1000002n, "testnet", { wasmHashes: { blsKeyRegistry: "1".repeat(64) } });
  const pkgRoot = path.resolve(FAKE_DIR, "..", "..", "..");
  const tsxCli = createRequire(import.meta.url).resolve("tsx/cli");
  const env = {
    ...process.env,
    ...Object.fromEntries(Object.entries(CLEAN).filter(([, v]) => v !== undefined)),
    ...NAMED,
    DEPLOY_ENV: "testnet",
    STELLAR_NETWORK: "testnet",
    STELLAR_CHAIN_ID: "1000002",
    STELLAR_WASM_DIR: wasmDirPath,
    FAKE_STELLAR_PASSPHRASE: NETWORK_PASSPHRASES.testnet,
    FAKE_STELLAR_KEYS_ENV: "testnet",
    FAKE_STELLAR_ADDRESS: DEPLOYER,
    PATH: `${FAKE_DIR}:${process.env.PATH}`,
  };
  for (const k of Object.keys(CLEAN)) if (!(k in env) || env[k] === undefined) delete env[k];
  const run = (args: string[], extra: Record<string, string>) =>
    spawnSync(process.execPath, [tsxCli, "bin/cli.ts", "deploy", "--out", path.join(tmp, out), ...args], { cwd: pkgRoot, env: { ...env, ...extra }, encoding: "utf8" });
  // the variable alone: refused on the mismatch, and the CLI says the variable did not count
  let r = run([], { STELLAR_ALLOW_WASM_MISMATCH: "1" });
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stderr, /STELLAR_ALLOW_WASM_MISMATCH is set but ignored for DEPLOY_ENV=testnet/);
  assert.match(r.stderr, /BLSKeyRegistry: the reused contract was deployed from wasm 1{64}/);
  // the flag: past the check to the next read
  r = run(["--allow-wasm-mismatch"], {});
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stderr, /WASM MISMATCH OVERRIDE ON/);
  assert.match(r.stderr, /no answer for contract invoke .* -- get_admin/);
});

// A fresh deploy must write the hashes it will be checked against next time: without them the next
// run refuses to reuse a registry that is this bundle's.
test("a fresh deploy records the bundle's registry, verifier and agent-account wasm hashes; the next run reuses them with no override", async () => {
  const out = "fresh.json";
  const ids = path.join(tmp, "fresh-ids.txt");
  fs.writeFileSync(ids, [...BUNDLE_WASM, "native"].map((w) => `${w} ${contractId()}`).join("\n") + "\n");
  const LOCAL = { FAKE_STELLAR_PASSPHRASE: NETWORK_PASSPHRASES.local, STELLAR_EVENT_VK: vkFile };
  const calls = await withFake({ ...LOCAL, FAKE_STELLAR_IDS: ids }, () => deploy("local", out));
  assert.ok(calls.some((c) => /^contract deploy --wasm \S*bls_key_registry\.wasm /.test(c)), "the registry was deployed");
  assert.ok(calls.some((c) => /^contract deploy --wasm \S*counterparty_verifier\.wasm /.test(c)), "the verifier was deployed");
  // #586: the launch fee, the pool (the deployer's account, as 32 bytes) before the bps.
  const poolHex = Buffer.from(StrKey.decodeEd25519PublicKey(DEPLOYER)).toString("hex");
  const poolAt = calls.findIndex((c) => c.includes(`--send yes -- set_protocol_fee_pool --pool ${poolHex}`));
  const bpsAt = calls.findIndex((c) => c.includes("--send yes -- set_fee_bps --lp_bps 30 --protocol_bps 20"));
  assert.ok(poolAt >= 0 && bpsAt > poolAt, "the fee pool, then the fee bps, were set");
  const back = JSON.parse(fs.readFileSync(path.join(tmp, out), "utf8")) as { wasmHashes?: Record<string, string>; feeConfig?: unknown };
  assert.deepEqual(back.feeConfig, { pool: DEPLOYER, lpBps: 30, protocolBps: 20 });
  assert.deepEqual(back.wasmHashes, { ...BUNDLE_HASHES, agentAccount: wasmSha256(path.join(wasmDirPath, "agent_account.wasm")) });
  // the manifest it wrote: both reused under the same bundle, past the checks to the next read, no override
  const again = await withFake({ ...LOCAL, FAKE_STELLAR_KEYS_ENV: "local" }, () => assert.rejects(deploy("local", out), PAST_WASM_CHECKS));
  assert.deepEqual(sent(again), []);
});

// ── link ───────────────────────────────────────────────────────────────

function manifest(
  file: string,
  chainId: bigint,
  env: string,
  opts: { disputeManager?: boolean; vk?: string; wasmHashes?: { blsKeyRegistry?: string; counterpartyVerifier?: string } | null } = {},
): string {
  const m = buildManifest({
    chainName: `c-${chainId}`,
    chainId,
    env,
    commit: "unknown",
    deployer: DEPLOYER,
    vk: opts.vk ? { vkSha256: opts.vk } : undefined,
    // recorded as the bundle's unless a case says otherwise (null: a manifest from before the record)
    wasmHashes: opts.wasmHashes === null ? undefined : { ...BUNDLE_HASHES, ...opts.wasmHashes },
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
const TESTNET = { ...CLOCKS, STELLAR_NETWORK: "testnet", FAKE_STELLAR_PASSPHRASE: NETWORK_PASSPHRASES.testnet };
const linkT = (localManifest: string, peerManifest: string) =>
  link({ localManifest, peerManifest, localChainId: 1000002n });
// Past every route check, the first thing link does is read the chain; the fake has no answer.
const PAST_CHECKS = /fake stellar: no answer for contract invoke/;

test("A-4: link checks the network against the manifest's env before any call", async () => {
  const local = manifest("lnk-l.json", 1000002n, "testnet");
  const calls = await withFake({ ...CLOCKS, STELLAR_NETWORK: "testnet", FAKE_STELLAR_PASSPHRASE: NETWORK_PASSPHRASES.local }, () =>
    assert.rejects(linkT(local, manifest("lnk-p.json", 11155111n, "testnet")), /DEPLOY_ENV=testnet but STELLAR_NETWORK=testnet is on local, not the testnet network/),
  );
  assert.deepEqual(calls, ["network info --network testnet --output json"]);
});

test("A-6: link refuses a peer deployed for another env, or against another VK", async () => {
  const local = manifest("c-l.json", 1000002n, "testnet", { vk: "0x" + "ab".repeat(32) });
  await withFake(TESTNET, () =>
    assert.rejects(linkT(local, manifest("c-p1.json", 11155111n, "mainnet")), /cannot span environments/),
  );
  await withFake(TESTNET, () =>
    assert.rejects(
      linkT(local, manifest("c-p2.json", 11155111n, "testnet", { vk: "0x" + "cd".repeat(32) })),
      /refuse each other's proofs/,
    ),
  );
});

test("the dispute bond floor is required outside local; a local route goes past the checks without it", async () => {
  const { DISPUTE_BOND_FLOOR: _floor, ...noFloor } = TESTNET;
  const local = manifest("f-l.json", 1000002n, "testnet");
  const peer = manifest("f-p.json", 11155111n, "testnet");
  const calls = await withFake(noFloor, () =>
    assert.rejects(linkT(local, peer), /DISPUTE_BOND_FLOOR is unset for env=testnet/),
  );
  assert.deepEqual(sent(calls), []);
  const localL = manifest("f-ll.json", 1000002n, "local");
  const peerL = manifest("f-lp.json", 11155111n, "local");
  await withFake({ STELLAR_NETWORK: "local", FAKE_STELLAR_PASSPHRASE: NETWORK_PASSPHRASES.local }, () =>
    assert.rejects(linkT(localL, peerL), PAST_CHECKS),
  );
});

test("link refuses a margin above half the buffer before anything is sent", async () => {
  const local = manifest("m-l.json", 1000002n, "testnet");
  const peer = manifest("m-p.json", 11155111n, "testnet");
  const calls = await withFake({ ...TESTNET, ROUTE_MARGIN_S: "901" }, () =>
    assert.rejects(linkT(local, peer), /ROUTE_MARGIN_S=901 exceeds half of ROUTE_BUFFER_S=1800/),
  );
  assert.deepEqual(sent(calls), []);
});

test("deploy makes the escrows MerkleManager managers and not the Registrar", async () => {
  const c = { adManager: contractId(), orderPortal: contractId(), registrar: contractId() };
  const managers = appendersAtDeploy(c);
  assert.deepEqual(managers, [c.adManager, c.orderPortal]);
  assert.ok(!managers.includes(c.registrar), "the Registrar waits for the T3 flip");
});
