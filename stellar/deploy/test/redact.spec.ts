import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "path";
import { Keypair } from "@stellar/stellar-sdk";
import { redact, stellar } from "../src/stellar-cli.js";

// STELLAR_SOURCE_ACCOUNT may be a raw secret seed; neither the echoed command nor a failed call's error may carry it.
const FAKE_DIR = path.join(path.dirname(new URL(import.meta.url).pathname), "helpers", "fake-stellar");

test("redact masks a valid secret seed and leaves public keys and other text alone", () => {
  const kp = Keypair.random();
  const out = redact(`--source ${kp.secret()} --to ${kp.publicKey()} already deployed`);
  assert.ok(!out.includes(kp.secret()));
  assert.ok(out.includes(kp.publicKey()));
  assert.ok(out.includes("already deployed"));
  // a 56-char S… string that is not a valid seed is left as is
  const notSeed = "S" + "A".repeat(55);
  assert.equal(redact(notSeed), notSeed);
});

test("a failed stellar call with a secret-seed source logs and throws without the seed", () => {
  const seed = Keypair.random().secret();
  const logged: string[] = [];
  const log = console.log;
  const pathBefore = process.env.PATH;
  console.log = (...a: unknown[]) => void logged.push(a.join(" "));
  process.env.PATH = `${FAKE_DIR}:${pathBefore}`;
  try {
    let thrown: unknown;
    try {
      stellar(["contract", "upload", "--wasm", "x.wasm", "--source", seed]);
    } catch (err) {
      thrown = err;
    }
    assert.ok(thrown instanceof Error, "the fake CLI refuses the upload");
    const e = thrown as Error & { stderr?: string };
    assert.ok(e.message.includes("contract upload"), "the error still names the command");
    assert.ok(!e.message.includes(seed), "error message carries no seed");
    assert.ok(!String(e.stderr ?? "").includes(seed), "stderr carries no seed");
    assert.ok(logged.some((l) => l.includes("[stellar] stellar contract upload")));
    assert.ok(logged.every((l) => !l.includes(seed)), "the echoed command carries no seed");
  } finally {
    console.log = log;
    process.env.PATH = pathBefore;
  }
});
