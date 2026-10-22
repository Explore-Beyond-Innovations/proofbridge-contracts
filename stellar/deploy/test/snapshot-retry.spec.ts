import { test } from "node:test";
import assert from "node:assert/strict";
import { isSnapshotRace, withSnapshotRetry } from "../src/stellar-cli.ts";

// A fresh localnet's RPC can simulate before its snapshot is complete (seen in CI's deploy-link step).
const race = Object.assign(new Error("Command failed: stellar contract invoke …"), {
  stderr: "❌ error: transaction simulation failed: setting ContractComputeV0 is not present in the snapshot\n",
});

test("the snapshot race is retried until the call passes, with growing pauses", () => {
  let calls = 0;
  const slept: number[] = [];
  const out = withSnapshotRetry(
    () => {
      if (++calls < 3) throw race;
      return "ok";
    },
    (ms) => slept.push(ms),
  );
  assert.equal(out, "ok");
  assert.equal(calls, 3);
  assert.deepEqual(slept, [1000, 2000]);
});

test("any other failure is thrown at once, never retried", () => {
  let calls = 0;
  const contractError = Object.assign(new Error("Command failed"), { stderr: "Error(Contract, #12)" });
  assert.throws(() => withSnapshotRetry(() => (calls++, (() => { throw contractError; })()), () => {}), /Command failed/);
  assert.equal(calls, 1);
});

test("the race gives up after the last attempt and throws it", () => {
  let calls = 0;
  assert.throws(() => withSnapshotRetry(() => (calls++, (() => { throw race; })()), () => {}, 3), /Command failed/);
  assert.equal(calls, 3);
  assert.equal(isSnapshotRace("simulation failed: Error(Contract, #4)"), false);
});
