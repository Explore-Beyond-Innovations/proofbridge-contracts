import { test } from "node:test";
import assert from "node:assert/strict";
import { MIN_BOND_FLOOR_OUTSIDE_LOCAL, disputeParamsFromEnv } from "../src/link.js";

// The dispute params as `link` reads them from env. The floor is the whole bond now, so a dust floor
// on a real network makes disputes free: refused below the minimum outside local, any legal value local.

const MIN = MIN_BOND_FLOOR_OUTSIDE_LOCAL.toString();
const base = { DISPUTE_CHALLENGE_PERIOD_S: "3600" };

test("outside local a floor below the minimum is refused and the minimum itself is accepted", () => {
  assert.throws(() => disputeParamsFromEnv("testnet", { ...base, DISPUTE_BOND_FLOOR: "1" }), /DISPUTE_BOND_FLOOR=1 is below the 10000000 minimum for env=testnet/);
  assert.throws(
    () => disputeParamsFromEnv("mainnet", { ...base, DISPUTE_BOND_FLOOR: (MIN_BOND_FLOOR_OUTSIDE_LOCAL - 1n).toString() }),
    /below the 10000000 minimum for env=mainnet/,
  );
  assert.equal(disputeParamsFromEnv("testnet", { ...base, DISPUTE_BOND_FLOOR: MIN }).bondFloor, MIN);
  // The minimum is a sanity bound, not the tuned value: anything above it goes through.
  assert.equal(disputeParamsFromEnv("mainnet", { ...base, DISPUTE_BOND_FLOOR: MIN + "0" }).bondFloor, MIN + "0");
});

test("local keeps the smallest legal floor: an explicit 1, or the default when nothing is set", () => {
  assert.equal(disputeParamsFromEnv("local", { ...base, DISPUTE_BOND_FLOOR: "1" }).bondFloor, "1");
  assert.deepEqual(disputeParamsFromEnv("local", {}), { challengePeriod: "3600", bondFloor: "1" });
});

test("a DISPUTE_BOND_BPS left in the env is refused in every env: the percentage term is gone", () => {
  for (const env of ["local", "testnet", "mainnet"]) {
    assert.throws(
      () => disputeParamsFromEnv(env, { ...base, DISPUTE_BOND_FLOOR: MIN, DISPUTE_BOND_BPS: "50" }),
      /DISPUTE_BOND_BPS is set, but the percentage term was removed/,
      env,
    );
  }
  // Even a zero, which used to mean "no percentage", is refused: the variable itself is the mistake.
  assert.throws(() => disputeParamsFromEnv("local", { DISPUTE_BOND_BPS: "0" }), /DISPUTE_BOND_BPS/);
});
