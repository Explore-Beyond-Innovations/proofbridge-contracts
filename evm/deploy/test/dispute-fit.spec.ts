import { test } from "node:test";
import assert from "node:assert/strict";
import { PUBLISHER_MARGIN_S, assertDisputeFitsBackstop, requiredBackstop } from "../src/dispute-fit.js";

const side = (buffer: number, longBackstop: number, challengePeriod?: number, anchorDelay?: number) => ({
  timing: { buffer: String(buffer), longBackstop: String(longBackstop) },
  ...(challengePeriod !== undefined ? { dispute: { challengePeriod: String(challengePeriod) } } : {}),
  ...(anchorDelay !== undefined ? { anchorDelay: String(anchorDelay) } : {}),
});

// C-10: a dispute that outlives the follower's backstop loses a BridgerForfeit.
test("the required backstop is challenge + 2 x primary buffer + follower anchor delay + one publisher round", () => {
  assert.equal(requiredBackstop(3600n, 1800n, 600n), 3600n + 3600n + 600n + PUBLISHER_MARGIN_S);
});

test("refuses a follower backstop one second short, accepts it at the bound, in both directions", () => {
  const need = Number(requiredBackstop(86400n, 3600n, 900n));
  const primary = side(3600, 86400 * 10, 86400);
  assert.throws(() => assertDisputeFitsBackstop(side(1800, need - 1, undefined, 900), primary, "link"), /this chain as follower/);
  assert.deepEqual(assertDisputeFitsBackstop(side(1800, need, undefined, 900), primary, "link"), ["this chain as follower"]);
  // the same route seen from the primary's side
  assert.throws(() => assertDisputeFitsBackstop(primary, side(1800, need - 1, undefined, 900), "link"), /this chain as primary/);
});

test("a direction whose data is not recorded yet is left to the other chain's link", () => {
  assert.deepEqual(assertDisputeFitsBackstop(side(1800, 100), { anchorDelay: "0" }, "link"), []);
});

test("the local defaults fit (a 1-hour challenge, 30-minute buffers, a 1-day backstop)", () => {
  assert.deepEqual(
    assertDisputeFitsBackstop(side(1800, 86400, 3600, 0), side(1800, 86400, 3600, 0), "link"),
    ["this chain as follower", "this chain as primary"],
  );
});
