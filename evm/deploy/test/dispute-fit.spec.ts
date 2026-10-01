import { test } from "node:test";
import assert from "node:assert/strict";
import { PUBLISHER_MARGIN_S, assertDisputeFitsBackstop, requiredBackstop } from "../src/dispute-fit.js";

const side = (buffer: number, longBackstop: number, challengePeriod?: number, anchorDelay?: number) => ({
  disputeModule: true,
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
  assert.deepEqual(assertDisputeFitsBackstop(side(1800, 100), { disputeModule: true, anchorDelay: "0" }, "link"), []);
});

test("the local defaults fit (a 1-hour challenge, 30-minute buffers, a 1-day backstop)", () => {
  assert.deepEqual(
    assertDisputeFitsBackstop(side(1800, 86400, 3600, 0), side(1800, 86400, 3600, 0), "link"),
    ["this chain as follower", "this chain as primary"],
  );
});

// A-5: a chain with no DisputeManager has no dispute params; its clocks are still checked.
test("a route with no dispute module on either side counts once both clocks are known", () => {
  const bare = (longBackstop: number) => ({ disputeModule: false, timing: { buffer: "1800", longBackstop: String(longBackstop) } });
  assert.deepEqual(assertDisputeFitsBackstop(bare(100), bare(100), "link"), [
    "this chain as follower (clocks only: no dispute module)",
    "this chain as primary (clocks only: no dispute module)",
  ]);
  // The clocks are still required: an unrecorded peer leaves its directions unchecked.
  assert.deepEqual(assertDisputeFitsBackstop(bare(100), { disputeModule: false }, "link"), []);
});

test("a mixed route (a module on one side only) is refused", () => {
  const bare = { disputeModule: false, timing: { buffer: "1800", longBackstop: "86400" } };
  const full = side(1800, 86400, 3600, 0);
  assert.throws(() => assertDisputeFitsBackstop(full, bare, "link"), /only this chain has a DisputeManager/);
  assert.throws(() => assertDisputeFitsBackstop(bare, full, "link"), /only the peer has a DisputeManager/);
});
