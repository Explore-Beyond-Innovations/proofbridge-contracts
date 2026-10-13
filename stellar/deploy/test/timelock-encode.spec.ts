import { test } from "node:test";
import assert from "node:assert/strict";
import { encodeCall, flagsToNamed, namedToFlags, TIMELOCKED_SETTERS } from "../src/timelock.js";
import { feeConfigFromEnv } from "../src/deploy-core.js";
import { tokenBondsFromEnv } from "../src/link.js";

// #586: the CLI's proposal encoder against the ids the contract computes, pinned on the Rust side in
// lib/proofbridge-core/src/timelock_test.rs. One call per argument type: a drift in either encoder
// (a field order, an integer width, an address form) turns one of these red.

const ACCOUNT = "GARCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCFRVX";
const CONTRACT = "CAIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRDB3V";

test("proposal ids match the contract's for every argument type", () => {
  assert.equal(
    encodeCall("DisputeManager", "set_dispute_params", { chain_id: "1000002", params: { challenge_period: 7200, bond_floor: "1000" } }).id,
    "66d8a158ae74a6c625d65297d0808577d1b4be0dd2edbc2d5d9a95d811f488b3",
  );
  assert.equal(
    encodeCall("AdManager", "set_chain", { order_chain_id: "7777", order_portal: "42".repeat(32) }).id,
    "e0bfc09fd7d4d14b64ca54e572e655222bc7b80a05b3dbf392b39179008b3bff",
  );
  assert.equal(encodeCall("AdManager", "set_fee_bps", { lp_bps: 30, protocol_bps: 20 }).id, "ea4f2da6bd9ea0128b70c3fdbf92fbc3d68a95b770fe1c9669119282f772b275");
  assert.equal(
    encodeCall("AdManager", "set_route_timing", {
      chain_id: "7777",
      timing: JSON.stringify({ min_window: 0, buffer: 1800, margin: 0, claim_stagger: 0 }),
    }).id,
    "937d6c2158d5bce4d88f155cb703ee0e86edf754d14e7ab016aa554aad1414cb",
  );
  assert.equal(
    encodeCall("DisputeManager", "set_bond_config", { token: CONTRACT, peer_chain_id: "1000002", config: { min_bond: "1000000", bond_bps: 50 } }).id,
    "dd1faec679716838e42560f4a0f81347ce0473b32a32b84ef05d97af0178db82",
  );
  assert.equal(encodeCall("MerkleManager", "set_manager", { manager: ACCOUNT, status: "true" }).id, "8d7bff83e54b34b14f272be202c745d99bad76ccb3645eb8bd7e5c763aa2498e");
  assert.equal(
    encodeCall("MerkleManager", "set_escrow_appender", { escrow: CONTRACT, enabled: "false" }).id,
    "7bbe7109b0cf1bf22f497e93d00c169387d256cd1568173929b16e11a0bb0df6",
  );
  assert.equal(
    encodeCall("RootAnchor", "set_signers", { signers: JSON.stringify([ACCOUNT]), threshold: 1 }).id,
    "100d2335126ea0e1dd3e4d59bbef42c0c34725f53cb6d9bc4d91c7da7b117fbe",
  );
  assert.equal(
    encodeCall("BLSKeyRegistry", "set_proof_registration", { anchor: CONTRACT, verifier: CONTRACT, sources: JSON.stringify(["1000002"]), enabled: "true" }).id,
    "47c0f7edb3e2211853a154b3bdd3b20b59220b4c489b450b5d1e3b21fe3dfd64",
  );
});

test("the CLI's flag form round-trips into the encoder", () => {
  const flags = ["--lp_bps", "30", "--protocol_bps", "20"];
  assert.deepEqual(flagsToNamed(flags), { lp_bps: "30", protocol_bps: "20" });
  assert.deepEqual(namedToFlags({ lp_bps: "30", protocol_bps: "20" }), flags);
  assert.equal(encodeCall("AdManager", "set_fee_bps", flagsToNamed(flags)).id, "ea4f2da6bd9ea0128b70c3fdbf92fbc3d68a95b770fe1c9669119282f772b275");
});

test("an unknown setter, a missing argument, or short bytes are refused", () => {
  assert.throws(() => encodeCall("AdManager", "pause", {}), /not a timelocked setter/);
  assert.throws(() => encodeCall("AdManager", "set_fee_bps", { lp_bps: 30 }), /needs --protocol_bps/);
  assert.throws(() => encodeCall("AdManager", "set_chain", { order_chain_id: "1", order_portal: "ab" }), /32 bytes of hex/);
});

test("every setter link and deploy send is in the encoder's table", () => {
  for (const fn of ["set_chain", "set_root_verifier", "set_route_timing", "set_root_anchor", "set_token_route", "set_dispute_manager", "set_key_registry", "set_protocol_fee_pool", "set_fee_bps"]) {
    assert.ok(TIMELOCKED_SETTERS.AdManager![fn], `AdManager.${fn}`);
  }
  for (const fn of ["set_escrow", "set_dispute_params", "set_arbiter", "set_protocol_fee_pool", "set_bond_config"]) {
    assert.ok(TIMELOCKED_SETTERS.DisputeManager![fn], `DisputeManager.${fn}`);
  }
  for (const fn of ["set_manager", "set_escrow_appender"]) assert.ok(TIMELOCKED_SETTERS.MerkleManager![fn], `MerkleManager.${fn}`);
  for (const fn of ["set_signers", "reset_latest_seq", "set_anchor_delay", "set_monotonic"]) {
    assert.ok(TIMELOCKED_SETTERS.RootAnchor![fn], `RootAnchor.${fn}`);
  }
  for (const fn of ["upgrade", "set_position_guards", "set_proof_registration"]) {
    assert.ok(TIMELOCKED_SETTERS.BLSKeyRegistry![fn], `BLSKeyRegistry.${fn}`);
  }
});

test("outside local every fee value is required; the pool is an account; each bps is at most 100", () => {
  assert.throws(() => feeConfigFromEnv("testnet", ACCOUNT, {}), /PROTOCOL_FEE_POOL is unset/);
  assert.throws(() => feeConfigFromEnv("local", ACCOUNT, { PROTOCOL_FEE_POOL: CONTRACT }), /must be a Stellar account/);
  assert.throws(() => feeConfigFromEnv("local", ACCOUNT, { PROTOCOL_FEE_BPS: "101" }), /at most 100/);
  assert.deepEqual(feeConfigFromEnv("local", ACCOUNT, {}), { pool: ACCOUNT, lpBps: 30, protocolBps: 20 });
});

test("DISPUTE_TOKEN_BONDS is checked with the contract's rules", () => {
  assert.deepEqual(tokenBondsFromEnv({ DISPUTE_TOKEN_BONDS: '{"usdc":{"minBond":"10000000","bondBps":50}}' }), {
    usdc: { minBond: "10000000", bondBps: 50 },
  });
  assert.throws(() => tokenBondsFromEnv({ DISPUTE_TOKEN_BONDS: '{"usdc":{"minBond":"1","bondBps":501}}' }), /0\.\.500/);
});
