import { test } from "node:test";
import assert from "node:assert/strict";
import { namedOutsideLocal, requireDeployEnv } from "../src/deploy-env.js";

// C-23: an unset DEPLOY_ENV used to mean local and gave a real network the local defaults.
test("DEPLOY_ENV is required, and only local, testnet or mainnet", () => {
  assert.throws(() => requireDeployEnv(undefined, {}), /DEPLOY_ENV is unset/);
  assert.throws(() => requireDeployEnv(undefined, { DEPLOY_ENV: "" }), /DEPLOY_ENV is unset/);
  assert.throws(() => requireDeployEnv(undefined, { DEPLOY_ENV: "staging" }), /not one of/);
  assert.equal(requireDeployEnv(undefined, { DEPLOY_ENV: "testnet" }), "testnet");
  assert.equal(requireDeployEnv("local", {}), "local", "the option wins over the environment");
});

// C-24: the anchor notary (and the dispute roles) default to the deployer on local only.
test("a deployer-defaulted role must be named outside local", () => {
  assert.equal(namedOutsideLocal("ANCHOR_PUBLISHER", "local", "0xdeployer", {}), "0xdeployer");
  assert.throws(() => namedOutsideLocal("ANCHOR_PUBLISHER", "testnet", "0xdeployer", {}), /ANCHOR_PUBLISHER is unset for DEPLOY_ENV=testnet/);
  assert.equal(namedOutsideLocal("ANCHOR_PUBLISHER", "testnet", "0xdeployer", { ANCHOR_PUBLISHER: "0xnotary" }), "0xnotary");
});
