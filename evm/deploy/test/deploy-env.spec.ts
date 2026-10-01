import { test } from "node:test";
import assert from "node:assert/strict";
import { assertChainIdForEnv, namedOutsideLocal, requireDeployEnv } from "../src/deploy-env.js";

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

// A-4: the stated environment must be the network the RPC is on.
test("DEPLOY_ENV is tied to the connected chain id", () => {
  assertChainIdForEnv(31337n, "local", {});
  assert.throws(() => assertChainIdForEnv(11155111n, "local", {}), /DEPLOY_ENV=local but the RPC is chain 11155111/);
  assertChainIdForEnv(11155111n, "testnet", {});
  assert.throws(() => assertChainIdForEnv(31337n, "testnet", {}), /is a local chain/);
  assert.throws(() => assertChainIdForEnv(1n, "testnet", {}), /is a mainnet chain/);
  assertChainIdForEnv(1n, "mainnet", {});
  assert.throws(() => assertChainIdForEnv(11155111n, "mainnet", {}), /which is a testnet chain/);
  // A private devnet or a new L1 is declared, never guessed.
  assertChainIdForEnv(9999n, "local", { LOCAL_EVM_CHAIN_IDS: "9999" });
  assertChainIdForEnv(5000n, "mainnet", { MAINNET_EVM_CHAIN_IDS: "5000, 5001" });
  assert.throws(() => assertChainIdForEnv(1n, "mainnet", { MAINNET_EVM_CHAIN_IDS: "abc" }), /decimal chain ids/);
});


// An allowlist per env: an unlisted id (an unknown mainnet, a fork) is never guessed to be a testnet.
test("every env is an allowlist: the known testnets pass, an unlisted id refuses everywhere", () => {
  for (const id of [11155111n, 84532n, 421614n, 11155420n, 17000n, 80002n]) {
    assertChainIdForEnv(id, "testnet", {});
    assert.throws(() => assertChainIdForEnv(id, "local", {}), /which is a testnet chain/);
    assert.throws(() => assertChainIdForEnv(id, "mainnet", {}), /which is a testnet chain/);
  }
  for (const e of ["local", "testnet", "mainnet"] as const) {
    assert.throws(() => assertChainIdForEnv(5000n, e, {}), /chain 5000, which no environment lists/);
  }
  assert.throws(() => assertChainIdForEnv(5000n, "testnet", {}), /TESTNET_EVM_CHAIN_IDS/, "names the list to extend");
  assertChainIdForEnv(5003n, "testnet", { TESTNET_EVM_CHAIN_IDS: "5003" });
  assert.throws(() => assertChainIdForEnv(5003n, "mainnet", { TESTNET_EVM_CHAIN_IDS: "5003" }), /which is a testnet chain/);
  // An id declared for two envs is ambiguous, not whichever list is read first.
  assert.throws(() => assertChainIdForEnv(31337n, "testnet", { TESTNET_EVM_CHAIN_IDS: "31337" }), /listed for local and testnet/);
});
