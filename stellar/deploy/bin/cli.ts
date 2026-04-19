#!/usr/bin/env -S tsx
// Stellar per-chain deploy CLI.
//
// Usage:
//   stellar-deploy deploy             [--out <manifest-path>] [--chain-id <n>]
//   stellar-deploy deploy-test-tokens [--out <manifest-path>] [--chain-id <n>]
//   stellar-deploy link --peer <peer-manifest> [--in <local-manifest>]
//
// Reads the `stellar` CLI environment:
//   STELLAR_NETWORK (default: testnet), STELLAR_SOURCE_ACCOUNT (default: admin)
// Optional: STELLAR_WASM_DIR, STELLAR_DEPOSIT_VK, STELLAR_DEPLOYMENTS_DIR,
//           DEPLOY_ENV, GIT_COMMIT, CHAIN_NAME.

import { deployCore } from "../src/deploy-core.js";
import { deployTestTokens } from "../src/deploy-test-tokens.js";
import { link } from "../src/link.js";

function parseFlag(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(name);
  if (i === -1) return undefined;
  return argv[i + 1];
}

function parseChainId(argv: string[]): bigint | undefined {
  const v = parseFlag(argv, "--chain-id");
  return v ? BigInt(v) : undefined;
}

async function main(): Promise<void> {
  const [, , cmd, ...rest] = process.argv;
  switch (cmd) {
    case "deploy": {
      await deployCore({
        manifestOut: parseFlag(rest, "--out"),
        chainId: parseChainId(rest),
      });
      return;
    }
    case "deploy-test-tokens": {
      await deployTestTokens({
        manifestOut: parseFlag(rest, "--out"),
        chainId: parseChainId(rest),
      });
      return;
    }
    case "link": {
      const peer = parseFlag(rest, "--peer");
      if (!peer) {
        console.error("link: --peer <peer-manifest> is required");
        process.exit(2);
      }
      await link({
        peerManifest: peer,
        localManifest: parseFlag(rest, "--in"),
        localChainId: parseChainId(rest),
      });
      return;
    }
    default:
      console.error(
        `Unknown command '${cmd ?? ""}'.\n` +
          "Usage: stellar-deploy {deploy|deploy-test-tokens|link} [flags]",
      );
      process.exit(2);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
