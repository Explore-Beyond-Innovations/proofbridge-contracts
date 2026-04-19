#!/usr/bin/env -S tsx
// EVM per-chain deploy CLI.
//
// Usage:
//   evm-deploy deploy             [--out <manifest-path>]
//   evm-deploy deploy-test-tokens [--out <manifest-path>]
//   evm-deploy link --peer <peer-manifest> [--in <local-manifest>]
//
// Reads EVM_RPC_URL, EVM_ADMIN_PRIVATE_KEY from env. Other knobs:
//   ADMIN, CHAIN_NAME, DEPLOY_ENV, GIT_COMMIT,
//   WNATIVE_NAME, WNATIVE_SYMBOL, WNATIVE_DECIMALS,
//   EVM_OUT_DIR, EVM_DEPLOYMENTS_DIR.

import { deployCore } from "../src/deploy-core.js";
import { deployTestTokens } from "../src/deploy-test-tokens.js";
import { link } from "../src/link.js";

function parseFlag(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(name);
  if (i === -1) return undefined;
  return argv[i + 1];
}

async function main(): Promise<void> {
  const [, , cmd, ...rest] = process.argv;
  switch (cmd) {
    case "deploy": {
      await deployCore({ manifestOut: parseFlag(rest, "--out") });
      return;
    }
    case "deploy-test-tokens": {
      await deployTestTokens({ manifestOut: parseFlag(rest, "--out") });
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
      });
      return;
    }
    default:
      console.error(
        `Unknown command '${cmd ?? ""}'.\n` +
          "Usage: evm-deploy {deploy|deploy-test-tokens|link} [flags]",
      );
      process.exit(2);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
