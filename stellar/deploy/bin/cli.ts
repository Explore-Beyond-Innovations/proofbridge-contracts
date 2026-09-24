#!/usr/bin/env -S tsx
// Stellar per-chain deploy CLI.
//
// Usage:
//   stellar-deploy deploy             [--out <manifest-path>] [--chain-id <n>]
//   stellar-deploy deploy-test-tokens [--out <manifest-path>] [--chain-id <n>]
//   stellar-deploy link --peer <peer-manifest> [--in <local-manifest>] [--enforce-bls]
//   stellar-deploy handover --to <G...> | --verify   [--in <manifest-path>] [--chain-id <n>]
//
// Reads the `stellar` CLI environment:
//   STELLAR_NETWORK (default: testnet), STELLAR_SOURCE_ACCOUNT (default: admin)
// Optional: STELLAR_WASM_DIR, STELLAR_EVENT_VK, STELLAR_DEPLOYMENTS_DIR,
//           DEPLOY_ENV, GIT_COMMIT, CHAIN_NAME.

import { deployCore } from "../src/deploy-core.js";
import { deployTestTokens } from "../src/deploy-test-tokens.js";
import { link } from "../src/link.js";
import { handover } from "../src/handover.js";

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
      const r = await deployCore({
        manifestOut: parseFlag(rest, "--out"),
        chainId: parseChainId(rest),
      });
      // Described, not sent: the admin has calls to make. Not a success a script may build on.
      if (r.described.length) process.exit(2);
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
      const r = await link({
        peerManifest: peer,
        localManifest: parseFlag(rest, "--in"),
        localChainId: parseChainId(rest),
        enforceBls: rest.includes("--enforce-bls"),
      });
      if (r.described.length) process.exit(2);
      return;
    }
    case "handover": {
      const verify = rest.includes("--verify");
      const to = parseFlag(rest, "--to");
      if (!verify && !to) {
        console.error("handover: --to <G...> is required (or --verify)");
        process.exit(2);
      }
      await handover({ to, verify, manifest: parseFlag(rest, "--in"), chainId: parseChainId(rest) });
      return;
    }
    default:
      console.error(
        `Unknown command '${cmd ?? ""}'.\n` +
          "Usage: stellar-deploy {deploy|deploy-test-tokens|link|handover} [flags]",
      );
      process.exit(2);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
