#!/usr/bin/env -S tsx
// EVM per-chain deploy CLI.
//
// Usage:
//   evm-deploy deploy             [--out <manifest-path>]
//   evm-deploy deploy-test-tokens [--out <manifest-path>]
//   evm-deploy link --peer <peer-manifest> [--in <local-manifest>]
//   evm-deploy handover --to <address> | --verify   [--in <manifest-path>]
//   evm-deploy retirements-audit --file <vault-export.json> [--in <manifest-path>]
//   evm-deploy timelock status|activate --confirm [--in <manifest-path>]
//   evm-deploy timelock propose|execute|cancel --contract <AdManager|OrderPortal|MerkleManager|DisputeManager>
//              --fn <setter> --args '<JSON array>' [--in <manifest-path>]
//
// Reads EVM_RPC_URL, EVM_ADMIN_PRIVATE_KEY from env. Other knobs:
//   CHAIN_NAME, DEPLOY_ENV, GIT_COMMIT (ADMIN is refused: the deployer is the admin; see handover),
//   WNATIVE_NAME, WNATIVE_SYMBOL, WNATIVE_DECIMALS,
//   EVM_OUT_DIR, EVM_DEPLOYMENTS_DIR.

import { deployCore } from "../src/deploy-core.js";
import { deployTestTokens } from "../src/deploy-test-tokens.js";
import { link } from "../src/link.js";
import { handover } from "../src/handover.js";
import { retirementsAudit } from "../src/retirements-audit.js";
import {
  timelockActivate,
  timelockCancel,
  timelockExecute,
  timelockPropose,
  timelockStatus,
  type TimelockContract,
} from "../src/timelock.js";

function parseFlag(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(name);
  if (i === -1) return undefined;
  return argv[i + 1];
}

async function main(): Promise<void> {
  const [, , cmd, ...rest] = process.argv;
  switch (cmd) {
    case "deploy": {
      const r = await deployCore({ manifestOut: parseFlag(rest, "--out") });
      // Described, not sent: the admin has calls to make. Not a success a script may build on.
      // Pending (#586): proposed under the 24-hour delay; a re-run after it executes them.
      if (r.described.length || r.pending.length) process.exit(2);
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
      const r = await link({
        peerManifest: peer,
        localManifest: parseFlag(rest, "--in"),
      });
      if (r.described.length || r.pending.length) process.exit(2);
      return;
    }
    case "handover": {
      const verify = rest.includes("--verify");
      const to = parseFlag(rest, "--to");
      if (!verify && !to) {
        console.error("handover: --to <address> is required (or --verify)");
        process.exit(2);
      }
      await handover({ to, verify, manifest: parseFlag(rest, "--in") });
      return;
    }
    case "retirements-audit": {
      // Review 50-4: pre-signed retirements the registry no longer accepts must be collected again.
      const file = parseFlag(rest, "--file");
      if (!file) {
        console.error("retirements-audit: --file <vault-export.json> is required");
        process.exit(2);
      }
      const rows = await retirementsAudit({ file, manifest: parseFlag(rest, "--in") });
      if (rows.some((r) => r.status === "stale-format" || r.status === "unchecked")) process.exit(1);
      return;
    }
    case "timelock": {
      // #586: the 24-hour admin delay.
      const [sub] = rest;
      const manifest = parseFlag(rest, "--in");
      if (sub === "status") {
        await timelockStatus({ manifest });
        return;
      }
      if (sub === "activate") {
        // Permanent: the setup window never reopens. Asked for in so many words.
        if (!rest.includes("--confirm")) {
          console.error("timelock activate is permanent: every later admin change waits 24 hours. Re-run with --confirm");
          process.exit(2);
        }
        await timelockActivate({ manifest });
        return;
      }
      const contract = parseFlag(rest, "--contract") as TimelockContract | undefined;
      const fn = parseFlag(rest, "--fn");
      const argsJson = parseFlag(rest, "--args") ?? "[]";
      if (!contract || !fn || !["propose", "execute", "cancel"].includes(sub ?? "")) {
        console.error("timelock: status | activate --confirm | {propose|execute|cancel} --contract <name> --fn <setter> --args '<JSON array>'");
        process.exit(2);
      }
      const args = JSON.parse(argsJson);
      if (!Array.isArray(args)) {
        console.error("timelock: --args must be a JSON array");
        process.exit(2);
      }
      const call = { manifest, contract, fn, args };
      if (sub === "propose") await timelockPropose(call);
      else if (sub === "execute") await timelockExecute(call);
      else await timelockCancel(call);
      return;
    }
    default:
      console.error(
        `Unknown command '${cmd ?? ""}'.\n` +
          "Usage: evm-deploy {deploy|deploy-test-tokens|link|handover|retirements-audit|timelock} [flags]",
      );
      process.exit(2);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
