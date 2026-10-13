#!/usr/bin/env -S tsx
// Stellar per-chain deploy CLI.
//
// Usage:
//   stellar-deploy deploy             [--out <manifest-path>] [--chain-id <n>] [--allow-wasm-mismatch]
//     --allow-wasm-mismatch: reuse a key registry / counterparty verifier whose recorded wasm hash is
//     missing or differs, for this one run (outside local this flag is the only override).
//   stellar-deploy deploy-test-tokens [--out <manifest-path>] [--chain-id <n>]
//   stellar-deploy link --peer <peer-manifest> [--in <local-manifest>]
//   stellar-deploy handover --to <G...> | --verify   [--in <manifest-path>] [--chain-id <n>]
//   stellar-deploy retirements-audit --file <vault-export.json> [--in <manifest-path>] [--chain-id <n>]
//   stellar-deploy timelock status|activate --confirm [--in <manifest-path>] [--chain-id <n>]
//   stellar-deploy timelock propose|execute|cancel --contract <AdManager|OrderPortal|MerkleManager|DisputeManager>
//                  --fn <setter> --args '<JSON object of the setter's arguments by name>' [--in] [--chain-id]
//
// Reads the `stellar` CLI environment:
//   STELLAR_NETWORK (required; `local` by default for DEPLOY_ENV=local only), STELLAR_SOURCE_ACCOUNT (default: admin)
// Optional: STELLAR_WASM_DIR, STELLAR_EVENT_VK, STELLAR_DEPLOYMENTS_DIR,
//           DEPLOY_ENV, GIT_COMMIT, CHAIN_NAME.

import { deployCore } from "../src/deploy-core.js";
import { deployTestTokens } from "../src/deploy-test-tokens.js";
import { link } from "../src/link.js";
import { handover } from "../src/handover.js";
import { formatAudit, retirementsAudit } from "../src/keys-env.js";
import { manifestPath, readManifest } from "../src/manifest.js";
import { requireDeployEnv, requireStellarChainId } from "../src/deploy-env.js";
import { WASM_MISMATCH_FLAG } from "../src/wasm-reuse.js";
import { timelockActivate, timelockCancel, timelockExecute, timelockPropose, timelockStatus, TIMELOCK_CONTRACTS } from "../src/timelock.js";

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
        // Passed: the override for this run. Absent: undefined, so deployCore reads the env (local only).
        ...(rest.includes(WASM_MISMATCH_FLAG) ? { allowWasmMismatch: true } : {}),
      });
      // Described, not sent: the admin has calls to make. Not a success a script may build on.
      // Pending (#586): proposed under the 24-hour delay; a re-run after it executes them.
      if (r.described.length || r.pending.length) process.exit(2);
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
      });
      if (r.described.length || r.pending.length) process.exit(2);
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
    case "retirements-audit": {
      // 50-4: pre-signed retirements the registry would refuse (an older message format) are listed.
      const file = parseFlag(rest, "--file");
      if (!file) {
        console.error("retirements-audit: --file <vault-export.json> is required");
        process.exit(2);
      }
      const inPath = parseFlag(rest, "--in") ?? manifestPath(requireStellarChainId(parseChainId(rest), requireDeployEnv()));
      const registry = (await readManifest(inPath)).contracts.blsKeyRegistry?.address;
      if (!registry) {
        console.error(`retirements-audit: ${inPath} names no BLSKeyRegistry`);
        process.exit(2);
      }
      const rows = retirementsAudit(registry, file);
      console.log(formatAudit(rows));
      if (rows.some((r) => r.status === "stale-format" || r.status === "error")) process.exit(1);
      return;
    }
    case "timelock": {
      // #586: the 24-hour admin delay.
      const [sub] = rest;
      const manifest = parseFlag(rest, "--in") ?? manifestPath(requireStellarChainId(parseChainId(rest), requireDeployEnv()));
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
      const contract = parseFlag(rest, "--contract");
      const fn = parseFlag(rest, "--fn");
      if (!contract || !(contract in TIMELOCK_CONTRACTS) || !fn || !["propose", "execute", "cancel"].includes(sub ?? "")) {
        console.error("timelock: status | activate --confirm | {propose|execute|cancel} --contract <name> --fn <setter> --args '<JSON object>'");
        process.exit(2);
      }
      const named = JSON.parse(parseFlag(rest, "--args") ?? "{}");
      const call = { manifest, contract: contract as keyof typeof TIMELOCK_CONTRACTS, fn, named };
      if (sub === "propose") await timelockPropose(call);
      else if (sub === "execute") await timelockExecute(call);
      else await timelockCancel(call);
      return;
    }
    default:
      console.error(
        `Unknown command '${cmd ?? ""}'.\n` +
          "Usage: stellar-deploy {deploy|deploy-test-tokens|link|handover|retirements-audit|timelock} [flags]",
      );
      process.exit(2);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
