import * as path from "path";
import { DEFAULT_STELLAR_CHAIN_ID, wasmDir } from "./common.js";
import {
  deployContract,
  getAddress,
} from "./stellar-cli.js";
import {
  manifestPath,
  patchManifest,
  tokenEntry,
  type StellarTokenInput,
} from "./manifest.js";
import type { TokenEntry } from "@proofbridge/deployment-manifest";

/** Token to deploy (or register) during `deploy-test-tokens`. */
export type TestTokenSpec =
  | {
      kind: "test-sep41";
      pairKey: string;
      symbol: string;
      name: string;
      decimals: number;
      initialSupply?: string;
    }
  | {
      /** Register w_native_token (native XLM SAC) as a tradeable token — no deploy; SAC doubles as infra + tradeable XLM. */
      kind: "native-sac";
      pairKey: string;
      symbol: string;
      name: string;
      decimals: number;
    };

/** Default test-token set for local / testnet. */
export const DEFAULT_TEST_TOKENS: readonly TestTokenSpec[] = [
  {
    kind: "native-sac",
    pairKey: "xlm",
    symbol: "XLM",
    name: "Stellar XLM",
    decimals: 7,
  },
  {
    kind: "test-sep41",
    pairKey: "eth",
    symbol: "wETH",
    name: "Wrapped ETH",
    decimals: 7,
  },
  {
    kind: "test-sep41",
    pairKey: "pb",
    symbol: "PB",
    name: "ProofBridge",
    decimals: 7,
  },
] as const;

export interface DeployTestTokensOptions {
  chainId?: bigint;
  manifestOut?: string;
  tokens?: readonly TestTokenSpec[];
  adminStrkey?: string;
}

export async function deployTestTokens(
  opts: DeployTestTokensOptions = {},
): Promise<TokenEntry[]> {
  const chainId = opts.chainId ?? DEFAULT_STELLAR_CHAIN_ID;
  const outPath = opts.manifestOut ?? manifestPath(chainId);
  const tokens = opts.tokens ?? DEFAULT_TEST_TOKENS;
  const adminStrkey = opts.adminStrkey ?? getAddress();

  console.log(`[stellar-deploy] deploying test tokens (chain=${chainId})`);

  // Need the current manifest to resolve the `native-sac` → w_native_token
  // link before we emit the tradeable XLM entry.
  const { readManifest } = await import("./manifest.js");
  const manifest = await readManifest(outPath);
  const nativeSac = manifest.contracts.wNativeToken.address;

  const testTokenWasm = path.join(wasmDir(), "test_token.wasm");
  const entries: StellarTokenInput[] = [];
  for (const spec of tokens) {
    if (spec.kind === "native-sac") {
      console.log(`  [native] ${spec.symbol} → ${nativeSac}`);
      entries.push({
        pairKey: spec.pairKey,
        symbol: spec.symbol,
        name: spec.name,
        contractId: nativeSac,
        kind: "NATIVE",
        decimals: spec.decimals,
        isTestToken: true,
      });
      continue;
    }

    const initialSupply = spec.initialSupply ?? "0";
    console.log(`  [deploy] ${spec.symbol} (test SEP-41)...`);
    const id = deployContract(testTokenWasm, [
      "--owner",
      adminStrkey,
      "--initial_supply",
      initialSupply,
      "--decimals",
      String(spec.decimals),
      "--name",
      spec.name,
      "--symbol",
      spec.symbol,
    ]);
    console.log(`  [deploy] ${spec.symbol}: ${id}`);
    entries.push({
      pairKey: spec.pairKey,
      symbol: spec.symbol,
      name: spec.name,
      contractId: id,
      kind: "SEP41",
      decimals: spec.decimals,
      isTestToken: true,
    });
  }

  const newEntries = entries.map(tokenEntry);
  await patchManifest(outPath, (m) => {
    const byKey = new Map<string, TokenEntry>();
    for (const t of m.tokens) byKey.set(t.pairKey, t);
    for (const t of newEntries) byKey.set(t.pairKey, t);
    return { ...m, tokens: [...byKey.values()] };
  });
  console.log(
    `[stellar-deploy] merged ${newEntries.length} test token(s) into ${outPath}`,
  );
  return newEntries;
}
