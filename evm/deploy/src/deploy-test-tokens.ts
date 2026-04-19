import {
  EVM_NATIVE_TOKEN_ADDRESS,
  connect,
  requireEnv,
} from "./common.js";
import { contractFactory } from "./artifacts.js";
import {
  manifestPath,
  patchManifest,
  type EvmTokenInput,
  tokenEntry,
} from "./manifest.js";
import type { TokenEntry } from "@proofbridge/deployment-manifest";

/** Test-token spec: `mock-erc20` deploys a fresh MockERC20; `native-sentinel` registers the 0xEE.. address. */
export type TestTokenSpec =
  | {
      kind: "mock-erc20";
      pairKey: string;
      symbol: string;
      name: string;
      decimals: number;
      initialSupply?: string; // decimal string of base units; default "0"
    }
  | {
      kind: "native-sentinel";
      pairKey: string;
      symbol: string;
      name: string;
      decimals: number;
    };

/** Default test tokens for local / testnet. */
export const DEFAULT_TEST_TOKENS: readonly TestTokenSpec[] = [
  {
    kind: "mock-erc20",
    pairKey: "xlm",
    symbol: "WXLM",
    name: "Wrapped XLM",
    decimals: 18,
  },
  {
    kind: "native-sentinel",
    pairKey: "eth",
    symbol: "ETH",
    name: "Ether",
    decimals: 18,
  },
  {
    kind: "mock-erc20",
    pairKey: "pb",
    symbol: "PB",
    name: "ProofBridge",
    decimals: 18,
  },
] as const;

export interface DeployTestTokensOptions {
  rpcUrl?: string;
  privateKey?: string;
  /** Absolute path to the manifest this run should update. Defaults to <chainId>.json. */
  manifestOut?: string;
  tokens?: readonly TestTokenSpec[];
}

export async function deployTestTokens(
  opts: DeployTestTokensOptions = {},
): Promise<TokenEntry[]> {
  const rpcUrl = opts.rpcUrl ?? requireEnv("EVM_RPC_URL");
  const privateKey = opts.privateKey ?? requireEnv("EVM_ADMIN_PRIVATE_KEY");
  const tokens = opts.tokens ?? DEFAULT_TEST_TOKENS;

  const { signer, nonces, chainId } = await connect(rpcUrl, privateKey);
  const outPath = opts.manifestOut ?? manifestPath(chainId);

  console.log(`[evm-deploy] deploying test tokens (chain=${chainId})`);

  const entries: EvmTokenInput[] = [];
  for (const spec of tokens) {
    if (spec.kind === "native-sentinel") {
      console.log(`  [native] ${spec.symbol} → ${EVM_NATIVE_TOKEN_ADDRESS}`);
      entries.push({
        pairKey: spec.pairKey,
        symbol: spec.symbol,
        name: spec.name,
        address: EVM_NATIVE_TOKEN_ADDRESS,
        kind: "NATIVE",
        decimals: spec.decimals,
        isTestToken: true,
      });
      continue;
    }

    const initialSupply = BigInt(spec.initialSupply ?? "0");
    const factory = contractFactory("MockERC20", "MockERC20", signer);
    console.log(`  [deploy] ${spec.symbol} (MockERC20)...`);
    const c = await factory.deploy(
      spec.name,
      spec.symbol,
      initialSupply,
      spec.decimals,
      { nonce: nonces.next() },
    );
    await c.deploymentTransaction()?.wait();
    const addr = await c.getAddress();
    console.log(`  [deploy] ${spec.symbol}: ${addr}`);
    entries.push({
      pairKey: spec.pairKey,
      symbol: spec.symbol,
      name: spec.name,
      address: addr,
      kind: "ERC20",
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
    `[evm-deploy] merged ${newEntries.length} test token(s) into ${outPath}`,
  );
  return newEntries;
}
