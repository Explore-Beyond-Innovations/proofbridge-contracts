// The deploy environment is stated, never assumed. An unset DEPLOY_ENV used to mean `local`, which
// silently gave a real network the local defaults: the admin as arbiter and anchor notary, a zero
// anchor delay, the shortest route clocks.

export const DEPLOY_ENVS = ["local", "testnet", "mainnet"] as const;
export type DeployEnv = (typeof DEPLOY_ENVS)[number];

/** The option, else `DEPLOY_ENV`; refuses unset or unknown values. */
export function requireDeployEnv(opt?: string, env: NodeJS.ProcessEnv = process.env): DeployEnv {
  const v = opt ?? env.DEPLOY_ENV;
  if (!v) {
    throw new Error(
      "DEPLOY_ENV is unset. Set it to local, testnet or mainnet in the chain's env file (an unset value no longer means local).",
    );
  }
  if (!(DEPLOY_ENVS as readonly string[]).includes(v)) {
    throw new Error(`DEPLOY_ENV=${v} is not one of ${DEPLOY_ENVS.join(", ")}`);
  }
  return v as DeployEnv;
}

/** A role that may default to the deployer on a local stack only; everywhere else it is named. */
export function namedOutsideLocal(
  name: string,
  deployEnv: DeployEnv,
  localFallback: string,
  env: NodeJS.ProcessEnv = process.env,
): string {
  const v = env[name];
  if (v && v.length > 0) return v;
  if (deployEnv === "local") return localFallback;
  throw new Error(`${name} is unset for DEPLOY_ENV=${deployEnv}; set it (it defaults to the deployer on local only)`);
}

/** Chain ids a `local` deploy may connect to (Anvil, Hardhat); `LOCAL_EVM_CHAIN_IDS` extends the list. */
export const LOCAL_EVM_CHAIN_IDS = [31337n, 1337n] as const;
/** Chain ids a `mainnet` deploy may connect to; `MAINNET_EVM_CHAIN_IDS` extends the list. */
export const MAINNET_EVM_CHAIN_IDS = [1n, 10n, 56n, 137n, 8453n, 42161n, 43114n] as const;

function idList(name: string, defaults: readonly bigint[], env: NodeJS.ProcessEnv): bigint[] {
  const extra = (env[name] ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      if (!/^\d+$/.test(s)) throw new Error(`${name} must be comma-separated decimal chain ids, got "${s}"`);
      return BigInt(s);
    });
  return [...defaults, ...extra];
}

/**
 * A-4: the stated environment and the connected network must agree. `DEPLOY_ENV=local` against
 * Sepolia would bring back every local default (the deployer as notary and arbiter, a zero anchor
 * delay, the shortest clocks) on a real network; `testnet` against a mainnet id would deploy test
 * clocks where money is real.
 */
export function assertChainIdForEnv(chainId: bigint, deployEnv: DeployEnv, env: NodeJS.ProcessEnv = process.env): void {
  const local = idList("LOCAL_EVM_CHAIN_IDS", LOCAL_EVM_CHAIN_IDS, env);
  const mainnet = idList("MAINNET_EVM_CHAIN_IDS", MAINNET_EVM_CHAIN_IDS, env);
  const isLocal = local.includes(chainId);
  const isMainnet = mainnet.includes(chainId);
  if (deployEnv === "local" && !isLocal) {
    throw new Error(
      `DEPLOY_ENV=local but the RPC is chain ${chainId}, not a local chain (${local.join(", ")}). ` +
        `A local deploy on a real network would use the local defaults. Set DEPLOY_ENV to the network's environment (or LOCAL_EVM_CHAIN_IDS for a private devnet).`,
    );
  }
  if (deployEnv === "mainnet" && !isMainnet) {
    throw new Error(
      `DEPLOY_ENV=mainnet but the RPC is chain ${chainId}, not a known mainnet (${mainnet.join(", ")}); set MAINNET_EVM_CHAIN_IDS if it is one.`,
    );
  }
  if (deployEnv === "testnet" && (isLocal || isMainnet)) {
    throw new Error(
      `DEPLOY_ENV=testnet but the RPC is chain ${chainId}, which is a ${isLocal ? "local" : "mainnet"} chain.`,
    );
  }
}

