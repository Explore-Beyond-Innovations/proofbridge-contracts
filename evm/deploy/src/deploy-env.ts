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
/** Chain ids a `testnet` deploy may connect to; `TESTNET_EVM_CHAIN_IDS` extends the list. */
export const TESTNET_EVM_CHAIN_IDS = [
  11155111n, // Sepolia
  84532n, // Base Sepolia
  421614n, // Arbitrum Sepolia
  11155420n, // OP Sepolia
  17000n, // Holesky
  80002n, // Polygon Amoy
] as const;
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
 * A-4: the stated environment and the connected network must agree. Every env is an allowlist: an
 * id nobody listed (an unknown mainnet, say) is refused everywhere rather than guessed to be a
 * testnet, and an id listed for two envs is refused as ambiguous.
 */
export function assertChainIdForEnv(chainId: bigint, deployEnv: DeployEnv, env: NodeJS.ProcessEnv = process.env): void {
  const lists: Record<DeployEnv, { name: string; ids: bigint[] }> = {
    local: { name: "LOCAL_EVM_CHAIN_IDS", ids: idList("LOCAL_EVM_CHAIN_IDS", LOCAL_EVM_CHAIN_IDS, env) },
    testnet: { name: "TESTNET_EVM_CHAIN_IDS", ids: idList("TESTNET_EVM_CHAIN_IDS", TESTNET_EVM_CHAIN_IDS, env) },
    mainnet: { name: "MAINNET_EVM_CHAIN_IDS", ids: idList("MAINNET_EVM_CHAIN_IDS", MAINNET_EVM_CHAIN_IDS, env) },
  };
  const envsOf = DEPLOY_ENVS.filter((e) => lists[e].ids.includes(chainId));
  if (envsOf.length > 1) {
    throw new Error(`chain ${chainId} is listed for ${envsOf.join(" and ")}; an id belongs to one environment`);
  }
  if (envsOf.length === 0) {
    throw new Error(
      `DEPLOY_ENV=${deployEnv} but the RPC is chain ${chainId}, which no environment lists. ` +
        `Add it to ${lists[deployEnv].name} if it is a ${deployEnv} chain (known ${deployEnv} ids: ${lists[deployEnv].ids.join(", ")}).`,
    );
  }
  if (envsOf[0] !== deployEnv) {
    const hint = deployEnv === "local" ? " A local deploy on a real network would use the local defaults." : "";
    throw new Error(`DEPLOY_ENV=${deployEnv} but the RPC is chain ${chainId}, which is a ${envsOf[0]} chain.${hint}`);
  }
}
