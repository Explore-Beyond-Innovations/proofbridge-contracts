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

/** The id local stacks and every e2e use. The encodings spec gives testnet `1000002`. */
export const LOCAL_STELLAR_CHAIN_ID = 1000001n;
export const TESTNET_STELLAR_CHAIN_ID = 1000002n;

/**
 * A-7: the synthetic id is tied to the environment — it is signed into every registration and
 * order, so testnet with the local id (or mainnet with either) would mint signatures for the
 * wrong network's rules while looking healthy.
 */
export function assertStellarChainIdForEnv(id: bigint, deployEnv: DeployEnv): void {
  if (deployEnv === "local" && id !== LOCAL_STELLAR_CHAIN_ID) {
    throw new Error(`DEPLOY_ENV=local uses STELLAR_CHAIN_ID ${LOCAL_STELLAR_CHAIN_ID}, got ${id}`);
  }
  if (deployEnv === "testnet" && id !== TESTNET_STELLAR_CHAIN_ID) {
    throw new Error(`DEPLOY_ENV=testnet uses STELLAR_CHAIN_ID ${TESTNET_STELLAR_CHAIN_ID} (encodings spec §4), got ${id}`);
  }
  if (deployEnv === "mainnet" && (id === LOCAL_STELLAR_CHAIN_ID || id === TESTNET_STELLAR_CHAIN_ID)) {
    throw new Error(`DEPLOY_ENV=mainnet cannot use the local or testnet STELLAR_CHAIN_ID (${id})`);
  }
}

/**
 * The synthetic Stellar chain id, bound into BLS registration and the order hash: a deployment
 * initialised with one id rejects every signature made under another, and only at verification.
 * The option, else `STELLAR_CHAIN_ID`; the local id only for `DEPLOY_ENV=local`.
 */
export function requireStellarChainId(
  opt: bigint | undefined,
  deployEnv: DeployEnv,
  env: NodeJS.ProcessEnv = process.env,
): bigint {
  const id = (() => {
    if (opt !== undefined) return opt;
    const v = env.STELLAR_CHAIN_ID;
    if (v && v.length > 0) {
      if (!/^\d+$/.test(v)) throw new Error(`STELLAR_CHAIN_ID=${v} is not a decimal id`);
      return BigInt(v);
    }
    if (deployEnv === "local") return LOCAL_STELLAR_CHAIN_ID;
    return undefined;
  })();
  if (id !== undefined) {
    assertStellarChainIdForEnv(id, deployEnv);
    return id;
  }
  throw new Error(
    `STELLAR_CHAIN_ID is unset for DEPLOY_ENV=${deployEnv}. Set it explicitly (testnet is 1000002, per the encodings spec §4); the id is signed into every registration and order.`,
  );
}

/** For commands that only locate an existing manifest (link, handover, test tokens). */
export function stellarChainIdOrLocal(opt: bigint | undefined, env: NodeJS.ProcessEnv = process.env): bigint {
  if (opt !== undefined) return opt;
  const v = env.STELLAR_CHAIN_ID;
  return v && /^\d+$/.test(v) ? BigInt(v) : LOCAL_STELLAR_CHAIN_ID;
}
