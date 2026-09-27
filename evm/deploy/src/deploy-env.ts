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
