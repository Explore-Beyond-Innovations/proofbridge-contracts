export { deployCore } from "./deploy-core.js";
export type {
  DeployStellarCoreOptions,
  DeployStellarCoreResult,
} from "./deploy-core.js";

export {
  deployTestTokens,
  DEFAULT_TEST_TOKENS,
  type TestTokenSpec,
} from "./deploy-test-tokens.js";
export type { DeployTestTokensOptions } from "./deploy-test-tokens.js";

export { link } from "./link.js";
export type { StellarLinkOptions, StellarLinkResult } from "./link.js";

export { manifestPath, readManifest, writeManifest } from "./manifest.js";
export { DEFAULT_STELLAR_CHAIN_ID } from "./common.js";

// Re-export CLI wrappers + address helpers so flow tests and other
// consumers don't need to duplicate the `stellar` shell-out plumbing.
export {
  stellar,
  deployContract,
  invokeContract,
  getAddress,
  getSecret,
  deploySAC,
  strkeyToHex,
  decodeEd25519Secret,
} from "./stellar-cli.js";
