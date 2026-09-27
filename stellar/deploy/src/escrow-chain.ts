// #466: the one-registry steps' view of a live chain, through the Stellar CLI. Reads and writes
// only: every decision lives in `one-registry.ts`, where the specs drive it with a fake chain.
import type { Acting } from "./stellar-cli.js";
import type { EscrowChain } from "./one-registry.js";

export function stellarEscrowChain(
  acting: Acting,
  readView: (contractId: string, fn: string, args?: string[]) => unknown,
): EscrowChain {
  return {
    rootVerifier: (escrow, peer) =>
      (readView(escrow, "root_verifier", ["--chain_id", peer]) as string | null) ?? null,
    wiredChains: (escrow) => (readView(escrow, "wired_chains") as (string | number)[]).map(String),
    registryOf: (verifier) => readView(verifier, "registry") as string,
    keyRegistry: (adManager) => String(readView(adManager, "key_registry")),
    setRootVerifier: (escrow, name, peer, verifier) =>
      acting.call(escrow, name, "set_root_verifier", ["--chain_id", peer, "--module", verifier],
        `${name}.set_root_verifier(${peer}, ${verifier})`),
    setKeyRegistry: (adManager, registry) =>
      acting.call(adManager, "AdManager", "set_key_registry", ["--registry", registry],
        `AdManager.set_key_registry(${registry})`),
  };
}
