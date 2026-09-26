/**
 * #464: the escrow's key registry (the lock gate and the denied rule) and a co-signature verifier's
 * registry (the co-signed unlock) must be one contract; otherwise a kill in the verifier's registry
 * never reaches the denied rule. The escrow refuses to run on a split; the CLI refuses to create one.
 */
export function assertOneRegistry(escrowRegistry: string, verifierRegistry: string, where: string): void {
  if (escrowRegistry.toLowerCase() !== verifierRegistry.toLowerCase()) {
    throw new Error(
      `${where}: registry split — the escrow's key registry is ${escrowRegistry} but the CounterpartyVerifier ` +
        `checks co-signatures against ${verifierRegistry}; redeploy the verifier on the escrow's registry`,
    );
  }
}
