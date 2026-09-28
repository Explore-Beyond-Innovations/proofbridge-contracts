// C-10: a dispute on the primary (the ad chain's AdManager) must end, and its FORFEIT leaf be
// anchored, before the follower (the order chain's OrderPortal) can refund the bridger by its long
// backstop. Otherwise a BridgerForfeit ruling pays nothing. The worst case, from the order deadline:
// filing closes at +buffer, the challenge period runs, finalize waits another buffer, and the
// follower's anchor delay plus one publisher round must pass.

/** One publisher round: how long a new root may wait before it is anchored at all. */
export const PUBLISHER_MARGIN_S = 3600n;

export interface RouteSide {
  /** This chain's clocks for the route to the other chain. */
  timing?: { buffer: string; longBackstop: string };
  /** This chain's dispute params for the route (present where a DisputeManager is wired). */
  dispute?: { challengePeriod: string };
  /** This chain's anchor delay for the other chain's roots. */
  anchorDelay?: string;
}

/** The shortest follower backstop that outlasts the primary's worst-case dispute. */
export function requiredBackstop(challengePeriod: bigint, primaryBuffer: bigint, followerAnchorDelay: bigint): bigint {
  return challengePeriod + 2n * primaryBuffer + followerAnchorDelay + PUBLISHER_MARGIN_S;
}

/**
 * Checks both directions across one route: `local` as follower of `peer`'s primary, and `local` as
 * primary for `peer`'s follower. A direction whose data is not recorded yet is skipped; the other
 * chain's link checks it. Returns the directions checked.
 */
export function assertDisputeFitsBackstop(local: RouteSide, peer: RouteSide, where: string): string[] {
  const checked: string[] = [];
  const check = (label: string, primary: RouteSide, follower: RouteSide) => {
    if (!primary.dispute || !primary.timing || !follower.timing) return;
    const need = requiredBackstop(
      BigInt(primary.dispute.challengePeriod),
      BigInt(primary.timing.buffer),
      BigInt(follower.anchorDelay ?? "0"),
    );
    const have = BigInt(follower.timing.longBackstop);
    if (have < need) {
      throw new Error(
        `${where}: ${label}: the follower's long backstop is ${have}s, but a dispute on the primary can run ` +
          `${need}s past the deadline (challenge period + 2 x buffer + anchor delay + ${PUBLISHER_MARGIN_S}s publisher margin). ` +
          `The follower would refund the bridger before a forfeit ruling reached it. Raise ROUTE_LONG_BACKSTOP_S or shorten DISPUTE_CHALLENGE_PERIOD_S.`,
      );
    }
    checked.push(label);
  };
  check("this chain as follower", peer, local);
  check("this chain as primary", local, peer);
  return checked;
}
