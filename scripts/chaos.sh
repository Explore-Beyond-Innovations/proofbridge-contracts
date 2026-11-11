#!/usr/bin/env bash
set -euo pipefail

# The chaos pack (CHAOS.md): every scenario C1–C8 on both chains, one forge run and one cargo run.
#
# Usage: scripts/chaos.sh [evm|stellar|all]    (default all)
#   CHAOS_SKIP_JOINT=1  leave out JointOutcomesTest (C7/C8 across both legs): it proves real event
#                       claims over ffi, so it needs node deps and the built event circuit
#                       (scripts/build_circuits.sh proof_circuits/events), as CI has by then.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# New tests are test_chaos_c<N>_*; the rest already covered a scenario and stay where they are.
EVM_CONTRACTS=(
  ChaosAgentTest              # C1 C3 C4 C5 C6 C8 (new)
  AgentPolicyRealEscrowTest   # C2
  AgentPolicyEnforcementTest  # C2
  CustodyAccountTest          # C2 C3
  SlotPinTest                 # C4
  DisputeTest                 # C6 C8
  AdManagerCancellationTest   # C7
)
EVM_TESTS=(
  'test_chaos_c[0-9]+_.*'
  # C2: over the cap is refused before the escrow, nothing debited
  test_c26_overTheCapIsRefusedBeforeTheRealAdManager
  test_overThePerOrderCapIsRefused
  test_theBucketDrainsAndThenRefuses
  test_theAccountCeilingBindsWhenTheAgentStillHasRoom
  test_everyRefusalIsPreflightsAndLeavesTheBucketsAlone
  # C3: next lock refused, tombstone sticky
  test_aRevokedAgentIsRefused
  test_revokingKillsTheAgentAndTheTombstoneIsSticky
  # C4: the order settles on its pinned slot, or moves with the signer's consent
  test_unlock_vouchesForThePinnedSlot
  test_repin_movesThePin_andTheUnlockVouchesForTheNewOne
  test_repin_needsTheSignersConsentFromTheCurrentPin
  test_noRepin_twoLiveSlots_ordinaryTiming
  # C6: one dispute per order, at the escrow and at the module
  test_oneDisputePerOrder
  test_c19_moduleEdgeRefusesStrangersAndDoubles
  # C7: the cancel and the unlock never share a second
  test_T45a_fastUnlockRace_bridgerUnlocksInsideTheWindow
  test_noSharedLastSecond_unlockBeforeTheEnd_cancelAtIt
  # C8: evidence closes a dispute, over any ruling
  test_b2_evidenceClosesTheDisputeAndReleasesTheBond
  test_s2_evidenceOverridesTheRulingForTheBondToo
)
if [ "${CHAOS_SKIP_JOINT:-0}" != "1" ]; then
  EVM_CONTRACTS+=(JointOutcomesTest) # C7 fast-unlock-race*, C8 settle-then-dispute-* (one sweep)
  EVM_TESTS+=(test_jointOutcomeSweep)
fi

join() {
  local IFS='|'
  echo "$*"
}

run_evm() {
  echo "=============================================================="
  echo " Chaos pack, EVM (Foundry): C1–C8"
  echo "=============================================================="
  cd "$ROOT/evm"
  local log
  log="$(mktemp)"
  forge test -vv \
    --match-contract "^($(join "${EVM_CONTRACTS[@]}"))\$" \
    --match-test "^($(join "${EVM_TESTS[@]}"))(\(\))?\$" | tee "$log"
  # forge exits 0 on zero matches: a renamed test or contract must fail here, not vanish.
  local suites
  suites="$(grep -cE 'Suite result: ok\. [1-9][0-9]* passed' "$log" || true)"
  rm -f "$log"
  if [ "$suites" -ne "${#EVM_CONTRACTS[@]}" ]; then
    echo "::error::chaos pack (EVM): $suites suites passed tests, want ${#EVM_CONTRACTS[@]}"
    exit 1
  fi
}

run_stellar() {
  echo "=============================================================="
  echo " Chaos pack, Stellar (Soroban): C1–C8"
  echo "=============================================================="
  # ---- STELLAR HALF: TODO (another builder fills this in) ----
  # Run the `chaos` test module from stellar/ with one cargo invocation, e.g.
  #   (cd "$ROOT/stellar" && cargo test chaos)
  echo "Stellar half not built yet: skipped"
}

case "${1:-all}" in
  evm) run_evm ;;
  stellar) run_stellar ;;
  all)
    run_evm
    run_stellar
    ;;
  *)
    echo "usage: $0 [evm|stellar|all]" >&2
    exit 2
    ;;
esac
