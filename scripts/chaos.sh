#!/usr/bin/env bash
set -euo pipefail

# The chaos pack (CHAOS.md): every scenario C1–C8 on both chains, one forge run and one cargo run per Soroban test target.
#
# Usage: scripts/chaos.sh [evm|stellar|all]    (default all)
#   CHAOS_SKIP_JOINT=1  leave out JointOutcomesTest (C7/C8 across both legs): it proves real event
#                       claims over ffi, so it needs node deps and the built event circuit
#                       (scripts/build_circuits.sh proof_circuits/events), as CI has by then.
#   The Stellar half needs the contract WASMs built (stellar contract build) and the integration
#   fixtures generated (stellar/tests/fixtures: npx tsx generate_fixtures.ts), as CI has by then.

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

# Soroban, one list per cargo test target. New tests are test_chaos_c<N>_*.
STELLAR_AGENT_ACCOUNT=(
  'test::chaos::test_chaos_c' # C1 C3 C4 C5 C6 C8 (new)
  # C2: over the cap is refused at __check_auth, before the escrow, and nothing is spent
  test::cap_exceeded_rejected_in_ad_units
  test::e2e_agent_lock_via_require_auth_address_v2_credentials
  test::e2e_agent_lock_via_require_auth_legacy_v1_credentials
  test::a_scoped_agent_is_held_to_its_ads_and_its_allowance_survives_a_refusal
  test::t07_two_agents_share_one_account_ceiling
  # C3: next lock refused, tombstone sticky
  test::revoke_stops_new_locks_but_not_settlement_of_co_signed_orders
)
STELLAR_DISPUTE_MANAGER=(
  test::one_dispute_per_order # C6: the module holds one record per order
)
STELLAR_INTEGRATION=(
  # C4: the order settles on its pinned slot, or moves with the signer's consent
  test_slot_pin_the_ad_unlock_accepts_only_the_pinned_slot
  test_slot_pin_repin_moves_the_pin_with_consent_from_the_current_pin
  test_slot_pin_no_repin_two_live_slots_ordinary_timing
  test_t14_locked_order_still_settles_under_old_signer_after_repoint
  # C6: a record the module already holds refuses the escrow's filing
  test_49s3_a_record_the_module_already_holds_is_dispute_exists
  # C7: the cancel and the unlock never share a second
  test_t45a_fast_unlock_race_bridger_unlocks_inside_the_window
  test_no_shared_last_second_unlock_before_the_end_cancel_at_it
  # C8: a settled leg is not disputable; evidence closes a dispute, over any ruling
  test_c19_dispute_on_a_settled_or_absent_order_is_not_disputable
  test_2_3g_evidence_closes_the_dispute_and_releases_the_bond
  test_t24_differential_scenarios # evidence-overrides-ruling
  test_t25_joint_outcome_sweep    # C7 fast-unlock-race*, C8 settle-then-dispute-*
)

# One cargo run per test target; cargo exits 0 on zero matches, so the passed count must be exact.
cargo_exact() {
  local want="$1"
  shift
  local log
  log="$(mktemp)"
  cargo test "$@" | tee "$log"
  if ! grep -qE "test result: ok\. $want passed; 0 failed" "$log"; then
    echo "::error::chaos pack (Stellar): cargo test $* wanted exactly $want passed, got: $(grep -E 'test result' "$log" || echo 'no test ran')"
    rm -f "$log"
    exit 1
  fi
  rm -f "$log"
}

run_stellar() {
  echo "=============================================================="
  echo " Chaos pack, Stellar (Soroban): C1–C8"
  echo "=============================================================="
  cd "$ROOT/stellar"
  local chaos
  chaos="$(grep -cE '^fn test_chaos_c[0-9]+_' contracts/agent-account/src/test/chaos.rs)"
  cargo_exact "$((chaos + ${#STELLAR_AGENT_ACCOUNT[@]} - 1))" \
    -p agent-account --lib -- "${STELLAR_AGENT_ACCOUNT[@]}"
  cargo_exact "${#STELLAR_DISPUTE_MANAGER[@]}" \
    -p dispute-manager --lib -- "${STELLAR_DISPUTE_MANAGER[@]}"
  cargo_exact "${#STELLAR_INTEGRATION[@]}" \
    --test integration_test -- --exact "${STELLAR_INTEGRATION[@]}"
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
