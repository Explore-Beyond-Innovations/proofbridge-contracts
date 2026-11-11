# Chaos test pack

This file lists the failure scenarios the ProofBridge contracts are tested against. Each scenario has tests on both
chains: Solidity (Foundry) in `evm/` and Soroban (Rust) in `stellar/`.

In plain terms: these tests deliberately break things, such as a stolen agent key, an agent that has been revoked,
a cancel racing an unlock, or a trade disputed after it already settled. Each one checks that nobody's money goes
anywhere it shouldn't. Every test written for this pack was also checked the other way round: the guard it relies on
was removed from the contract, and the test had to fail before it counted.

## Run it

From the repo root:

```bash
scripts/chaos.sh all        # both chains
scripts/chaos.sh evm        # Foundry only
scripts/chaos.sh stellar    # Soroban only
```

Both CI workflows run the pack as a named step on every pull request: **Chaos pack (EVM)** and **Chaos pack
(Stellar)**.

You need the same setup the full suites need:

- **EVM:** the event circuit, built with `scripts/build_circuits.sh proof_circuits/events` and with `../proof_circuits`
  next to this repo, plus `pnpm install`. The cross-leg sweep calls the prover through ffi.
  `CHAOS_SKIP_JOINT=1` skips that one test.
- **Stellar:** the contract WASMs (`stellar contract build --optimize`) and the generated fixtures
  (`npx tsx generate_fixtures.ts`). The script header has the exact commands.

## The scenarios

New tests are named `test_chaos_c<N>_…` and live in [`evm/test/chaos/ChaosAgent.t.sol`](evm/test/chaos/ChaosAgent.t.sol)
and [`stellar/contracts/agent-account/src/test/chaos.rs`](stellar/contracts/agent-account/src/test/chaos.rs). Each one
runs the real escrow, agent account, policy and dispute contracts together. Older tests that already covered a
scenario stay where they are, and are listed by name below.

### Agent compromise

**C1: the agent's key is stolen while a trade it locked is still open.**
The thief can only do what the policy allows: lock within the caps, for the allowed ads and tokens. It can't
withdraw, close the ad, swap the signer, move tokens, change the policy or call any owner-only function, and it
can't redirect the open trade's payout. After the owner revokes the agent, its next lock is refused and the open
trade still pays the right person.
- EVM: `test_chaos_c1_stolenKeyCannotDefundTheAdOrTouchThePolicy`, `test_chaos_c1_stolenKeyStaysInsideTheCaps`,
  `test_chaos_c1_afterTheRevokeTheOpenTradeStillSettlesToItsParties`
- Soroban: `test_chaos_c1_stolen_key_cannot_defund_the_ad_or_touch_the_policy`,
  `test_chaos_c1_stolen_key_stays_inside_the_caps`, `test_chaos_c1_after_the_revoke_the_open_trade_still_settles_to_its_parties`

**C2: the agent tries to lock more than its cap.**
The lock is refused before it reaches the escrow, and nothing is counted against the cap.
- EVM: `AgentPolicyRealEscrow.t.sol::test_c26_overTheCapIsRefusedBeforeTheRealAdManager`;
  `AgentPolicyEnforcement.t.sol::{test_overThePerOrderCapIsRefused, test_theBucketDrainsAndThenRefuses,
  test_theAccountCeilingBindsWhenTheAgentStillHasRoom}`; `CustodyAccount.t.sol::test_everyRefusalIsPreflightsAndLeavesTheBucketsAlone`
- Soroban (agent-account): `cap_exceeded_rejected_in_ad_units`, `e2e_agent_lock_via_require_auth_address_v2_credentials`,
  `e2e_agent_lock_via_require_auth_legacy_v1_credentials`, `a_scoped_agent_is_held_to_its_ads_and_its_allowance_survives_a_refusal`,
  `t07_two_agents_share_one_account_ceiling`

**C3: the agent is revoked while a trade it locked is still open.**
The revoke takes effect at once for new locks, and it is permanent. The open trade is untouched: it settles on the
co-signed unlock, or the bridger is refunded after the deadline.
- EVM: `test_chaos_c3_revokedMidTrade_theOpenOrderSettles`, `test_chaos_c3_revokedMidTrade_theBridgerIsRefundedAfterTheDeadline`,
  `test_chaos_c3_theRevokeIsPermanent`; also `CustodyAccount.t.sol::test_aRevokedAgentIsRefused` and
  `AgentPolicyEnforcement.t.sol::test_revokingKillsTheAgentAndTheTombstoneIsSticky`
- Soroban: `test_chaos_c3_revoked_mid_trade_the_open_order_settles`,
  `test_chaos_c3_revoked_mid_trade_the_bridger_is_refunded_after_the_deadline`, `test_chaos_c3_the_revoke_is_permanent`;
  also `revoke_stops_new_locks_but_not_settlement_of_co_signed_orders`

**C4: a settlement key is rotated while orders are in flight.**
Adding a key never disturbs an open order. The order stays pinned to the key it was locked with and settles on it,
or the signer consents to re-pin it to the new key. No ad is closed.
- EVM: `test_chaos_c4_aKeyAddedMidTradeLeavesTheOrderOnItsPin`; also `SlotPin.t.sol::{test_unlock_vouchesForThePinnedSlot,
  test_repin_movesThePin_andTheUnlockVouchesForTheNewOne, test_repin_needsTheSignersConsentFromTheCurrentPin,
  test_noRepin_twoLiveSlots_ordinaryTiming}`
- Soroban: `test_chaos_c4_a_key_added_mid_trade_leaves_the_order_on_its_pin`; also, in `stellar/tests/integration_test.rs`,
  `test_slot_pin_the_ad_unlock_accepts_only_the_pinned_slot`, `test_slot_pin_repin_moves_the_pin_with_consent_from_the_current_pin`,
  `test_slot_pin_no_repin_two_live_slots_ordinary_timing` and `test_t14_locked_order_still_settles_under_old_signer_after_repoint`

### Dispute edge cases

**C5: a dispute is filed against a lock the agent made.**
The dispute runs exactly as it would for a lock made by hand. Each outcome pays out from the ad the account owns,
the bond goes where the outcome says, and the agent can't answer, rule, or profit from the dispute. The arbiter can
never rule TradeProceeds: only a settlement proof reaches it.
- EVM: `test_chaos_c5_mutualRefund…`, `test_chaos_c5_bridgerForfeit…`, `test_chaos_c5_makerForfeit…`,
  `test_chaos_c5_tradeProceedsByEvidence…`, `test_chaos_c5_theAgentCannotAnswerRuleOrProfitFromTheDispute`
- Soroban: `test_chaos_c5_mutual_refund_…`, `test_chaos_c5_bridger_forfeit_…`, `test_chaos_c5_maker_forfeit_…`,
  `test_chaos_c5_trade_proceeds_by_evidence_…`, `test_chaos_c5_the_agent_cannot_answer_rule_or_profit_from_the_dispute`

**C6: two disputes are filed on one trade.**
The second filing is refused, and the contract holds one bond, paid out once.
- EVM: `test_chaos_c6_aSecondFilingIsRefused_oneBondHeldOnce`; also `Dispute.t.sol::{test_oneDisputePerOrder,
  test_c19_moduleEdgeRefusesStrangersAndDoubles}`
- Soroban: `test_chaos_c6_a_second_filing_is_refused_one_bond_held_once`; also dispute-manager `one_dispute_per_order` and
  integration `test_49s3_a_record_the_module_already_holds_is_dispute_exists`

**C7: a cancel races an unlock at the deadline.**
Exactly one of them wins, and funds are never paid twice. There is one known boundary, which is stated in the design
rather than a bug. The order leg can settle just before the deadline. If nobody then presents that settlement proof on
the ad chain for the whole cancel window, the ad leg cancels anyway: it ends Cancelled while the order leg ends
Filled. The proof is public, and the bridger and the relayer's janitor both hold it. Presenting it at any point in
the window settles the trade instead. The joint-outcome fixture records this case as `fast-unlock-race-silent`.
- EVM: `Cancellation.t.sol::{test_T45a_fastUnlockRace_bridgerUnlocksInsideTheWindow, test_noSharedLastSecond_unlockBeforeTheEnd_cancelAtIt}`;
  `JointOutcomes.t.sol::test_jointOutcomeSweep` (`fast-unlock-race`, `fast-unlock-race-silent`)
- Soroban (integration): `test_t45a_fast_unlock_race_bridger_unlocks_inside_the_window`,
  `test_no_shared_last_second_unlock_before_the_end_cancel_at_it`, `test_t25_joint_outcome_sweep` (same two scenarios)

**C8: a trade that already settled is then disputed.**
A settled trade can't be disputed or ruled on. A dispute filed before settlement is closed by presenting the
settlement proof, and that proof overrides any ruling.
- EVM: `test_chaos_c8_aSettledTradeCannotBeDisputedOrRuled`; also `Dispute.t.sol::{test_b2_evidenceClosesTheDisputeAndReleasesTheBond,
  test_s2_evidenceOverridesTheRulingForTheBondToo}` and `JointOutcomes.t.sol::test_jointOutcomeSweep`
  (`settle-then-dispute-leafproof`, `settle-then-dispute-cosign-unlock`)
- Soroban: `test_chaos_c8_a_settled_trade_cannot_be_disputed_or_ruled`; also integration
  `test_c19_dispute_on_a_settled_or_absent_order_is_not_disputable`, `test_2_3g_evidence_closes_the_dispute_and_releases_the_bond`,
  `test_t24_differential_scenarios` and `test_t25_joint_outcome_sweep` (the settle-then-dispute scenarios)

## Run one scenario

```bash
# EVM, from evm/
forge test --match-contract ChaosAgentTest --match-test test_chaos_c1_    # or c3_, c4_, c5_, c6_, c8_
forge test --match-contract '^JointOutcomesTest$' --match-test test_jointOutcomeSweep

# Soroban, from stellar/
cargo test -p agent-account --lib test_chaos_c1_                          # or c3_, c4_, c5_, c6_, c8_
cargo test --test integration_test -- --exact test_t25_joint_outcome_sweep
```

`scripts/chaos.sh` has the full lists of older tests for each scenario, and it fails if any run passes fewer tests
than expected.

## Limits

- **Signatures and proofs are stubbed in the new tests.** The chaos tests replace the root and proof checks with
  test doubles, so they test the escrow, policy and dispute logic and not the cryptography. The real BLS co-signature
  and ZK proof path is covered by the joint-outcome sweep, which builds real proofs, and by the cross-chain
  end-to-end runs in the monorepo.
- **Some owner-only functions exist only on EVM.** The custody account's `execute`, ownership transfer and module
  hooks have no Soroban counterpart. On Soroban, C1 checks the same property instead: every owner-only function
  requires the owner's authorization.
