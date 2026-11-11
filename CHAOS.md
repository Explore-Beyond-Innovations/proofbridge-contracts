# Chaos test pack

This file lists the failure scenarios the ProofBridge contracts are tested against. Each scenario has a test on
both chains: Solidity (Foundry) in `evm/` and Soroban (Rust) in `stellar/`.

In plain terms: these tests deliberately break things, such as a stolen agent key, an agent that has been
revoked, a cancel racing an unlock, or a trade disputed after it already settled. Each one checks that nobody's
money goes anywhere it shouldn't.

> **Status: plan.** This file is the plan for the pack. Scenarios marked *to build* do not have tests yet. Each row
> gets its test names and a reproduction command as it lands, and this banner is removed when all eight are green.

## The scenarios

### Agent compromise

| # | Scenario | What must hold | Status |
| --- | --- | --- | --- |
| C1 | The agent's key is stolen while a trade it locked is still open | The thief can only do what the policy allows: lock within the caps, for the allowed tokens. It can't withdraw, change the policy, or move the open trade's payout. The owner revokes the agent; its next lock is refused; the open trade still settles (or cancels) to the right parties. | to build |
| C2 | The agent tries to lock more than its cap | The lock is refused before it reaches the escrow, and nothing is counted against the cap. | existing tests, to index |
| C3 | The agent is revoked while a trade it locked is still open | The revoke is permanent and immediate for new locks. The open trade is untouched: it settles on the co-signed unlock, or the bridger is refunded after the deadline. | to build (today only "next lock refused" is tested) |
| C4 | A settlement key is rotated while orders are in flight | Adding a key never disturbs an open order: the order stays pinned to the key it was locked with and settles on it, or is re-pinned to the new key with the signer's consent. No ad is closed. | existing tests, to index |

### Dispute edge cases

| # | Scenario | What must hold | Status |
| --- | --- | --- | --- |
| C5 | A dispute is filed against a lock the agent made | The dispute runs exactly as for a hand-made lock: every outcome pays out from the account-owned ad correctly, the bond goes where the outcome says, and the agent can't answer, rule or move funds in the dispute. | to build (today the lock in the test is the owner's) |
| C6 | Two disputes are filed on one trade | The second filing is refused; one bond is held, once. | existing tests, to index |
| C7 | A cancel races an unlock at the deadline | Exactly one of them wins. Funds are never paid twice, and both legs end in matching states. | existing tests, to index |
| C8 | A trade that already settled is then disputed | Presenting the settlement proof closes the dispute; no ruling can undo a settled trade. | existing tests, to index |

## How it runs

- New tests live in `evm/test/chaos/` and in a `chaos` test module on the Soroban side, with names starting
  `test_chaos_c<N>_`. Existing tests that already cover a scenario stay where they are and are listed here by name.
- `scripts/chaos.sh` runs the whole pack on both chains. Both CI workflows run it as a named step, so the
  pack shows as its own green check on every pull request.
- Every new test is checked to fail: the guard it relies on is removed and the test must go red before it counts.

## Running it yourself

To be filled in with the exact commands as the tests land.
