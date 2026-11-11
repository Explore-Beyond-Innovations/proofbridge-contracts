# ProofBridge contracts

Smart contracts for the ProofBridge cross-chain settlement protocol. A maker and a bridger trade
directly: each side's funds sit in an escrow on its own chain, and a zero-knowledge proof plus both
parties' BLS co-signature release them. There is no pooled liquidity.

The protocol is built twice, with the same rules on both chains:

| Implementation | Language | Networks today | README |
| --- | --- | --- | --- |
| EVM | Solidity, Foundry | Ethereum Sepolia (chain id `11155111`) | [evm/README.md](./evm/README.md) |
| Stellar | Soroban, Rust | Stellar testnet (ProofBridge chain id `1000002`) | [stellar/README.md](./stellar/README.md) |

Deployed addresses are not listed here. The deploy CLIs write one manifest per chain, at
`evm/deployments/<chainId>.json` and `stellar/deployments/<chainId>.json` (for the networks above,
`evm/deployments/11155111.json` and `stellar/deployments/1000002.json`). The manifests are kept out
of git, so read them from the deploy that produced them.

## How a trade settles

1. The **maker** creates an ad on the `AdManager` of the ad chain and funds it.
2. The **bridger** opens an order on the `OrderPortal` of the order chain and deposits the order
   token (`createOrder`). The deposit appends a leaf to the order chain's MMR.
3. The maker locks the order amount from the ad (`lockForOrder`). The lock appends a leaf to the ad
   chain's MMR.
4. Both parties BLS co-sign one `SettlementAuth` naming both chains' MMR roots. With that
   signature and a ZK proof that the counterparty's leaf is in the counterparty chain's root, each
   side is paid by calling `unlock` on its own chain:
   * `AdManager.unlock` pays the ad token, less the fee, to the bridger's `orderRecipient`;
   * `OrderPortal.unlock` pays the deposit to the maker's `adRecipient`.

If the trade does not finish, the order ends through the termination paths (cancel, refund,
evidence of settlement) or a dispute. Both are described below.

## Contracts

Each chain runs the same set. Soroban crates live under `stellar/contracts/`.

| EVM (`evm/src`) | Soroban crate | What it does |
| --- | --- | --- |
| `AdManager` | `ad-manager` | The maker's leg: ads, locks, the bridger's unlock, the cancel clock, disputes. The termination primary. |
| `OrderPortal` | `order-portal` | The bridger's leg: deposits, the maker's unlock, refunds. Follows the AdManager's outcome by proof. |
| `escrow/EscrowBase` | `proofbridge-core` (`escrow_ops`) | What both escrows share: admin, the order ledger, payouts, the termination core. |
| `MerkleManager` | `merkle-manager` | The chain's Poseidon2 MMR of order leaves. |
| `Verifier` | `verifier` | UltraHonk verifier for the event circuit. |
| `CounterpartyVerifier` | `counterparty-verifier` | The root verifier: checks the parties' aggregate BLS signature over the `SettlementAuth`. |
| `BLSKeyRegistry` | `bls-key-registry` | Maps a 32-byte account id to its BLS key slots. |
| `RootAnchor` | `root-anchor` | Notarizes the other chain's MMR roots for the evidence paths. |
| `DisputeManager` | `dispute-manager` | Filing, bonds, the arbiter's ruling and the fallback. |
| `Registrar` | `registrar` | Appends `REGISTERED` leaves so a keyless account can register a key by proof. |
| `wNativeToken` | the native XLM SAC | Wraps the native token so the escrows handle it as a token. |
| `agent/*` | `agent-account` | The maker's custody account and the scoped agent policy. |
| — | `test-token` | A SEP-41 token for tests and localnet. |

Shared Solidity libraries in `evm/src/libraries/` include `ProofBridgeUtils` (the one deployed
library both escrows link: order hashing, lock rules, fees, timelock rules), `AdminTimelock`,
`Timelock`, `TwoStepAdmin`, `RouteTiming`, `Dispute` and `OrderHash`.

```text
             Ad chain                                  Order chain
  ┌──────────────────────────┐              ┌──────────────────────────┐
  │ AdManager                │   co-signed  │              OrderPortal │
  │  ├─ MerkleManager ───────┼─── roots ────┼─────── MerkleManager ─┤  │
  │  ├─ Verifier             │              │             Verifier ─┤  │
  │  ├─ CounterpartyVerifier │              │ CounterpartyVerifier ─┤  │
  │  │    └─ BLSKeyRegistry  │              │  BLSKeyRegistry ─┘    │  │
  │  ├─ RootAnchor ◄─────────┼── anchored ──┼──────────► RootAnchor ┘  │
  │  └─ DisputeManager       │    roots     │                          │
  └──────────────────────────┘              └──────────────────────────┘
```

Each escrow names its peer on the other chain (`setPeerEscrow`, or `set_chain` on Stellar), so it
only accepts orders and proofs that name that peer.

### AdManager

Ads and the maker's controls:

| Function | Notes |
| --- | --- |
| `createAd(string adId, address adToken, uint256 initialAmount, uint256 orderChainId, bytes32 adRecipient, bytes32 settlementSigner)` | Payable. Needs a token route to `orderChainId` and a settlement signer registered in the key registry. |
| `fundAd(string adId, uint256 amount)` | Payable. Adds liquidity. |
| `withdrawFromAd(string adId, uint256 amount, address to)` | Unlocked balance only. |
| `closeAd(string adId, address to)` | Refused while any amount is locked. |
| `setSettlementSigner(string adId, bytes32 identity)` | Re-points the ad's co-signing account. Open orders keep the signer in their own hash. |
| `haltSettlement()` / `resumeSettlement()` | The maker's halt: while set, the co-signed `unlock` of every order on the maker's ads is refused. Evidence paths still pay. |

Order lifecycle:

| Function | Notes |
| --- | --- |
| `lockForOrder(OrderParams params, uint32 signerSlot) returns (bytes32 orderHash)` | Locks the amount, pins the settlement signer's key slot (which must be usable now) and appends the leaf. |
| `unlock(OrderParams params, bytes32 nullifierHash, bytes32 targetRoot, bytes proof, bytes cosigData)` | Pays the bridger. Accepted until `deadline + buffer − margin`. |
| `repinOrder(OrderParams params)` | Moves an open order's pinned slot, with the signer's consent recorded in the key registry. |
| `recordSettled(OrderParams params)` | Appends the SETTLED leaf after a fill. Once per order; anyone may call it. |

Termination and disputes:

| Function | Notes |
| --- | --- |
| `claimCancel(OrderParams params)` | After the deadline, opens the window `[deadline, deadline + buffer)`. |
| `finalizeCancel(OrderParams params)` | At the window's end, releases the lock and appends the CANCEL leaf. |
| `cancelNeverLocked(OrderParams params, bytes32 targetRoot, bytes32 nullifierHash, bytes proof)` | After the deadline, cancels an order that was never locked, by proving its deposit leaf under an anchored root. |
| `presentSettled(OrderParams params, bytes32 targetRoot, bytes proof)` | Pays the bridger on proof of the order chain's SETTLED leaf. |
| `dispute(OrderParams params, bytes32 evidence)` | Payable (the bond). Only the maker or the bridger's recipient may file. |
| `respondToDispute(OrderParams params, bytes32 evidence)` | The other party's answer. |
| `finalizeDispute(OrderParams params)` | Applies the outcome once the dispute window is over. |

Admin, on the AdManager only: `setKeyRegistry`, `setProtocolFeePool`,
`setFeeBps(uint16 lpBps, uint16 protocolBps)` and `setDisputeManager`. Views include
`availableLiquidity`, `cancelFinalizesAt` and `disputeFinalizesAt`.

### OrderPortal

| Function | Notes |
| --- | --- |
| `createOrder(OrderParams params) returns (bytes32 orderHash)` | Payable. The caller must be `params.bridger`. Pulls the deposit and appends the leaf. |
| `unlock(OrderParams params, bytes32 nullifierHash, bytes32 targetRoot, bytes proof, bytes cosigData)` | Pays the maker. Accepted until `deadline − claimStagger`. |
| `refundByCancel(OrderParams params, bytes32 targetRoot, bytes proof)` | Refunds the bridger on proof of the ad chain's CANCEL leaf. |
| `payMakerByForfeit(OrderParams params, bytes32 targetRoot, bytes proof)` | Pays the maker on proof of the ad chain's FORFEIT leaf (a `BridgerForfeit` ruling). |
| `presentSettled(OrderParams params, bytes32 targetRoot, bytes proof)` | Pays the maker on proof of the ad chain's SETTLED leaf. |
| `recordSettled(OrderParams params)` | Appends the SETTLED leaf after a fill. |

The OrderPortal runs no clock after the deadline. It ends an order only on proof of one of the
AdManager's leaves, so it never decides differently from the AdManager.

### Shared by both escrows

From `EscrowBase`:

* Admin: `pause()` / `unpause()`, `setPeerEscrow(uint256 chainId, bytes32 peer)`,
  `setRootVerifier(uint256 chainId, address verifier)`,
  `setTokenRoute(address localToken, uint256 peerChainId, bytes32 peerToken)`,
  `removeTokenRoute(address localToken, uint256 peerChainId)`,
  `setRouteTiming(uint256 chainId, RouteTiming.Timing timing)` and `setRootAnchor(IRootAnchor anchor)`.
* Payouts: a payout that fails is credited instead. The recipient takes it with
  `claim(address recipient, address token)` or `claimTo(address token, address to)`.
* A pause stops entries only (`createAd`, `fundAd`, `lockForOrder`, `createOrder`). Every exit stays open.

Storage names:

| Name | Where | Holds |
| --- | --- | --- |
| `peerEscrow[chainId]` | both | The peer escrow's 32-byte id. Zero means the chain is not supported. |
| `tokenRoute[localToken][peerChainId]` | both | The peer chain's token id. |
| `orders(orderHash)` | both | `(status, timingVersion, registryEpoch, pinnedSlot)` |
| `nullifierUsed[nullifierHash]` | both | Consumed nullifiers. |
| `inFlightOf[account]` | both | Open legs per account. The key registry reads it before a revoke. |
| `claimable[recipient][token]` | both | Credited payouts. |
| `timingVersion[chainId]`, `routeTimingAt[chainId][version]` | both | Versioned route timing. |
| `claims[orderHash]`, `settledRecorded[orderHash]` | both | The open cancel window, and whether SETTLED was appended. |
| `ads[adId]` | AdManager | The `Ad` struct. |
| `feeConfig` | AdManager | `(pool, lpBps, protocolBps)` |
| `halted[maker]`, `lastResumedAt[maker]` | AdManager | The maker's settlement halt. |
| `keyRegistry`, `registryEpoch`, `registryAt[epoch]` | AdManager | The key registry, and the one each order was locked under. |
| `disputeManager`, `disputeModuleOf[orderHash]` | AdManager | The dispute module, and the one each dispute was filed under. |

Order status runs `None → Open → (Claimed | Disputed) → Filled | Cancelled | Resolved`.
`Filled`, `Cancelled` and `Resolved` are terminal.

### MerkleManager

A Poseidon2 Merkle Mountain Range of order leaves. A leaf is `poseidon2(orderHash mod p, side)`,
where `side` is the leaf domain (below).

* `appendOrderHash(bytes32 orderHash, uint256 side)`: managers only.
* `getRoot()`, `getRootAtIndex(uint256 leafIndex)`, `getWidth()`, `getSize()`.
* `setEscrowAppender(address escrow, bool enabled)`: adds or removes an escrow as an appender.
  Both directions go through the timelock, because an escrow's exits append leaves.
* `setManager(address account, bool enabled)`: non-escrow appenders (the Registrar). Removing one is
  instant. Adding one goes through the timelock.

The EVM and Soroban trees produce the same roots for the same leaves.

### Verifier

UltraHonk over BN254, with keccak Fiat-Shamir. On EVM the verification key is compiled into
`Verifier.sol` (generated by `scripts/gen-verifier.sh`), so a circuit change means regenerating the
contract. The Soroban verifier takes its key as data at deploy.

### Root verifier and key registry

`CounterpartyVerifier` is the root verifier each escrow wires per peer chain (`setRootVerifier`).
It reads keys from `BLSKeyRegistry`. Registry limits (`evm/src/BLSKeyRegistry.sol`,
`stellar/contracts/bls-key-registry/src/lib.rs`):

| Constant | Value |
| --- | --- |
| `MAX_ACTIVE_SLOTS` | 5 live key slots per account |
| `GRACE_PERIOD` | 30 days |
| `MAX_REGISTER_TTL` | 7 days (a registration deadline further out is refused) |

Registry changes are authenticated by the owner's wallet signature plus a BLS proof of possession,
not by the caller, so anyone can relay them.

### RootAnchor

The evidence paths (`presentSettled`, `refundByCancel`, `payMakerByForfeit`, `cancelNeverLocked`)
have no co-signature. They prove a leaf against a root the `RootAnchor` notarized. A signer set
(`setSigners`) approves `(sourceChainId, root, ledgerSeq)` through `anchor` until `threshold`
approvals are in, and the root becomes usable `anchorDelay[sourceChainId]` later (`isAnchored`).
The admin can `revokeAnchor`. `MAX_ANCHOR_DELAY` is 7 days (`evm/src/RootAnchor.sol`).

## Order struct and EIP-712

The domain is `EIP712Domain(string name, string version)` with `name = "Proofbridge"` and
`version = "1"`. Chain ids and contract addresses are fields of the order instead of the domain.

The order has nineteen fields, hashed in this order (`OrderHash.ORDER_TYPEHASH`, the Soroban
`eip712` module):

```text
Order {
    orderChainToken     // token deposited on the order chain
    adChainToken        // token paid out on the ad chain
    amount              // amount, in the order chain's decimals
    bridger             // the bridger's account
    orderChainId        // order chain id
    orderPortal         // the OrderPortal on the order chain
    orderRecipient      // who the ad chain pays (the bridger's recipient)
    adChainId           // ad chain id
    adManager           // the AdManager on the ad chain
    adId                // the ad (string)
    adCreator           // the maker's custody account on the ad chain
    adRecipient         // who the order chain pays (the maker's recipient)
    salt                // caller-controlled nonce
    orderDecimals       // the order-chain token's decimals
    adDecimals          // the ad-chain token's decimals
    deadline            // unix seconds; the termination clocks run from it
    adSettlementSigner  // the account whose BLS key co-signs for the maker
    lpFeeBps            // the maker's fee, bps (uint16), kept in the ad
    protocolFeeBps      // the protocol's fee, bps (uint16), paid to the fee pool
}
```

Each escrow takes the fields it cannot know from its caller as `OrderParams` and fills in its own
chain id and address, so both legs hash the same order. The per-chain `OrderParams` structs are in
the EVM and Stellar READMEs.

Address-like fields are 32 bytes on both chains. An EVM address is left-padded with zeros; a
Stellar address is its full 32-byte key (`C...` contracts, `G...` accounts).

**Recipient rule.** `orderRecipient` must not be zero and must not equal `adCreator` or
`adSettlementSigner`. Both `createOrder` and `lockForOrder` refuse it (`RecipientIsMaker`), so a
deposit that no lock would accept cannot land.

## Fees

The bridge fee is taken from the bridger's payout on the ad chain. `lpFeeBps` stays in the maker's
ad and `protocolFeeBps` goes to the fee pool.

* Each share is capped at `MAX_FEE_BPS = 100` (1%) (`evm/src/libraries/ProofBridgeUtils.sol`,
  `stellar/lib/proofbridge-core/src/fees.rs`). A protocol fee above zero needs a pool.
* The fee is in the order hash, so it is fixed at the deposit. `lockForOrder` refuses an order whose
  fees differ from the AdManager's live `feeConfig`.
* The launch split is 30 bps to the maker and 20 bps to the protocol. It is the deploy CLIs'
  default for local deploys (`LP_FEE_BPS` and `PROTOCOL_FEE_BPS` in `evm/deploy/src/deploy-core.ts`
  and `stellar/deploy/src/deploy-core.ts`). Other environments must set it explicitly.
* A `MakerForfeit` dispute outcome charges only the protocol share.

## Admin timelock

Every contract with admin setters has one two-step admin (`transferAdmin`, then `acceptAdmin`) and a
24-hour delay on its setters (`evm/src/libraries/Timelock.sol`,
`stellar/lib/proofbridge-core/src/timelock.rs`):

* Before `activateTimelock()`, the admin calls setters directly, so a fresh chain can be configured.
  Activation is one-way. The first `proposeAction` also activates it.
* After activation, the admin proposes the exact calldata (`proposeAction(bytes)`). Once
  `TIMELOCK_DELAY` (24 hours) has passed, anyone may send it, for up to 14 days (`GRACE`). The admin
  can `cancelAction` before then.
* `pause`, `unpause` and the admin handover stay instant. A handover voids the old admin's proposals.
* Brakes stay instant: unwiring a root verifier, removing a non-escrow appender, revoking an anchor.
  A brake voids any pending proposal that would undo it.

## Route timing

Each escrow keeps a `RouteTiming.Timing` per peer chain (`setRouteTiming`). Every write is a new
version, and each order keeps the version it opened under. Unset timing fails closed.

```solidity
struct Timing {
    uint64 minWindow;
    uint64 buffer;
    uint64 margin;
    uint64 claimStagger;
}
```

Bounds are in `evm/src/libraries/RouteTiming.sol` and `stellar/lib/proofbridge-core/src/timing.rs`:

| Field | Meaning | Bound |
| --- | --- | --- |
| `buffer` | The AdManager's window after the deadline | 30 minutes to 1 day |
| `margin` | How long before the window's end the AdManager stops the co-signed unlock | at most `buffer / 2` |
| `minWindow` | The shortest `deadline − now` a lock or deposit accepts | at least `margin`, at most 3.5 days (`MAX_ORDER_WINDOW / 2`) |
| `claimStagger` | How long before the deadline the OrderPortal stops the co-signed unlock | `0` (off) or less than `minWindow` |

A deadline more than `MAX_ORDER_WINDOW` (7 days) away is refused.

## Termination

The AdManager is the only leg with a clock, and a clock only opens a window. Evidence inside the
window always wins over the cancel after it.

* After the deadline anyone may `claimCancel`. The bridger can still `unlock` until
  `deadline + buffer − margin`, and `presentSettled` works until the cancel is finalized.
* At the window's end `finalizeCancel` releases the lock and appends CANCEL. The bridger then calls
  `refundByCancel` on the OrderPortal.
* If the co-signed payout was denied during the order (the maker halted, or the pinned key was
  killed), `finalizeCancel` waits a further grace of the route's anchor delay plus `buffer`, so
  evidence of a settlement on the other chain can still arrive.

## Disputes

`DisputeManager` holds the filing, the bond and the ruling. The escrows apply the outcome. Only the
AdManager takes filings; the OrderPortal learns the result from the AdManager's CANCEL or FORFEIT leaf.

* Only the order's two parties may file, while the order is `Open` or `Claimed` and before its
  window ends.
* Outcomes are `MutualRefund`, `TradeProceeds`, `BridgerForfeit` and `MakerForfeit`. The arbiter
  (`resolveDispute`) can never rule `TradeProceeds`; only evidence reaches it. With no ruling, the
  outcome is `MutualRefund`.
* A ruling opens a window and does not pay. Evidence of settlement inside it closes the dispute.
* The bond goes back to the filer on `MutualRefund`, or when the accused party forfeits. Otherwise
  it goes to the protocol fee pool (or to the filer if no pool is set).

Limits (`evm/src/libraries/Dispute.sol`, `stellar/lib/proofbridge-core/src/dispute.rs`):

| Setting | Bound |
| --- | --- |
| `challengePeriod` (per route) | 1 hour to 7 days |
| `bondFloor` (per route, in wrapped native) | above zero |
| `BondConfig.bondBps` (per token and route) | at most 500 (5%) |

A route with a `BondConfig` bonds `max(minBond, amount × bondBps / 10,000)` in the order's own
token. Otherwise the bond is the flat `bondFloor`.

## Zero-knowledge proofs

One Noir circuit, `events`, proves that a leaf `poseidon2(orderHash % p, leafDomain)` is in an MMR
root. The circuit lives in
[Explore-Beyond-Innovations/proofbridge-circuits](https://github.com/Explore-Beyond-Innovations/proofbridge-circuits).
This repo pins the commit it builds against in [`CIRCUITS_COMMIT`](./CIRCUITS_COMMIT).

Leaf domains (`evm/src/libraries/LeafDomain.sol`):

| Domain | Name | Appended by |
| --- | --- | --- |
| 0 | ORDER | `AdManager.lockForOrder` (unlocked on the order chain) |
| 1 | AD | `OrderPortal.createOrder` (unlocked on the ad chain) |
| 2 | CANCEL | `finalizeCancel`, `cancelNeverLocked`, `finalizeDispute` |
| 3 | SETTLED | `recordSettled` |
| 4 | REGISTERED | `Registrar` |
| 5 | FORFEIT | `finalizeDispute` on a `BridgerForfeit` |

Domains 0 and 1 are deposit proofs and also prove half of the trade secret. Domains 2 and up are
event claims and carry no secret.

**Nullifiers.** The trade secret's 32 bytes split into `a` (high 16 bytes) and `b` (low 16 bytes):

* the ad leg (`AdManager.unlock`, leaf domain 1, pays the bridger): `poseidon2(a, orderHash % p)`;
* the order leg (`OrderPortal.unlock`, leaf domain 0, pays the maker): `poseidon2(orderHash % p, b)`.

Both values are part of the co-signed `SettlementAuth`, so an unlock can only consume the nullifier
the two parties signed for its leg.

### Verifier public inputs

Four 32-byte public inputs, always written by the contract, never taken from calldata:

| | `OrderPortal.unlock` | `AdManager.unlock` | event claims |
| --- | --- | --- | --- |
| 0 | the order leg's nullifier | the ad leg's nullifier | `0` |
| 1 | `orderHash % p` | `orderHash % p` | the leaf's subject `% p` |
| 2 | the co-signed ad-chain root | the co-signed order-chain root | an anchored root |
| 3 | `0` (ORDER leaf) | `1` (AD leaf) | the event domain |

`AdManager.cancelNeverLocked` also proves domain 1, under an order-chain root the RootAnchor
notarized, so only a real order can be marked never locked. It consumes no nullifier.

### The co-signed root

The destination chain cannot read the source chain, so the root an unlock proves against is
authenticated by both parties. They BLS-sign one `SettlementAuth` (`evm/src/CounterpartyVerifier.sol`):

```solidity
struct SettlementAuth {
    uint256 orderChainId;
    uint256 adChainId;
    bytes32 orderHash;
    bytes32 orderChainRoot;
    bytes32 adChainRoot;
    bytes32 makerKeyCommitment;
    bytes32 adLegNullifier;
    bytes32 orderLegNullifier;
}
```

At unlock the escrow builds the envelope itself:
`(settlementSigner, bridger, orderHash, pinnedSlot, nullifierHash, side, cosigData)`. The verifier
(`METADATA_VERSION = 4`) accepts only if:

* the auth names this order;
* `side` picks the leg: side 1 (AdManager) needs the order chain, its root and `adLegNullifier`;
  side 0 (OrderPortal) needs the ad chain, its root and `orderLegNullifier`;
* on the ad leg, the maker's slot is the one the lock pinned (the order leg sends an unpinned sentinel);
* both keys sit in live registry slots of the settlement signer and the bridger, the maker key is
  the one the auth names, and the aggregate signature verifies.

## Security model

* **Order binding.** The EIP-712 order hash includes both chain ids and both escrow addresses, and
  each escrow only accepts orders that name its wired peer.
* **One payout per leg.** Each unlock consumes the nullifier both parties signed for it, once.
* **MMR integrity.** Only the escrows (and the Registrar, once enabled) may append.
* **Clocks open windows, evidence decides.** Every terminal step needs evidence or an elapsed
  window, and a pause never blocks an exit.
* **Admin changes are delayed.** Setters that add trust wait 24 hours. Brakes are instant.
* **Disputes are bonded.** A filer posts a bond and loses it if the outcome goes against them.
