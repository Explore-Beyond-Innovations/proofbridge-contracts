# ProofBridge Contracts

Smart contracts implementing the ProofBridge cross-chain settlement protocol. Two implementations sharing identical protocol logic across different blockchain ecosystems.

* **[EVM](./evm/README.md)** — Solidity/Foundry (Ethereum Sepolia, Hedera Testnet)
* **[Stellar](./stellar/README.md)** — Soroban/Rust (Stellar)

## Architecture

### System Overview

```text
                    CHAIN 1 (Ad Chain)                   CHAIN 2 (Order Chain)
    ┌──────────────────────────────┐      ┌──────────────────────────────┐
    │                              │      │                              │
    │  ┌────────────────────┐      │      │      ┌────────────────────┐  │
    │  │   AdManager        │◄─────┼──────┼──────┤   OrderPortal      │  │
    │  └────────────────────┘      │      │      └────────────────────┘  │
    │          │                   │      │                   │          │
    │          │ Manager           │      │          Manager  │          │
    │          ▼                   │      │                   ▼          │
    │  ┌────────────────────┐      │      │      ┌────────────────────┐  │
    │  │  MerkleManager     │      │      │      │  MerkleManager     │  │
    │  └────────────────────┘      │      │      └────────────────────┘  │
    │          ▲                   │      │                   ▲          │
    │          │ Manager           │      │          Manager  │          │
    │          │                   │      │                   │          │
    │  ┌────────────────────┐      │      │      ┌────────────────────┐  │
    │  │   OrderPortal      │──────┼──────┼─────►│   AdManager        │  │
    │  └────────────────────┘      │      │      └────────────────────┘  │
    │          │                   │      │                   │          │
    │  ┌────────────────────┐      │      │      ┌────────────────────┐  │
    │  │   Verifier         │      │      │      │   Verifier         │  │
    │  └────────────────────┘      │      │      └────────────────────┘  │
    │                              │      │                              │
    └──────────────────────────────┘      └──────────────────────────────┘
```

### Flow

1. **Maker** creates an **Ad** on AdManager, funding it with the destination-chain token.
2. **Bridger** opens an **order** on **OrderPortal**, depositing the source-chain token.
3. The system relays the **order hash** to the maker off-chain; the maker locks an amount from the Ad against that order.
4. After the maker fulfills the user on the opposite chain, a **zk proof** is generated and submitted to unlock:
   * On **OrderPortal**: release order-token to the **maker destination recipient** recorded in the order.
   * On **AdManager**: release **ad token** from contract to the **bridger's designated recipient**.

### Security

Replay is prevented via:

* **EIP-712 struct hash** that binds chain ids and contract addresses.
* A **nullifier** recorded once per successful proof.
* **Bidirectional chain linking** ensures contracts only accept proofs from configured counterparts.
* **Manager permissions** on MerkleManager restrict who can append order hashes.

NATIVE TOKENS are denoted by the all-`0xEE` sentinel address on EVM.

## Contracts

### AdManager

The destination chain contract where liquidity providers (makers) manage their advertisements and fulfill cross-chain orders.

**Core Functions:**

* **createAd**: Creates a new liquidity advertisement with specified parameters
* **fundAd**: Deposits tokens into an existing ad to increase available liquidity
* **withdrawFromAd**: Withdraws unused tokens from an ad
* **closeAd**: Permanently closes an ad and withdraws all remaining funds
* **lockForOrder**: Reserves liquidity for a specific EIP-712 order hash, pins the settlement signer's co-signing slot (`signerSlot`, which must be usable), appends to MMR
* **unlock**: Verifies ZK proof, consumes nullifier, transfers ad token to the **orderRecipient**
* **setPeerEscrow** / **setTokenRoute**: Admin configuration for cross-chain routing (`setPeerEscrow(chainId, peer)`, zero removes; `setTokenRoute(localToken, peerChainId, peerToken)`)

**Key Storage:**

* `chains[orderChainId] → { orderPortal }`: Source chain configuration (an entry means supported)
* `tokenRoute[adToken][orderChainId] → orderToken`: Cross-chain token mapping
* `ads[adId] → { creator, token, balance, locked, open, … }`: Ad state management
* `orders[orderHash] → Status`: Order execution tracking
* `nullifiers[hash] → bool`: Proof replay prevention

### OrderPortal

The source chain contract where users initiate cross-chain transfers by creating orders.

**Core Functions:**

* **createOrder**: Initiates a cross-chain order by depositing source chain tokens, appends to MMR
* **unlock**: Verifies ZK proof and releases funds to the designated recipient
* **setPeerEscrow** / **setTokenRoute**: Admin configuration (the same signatures as AdManager)

**Key Storage:**

* `chains[dstChainId] → { adManager }`: Destination chain configuration (an entry means supported)
* `tokenRoute[token1][dstChainId] → token2`: Cross-chain token routing
* `orders[orderHash] → Status`: Order lifecycle management
* `nullifiers[hash] → bool`: Prevents proof reuse

### MerkleManager

Poseidon2-based Merkle Mountain Range (MMR) for order hash storage and inclusion proofs.

**Core Functions:**

* **appendOrderHash**: Adds new order hashes to the MMR (manager-only)
* **getRootHash**: Returns the current MMR root for proof verification
* **verifyProof**: Validates inclusion proofs against the MMR

**Technical Features:**

* **Poseidon2 Hashing**: Same hash function as the Noir ZK circuit
* **Field Modular Reduction**: Applies BN254 field mod to order hashes for circuit compatibility
* **Root History**: Maintains roots for proof validation
* **Cross-Chain Compatible**: EVM and Stellar implementations produce identical roots

### Verifier

UltraHonk zero-knowledge proof verifier.

* **Proving System**: UltraHonk (keccak-based Fiat-Shamir for on-chain verification)
* **Elliptic Curve**: BN254
* **Verification Key**: Stored on-chain at construction

## Data Structures & EIP-712

### Minimal domain (both contracts)

* **Domain**: `EIP712Domain(string name, string version)`

  * `name = "Proofbridge"`
  * `version = "1"`

> **Note:** We do **not** include `chainId` or `verifyingContract` in the domain. Instead, those values are explicit fields in the Order struct.

### Order struct

Seventeen fields, hashed in this order (`OrderHash.ORDER_TYPEHASH`, the Soroban `eip712` module):

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
}
```

Each escrow passes the fields it holds and fills in its own chain id and address (the AdManager's
`OrderParams` names the portal `srcOrderPortal`; the two chain/contract pairs come from the
contract), so both legs hash the same order.

**Address encoding differs by implementation:**

* **EVM**: `address` (20 bytes, zero-padded to 32 for hashing)
* **Stellar**: `BytesN<32>` (full 32 bytes — `C...` for contracts, `G...` for ed25519 accounts)

Both produce identical EIP-712 hashes when given the same 32-byte values.

## Zero-Knowledge Proof System

One Noir circuit (`proof_circuits/events`) proves that a leaf `poseidon2(orderHash % p, leafDomain)`
is in an MMR root. Domains 0 and 1 are deposits and also prove half of the trade secret; domains 2
and up are event leaves (CANCEL, SETTLED, REGISTERED, FORFEIT) and carry no secret.

**Nullifiers.** The trade secret's 32 bytes split into `a` (high 16 bytes) and `b` (low 16 bytes):

* the ad leg (`AdManager.unlock`, leaf domain 1, pays the bridger): `poseidon2(a, orderHash % p)`;
* the order leg (`OrderPortal.unlock`, leaf domain 0, pays the maker): `poseidon2(orderHash % p, b)`.

Both values are part of the co-signed `SettlementAuth` (below), so an unlock can only consume the
nullifier the two parties signed for its leg. `legNullifiers` in the `proofbridge-mmr` package is the
off-chain rule, pinned to the circuit's proven public inputs.

**Proof circuits**: See [proof_circuits/](../proof_circuits/)

### Verifier Public Inputs

Four 32-byte public inputs, always written by the contract, never taken from calldata as a vector:

| | `OrderPortal.unlock` | `AdManager.unlock` | event claims |
| --- | --- | --- | --- |
| 0 | the order leg's nullifier | the ad leg's nullifier | `0` |
| 1 | `orderHash % p` | `orderHash % p` | the leaf's subject `% p` |
| 2 | the co-signed ad-chain root | the co-signed order-chain root | an anchored root |
| 3 | `0` (ORDER leaf) | `1` (AD leaf) | the event domain |

`AdManager.cancelNeverLocked` also proves domain 1: the order's AD leaf under an order-chain root the
RootAnchor notarized, so only a real order can be marked never locked. It consumes no nullifier.

### The co-signed root gate

The destination chain cannot read the source chain, so the root an unlock proves against is
authenticated by both parties: they BLS-sign one `SettlementAuth`
(`orderChainId, adChainId, orderHash, orderChainRoot, adChainRoot, makerKeyCommitment,
adLegNullifier, orderLegNullifier`, a 288-byte preimage under `ProofBridge.Settlement.v1`). At unlock
the escrow hands its route's root verifier (`CounterpartyVerifier`, metadata version 4) an envelope
it builds itself: `(settlementSigner, bridger, orderHash, pinnedSlot, nullifierHash, side, cosigData)`.
The verifier accepts only if:

* the auth names this order and the version is 4;
* the escrow's `side` picks the leg — side 1 (AdManager) needs the order chain, its root and
  `adLegNullifier`; side 0 (OrderPortal) the ad chain, its root and `orderLegNullifier`;
* on the ad leg, the maker's slot is the one the lock pinned (`pinnedSlot`; the settlement signer can
  move it with a signed `RepinOrder` consent applied by `repinOrder` while the order is open); the
  order leg sends an unpinned sentinel;
* both keys sit in live registry slots of the settlement signer and the bridger, the maker key is
  the one the auth names, and the aggregate signature verifies over the preimage.

The evidence paths (`presentSettled`, `refundByCancel`, `payMakerByForfeit`, the never-locked
cancel) need no co-signature: they prove a leaf against a root the RootAnchor notarized.

## Security Model

**Multi-Layer Protection:**

1. **EIP-712 Domain Separation**: Prevents cross-contract and cross-chain replay attacks
2. **Co-signed nullifiers**: each unlock consumes only the nullifier both parties signed for its leg, once
3. **MMR Integrity**: Tamper-proof order history with Poseidon2 hashing
4. **Manager Permissions**: Only authorized contracts can append to the MMR
5. **Bidirectional Chain Linking**: Contracts only accept proofs from configured counterparts

**Economic Security:**

* **Collateral Requirements**: Makers must lock funds before order matching
* **Slashing Mechanisms**: Penalties for malicious behavior or failed settlements (TBA)
* **Liquidity Guarantees**: Orders are only created when sufficient liquidity is available (TBA)
