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
* **lockForOrder**: Reserves liquidity for a specific EIP-712 order hash, appends to MMR
* **unlock**: Verifies ZK proof, consumes nullifier, transfers ad token to the **orderRecipient**
* **setChain** / **setTokenRoute**: Admin configuration for cross-chain routing

**Key Storage:**

* `chains[orderChainId] → { supported, orderPortal }`: Source chain configuration
* `tokenRoute[adToken][orderChainId] → orderToken`: Cross-chain token mapping
* `ads[adId] → { creator, token, balance, locked, open, … }`: Ad state management
* `orders[orderHash] → Status`: Order execution tracking
* `nullifiers[hash] → bool`: Proof replay prevention

### OrderPortal

The source chain contract where users initiate cross-chain transfers by creating orders.

**Core Functions:**

* **createOrder**: Initiates a cross-chain order by depositing source chain tokens, appends to MMR
* **unlock**: Verifies ZK proof and releases funds to the designated recipient
* **setChain** / **setTokenRoute**: Admin configuration

**Key Storage:**

* `chains[dstChainId] → { supported, adManager }`: Destination chain configuration
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

```text
Order {
    orderChainToken     // source token (order chain)
    adChainToken        // destination token (ad chain)
    amount              // transfer amount
    bridger             // bridger address
    orderChainId        // source chain ID
    orderPortal         // order portal contract address
    orderRecipient      // recipient on order chain
    adChainId           // destination chain ID
    adManager           // ad manager contract address
    adId                // advertisement identifier
    adCreator           // ad creator address
    adRecipient         // recipient on ad chain
    salt                // caller-controlled nonce
}
```

**Address encoding differs by implementation:**

* **EVM**: `address` (20 bytes, zero-padded to 32 for hashing)
* **Stellar**: `BytesN<32>` (full 32 bytes — `C...` for contracts, `G...` for ed25519 accounts)

Both produce identical EIP-712 hashes when given the same 32-byte values.

## Zero-Knowledge Proof System

The protocol employs a ZK proof system for privacy-preserving cross-chain settlements:

**Proof Generation Process:**

1. **Secret Generation**: Each participant generates a private secret for nullifier computation
2. **Nullifier Calculation**: `nullifierHash = poseidon2(secret_half, orderHashMod)` — bridger uses left half, ad creator uses right half
3. **Circuit Execution**: Noir circuit validates the relationship between secrets, nullifiers, and MMR inclusion
4. **Proof Creation**: UltraHonk backend generates proof with keccak-based Fiat-Shamir

**Proof circuits**: See [proof_circuits/](../proof_circuits/)

### Verifier Public Inputs

The circuit produces 4 public inputs (each 32 bytes, 128 bytes total):

**OrderPortal.unlock** (Source Chain):

1. **`adCreator's nullifierHash`**: Poseidon2 commitment proving ad creator's secret knowledge
2. **`orderHashMod`**: EIP-712 order hash reduced to BN254 field
3. **`targetRoot`**: MMR root at the time of proof generation
4. **`0`**: Chain flag (0 = source chain / order portal)

**AdManager.unlock** (Destination Chain):

1. **`bridger's nullifierHash`**: Poseidon2 commitment proving bridger's secret knowledge
2. **`orderHashMod`**: EIP-712 order hash reduced to BN254 field
3. **`targetRoot`**: MMR root at the time of proof generation
4. **`1`**: Chain flag (1 = destination chain / ad manager)

## Security Model

**Multi-Layer Protection:**

1. **EIP-712 Domain Separation**: Prevents cross-contract and cross-chain replay attacks
2. **Nullifier Uniqueness**: Cryptographic guarantee against double-spending
3. **MMR Integrity**: Tamper-proof order history with Poseidon2 hashing
4. **Manager Permissions**: Only authorized contracts can append to the MMR
5. **Bidirectional Chain Linking**: Contracts only accept proofs from configured counterparts

**Economic Security:**

* **Collateral Requirements**: Makers must lock funds before order matching
* **Slashing Mechanisms**: Penalties for malicious behavior or failed settlements (TBA)
* **Liquidity Guarantees**: Orders are only created when sufficient liquidity is available (TBA)
