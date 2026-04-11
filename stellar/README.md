# ProofBridge Stellar Contracts

Soroban/Rust implementation of the ProofBridge protocol for the Stellar network.

For shared architecture, contract descriptions, and protocol details, see the [contracts README](../README.md).

## Stellar-Specific Details

* **Ed25519 Authentication**: All state-changing functions require real ed25519 signatures over request hashes (not Soroban `require_auth` — verified via `env.crypto().ed25519_verify()`)
* **Request Hash Binding**: `keccak256(auth_token + expiry + action_hash + params + chain_id + contract_address)`
* **SAC-Convention Tokens**: Uses `stellar-tokens` crate's `FungibleToken` trait for token handling
* **Address Format**: Full 32-byte `BytesN<32>` — `C...` strkey for contracts/tokens, `G...` strkey for ed25519 accounts
* **Native Token**: Wrapped native XLM support via sentinel address (`0xEE...EE`)

### ProofBridge Core (shared library)

Shared Rust library used by both AdManager and OrderPortal:

* **`auth.rs`**: Ed25519 signature verification, request hash computation, auth token tracking
* **`eip712.rs`**: EIP-712 domain separator, Order struct hashing, `address_to_bytes32` conversions
* **`token.rs`**: `BytesN<32>` <-> `Address` conversion, native token detection, transfer helpers
* **`cross_contract.rs`**: Cross-contract call wrappers for MerkleManager and Verifier
* **`types.rs`**: Shared types (OrderParams, etc.)
* **`errors.rs`**: Error trait for contract-specific error enums

### Order Struct (Rust)

```rust
Order {
    order_chain_token: BytesN<32>,   // source token (C... contract address)
    ad_chain_token: BytesN<32>,      // destination token (C... contract address)
    amount: u128,
    bridger: BytesN<32>,             // G... ed25519 address
    order_chain_id: u128,
    order_portal: BytesN<32>,        // C... contract address
    order_recipient: BytesN<32>,     // G... ed25519 address
    ad_chain_id: u128,
    ad_manager: BytesN<32>,          // C... contract address
    ad_id: String,
    ad_creator: BytesN<32>,          // G... ed25519 address
    ad_recipient: BytesN<32>,        // G... ed25519 address
    salt: u128,
}
```

## Project Structure

```text
.
├── contracts/
│   ├── ad-manager/            # Destination chain: ad creation, order locking, bridger unlock
│   ├── order-portal/          # Source chain: order creation, ad-creator unlock
│   ├── merkle-manager/        # Poseidon2-based MMR for order hash storage
│   └── verifier/              # UltraHonk ZK proof verifier (keccak Fiat-Shamir)
├── lib/
│   └── proofbridge-core/      # Shared: EIP-712 hashing, auth, token utils, cross-contract
├── tests/
│   ├── integration_test.rs    # End-to-end tests across all 4 contracts
│   └── fixtures/
│       ├── generate_fixtures.ts   # Generates ZK proofs, MMR roots, test params
│       ├── test_params.json       # Deterministic test parameters (Stellar addresses)
│       ├── proof_bridger.bin      # UltraHonk proof for bridger unlock
│       ├── proof_ad_creator.bin   # UltraHonk proof for ad-creator unlock
│       └── vk                     # Verification key
├── src/lib.rs
└── Cargo.toml                 # Workspace configuration
```

## Install & Build

```bash
cd contracts/stellar

# Requires wasm target
rustup target add wasm32v1-none

# Build all contract WASMs
for dir in contracts/*/; do
  (cd "$dir" && make build)
done

# Or build individually
cd contracts/ad-manager && make build
```

## Testing

### Unit tests (per-contract)

```bash
cargo test
```

### End-to-end integration tests

The integration tests deploy all 4 contracts and exercise the full cross-chain flow with real ed25519 signatures and ZK proofs.

```bash
# Build contract WASMs first (tests load them via include_bytes!)
cargo test --test integration_test
```

### Regenerating test fixtures

If the ZK circuit or order parameters change, regenerate the fixture files:

```bash
cd tests/fixtures
npm install
npx tsx generate_fixtures.ts
```

This produces deterministic proofs, MMR roots, and `test_params.json` with native Stellar strkey addresses (`C...` for contracts/tokens, `G...` for users).

## E2E Test Coverage

| Test                                       | Description                                                                  |
| ------------------------------------------ | ---------------------------------------------------------------------------- |
| `test_ad_manager_lock_for_order`           | Locks an order on the ad chain, verifies order hash and merkle root          |
| `test_ad_manager_unlock_with_bridger_proof`| Unlocks with bridger ZK proof, verifies Filled status                        |
| `test_order_portal_create_and_unlock`      | Creates order on order chain, unlocks with ad-creator ZK proof               |
| `test_full_cross_chain_flow`               | Full round-trip: lock, create, bridger unlock, ad-creator unlock             |
| `test_nullifier_prevents_double_unlock`    | Verifies nullifier replay protection                                         |

## Dependencies

* **Soroban SDK** v26.0.0-rc.1
* **stellar-tokens** — SAC-convention fungible token trait
* **soroban-poseidon** — Poseidon2 hash for MMR
* **ultrahonk_soroban_verifier** — On-chain UltraHonk proof verification
* **stellar-strkey** — Stellar address encoding/decoding
