# ProofBridge EVM Contracts

Solidity implementation of the ProofBridge protocol using Foundry. Deployed on Ethereum Sepolia and Hedera Testnet.

For shared architecture, contract descriptions, and protocol details, see the [contracts README](../README.md).

## EVM-Specific Details

* **Access Control**: OpenZeppelin `AccessControl` with `MANAGER_ROLE` for MerkleManager
* **Reentrancy Protection**: OpenZeppelin `ReentrancyGuard` on all state-changing functions
* **Native Token Handling**: `wNativeToken` wraps ETH/HBAR automatically on deposit and unwraps on withdrawal
* **Address Format**: Standard 20-byte `address` type, zero-padded to 32 bytes for EIP-712 hashing

### wNativeToken

Wrapped native token (WETH/WHBAR) providing ERC20 interface for native blockchain tokens.

* Gas-optimized assembly-level deposit/withdraw
* Full ERC20 compatibility
* Seamless integration with AdManager and OrderPortal

### Order Struct (Solidity)

```solidity
struct Order {
    address orderToken;
    address adToken;
    uint256 amount;
    address bridger;
    uint256 orderChainId;
    address orderPortal;
    address orderRecipient;
    uint256 adChainId;
    address adManager;
    uint256 adId;
    address adCreator;
    address adRecipient;
    uint256 salt;
}
```

## Deployed Contracts

ProofBridge is currently live on **Ethereum Sepolia** and **Hedera Testnet** with full cross-chain bridging capabilities.

### Ethereum Sepolia (Chain ID: 11155111)

| Contract            | Address                                      | Explorer                                                                                             |
| ------------------- | -------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Verifier            | `0xDc930A3b5CC073092750aE7f4FF45409B2428592` | [View on Etherscan](https://sepolia.etherscan.io/address/0xDc930A3b5CC073092750aE7f4FF45409B2428592) |
| MerkleManager       | `0x397E7356aF447B2754D8Ea0838d285FB78F2482d` | [View on Etherscan](https://sepolia.etherscan.io/address/0x397E7356aF447B2754D8Ea0838d285FB78F2482d) |
| wNativeToken (WETH) | `0xf635e2661c950c7947a13d03e16076F7b5aA5DbE` | [View on Etherscan](https://sepolia.etherscan.io/address/0xf635e2661c950c7947a13d03e16076F7b5aA5DbE) |
| AdManager           | `0x366D90CB2A8606A82164C717cF1889c3ed5aE1f4` | [View on Etherscan](https://sepolia.etherscan.io/address/0x366D90CB2A8606A82164C717cF1889c3ed5aE1f4) |
| OrderPortal         | `0xF1C313faAD40ccAeDb4Fd3e7C838993569E2572C` | [View on Etherscan](https://sepolia.etherscan.io/address/0xF1C313faAD40ccAeDb4Fd3e7C838993569E2572C) |
| wHBAR               | `0xdf386137388b4f39873708fD11505AF86238b666` | [View on Etherscan](https://sepolia.etherscan.io/address/0xdf386137388b4f39873708fD11505AF86238b666) |
| ProofBridge Token   | `0x1B62aDdB315CC98ab4625ffA170c1BC5C75F9da7` | [View on Etherscan](https://sepolia.etherscan.io/address/0x1B62aDdB315CC98ab4625ffA170c1BC5C75F9da7) |

### Hedera Testnet (Chain ID: 296)

| Contract             | Address                                      | Explorer                                                                                            |
| -------------------- | -------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Verifier             | `0xDbf6dA1aBD40f7b7eA7B935663D4F78325930e48` | [View on HashScan](https://hashscan.io/testnet/contract/0xDbf6dA1aBD40f7b7eA7B935663D4F78325930e48) |
| MerkleManager        | `0x04cD7aCc919F2916Ae0eAEa7BFc40962BC99AC8E` | [View on HashScan](https://hashscan.io/testnet/contract/0x04cD7aCc919F2916Ae0eAEa7BFc40962BC99AC8E) |
| wNativeToken (WHBAR) | `0xb1f616b8134f602c3bb465fb5b5e6565ccad37ed` | [View on HashScan](https://hashscan.io/testnet/contract/0xb1f616b8134f602c3bb465fb5b5e6565ccad37ed) |
| AdManager            | `0x9AeF534c50D4BAA10c2cBA14590a37798Ea4c768` | [View on HashScan](https://hashscan.io/testnet/contract/0x9AeF534c50D4BAA10c2cBA14590a37798Ea4c768) |
| OrderPortal          | `0x4C5dDf1CC71a709704d26648f71bD3E629BE5914` | [View on HashScan](https://hashscan.io/testnet/contract/0x4C5dDf1CC71a709704d26648f71bD3E629BE5914) |
| wETH                 | `0x291b2e449Dd2C036142186Ab2Ef81DE6c68E00fe` | [View on HashScan](https://hashscan.io/testnet/contract/0x291b2e449Dd2C036142186Ab2Ef81DE6c68E00fe) |
| ProofBridge Token    | `0x9318E8f8C1F7Bff8c00A062F80b391866fBE8d87` | [View on HashScan](https://hashscan.io/testnet/contract/0x9318E8f8C1F7Bff8c00A062F80b391866fBE8d87) |

### Supported Cross-Chain Routes

**Native Token Bridging:**

* **ETH (Sepolia) <-> wETH (Hedera)** - Automatically wrapped/unwrapped by wNativeToken
* **HBAR (Hedera) <-> wHBAR (Sepolia)** - Automatically wrapped/unwrapped by wNativeToken

**ERC20 Token Bridging:**

* **ProofBridge Token** - Example ERC20 demonstrating cross-chain token bridging

## Install & Build

```bash
cd contracts/evm

# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Install dependencies
forge install
npm install

# Build contracts
forge build
```

## Testing

```bash
forge test -vvv
```

## Deploy

### Automated Deployment (Recommended)

Deploy to two chains with automated configuration:

```bash
export PRIVATE_KEY="0x..."
cd js-scripts/deploy
cp config.template.json config.json
# Edit config.json - update admin addresses

npm run deploy -- --chain1 296 --chain2 84532
```

This deploys all contracts on both chains, grants MANAGER_ROLE, links chains bidirectionally, and configures token routes.

See [QUICKSTART.md](./QUICKSTART.md) for quick deployment guide.

See [js-scripts/deploy/README.md](./js-scripts/deploy/README.md) for detailed documentation.

### Manual Deployment (Advanced)

```bash
export PRIVATE_KEY=0xYOUR_KEY

forge script script/DeployProofbridge.s.sol:DeployProofbridge \
  --rpc-url https://YOUR_RPC \
  --broadcast --verify
```

## Post-Deploy Configuration

If using manual deployment, run these **admin** calls to connect chains and tokens.

**On OrderPortal (source chain):**

```solidity
setChain(dstChainId, dstAdManager, true);
setTokenRoute(token1, dstChainId, token2);
```

**On AdManager (destination chain):**

```solidity
setChain(orderChainId, orderPortal, true);
setTokenRoute(adToken, orderToken, orderChainId);
```

**On MerkleManager (both chains):**

```solidity
grantRole(MANAGER_ROLE, adManagerAddress);
grantRole(MANAGER_ROLE, orderPortalAddress);
```
