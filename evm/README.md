# ProofBridge EVM Contracts

Solidity implementation of the ProofBridge protocol using Foundry.

For shared architecture, contract descriptions, and protocol details, see the [contracts README](../README.md).

## EVM-Specific Details

* **Access Control**: OpenZeppelin `AccessControl` with `MANAGER_ROLE` for MerkleManager
* **Reentrancy Protection**: OpenZeppelin `ReentrancyGuard` on all state-changing functions
* **Native Token Handling**: `wNativeToken` wraps the native EVM token automatically on deposit and unwraps on withdrawal
* **Address Format**: 32-byte `bytes32` across all cross-chain fields so the same order hash shape covers both 20-byte EVM addresses (zero-padded) and 32-byte Stellar strkeys

### wNativeToken

Wrapped native token (e.g. WETH) providing an ERC20 interface for native chain tokens.

* Gas-optimized assembly-level deposit/withdraw
* Full ERC20 compatibility
* Seamless integration with AdManager and OrderPortal

### OrderParams Struct (Solidity)

```solidity
struct OrderParams {
    bytes32 orderChainToken;
    bytes32 adChainToken;
    uint256 amount;
    bytes32 bridger;
    bytes32 orderRecipient;
    uint256 adChainId;
    bytes32 adManager;
    string  adId;
    bytes32 adCreator;
    bytes32 adRecipient;
    uint256 salt;
}
```

`AdManager.OrderParams` mirrors this with `orderChainId` + `srcOrderPortal` in place of `adChainId` + `adManager`, reflecting the direction of the flow.

## Install & Build

```bash
cd contracts/evm

# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Install dependencies
forge install

# Build contracts
forge build
```

## Testing

```bash
forge test -vvv
```

## Deploy

```bash
export PRIVATE_KEY=0xYOUR_KEY

forge script script/DeployProofbridge.s.sol:DeployProofbridge \
  --rpc-url https://YOUR_RPC \
  --broadcast --verify
```

## Post-Deploy Configuration

Run these **admin** calls to connect chains and tokens.

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
