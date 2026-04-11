// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {WETH} from "lib/solady/src/tokens/WETH.sol";

interface IwNativeToken {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
}

library SafeNativeToken {
    uint256 private constant _RAW_CALL_GAS_LIMIT = 5000;

    /**
     * @notice Safely deposits a specified amount of Native token into the IwNativeToken contract. Consumes less gas than regular `IwNativeToken.deposit`.
     * @param nativeToken The IwNativeToken token contract.
     * @param amount The amount of Native token to deposit into the IwNativeToken contract.
     */
    function safeDeposit(IwNativeToken nativeToken, uint256 amount) internal {
        if (amount > 0) {
            bytes4 selector = IwNativeToken.deposit.selector;
            assembly ("memory-safe") {
                // solhint-disable-line no-inline-assembly
                mstore(0, selector)
                if iszero(call(gas(), nativeToken, amount, 0, 4, 0, 0)) {
                    let ptr := mload(0x40)
                    returndatacopy(ptr, 0, returndatasize())
                    revert(ptr, returndatasize())
                }
            }
        }
    }

    /**
     * @notice Safely withdraws a specified amount of wrapped Native token from the IwNativeToken contract. Consumes less gas than regular `IwNativeToken.withdraw`.
     * @dev Uses inline assembly to interact with the IwNativeToken contract.
     * @param nativeToken The IwNativeToken token contract.
     * @param amount The amount of wrapped Native token to withdraw from the IwNativeToken contract.
     */
    function safeWithdraw(IwNativeToken nativeToken, uint256 amount) internal {
        bytes4 selector = IwNativeToken.withdraw.selector;
        assembly ("memory-safe") {
            // solhint-disable-line no-inline-assembly
            mstore(0, selector)
            mstore(4, amount)
            if iszero(call(gas(), nativeToken, 0, 0, 0x24, 0, 0)) {
                let ptr := mload(0x40)
                returndatacopy(ptr, 0, returndatasize())
                revert(ptr, returndatasize())
            }
        }
    }

    /**
     * @notice Safely withdraws a specified amount of wrapped Native token from the IwNativeToken contract to a specified recipient.
     * Consumes less gas then regular `IwNativeToken.withdraw`.
     * @param nativeToken The IwNativeToken token contract.
     * @param amount The amount of wrapped Native token to withdraw from the IwNativeToken contract.
     * @param to The recipient of the withdrawn Native token.
     */
    function safeWithdrawTo(IwNativeToken nativeToken, uint256 amount, address to) internal {
        safeWithdraw(nativeToken, amount);
        if (to != address(this)) {
            assembly ("memory-safe") {
                // solhint-disable-line no-inline-assembly
                if iszero(call(_RAW_CALL_GAS_LIMIT, to, amount, 0, 0, 0, 0)) {
                    let ptr := mload(0x40)
                    returndatacopy(ptr, 0, returndatasize())
                    revert(ptr, returndatasize())
                }
            }
        }
    }
}

contract wNativeToken is WETH, IwNativeToken {
    string private w_name;
    string private w_symbol;
    uint256 private immutable i_decimals;

    event Deposit(address indexed dst, uint256 wad);
    event Withdrawal(address indexed src, uint256 wad);

    constructor(string memory _name, string memory _symbol, uint256 _decimals) {
        w_name = _name;
        w_symbol = _symbol;
        i_decimals = _decimals;
    }

    function name() public view virtual override returns (string memory) {
        return w_name;
    }

    function symbol() public view virtual override returns (string memory) {
        return w_symbol;
    }

    function deposit() public payable virtual override(WETH, IwNativeToken) {
        super.deposit();
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) public virtual override(WETH, IwNativeToken) {
        super.withdraw(amount);
        emit Withdrawal(msg.sender, amount);
    }

    function decimals() public view virtual override returns (uint8) {
        return uint8(i_decimals);
    }
}
