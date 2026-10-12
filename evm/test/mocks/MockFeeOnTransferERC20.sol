// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {MockERC20} from "src/mocks/MockERC20.sol";

/// A token whose transfers deliver `fee` less than asked (the fee is burned), like a
/// fee-on-transfer token, or `bonus` more than asked (minted to the receiver), like a token that
/// pays a reward on receipt. Both are settable so one token can show every behaviour.
contract MockFeeOnTransferERC20 is MockERC20 {
    uint256 public fee;
    uint256 public bonus;

    constructor(uint256 _decimals) MockERC20("Fee", "FEE", 0, _decimals) {}

    function setFee(uint256 fee_) external {
        fee = fee_;
    }

    function setBonus(uint256 bonus_) external {
        bonus = bonus_;
    }

    function _update(address from, address to, uint256 value) internal override {
        if (from != address(0) && to != address(0)) {
            if (fee != 0) {
                super._update(from, address(0), fee);
                value -= fee;
            }
            if (bonus != 0) super._update(address(0), to, bonus);
        }
        super._update(from, to, value);
    }
}
