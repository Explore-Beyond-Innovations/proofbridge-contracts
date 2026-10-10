// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {wNativeToken, IwNativeToken, SafeNativeToken} from "src/wNativeToken.sol";

/// A recipient whose receive costs more than 5,000 gas, like a Safe or an ERC-1967 proxy.
contract HeavyReceiver {
    uint256 public hits;

    receive() external payable {
        hits += 1;
    }
}

contract RefusingReceiver {
    receive() external payable {
        revert("refused");
    }
}

contract NativeSender {
    using SafeNativeToken for IwNativeToken;

    IwNativeToken internal immutable w;

    constructor(IwNativeToken w_) {
        w = w_;
    }

    function fund() external payable {
        w.deposit{value: msg.value}();
    }

    function send(address to, uint256 amount) external {
        w.safeWithdrawTo(amount, to);
    }

    receive() external payable {}
}

/// Audit lead OE-12: the native push forwarded 5,000 gas, which every proxy wallet needs more than.
contract SafeNativeTokenTest is Test {
    wNativeToken internal w;
    NativeSender internal sender;

    function setUp() public {
        w = new wNativeToken("Wrapped Native", "WNATIVE", 18);
        sender = new NativeSender(IwNativeToken(address(w)));
        sender.fund{value: 10 ether}();
    }

    function test_safeWithdrawTo_paysARecipientWhoseReceiveNeedsMoreThan5000Gas() public {
        HeavyReceiver r = new HeavyReceiver();
        sender.send(address(r), 1 ether);
        assertEq(address(r).balance, 1 ether);
        assertEq(r.hits(), 1);
    }

    function test_safeWithdrawTo_paysAnEOA() public {
        address eoa = makeAddr("eoa");
        sender.send(eoa, 2 ether);
        assertEq(eoa.balance, 2 ether);
    }

    function test_safeWithdrawTo_stillRevertsWhenTheRecipientRefuses() public {
        RefusingReceiver r = new RefusingReceiver();
        vm.expectRevert(bytes("refused"));
        sender.send(address(r), 1 ether);
        assertEq(w.balanceOf(address(sender)), 10 ether, "the unwrap rolls back with the push");
    }
}
