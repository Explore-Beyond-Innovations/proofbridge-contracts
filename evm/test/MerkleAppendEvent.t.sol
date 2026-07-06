// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test, Vm} from "forge-std/Test.sol";
import {MerkleManager} from "src/MerkleManager.sol";
import {Poseidon2Yul} from "@poseidon2/src/Poseidon2Yul.sol";

/// Self-verifying event: each append's emitted newRoot equals the tree root.
/// Emitted indexes are MMR node positions (1, 2, 4, 5, 8...), strictly increasing.
contract LeafAppendedTest is Test {
    MerkleManager mm;

    function setUp() public {
        mm = new MerkleManager(address(this), address(new Poseidon2Yul()));
        mm.grantRole(mm.MANAGER_ROLE(), address(this));
    }

    function test_eventCarriesTheCoreAndMatchesTheTree() public {
        uint256 lastIndex = 0;
        for (uint256 i = 0; i < 5; i++) {
            bytes32 orderHash = keccak256(abi.encode("leaf", i));
            uint256 side = i % 2;

            vm.recordLogs();
            mm.appendOrderHash(orderHash, side);
            Vm.Log[] memory logs = vm.getRecordedLogs();

            assertEq(logs.length, 1);
            assertEq(logs[0].topics[0], keccak256("DepositHashAppended(uint256,bytes32,uint256,bytes32)"));
            uint256 index = uint256(logs[0].topics[1]);
            assertGt(index, lastIndex, "index strictly increasing");
            lastIndex = index;
            assertEq(logs[0].topics[2], orderHash, "orderHash");
            (uint256 emittedSide, bytes32 newRoot) = abi.decode(logs[0].data, (uint256, bytes32));
            assertEq(emittedSide, side, "side");
            assertEq(newRoot, mm.getRoot(), "event root != tree root");
            assertEq(mm.getWidth(), i + 1, "width");
        }
    }
}
