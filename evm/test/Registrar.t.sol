// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {Registrar} from "src/Registrar.sol";
import {MerkleManager, IMerkleManager} from "src/MerkleManager.sol";
import {Poseidon2Yul_BN254 as Poseidon2Yul} from "@poseidon2/src/bn254/yul/Poseidon2Yul.sol";

/// A contract account whose "signature" is whatever it says it is — the shape a Safe / 4337
/// wallet presents through EIP-1271.
contract Mock1271Account is IERC1271 {
    bool public approves;

    function set(bool ok) external {
        approves = ok;
    }

    function isValidSignature(bytes32, bytes memory) external view returns (bytes4) {
        return approves ? IERC1271.isValidSignature.selector : bytes4(0);
    }
}

/// 2.1b (#324), T-67a: the registrar appends a domain-4 leaf only after the account's own
/// authorization passes — direct call, EOA signature, or EIP-1271 — and never for a stranger.
contract RegistrarTest is Test {
    MerkleManager internal mm;
    Registrar internal registrar;

    bytes32 internal constant COMMITMENT = keccak256("some bls pubkey");

    function _b32(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    function setUp() public {
        mm = new MerkleManager(address(this), address(new Poseidon2Yul()));
        registrar = new Registrar(IMerkleManager(address(mm)));
        mm.grantRole(mm.MANAGER_ROLE(), address(registrar));
    }

    function test_subjectIsKeccakOfPackedFields() public view {
        bytes32 acct = bytes32(uint256(0xACC));
        assertEq(registrar.subjectOf(acct, COMMITMENT, 7), keccak256(abi.encodePacked(acct, COMMITMENT, uint64(7))));
    }

    function test_directCall_appendsDomain4Leaf() public {
        address account = makeAddr("account");
        uint256 before = mm.getWidth();
        // Resolve the expected subject first: a call inside the emit arguments would consume the prank.
        bytes32 expected = registrar.subjectOf(_b32(account), COMMITMENT, 1);

        vm.expectEmit(true, true, false, true);
        emit Registrar.RegistrationLeaf(_b32(account), COMMITMENT, 1, expected);
        vm.prank(account);
        bytes32 subject = registrar.registerLeaf(_b32(account), COMMITMENT, 1, "");

        assertEq(mm.getWidth(), before + 1, "one leaf appended");
        assertEq(subject, expected);
    }

    function test_stranger_directCall_reverts() public {
        address account = makeAddr("account");
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Registrar.Registrar__NotAccount.selector);
        registrar.registerLeaf(_b32(account), COMMITMENT, 1, "");
    }

    function test_eoaSignature_appends_fromAnySender() public {
        (address eoa, uint256 pk) = makeAddrAndKey("eoa");
        bytes32 digest = registrar.leafDigest(_b32(eoa), COMMITMENT, 2);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);

        vm.prank(makeAddr("relayer"));
        registrar.registerLeaf(_b32(eoa), COMMITMENT, 2, abi.encodePacked(r, s, v));
        assertEq(mm.getWidth(), 1);
    }

    function test_eoaSignature_wrongSigner_reverts() public {
        (address eoa,) = makeAddrAndKey("eoa");
        (, uint256 otherPk) = makeAddrAndKey("other");
        bytes32 digest = registrar.leafDigest(_b32(eoa), COMMITMENT, 2);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(otherPk, digest);

        vm.expectRevert(Registrar.Registrar__BadAuth.selector);
        registrar.registerLeaf(_b32(eoa), COMMITMENT, 2, abi.encodePacked(r, s, v));
    }

    function test_eoaSignature_boundToFields() public {
        (address eoa, uint256 pk) = makeAddrAndKey("eoa");
        bytes32 digest = registrar.leafDigest(_b32(eoa), COMMITMENT, 2);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);

        // Same signature, different epoch: a different leaf, not authorized.
        vm.expectRevert(Registrar.Registrar__BadAuth.selector);
        registrar.registerLeaf(_b32(eoa), COMMITMENT, 3, abi.encodePacked(r, s, v));
    }

    function test_erc1271_appends_whenTheAccountApproves() public {
        Mock1271Account account = new Mock1271Account();
        account.set(true);
        registrar.registerLeaf(_b32(address(account)), COMMITMENT, 1, hex"01");
        assertEq(mm.getWidth(), 1);
    }

    function test_erc1271_reverts_whenTheAccountRefuses() public {
        Mock1271Account account = new Mock1271Account();
        vm.expectRevert(Registrar.Registrar__BadAuth.selector);
        registrar.registerLeaf(_b32(address(account)), COMMITMENT, 1, hex"01");
    }

    function test_withoutManagerRole_reverts() public {
        Registrar bare = new Registrar(IMerkleManager(address(mm)));
        address account = makeAddr("account");
        vm.prank(account);
        vm.expectRevert();
        bare.registerLeaf(_b32(account), COMMITMENT, 1, "");
    }
}
