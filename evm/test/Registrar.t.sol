// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {IRegistrar} from "src/interfaces/IRegistrar.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {Registrar} from "src/Registrar.sol";
import {RegistrationSubject} from "src/libraries/RegistrationSubject.sol";
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
/// authorization passes — direct call, EOA signature, or EIP-1271 — never for a stranger, and never
/// twice for the same epoch.
contract RegistrarTest is Test {
    MerkleManager internal mm;
    Registrar internal registrar;

    bytes32 internal constant COMMITMENT = keccak256("some bls pubkey");
    // The destination the leaf is minted for: the vectors' Sepolia registry.
    uint256 internal constant DST_CHAIN = 11155111;
    bytes32 internal constant DST_REGISTRY = bytes32(uint256(uint160(0x1111111111111111111111111111111111111111)));

    function _b32(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    function _sign(uint256 pk, bytes32 acct, uint64 epoch) internal view returns (bytes memory) {
        bytes32 digest = registrar.leafDigest(acct, COMMITMENT, epoch, DST_CHAIN, DST_REGISTRY);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function setUp() public {
        mm = new MerkleManager(address(this), address(new Poseidon2Yul()));
        registrar = new Registrar(IMerkleManager(address(mm)));
        mm.grantRole(mm.MANAGER_ROLE(), address(registrar));
    }

    // --- the subject -------------------------------------------------------------

    function test_subjectIsTheTaggedRegistrationMessage() public view {
        bytes32 acct = bytes32(uint256(0xACC));
        bytes32 expected = keccak256(
            bytes.concat(
                RegistrationSubject.TAG, bytes32(DST_CHAIN), DST_REGISTRY, acct, COMMITMENT, bytes32(uint256(7))
            )
        );
        assertEq(registrar.subjectOf(acct, COMMITMENT, 7, DST_CHAIN, DST_REGISTRY), expected);
        assertEq(RegistrationSubject.TAG, keccak256("ProofBridge.BLSKeyRegistry.RegistrationLeaf.v1"));
    }

    function test_subjectBindsTheDestination() public view {
        bytes32 acct = bytes32(uint256(0xACC));
        bytes32 here = registrar.subjectOf(acct, COMMITMENT, 7, DST_CHAIN, DST_REGISTRY);
        // Another chain, or another registry on the same chain, is another leaf.
        assertNotEq(here, registrar.subjectOf(acct, COMMITMENT, 7, DST_CHAIN + 1, DST_REGISTRY));
        assertNotEq(here, registrar.subjectOf(acct, COMMITMENT, 7, DST_CHAIN, bytes32(uint256(0xBEEF))));
    }

    // --- authorization -------------------------------------------------------------

    function test_directCall_appendsDomain4Leaf() public {
        address account = makeAddr("account");
        uint256 before = mm.getWidth();
        // Resolve the expected subject first: a call inside the emit arguments would consume the prank.
        bytes32 expected = registrar.subjectOf(_b32(account), COMMITMENT, 1, DST_CHAIN, DST_REGISTRY);

        vm.expectEmit(true, true, false, true);
        emit IRegistrar.RegistrationLeaf(_b32(account), COMMITMENT, 1, DST_CHAIN, DST_REGISTRY, expected);
        vm.prank(account);
        bytes32 subject = registrar.registerLeaf(_b32(account), COMMITMENT, 1, DST_CHAIN, DST_REGISTRY, "");

        assertEq(mm.getWidth(), before + 1, "one leaf appended");
        assertEq(subject, expected);
        assertEq(registrar.nextEpoch(_b32(account)), 2);
    }

    function test_stranger_directCall_reverts() public {
        address account = makeAddr("account");
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(IRegistrar.Registrar__NotAccount.selector);
        registrar.registerLeaf(_b32(account), COMMITMENT, 1, DST_CHAIN, DST_REGISTRY, "");
    }

    function test_eoaSignature_appends_fromAnySender() public {
        (address eoa, uint256 pk) = makeAddrAndKey("eoa");
        bytes memory sig = _sign(pk, _b32(eoa), 2);

        vm.prank(makeAddr("relayer"));
        registrar.registerLeaf(_b32(eoa), COMMITMENT, 2, DST_CHAIN, DST_REGISTRY, sig);
        assertEq(mm.getWidth(), 1);
    }

    function test_eoaSignature_wrongSigner_reverts() public {
        (address eoa,) = makeAddrAndKey("eoa");
        (, uint256 otherPk) = makeAddrAndKey("other");
        bytes memory sig = _sign(otherPk, _b32(eoa), 2);

        vm.expectRevert(IRegistrar.Registrar__BadAuth.selector);
        registrar.registerLeaf(_b32(eoa), COMMITMENT, 2, DST_CHAIN, DST_REGISTRY, sig);
    }

    function test_eoaSignature_boundToEveryField() public {
        (address eoa, uint256 pk) = makeAddrAndKey("eoa");
        bytes memory sig = _sign(pk, _b32(eoa), 2);

        // Same signature, different epoch / chain / registry: a different leaf, not authorized.
        vm.expectRevert(IRegistrar.Registrar__BadAuth.selector);
        registrar.registerLeaf(_b32(eoa), COMMITMENT, 3, DST_CHAIN, DST_REGISTRY, sig);
        vm.expectRevert(IRegistrar.Registrar__BadAuth.selector);
        registrar.registerLeaf(_b32(eoa), COMMITMENT, 2, DST_CHAIN + 1, DST_REGISTRY, sig);
        vm.expectRevert(IRegistrar.Registrar__BadAuth.selector);
        registrar.registerLeaf(_b32(eoa), COMMITMENT, 2, DST_CHAIN, bytes32(uint256(0xBEEF)), sig);
    }

    function test_erc1271_appends_whenTheAccountApproves() public {
        Mock1271Account account = new Mock1271Account();
        account.set(true);
        registrar.registerLeaf(_b32(address(account)), COMMITMENT, 1, DST_CHAIN, DST_REGISTRY, hex"01");
        assertEq(mm.getWidth(), 1);
    }

    function test_erc1271_reverts_whenTheAccountRefuses() public {
        Mock1271Account account = new Mock1271Account();
        vm.expectRevert(IRegistrar.Registrar__BadAuth.selector);
        registrar.registerLeaf(_b32(address(account)), COMMITMENT, 1, DST_CHAIN, DST_REGISTRY, hex"01");
    }

    function test_withoutManagerRole_reverts() public {
        Registrar bare = new Registrar(IMerkleManager(address(mm)));
        address account = makeAddr("account");
        vm.prank(account);
        vm.expectRevert();
        bare.registerLeaf(_b32(account), COMMITMENT, 1, DST_CHAIN, DST_REGISTRY, "");
    }

    // --- epochs are strictly increasing per account (B2) -----------------------------

    function test_firstLeafMayUseEpochZero() public {
        address account = makeAddr("account");
        vm.prank(account);
        registrar.registerLeaf(_b32(account), COMMITMENT, 0, DST_CHAIN, DST_REGISTRY, "");
        assertEq(registrar.nextEpoch(_b32(account)), 1);
    }

    function test_directPath_cannotRepeatOrLowerTheEpoch() public {
        address account = makeAddr("account");
        vm.startPrank(account);
        registrar.registerLeaf(_b32(account), COMMITMENT, 5, DST_CHAIN, DST_REGISTRY, "");

        vm.expectRevert(abi.encodeWithSelector(IRegistrar.Registrar__StaleEpoch.selector, 6, 5));
        registrar.registerLeaf(_b32(account), COMMITMENT, 5, DST_CHAIN, DST_REGISTRY, "");
        vm.expectRevert(abi.encodeWithSelector(IRegistrar.Registrar__StaleEpoch.selector, 6, 2));
        registrar.registerLeaf(_b32(account), COMMITMENT, 2, DST_CHAIN, DST_REGISTRY, "");

        // Gaps are fine; only the order is fixed.
        registrar.registerLeaf(_b32(account), COMMITMENT, 9, DST_CHAIN, DST_REGISTRY, "");
        vm.stopPrank();
        assertEq(registrar.nextEpoch(_b32(account)), 10);
        assertEq(mm.getWidth(), 2);
    }

    function test_relayedSignature_landsOnce() public {
        (address eoa, uint256 pk) = makeAddrAndKey("eoa");
        bytes memory sig = _sign(pk, _b32(eoa), 2);
        registrar.registerLeaf(_b32(eoa), COMMITMENT, 2, DST_CHAIN, DST_REGISTRY, sig);

        // Whoever holds the signature cannot land it again: the epoch is consumed.
        vm.expectRevert(abi.encodeWithSelector(IRegistrar.Registrar__StaleEpoch.selector, 3, 2));
        registrar.registerLeaf(_b32(eoa), COMMITMENT, 2, DST_CHAIN, DST_REGISTRY, sig);
        assertEq(mm.getWidth(), 1);
    }

    function test_epochIsPerAccount() public {
        address a = makeAddr("a");
        address b = makeAddr("b");
        vm.prank(a);
        registrar.registerLeaf(_b32(a), COMMITMENT, 7, DST_CHAIN, DST_REGISTRY, "");
        vm.prank(b);
        registrar.registerLeaf(_b32(b), COMMITMENT, 0, DST_CHAIN, DST_REGISTRY, "");
        assertEq(registrar.nextEpoch(_b32(a)), 8);
        assertEq(registrar.nextEpoch(_b32(b)), 1);
    }
}
