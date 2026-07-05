// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {BLSKeyRegistry, IPositionGuard} from "../src/BLSKeyRegistry.sol";

contract MockGuard is IPositionGuard {
    function hasOpenPositions(bytes32) external pure returns (bool) {
        return true;
    }
}

/// Vector-driven tests; the Soroban registry suite consumes the same JSON.
contract BLSKeyRegistryTest is Test {
    using stdJson for string;

    // The vectors bind the Sepolia registry to this chain id + dummy address.
    uint256 constant CHAIN_ID = 11155111;
    address constant REGISTRY = 0x1111111111111111111111111111111111111111;

    string v;
    BLSKeyRegistry registry;

    function setUp() public {
        v = vm.readFile("../test-vectors/bls-encodings.json");
        vm.chainId(CHAIN_ID);

        // Deploy normally (auto-links the SCL libraries), then move the
        // runtime code to the address the vector digests bind.
        BLSKeyRegistry impl = new BLSKeyRegistry(address(this));
        vm.etch(REGISTRY, address(impl).code);
        vm.store(REGISTRY, bytes32(0), bytes32(uint256(uint160(address(this))))); // admin
        registry = BLSKeyRegistry(REGISTRY);
    }

    function reg(string memory who, string memory field) internal view returns (bytes memory) {
        return v.readBytes(string.concat(".registration.", who, ".", field));
    }

    function reg32(string memory who, string memory field) internal view returns (bytes32) {
        return v.readBytes32(string.concat(".registration.", who, ".", field));
    }

    function sep53Auth(string memory path) internal view returns (BLSKeyRegistry.OwnerAuth memory) {
        bytes memory data = abi.encode(
            uint256(v.readBytes32(string.concat(path, ".scl.r"))),
            uint256(v.readBytes32(string.concat(path, ".scl.s"))),
            uint256(v.readBytes32(string.concat(path, ".scl.edX"))),
            uint256(v.readBytes32(string.concat(path, ".scl.edY")))
        );
        return BLSKeyRegistry.OwnerAuth(BLSKeyRegistry.Scheme.Sep53, data);
    }

    function eip712Auth(string memory path) internal view returns (BLSKeyRegistry.OwnerAuth memory) {
        bytes memory data = abi.encodePacked(
            v.readBytes32(string.concat(path, ".sig.r")),
            v.readBytes32(string.concat(path, ".sig.s")),
            uint8(v.readUint(string.concat(path, ".sig.v")))
        );
        return BLSKeyRegistry.OwnerAuth(BLSKeyRegistry.Scheme.Eip712, data);
    }

    function registerMaker() internal returns (bytes32 account) {
        account = reg32("makerOnSepolia", "account");
        registry.register(
            account,
            sep53Auth(".registration.makerOnSepolia.ownerSig"),
            reg("makerOnSepolia", "pkNative"),
            reg("makerOnSepolia", "pop"),
            0
        );
    }

    function registerBridger() internal returns (bytes32 account) {
        account = reg32("bridgerOnSepolia", "account");
        registry.register(
            account,
            eip712Auth(".registration.bridgerOnSepolia.ownerSig"),
            reg("bridgerOnSepolia", "pkNative"),
            reg("bridgerOnSepolia", "pop"),
            0
        );
    }

    // =========================================================================
    // Happy paths
    // =========================================================================

    function test_registerStellarHomeAccountViaSep53() public {
        bytes32 account = registerMaker();
        assertEq(registry.keyOf(account), reg32("makerOnSepolia", "commitment"));
        assertEq(registry.nonceOf(account), 1);
    }

    function test_registerEvmHomeAccountViaEip712() public {
        bytes32 account = registerBridger();
        assertEq(registry.keyOf(account), reg32("bridgerOnSepolia", "commitment"));
    }

    function test_revokeStellarHomeThenKeyIsGone() public {
        bytes32 account = registerMaker();
        registry.revoke(account, sep53Auth(".registration.makerOnSepolia.revokeAtNonce1.ownerSig"), 1);
        vm.expectRevert(BLSKeyRegistry.NotRegistered.selector);
        registry.keyOf(account);
        assertEq(registry.nonceOf(account), 2);
    }

    function test_revokeEvmHomeWithNonce1Signature() public {
        bytes32 account = registerBridger();
        registry.revoke(account, eip712Auth(".registration.bridgerOnSepolia.revokeAtNonce1.ownerSig"), 1);
        vm.expectRevert(BLSKeyRegistry.NotRegistered.selector);
        registry.keyOf(account);
    }

    // =========================================================================
    // Negative paths
    // =========================================================================

    /// Same nonce -> BadNonce; bumped nonce with a stale PoP -> InvalidPop.
    function test_reregisterWithoutFreshPopReverts() public {
        bytes32 account = registerMaker();
        BLSKeyRegistry.OwnerAuth memory auth = sep53Auth(".registration.makerOnSepolia.ownerSig");
        bytes memory pk = reg("makerOnSepolia", "pkNative");
        bytes memory pop = reg("makerOnSepolia", "pop");

        vm.expectRevert(BLSKeyRegistry.BadNonce.selector);
        registry.register(account, auth, pk, pop, 0);

        vm.expectRevert(BLSKeyRegistry.InvalidPop.selector);
        registry.register(account, auth, pk, pop, 1);
    }

    function test_identityPubkeyRejected() public {
        vm.expectRevert(BLSKeyRegistry.IdentityKey.selector);
        registry.register(
            reg32("makerOnSepolia", "account"),
            sep53Auth(".registration.makerOnSepolia.ownerSig"),
            v.readBytes(".negative.identityPubkey.eip2537"),
            reg("makerOnSepolia", "pop"),
            0
        );
    }

    function test_popSignedWithWrongDstRejected() public {
        vm.expectRevert(BLSKeyRegistry.InvalidPop.selector);
        registry.register(
            reg32("makerOnSepolia", "account"),
            sep53Auth(".registration.makerOnSepolia.ownerSig"),
            reg("makerOnSepolia", "pkNative"),
            v.readBytes(".negative.popWrongDstSepolia.pop"),
            0
        );
    }

    function test_eip712WrongSignerRejected() public {
        BLSKeyRegistry.OwnerAuth memory auth = eip712Auth(".registration.bridgerOnSepolia.ownerSig");
        auth.data[64] = auth.data[64] == bytes1(uint8(27)) ? bytes1(uint8(28)) : bytes1(uint8(27));

        vm.expectRevert(BLSKeyRegistry.OwnerMismatch.selector);
        registry.register(
            reg32("bridgerOnSepolia", "account"),
            auth,
            reg("bridgerOnSepolia", "pkNative"),
            reg("bridgerOnSepolia", "pop"),
            0
        );
    }

    function test_sep53TamperedPointRejected() public {
        BLSKeyRegistry.OwnerAuth memory auth = sep53Auth(".registration.makerOnSepolia.ownerSig");
        (uint256 r, uint256 s, uint256 edX, uint256 edY) = abi.decode(auth.data, (uint256, uint256, uint256, uint256));
        auth.data = abi.encode(r, s, edX + 1, edY);

        vm.expectRevert(BLSKeyRegistry.OwnerMismatch.selector);
        registry.register(
            reg32("makerOnSepolia", "account"), auth, reg("makerOnSepolia", "pkNative"), reg("makerOnSepolia", "pop"), 0
        );
    }

    function test_revokeUnregisteredRejected() public {
        vm.expectRevert(BLSKeyRegistry.NotRegistered.selector);
        registry.revoke(
            reg32("makerOnSepolia", "account"), sep53Auth(".registration.makerOnSepolia.revokeAtNonce1.ownerSig"), 0
        );
    }

    function test_revokeBlockedWhileInFlight() public {
        bytes32 account = registerMaker();
        registry.setPositionGuard(address(new MockGuard()));

        vm.expectRevert(BLSKeyRegistry.AccountInFlight.selector);
        registry.revoke(account, sep53Auth(".registration.makerOnSepolia.revokeAtNonce1.ownerSig"), 1);
    }
}
