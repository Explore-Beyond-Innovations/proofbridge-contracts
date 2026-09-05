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

contract ToggleGuard is IPositionGuard {
    bool public busy;

    function setBusy(bool b) external {
        busy = b;
    }

    function hasOpenPositions(bytes32) external view returns (bool) {
        return busy;
    }
}

/// Vector-driven tests; the Soroban registry suite consumes the same JSON.
contract BLSKeyRegistryTest is Test {
    using stdJson for string;

    // The vectors bind the Sepolia registry to this chain id + dummy address.
    uint256 constant CHAIN_ID = 11155111;
    address constant REGISTRY = 0x1111111111111111111111111111111111111111;
    uint64 constant T0 = 1_700_000_000;

    string v;
    BLSKeyRegistry registry;

    function setUp() public {
        v = vm.readFile("../test-vectors/bls-encodings.json");
        vm.chainId(CHAIN_ID);
        vm.warp(T0);

        // Deploy normally (auto-links the SCL libraries), then move the
        // runtime code to the address the vector digests bind.
        BLSKeyRegistry impl = new BLSKeyRegistry(address(this));
        vm.etch(REGISTRY, address(impl).code);
        vm.store(REGISTRY, bytes32(0), bytes32(uint256(uint160(address(this))))); // admin
        registry = BLSKeyRegistry(REGISTRY);
    }

    // =========================================================================
    // Vector helpers
    // =========================================================================

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

    // ---- registry v2 slot vectors: `slots.<who>.registrations[i]` (nonce i, distinct key) ----

    function slotPath(string memory who, uint256 i) internal pure returns (string memory) {
        return string.concat(".slots.", who, ".registrations[", vm.toString(i), "]");
    }

    function slotAuth(string memory who, uint256 i) internal view returns (BLSKeyRegistry.OwnerAuth memory) {
        string memory path = string.concat(slotPath(who, i), ".ownerSig");
        return isMaker(who) ? sep53Auth(path) : eip712Auth(path);
    }

    function isMaker(string memory who) internal pure returns (bool) {
        return keccak256(bytes(who)) == keccak256("makerOnSepolia");
    }

    /// Registers slot vector i for `who` at nonce i; returns the slot id.
    function registerSlot(string memory who, uint256 i) internal returns (uint32) {
        return registry.register(
            v.readBytes32(string.concat(".slots.", who, ".account")),
            slotAuth(who, i),
            v.readBytes(string.concat(slotPath(who, i), ".pkNative")),
            v.readBytes(string.concat(slotPath(who, i), ".pop")),
            i
        );
    }

    function slotCommitment(string memory who, uint256 i) internal view returns (bytes32) {
        return v.readBytes32(string.concat(slotPath(who, i), ".commitment"));
    }

    /// `slots.<who>.setValidUntil[]` is (slotId, validUntil) x {1, graceTs}, index = slotId*2 + (validUntil==1 ? 0 : 1).
    function svuAuth(string memory who, uint32 slotId, bool retire)
        internal
        view
        returns (BLSKeyRegistry.OwnerAuth memory)
    {
        string memory path = string.concat(
            ".slots.", who, ".setValidUntil[", vm.toString(uint256(slotId) * 2 + (retire ? 0 : 1)), "].ownerSig"
        );
        return isMaker(who) ? sep53Auth(path) : eip712Auth(path);
    }

    function graceTs() internal view returns (uint64) {
        return uint64(vm.parseUint(v.readString(".slots.graceTs")));
    }

    function setValidUntil(string memory who, uint32 slotId, bool retire) internal {
        registry.setValidUntil(
            v.readBytes32(string.concat(".slots.", who, ".account")),
            svuAuth(who, slotId, retire),
            slotId,
            retire ? 1 : graceTs()
        );
    }

    function busyGuard() internal {
        address[] memory guards = new address[](1);
        guards[0] = address(new MockGuard());
        registry.setPositionGuards(guards);
    }

    // =========================================================================
    // Happy paths
    // =========================================================================

    function test_registerStellarHomeAccountViaSep53() public {
        bytes32 account = registerMaker();
        assertEq(registry.commitmentAt(account, 0), reg32("makerOnSepolia", "commitment"));
        assertEq(registry.nonceOf(account), 1);
        assertEq(registry.nextSlotId(account), 1);
        assertEq(registry.liveSlots(account).length, 1);
    }

    function test_registerEvmHomeAccountViaEip712() public {
        bytes32 account = registerBridger();
        assertEq(registry.commitmentAt(account, 0), reg32("bridgerOnSepolia", "commitment"));
        BLSKeyRegistry.KeySlot memory slot = registry.lookup(account, 0);
        assertEq(slot.validUntil, 0);
        assertEq(slot.registeredAt, T0);
    }

    function test_revokeStellarHomeThenKeyIsGone() public {
        bytes32 account = registerMaker();
        registry.revoke(account, sep53Auth(".registration.makerOnSepolia.revokeAtNonce1.ownerSig"), 1);
        vm.expectRevert(BLSKeyRegistry.NoSuchSlot.selector);
        registry.commitmentAt(account, 0);
        assertEq(registry.nonceOf(account), 2);
        assertEq(registry.liveSlots(account).length, 0);
    }

    function test_revokeEvmHomeWithNonce1Signature() public {
        bytes32 account = registerBridger();
        registry.revoke(account, eip712Auth(".registration.bridgerOnSepolia.revokeAtNonce1.ownerSig"), 1);
        vm.expectRevert(BLSKeyRegistry.NoSuchSlot.selector);
        registry.commitmentAt(account, 0);
    }

    // =========================================================================
    // Slots: additive register, monotonic ids, cap + prune, key reuse
    // =========================================================================

    function test_additiveRegisterAssignsMonotonicSlotIds() public {
        bytes32 account = v.readBytes32(".slots.bridgerOnSepolia.account");
        for (uint256 i = 0; i < 3; i++) {
            assertEq(registerSlot("bridgerOnSepolia", i), uint32(i));
            assertEq(registry.commitmentAt(account, uint32(i)), slotCommitment("bridgerOnSepolia", i));
        }
        assertEq(registry.nonceOf(account), 3);
        assertEq(registry.liveSlots(account).length, 3);
        // Earlier slots are untouched by later registrations.
        assertEq(registry.commitmentAt(account, 0), slotCommitment("bridgerOnSepolia", 0));
    }

    function test_sixthSlotRevertsRegistryFull() public {
        for (uint256 i = 0; i < 5; i++) {
            registerSlot("makerOnSepolia", i);
        }
        vm.expectRevert(BLSKeyRegistry.RegistryFull.selector);
        registerSlot("makerOnSepolia", 5);
    }

    /// A slot past validUntil + GRACE_PERIOD is pruned to make room; its id is never reissued.
    function test_registerAtCapPrunesExpiredSlot() public {
        bytes32 account = v.readBytes32(".slots.makerOnSepolia.account");
        for (uint256 i = 0; i < 5; i++) {
            registerSlot("makerOnSepolia", i);
        }
        setValidUntil("makerOnSepolia", 2, true); // validUntil = 1
        vm.warp(T0 + 1); // past grace already (1 + 30 days < T0)

        vm.expectEmit(true, true, false, true, REGISTRY);
        emit BLSKeyRegistry.SlotPruned(account, 2);
        assertEq(registerSlot("makerOnSepolia", 5), 5);

        vm.expectRevert(BLSKeyRegistry.NoSuchSlot.selector);
        registry.lookup(account, 2);
        assertEq(registry.liveSlots(account).length, 5);
        assertEq(registry.nextSlotId(account), 6);
    }

    /// In-grace slots still count toward the cap and are not pruned.
    function test_inGraceSlotIsNotPruned() public {
        for (uint256 i = 0; i < 5; i++) {
            registerSlot("makerOnSepolia", i);
        }
        setValidUntil("makerOnSepolia", 0, false); // graceTs, in the future
        vm.expectRevert(BLSKeyRegistry.RegistryFull.selector);
        registerSlot("makerOnSepolia", 5);
    }

    /// The T1 "re-register the same key at nonce 1" vector is now a reuse: rejected.
    function test_reusedKeyRejected() public {
        bytes32 account = registerMaker();
        vm.expectRevert(BLSKeyRegistry.KeyPreviouslyUsed.selector);
        registry.register(
            account,
            sep53Auth(".registration.makerOnSepolia.registerAtNonce1.ownerSig"),
            reg("makerOnSepolia", "registerAtNonce1.pkNative"),
            reg("makerOnSepolia", "registerAtNonce1.pop"),
            1
        );
    }

    /// A retired key stays used: it cannot re-enter a slot.
    function test_reusedKeyRejectedAfterRetirement() public {
        bytes32 account = registerMaker(); // == slots.makerOnSepolia slot 0 key
        setValidUntil("makerOnSepolia", 0, true);
        vm.expectRevert(BLSKeyRegistry.KeyPreviouslyUsed.selector);
        registry.register(
            account,
            sep53Auth(".registration.makerOnSepolia.registerAtNonce1.ownerSig"),
            reg("makerOnSepolia", "registerAtNonce1.pkNative"),
            reg("makerOnSepolia", "registerAtNonce1.pop"),
            1
        );
    }

    /// revoke drops every slot; the next registration continues the id sequence.
    function test_revokeClearsAllSlotsAndNextIdKeepsAdvancing() public {
        bytes32 account = registerMaker(); // nonce 0 -> slot 0
        registry.revoke(account, sep53Auth(".registration.makerOnSepolia.revokeAtNonce1.ownerSig"), 1);
        assertEq(registry.liveSlots(account).length, 0);

        assertEq(registerSlot("makerOnSepolia", 2), 1); // nonce 2, fresh key -> slot 1
        assertEq(registry.liveSlots(account).length, 1);
        assertEq(registry.nextSlotId(account), 2);
        vm.expectRevert(BLSKeyRegistry.NoSuchSlot.selector);
        registry.lookup(account, 0);
    }

    // =========================================================================
    // setValidUntil: shorten-only, nonce-free, use-time expiry
    // =========================================================================

    function test_setValidUntilRetiresImmediately() public {
        bytes32 account = v.readBytes32(".slots.bridgerOnSepolia.account");
        registerSlot("bridgerOnSepolia", 0);
        uint256 nonceBefore = registry.nonceOf(account);

        vm.expectEmit(true, true, false, true, REGISTRY);
        emit BLSKeyRegistry.SlotValidUntilSet(account, 0, 1);
        setValidUntil("bridgerOnSepolia", 0, true);

        vm.expectRevert(BLSKeyRegistry.SlotExpired.selector);
        registry.commitmentAt(account, 0);
        assertEq(registry.lookup(account, 0).validUntil, 1); // history kept
        assertEq(registry.nonceOf(account), nonceBefore); // nonce-free
    }

    function test_setValidUntilGraceBoundary() public {
        bytes32 account = v.readBytes32(".slots.makerOnSepolia.account");
        registerSlot("makerOnSepolia", 0);
        setValidUntil("makerOnSepolia", 0, false);
        uint64 g = graceTs();

        vm.warp(g - 1);
        assertEq(registry.commitmentAt(account, 0), slotCommitment("makerOnSepolia", 0));
        vm.warp(g);
        vm.expectRevert(BLSKeyRegistry.SlotExpired.selector);
        registry.commitmentAt(account, 0);
    }

    function test_setValidUntilShortenOnly() public {
        registerSlot("bridgerOnSepolia", 0);
        setValidUntil("bridgerOnSepolia", 0, true); // -> 1
        vm.expectRevert(BLSKeyRegistry.BadValidUntil.selector);
        setValidUntil("bridgerOnSepolia", 0, false); // graceTs > 1: extend rejected
    }

    function test_setValidUntilZeroRejected() public {
        bytes32 account = v.readBytes32(".slots.bridgerOnSepolia.account");
        registerSlot("bridgerOnSepolia", 0);
        vm.expectRevert(BLSKeyRegistry.BadValidUntil.selector);
        registry.setValidUntil(account, svuAuth("bridgerOnSepolia", 0, true), 0, 0);
    }

    function test_setValidUntilUnknownSlotRejected() public {
        bytes32 account = v.readBytes32(".slots.bridgerOnSepolia.account");
        registerSlot("bridgerOnSepolia", 0);
        vm.expectRevert(BLSKeyRegistry.NoSuchSlot.selector);
        registry.setValidUntil(account, svuAuth("bridgerOnSepolia", 1, true), 1, 1);
    }

    function test_setValidUntilWrongSignerRejected() public {
        bytes32 account = v.readBytes32(".slots.bridgerOnSepolia.account");
        registerSlot("bridgerOnSepolia", 0);
        BLSKeyRegistry.OwnerAuth memory auth = svuAuth("bridgerOnSepolia", 0, true);
        auth.data[64] = auth.data[64] == bytes1(uint8(27)) ? bytes1(uint8(28)) : bytes1(uint8(27));
        vm.expectRevert(BLSKeyRegistry.OwnerMismatch.selector);
        registry.setValidUntil(account, auth, 0, 1);
    }

    function test_setValidUntilSigBoundToSlotAndValue() public {
        bytes32 account = v.readBytes32(".slots.makerOnSepolia.account");
        registerSlot("makerOnSepolia", 0);
        registerSlot("makerOnSepolia", 1);
        // slot-0 signature replayed against slot 1
        vm.expectRevert(BLSKeyRegistry.OwnerMismatch.selector);
        registry.setValidUntil(account, svuAuth("makerOnSepolia", 0, true), 1, 1);
        // value-1 signature used for a different value
        vm.expectRevert(BLSKeyRegistry.OwnerMismatch.selector);
        registry.setValidUntil(account, svuAuth("makerOnSepolia", 0, true), 0, 2);
    }

    /// A retirement signed before later writes still lands (no nonce), and replay is a no-op.
    function test_preSignedRetirementSurvivesLaterWritesAndReplayIsNoop() public {
        bytes32 account = v.readBytes32(".slots.bridgerOnSepolia.account");
        registerSlot("bridgerOnSepolia", 0);
        BLSKeyRegistry.OwnerAuth memory preSigned = svuAuth("bridgerOnSepolia", 0, true);

        registerSlot("bridgerOnSepolia", 1); // rotation
        setValidUntil("bridgerOnSepolia", 1, false); // another retirement on a different slot
        uint256 nonce = registry.nonceOf(account);

        registry.setValidUntil(account, preSigned, 0, 1);
        vm.expectRevert(BLSKeyRegistry.SlotExpired.selector);
        registry.commitmentAt(account, 0);

        vm.expectRevert(BLSKeyRegistry.BadValidUntil.selector);
        registry.setValidUntil(account, preSigned, 0, 1); // replay
        assertEq(registry.nonceOf(account), nonce);
        assertEq(registry.commitmentAt(account, 1), slotCommitment("bridgerOnSepolia", 1)); // slot 1 untouched
    }

    // =========================================================================
    // T-01 / T-04: guards never gate retirement or additive register; PoP per slot
    // =========================================================================

    /// T-01: with the account in flight, retirement and a new slot both succeed.
    function test_T01_retireAndRegisterWhileInFlight() public {
        bytes32 account = v.readBytes32(".slots.makerOnSepolia.account");
        registerSlot("makerOnSepolia", 0);
        busyGuard();

        setValidUntil("makerOnSepolia", 0, true);
        vm.expectRevert(BLSKeyRegistry.SlotExpired.selector);
        registry.commitmentAt(account, 0);

        assertEq(registerSlot("makerOnSepolia", 1), 1);
        assertEq(registry.commitmentAt(account, 1), slotCommitment("makerOnSepolia", 1));
    }

    function test_T01_evmHomeRetireAndRegisterWhileInFlight() public {
        registerSlot("bridgerOnSepolia", 0);
        busyGuard();
        setValidUntil("bridgerOnSepolia", 0, true);
        assertEq(registerSlot("bridgerOnSepolia", 1), 1);
    }

    /// T-04: a second slot needs its own PoP; a PoP bound to another nonce/key fails.
    function test_T04_secondSlotNeedsFreshPop() public {
        bytes32 account = v.readBytes32(".slots.bridgerOnSepolia.account");
        registerSlot("bridgerOnSepolia", 0);
        vm.expectRevert(BLSKeyRegistry.InvalidPop.selector);
        registry.register(
            account,
            slotAuth("bridgerOnSepolia", 1),
            v.readBytes(string.concat(slotPath("bridgerOnSepolia", 1), ".pkNative")),
            v.readBytes(string.concat(slotPath("bridgerOnSepolia", 0), ".pop")), // slot-0 PoP
            1
        );
    }

    function test_firstRegistrationIgnoresBusyGuards() public {
        busyGuard();
        bytes32 account = registerMaker();
        assertEq(registry.commitmentAt(account, 0), reg32("makerOnSepolia", "commitment"));
    }

    // =========================================================================
    // Negative paths (T1 set, carried forward)
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
        busyGuard();
        vm.expectRevert(BLSKeyRegistry.AccountInFlight.selector);
        registry.revoke(account, sep53Auth(".registration.makerOnSepolia.revokeAtNonce1.ownerSig"), 1);
    }

    // A single open position in EITHER escrow must block the revoke; both clear allows it.
    function test_revokeChecksEveryGuard() public {
        bytes32 account = registerMaker();
        ToggleGuard adSide = new ToggleGuard();
        ToggleGuard orderSide = new ToggleGuard();
        address[] memory guards = new address[](2);
        guards[0] = address(adSide);
        guards[1] = address(orderSide);
        registry.setPositionGuards(guards);

        adSide.setBusy(true);
        vm.expectRevert(BLSKeyRegistry.AccountInFlight.selector);
        registry.revoke(account, sep53Auth(".registration.makerOnSepolia.revokeAtNonce1.ownerSig"), 1);

        adSide.setBusy(false);
        orderSide.setBusy(true);
        vm.expectRevert(BLSKeyRegistry.AccountInFlight.selector);
        registry.revoke(account, sep53Auth(".registration.makerOnSepolia.revokeAtNonce1.ownerSig"), 1);

        orderSide.setBusy(false);
        registry.revoke(account, sep53Auth(".registration.makerOnSepolia.revokeAtNonce1.ownerSig"), 1);
        vm.expectRevert(BLSKeyRegistry.NoSuchSlot.selector);
        registry.commitmentAt(account, 0);
    }
}
