// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {IBLSKeyRegistry} from "src/interfaces/IBLSKeyRegistry.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {BLSKeyRegistry, IPositionGuard} from "../src/BLSKeyRegistry.sol";
import {KeyMessages} from "../src/libraries/KeyMessages.sol";
import {OwnerAuthVectors} from "./utils/OwnerAuthVectors.sol";

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

    /// `ownerAuth.<maker|bridger>.<entry>` (2.6): one signature whose legs name both registries.
    function oa(string memory who, string memory entry) internal view returns (IBLSKeyRegistry.OwnerAuth memory) {
        return OwnerAuthVectors.auth(v, oaPath(who, entry));
    }

    function oaPath(string memory who, string memory entry) internal pure returns (string memory) {
        return string.concat(".ownerAuth.", isMaker(who) ? "maker" : "bridger", ".", entry);
    }

    function idx(string memory name, uint256 i) internal pure returns (string memory) {
        return string.concat(name, "[", vm.toString(i), "]");
    }

    function registerMaker() internal returns (bytes32 account) {
        account = reg32("makerOnSepolia", "account");
        registry.register(
            account,
            oa("makerOnSepolia", "register[0]"),
            reg("makerOnSepolia", "pkNative"),
            reg("makerOnSepolia", "pop"),
            0
        );
    }

    function registerBridger() internal returns (bytes32 account) {
        account = reg32("bridgerOnSepolia", "account");
        registry.register(
            account,
            oa("bridgerOnSepolia", "register[0]"),
            reg("bridgerOnSepolia", "pkNative"),
            reg("bridgerOnSepolia", "pop"),
            0
        );
    }

    // ---- registry v2 slot vectors: `slots.<who>.registrations[i]` (nonce i, distinct key) ----

    function slotPath(string memory who, uint256 i) internal pure returns (string memory) {
        return string.concat(".slots.", who, ".registrations[", vm.toString(i), "]");
    }

    function slotAuth(string memory who, uint256 i) internal view returns (IBLSKeyRegistry.OwnerAuth memory) {
        return oa(who, idx("register", i));
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

    /// `ownerAuth.<who>.retire[]` is (key, validUntil) x {1, graceTs}, index = key*2 + (validUntil==1 ? 0 : 1).
    function svuAuth(string memory who, uint32 key, bool retire)
        internal
        view
        returns (IBLSKeyRegistry.OwnerAuth memory)
    {
        return oa(who, idx("retire", uint256(key) * 2 + (retire ? 0 : 1)));
    }

    /// The fingerprint key i is named by (on EVM, the stored commitment).
    function fp(string memory who, uint256 i) internal view returns (bytes32) {
        return OwnerAuthVectors.key(v, oaPath(who, idx("register", i)));
    }

    function graceTs() internal view returns (uint64) {
        return uint64(vm.parseUint(v.readString(".slots.graceTs")));
    }

    /// Retires key i (whatever slot it occupies) under its pre-signed `RetireKey`.
    function setValidUntil(string memory who, uint32 key, bool retire) internal {
        registry.setValidUntil(
            v.readBytes32(string.concat(".slots.", who, ".account")),
            svuAuth(who, key, retire),
            fp(who, key),
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

    function test_registerEvmHomeAccountViaSecp256k1() public {
        bytes32 account = registerBridger();
        assertEq(registry.commitmentAt(account, 0), reg32("bridgerOnSepolia", "commitment"));
        IBLSKeyRegistry.KeySlot memory slot = registry.lookup(account, 0);
        assertEq(slot.validUntil, 0);
        assertEq(slot.registeredAt, T0);
    }

    function test_revokeStellarHomeThenKeyIsGone() public {
        bytes32 account = registerMaker();
        registry.revoke(account, oa("makerOnSepolia", "revoke[1]"), 1);
        vm.expectRevert(IBLSKeyRegistry.NoSuchSlot.selector);
        registry.commitmentAt(account, 0);
        assertEq(registry.nonceOf(account), 2);
        assertEq(registry.liveSlots(account).length, 0);
    }

    function test_revokeEvmHomeWithNonce1Signature() public {
        bytes32 account = registerBridger();
        registry.revoke(account, oa("bridgerOnSepolia", "revoke[1]"), 1);
        vm.expectRevert(IBLSKeyRegistry.NoSuchSlot.selector);
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
        vm.expectRevert(IBLSKeyRegistry.RegistryFull.selector);
        registerSlot("makerOnSepolia", 5);
    }

    /// A slot past validUntil + GRACE_PERIOD is pruned to make room; its id is never reissued.
    function idleGuard() internal {
        address[] memory guards = new address[](1);
        guards[0] = address(new ToggleGuard());
        registry.setPositionGuards(guards);
    }

    function test_registerAtCapPrunesExpiredSlot() public {
        bytes32 account = v.readBytes32(".slots.makerOnSepolia.account");
        idleGuard();
        for (uint256 i = 0; i < 5; i++) {
            registerSlot("makerOnSepolia", i);
        }
        setValidUntil("makerOnSepolia", 2, true); // validUntil = 1, expired at the kill (D14)
        vm.warp(T0 + 1);
        // D17: the guard is wired and reports no positions, so no order can need the dead slot's
        // history — pruned at once.

        vm.expectEmit(true, true, false, true, REGISTRY);
        emit IBLSKeyRegistry.SlotPruned(account, 2);
        assertEq(registerSlot("makerOnSepolia", 5), 5);

        vm.expectRevert(IBLSKeyRegistry.NoSuchSlot.selector);
        registry.lookup(account, 2);
        assertEq(registry.liveSlots(account).length, 5);
        assertEq(registry.nextSlotId(account), 6);
    }

    /// #422 D17: while a guard reports positions a dead slot keeps its place for the grace — an open
    /// order's cancel may still ask about it — and leaves once the grace is over regardless.
    function test_registerAtCap_deadSlotKeptWhileInFlight_prunedAfterTheGrace() public {
        bytes32 account = v.readBytes32(".slots.makerOnSepolia.account");
        busyGuard();
        for (uint256 i = 0; i < 5; i++) {
            registerSlot("makerOnSepolia", i);
        }
        setValidUntil("makerOnSepolia", 2, true);
        vm.warp(T0 + 1);
        vm.expectRevert(IBLSKeyRegistry.RegistryFull.selector);
        registerSlot("makerOnSepolia", 5);

        vm.warp(T0 + 30 days + 1);
        assertEq(registerSlot("makerOnSepolia", 5), 5);
        vm.expectRevert(IBLSKeyRegistry.NoSuchSlot.selector);
        registry.lookup(account, 2);
    }

    /// #422 D17b: with no guard wired there is nobody to ask, so a dead slot keeps its place for the grace.
    function test_registerAtCap_noGuardWired_deadSlotKeptUntilTheGrace() public {
        bytes32 account = v.readBytes32(".slots.makerOnSepolia.account");
        for (uint256 i = 0; i < 5; i++) {
            registerSlot("makerOnSepolia", i);
        }
        setValidUntil("makerOnSepolia", 2, true);
        vm.warp(T0 + 1);
        vm.expectRevert(IBLSKeyRegistry.RegistryFull.selector);
        registerSlot("makerOnSepolia", 5);

        vm.warp(T0 + 30 days + 1);
        assertEq(registerSlot("makerOnSepolia", 5), 5);
        vm.expectRevert(IBLSKeyRegistry.NoSuchSlot.selector);
        registry.lookup(account, 2);
    }

    /// #422 D14b: a shorten on a slot that already died cannot move its death later — a re-kill
    /// after an order's window must not erase an expiry inside it.
    function test_setValidUntil_recordedExpiryOnlyMovesEarlier() public {
        bytes32 account = v.readBytes32(".slots.makerOnSepolia.account");
        registerSlot("makerOnSepolia", 0);
        setValidUntil("makerOnSepolia", 0, false); // at T0, naming graceTs
        uint64 g = graceTs();
        vm.warp(g + 100);
        setValidUntil("makerOnSepolia", 0, true); // a kill to 1, after the slot died at g
        assertTrue(registry.anySlotExpiredWithin(account, g, g), "still died at g");
        assertFalse(registry.anySlotExpiredWithin(account, g + 1, type(uint64).max), "not at the re-kill");
    }

    /// In-grace slots still count toward the cap and are not pruned.
    function test_inGraceSlotIsNotPruned() public {
        for (uint256 i = 0; i < 5; i++) {
            registerSlot("makerOnSepolia", i);
        }
        setValidUntil("makerOnSepolia", 0, false); // graceTs, in the future
        vm.expectRevert(IBLSKeyRegistry.RegistryFull.selector);
        registerSlot("makerOnSepolia", 5);
    }

    /// The T1 "re-register the same key at nonce 1" vector is now a reuse: rejected.
    function test_reusedKeyRejected() public {
        bytes32 account = registerMaker();
        vm.expectRevert(IBLSKeyRegistry.KeyPreviouslyUsed.selector);
        registry.register(
            account,
            oa("makerOnSepolia", "reuseKey0AtNonce1"),
            reg("makerOnSepolia", "registerAtNonce1.pkNative"),
            reg("makerOnSepolia", "registerAtNonce1.pop"),
            1
        );
    }

    /// A retired key stays used: it cannot re-enter a slot.
    function test_reusedKeyRejectedAfterRetirement() public {
        bytes32 account = registerMaker(); // == slots.makerOnSepolia slot 0 key
        setValidUntil("makerOnSepolia", 0, true);
        vm.expectRevert(IBLSKeyRegistry.KeyPreviouslyUsed.selector);
        registry.register(
            account,
            oa("makerOnSepolia", "reuseKey0AtNonce1"),
            reg("makerOnSepolia", "registerAtNonce1.pkNative"),
            reg("makerOnSepolia", "registerAtNonce1.pop"),
            1
        );
    }

    /// revoke drops every slot; the next registration continues the id sequence.
    function test_revokeClearsAllSlotsAndNextIdKeepsAdvancing() public {
        bytes32 account = registerMaker(); // nonce 0 -> slot 0
        registry.revoke(account, oa("makerOnSepolia", "revoke[1]"), 1);
        assertEq(registry.liveSlots(account).length, 0);

        assertEq(registerSlot("makerOnSepolia", 2), 1); // nonce 2, fresh key -> slot 1
        assertEq(registry.liveSlots(account).length, 1);
        assertEq(registry.nextSlotId(account), 2);
        vm.expectRevert(IBLSKeyRegistry.NoSuchSlot.selector);
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
        emit IBLSKeyRegistry.SlotValidUntilSet(account, 0, 1);
        setValidUntil("bridgerOnSepolia", 0, true);

        vm.expectRevert(IBLSKeyRegistry.SlotExpired.selector);
        registry.commitmentAt(account, 0);
        assertEq(registry.lookup(account, 0).validUntil, 1); // history kept
        assertEq(registry.nonceOf(account), nonceBefore); // nonce-free
    }

    /// #422 D12: the escrow's question, answered directly — did any slot expire in [from, to].
    function test_anySlotExpiredWithin() public {
        bytes32 account = v.readBytes32(".slots.makerOnSepolia.account");
        registerSlot("makerOnSepolia", 0);
        assertFalse(registry.anySlotExpiredWithin(account, 0, type(uint64).max), "no expiry: never");
        setValidUntil("makerOnSepolia", 0, false);
        uint64 g = graceTs();
        assertTrue(registry.anySlotExpiredWithin(account, g, g), "the boundary is inclusive");
        assertTrue(registry.anySlotExpiredWithin(account, g - 100, g + 100));
        assertFalse(registry.anySlotExpiredWithin(account, g + 1, g + 100), "after it: no");
        assertFalse(registry.anySlotExpiredWithin(account, 0, g - 1), "before it: no");
    }

    /// #422 D14: our own retirement names `validUntil = 1`; the slot expired at the kill, not in 1970.
    function test_anySlotExpiredWithin_aKillExpiresAtTheKill() public {
        bytes32 account = v.readBytes32(".slots.makerOnSepolia.account");
        registerSlot("makerOnSepolia", 0);
        vm.warp(T0 + 100);
        setValidUntil("makerOnSepolia", 0, true);
        assertTrue(registry.anySlotExpiredWithin(account, T0 + 100, T0 + 100), "the kill's own second");
        assertTrue(registry.anySlotExpiredWithin(account, T0 + 50, T0 + 150));
        assertFalse(registry.anySlotExpiredWithin(account, 0, T0 + 99), "before the kill: no");
        assertFalse(registry.anySlotExpiredWithin(account, T0 + 101, type(uint64).max), "after it: no");
    }

    /// #422 D14: a shorten made before `from`, naming a date inside `[from, to]`, expires at the date.
    function test_anySlotExpiredWithin_anEarlyShortenExpiresAtItsDate() public {
        bytes32 account = v.readBytes32(".slots.makerOnSepolia.account");
        registerSlot("makerOnSepolia", 0);
        setValidUntil("makerOnSepolia", 0, false); // at T0, naming graceTs
        uint64 g = graceTs();
        assertTrue(registry.anySlotExpiredWithin(account, T0 + 1, g), "the date, not the shorten");
        assertFalse(registry.anySlotExpiredWithin(account, T0 + 1, g - 1));
    }

    function test_setValidUntilGraceBoundary() public {
        bytes32 account = v.readBytes32(".slots.makerOnSepolia.account");
        registerSlot("makerOnSepolia", 0);
        setValidUntil("makerOnSepolia", 0, false);
        uint64 g = graceTs();

        vm.warp(g - 1);
        assertEq(registry.commitmentAt(account, 0), slotCommitment("makerOnSepolia", 0));
        vm.warp(g);
        vm.expectRevert(IBLSKeyRegistry.SlotExpired.selector);
        registry.commitmentAt(account, 0);
    }

    function test_setValidUntilShortenOnly() public {
        registerSlot("bridgerOnSepolia", 0);
        setValidUntil("bridgerOnSepolia", 0, true); // -> 1
        vm.expectRevert(IBLSKeyRegistry.BadValidUntil.selector);
        setValidUntil("bridgerOnSepolia", 0, false); // graceTs > 1: extend rejected
    }

    function test_setValidUntilZeroRejected() public {
        bytes32 account = v.readBytes32(".slots.bridgerOnSepolia.account");
        registerSlot("bridgerOnSepolia", 0);
        vm.expectRevert(IBLSKeyRegistry.BadValidUntil.selector);
        registry.setValidUntil(account, svuAuth("bridgerOnSepolia", 0, true), fp("bridgerOnSepolia", 0), 0);
    }

    function test_setValidUntilUnknownSlotRejected() public {
        bytes32 account = v.readBytes32(".slots.bridgerOnSepolia.account");
        registerSlot("bridgerOnSepolia", 0);
        vm.expectRevert(IBLSKeyRegistry.NoSuchSlot.selector);
        registry.setValidUntil(account, svuAuth("bridgerOnSepolia", 1, true), fp("bridgerOnSepolia", 1), 1);
    }

    function test_setValidUntilWrongSignerRejected() public {
        bytes32 account = v.readBytes32(".slots.bridgerOnSepolia.account");
        registerSlot("bridgerOnSepolia", 0);
        IBLSKeyRegistry.OwnerAuth memory auth = svuAuth("bridgerOnSepolia", 0, true);
        auth.sig[64] = auth.sig[64] == bytes1(uint8(27)) ? bytes1(uint8(28)) : bytes1(uint8(27));
        vm.expectRevert(IBLSKeyRegistry.OwnerMismatch.selector);
        registry.setValidUntil(account, auth, fp("bridgerOnSepolia", 0), 1);
    }

    function test_setValidUntilSigBoundToKeyAndValue() public {
        bytes32 account = v.readBytes32(".slots.makerOnSepolia.account");
        registerSlot("makerOnSepolia", 0);
        registerSlot("makerOnSepolia", 1);
        // key-0 signature replayed against key 1
        vm.expectRevert(IBLSKeyRegistry.OwnerMismatch.selector);
        registry.setValidUntil(account, svuAuth("makerOnSepolia", 0, true), fp("makerOnSepolia", 1), 1);
        // value-1 signature used for a different value
        vm.expectRevert(IBLSKeyRegistry.OwnerMismatch.selector);
        registry.setValidUntil(account, svuAuth("makerOnSepolia", 0, true), fp("makerOnSepolia", 0), 2);
    }

    /// A retirement signed before later writes still lands (no nonce), and replay is a no-op.
    function test_preSignedRetirementSurvivesLaterWritesAndReplayIsNoop() public {
        bytes32 account = v.readBytes32(".slots.bridgerOnSepolia.account");
        registerSlot("bridgerOnSepolia", 0);
        IBLSKeyRegistry.OwnerAuth memory preSigned = svuAuth("bridgerOnSepolia", 0, true);

        registerSlot("bridgerOnSepolia", 1); // rotation
        setValidUntil("bridgerOnSepolia", 1, false); // another retirement on a different slot
        uint256 nonce = registry.nonceOf(account);

        registry.setValidUntil(account, preSigned, fp("bridgerOnSepolia", 0), 1);
        vm.expectRevert(IBLSKeyRegistry.SlotExpired.selector);
        registry.commitmentAt(account, 0);

        vm.expectRevert(IBLSKeyRegistry.BadValidUntil.selector);
        registry.setValidUntil(account, preSigned, fp("bridgerOnSepolia", 0), 1); // replay
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
        vm.expectRevert(IBLSKeyRegistry.SlotExpired.selector);
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
        vm.expectRevert(IBLSKeyRegistry.InvalidPop.selector);
        registry.register(
            account,
            slotAuth("bridgerOnSepolia", 1),
            v.readBytes(string.concat(slotPath("bridgerOnSepolia", 1), ".pkNative")),
            v.readBytes(string.concat(slotPath("bridgerOnSepolia", 0), ".pop")), // slot-0 PoP
            1
        );
    }

    /// Retirement is the incident lever: it lands while the registry is paused.
    function test_setValidUntilLandsWhilePaused() public {
        bytes32 account = v.readBytes32(".slots.makerOnSepolia.account");
        registerSlot("makerOnSepolia", 0);
        registry.pause();

        vm.expectRevert(IBLSKeyRegistry.EnforcedPause.selector);
        registerSlot("makerOnSepolia", 1);

        setValidUntil("makerOnSepolia", 0, true);
        vm.expectRevert(IBLSKeyRegistry.SlotExpired.selector);
        registry.commitmentAt(account, 0);
    }

    function test_hasUsableSlot() public {
        bytes32 account = v.readBytes32(".slots.makerOnSepolia.account");
        assertFalse(registry.hasUsableSlot(account));
        registerSlot("makerOnSepolia", 0);
        assertTrue(registry.hasUsableSlot(account));
        setValidUntil("makerOnSepolia", 0, false); // in grace
        assertTrue(registry.hasUsableSlot(account));
        vm.warp(graceTs());
        assertFalse(registry.hasUsableSlot(account));
        registerSlot("makerOnSepolia", 1);
        assertTrue(registry.hasUsableSlot(account));
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
        IBLSKeyRegistry.OwnerAuth memory auth = oa("makerOnSepolia", "register[0]");
        bytes memory pk = reg("makerOnSepolia", "pkNative");
        bytes memory pop = reg("makerOnSepolia", "pop");

        vm.expectRevert(IBLSKeyRegistry.BadNonce.selector);
        registry.register(account, auth, pk, pop, 0);

        vm.expectRevert(IBLSKeyRegistry.InvalidPop.selector);
        registry.register(account, auth, pk, pop, 1);
    }

    function test_identityPubkeyRejected() public {
        vm.expectRevert(IBLSKeyRegistry.IdentityKey.selector);
        registry.register(
            reg32("makerOnSepolia", "account"),
            oa("makerOnSepolia", "register[0]"),
            v.readBytes(".negative.identityPubkey.eip2537"),
            reg("makerOnSepolia", "pop"),
            0
        );
    }

    function test_popSignedWithWrongDstRejected() public {
        vm.expectRevert(IBLSKeyRegistry.InvalidPop.selector);
        registry.register(
            reg32("makerOnSepolia", "account"),
            oa("makerOnSepolia", "register[0]"),
            reg("makerOnSepolia", "pkNative"),
            v.readBytes(".negative.popWrongDstSepolia.pop"),
            0
        );
    }

    function test_secp256k1WrongSignerRejected() public {
        IBLSKeyRegistry.OwnerAuth memory auth = oa("bridgerOnSepolia", "register[0]");
        auth.sig[64] = auth.sig[64] == bytes1(uint8(27)) ? bytes1(uint8(28)) : bytes1(uint8(27));

        vm.expectRevert(IBLSKeyRegistry.OwnerMismatch.selector);
        registry.register(
            reg32("bridgerOnSepolia", "account"),
            auth,
            reg("bridgerOnSepolia", "pkNative"),
            reg("bridgerOnSepolia", "pop"),
            0
        );
    }

    function test_sep53TamperedPointRejected() public {
        IBLSKeyRegistry.OwnerAuth memory auth = oa("makerOnSepolia", "register[0]");
        (uint256 r, uint256 s, uint256 edX, uint256 edY) = abi.decode(auth.sig, (uint256, uint256, uint256, uint256));
        auth.sig = abi.encode(r, s, edX + 1, edY);

        vm.expectRevert(IBLSKeyRegistry.OwnerMismatch.selector);
        registry.register(
            reg32("makerOnSepolia", "account"), auth, reg("makerOnSepolia", "pkNative"), reg("makerOnSepolia", "pop"), 0
        );
    }

    function test_revokeUnregisteredRejected() public {
        vm.expectRevert(IBLSKeyRegistry.NotRegistered.selector);
        registry.revoke(reg32("makerOnSepolia", "account"), oa("makerOnSepolia", "revoke[1]"), 0);
    }

    function test_revokeBlockedWhileInFlight() public {
        bytes32 account = registerMaker();
        busyGuard();
        vm.expectRevert(IBLSKeyRegistry.AccountInFlight.selector);
        registry.revoke(account, oa("makerOnSepolia", "revoke[1]"), 1);
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
        vm.expectRevert(IBLSKeyRegistry.AccountInFlight.selector);
        registry.revoke(account, oa("makerOnSepolia", "revoke[1]"), 1);

        adSide.setBusy(false);
        orderSide.setBusy(true);
        vm.expectRevert(IBLSKeyRegistry.AccountInFlight.selector);
        registry.revoke(account, oa("makerOnSepolia", "revoke[1]"), 1);

        orderSide.setBusy(false);
        registry.revoke(account, oa("makerOnSepolia", "revoke[1]"), 1);
        vm.expectRevert(IBLSKeyRegistry.NoSuchSlot.selector);
        registry.commitmentAt(account, 0);
    }

    // =========================================================================
    // 2.6 plan §4: one owner signature, every refusal, both schemes
    // =========================================================================

    function whoAt(uint256 k) internal pure returns (string memory) {
        return k == 0 ? "makerOnSepolia" : "bridgerOnSepolia";
    }

    function registerWith(string memory who, IBLSKeyRegistry.OwnerAuth memory auth) internal returns (uint32) {
        return registry.register(
            v.readBytes32(string.concat(".slots.", who, ".account")),
            auth,
            v.readBytes(string.concat(slotPath(who, 0), ".pkNative")),
            v.readBytes(string.concat(slotPath(who, 0), ".pop")),
            0
        );
    }

    /// A single-leg signature naming only this registry is enough here.
    function test_aSignatureNamingOnlyThisRegistryRegisters() public {
        for (uint256 k = 0; k < 2; k++) {
            assertEq(registerWith(whoAt(k), oa(whoAt(k), "onlySepoliaLeg")), 0);
        }
    }

    /// Refusal: a signature over a different leg set (the other registry's nonce moved, or a leg added).
    function test_aSignatureOverADifferentLegSetIsRefused() public {
        for (uint256 k = 0; k < 2; k++) {
            IBLSKeyRegistry.OwnerAuth memory moved = oa(whoAt(k), "register[0]");
            moved.legs[1].nonce += 1;
            vm.expectRevert(IBLSKeyRegistry.OwnerMismatch.selector);
            registerWith(whoAt(k), moved);

            IBLSKeyRegistry.OwnerAuth memory base = oa(whoAt(k), "register[0]");
            IBLSKeyRegistry.OwnerAuth memory added;
            added.scheme = base.scheme;
            added.sig = base.sig;
            added.legs = new IBLSKeyRegistry.KeyLeg[](3);
            added.legs[0] = base.legs[0];
            added.legs[1] = base.legs[1];
            added.legs[2] = IBLSKeyRegistry.KeyLeg(84532, bytes32(uint256(0x33)), 0);
            vm.expectRevert(IBLSKeyRegistry.OwnerMismatch.selector);
            registerWith(whoAt(k), added);
        }
    }

    /// Refusal: `legs` without this registry's own leg (a valid signature naming only the Soroban leg).
    function test_legsWithoutTheOwnLegAreRefused() public {
        for (uint256 k = 0; k < 2; k++) {
            vm.expectRevert(IBLSKeyRegistry.LegMismatch.selector);
            registerWith(whoAt(k), oa(whoAt(k), "onlyStellarLeg"));
        }
    }

    /// Refusal: this registry's own leg twice, under a valid signature over exactly those legs.
    function test_theOwnLegTwiceIsRefused() public {
        for (uint256 k = 0; k < 2; k++) {
            vm.expectRevert(IBLSKeyRegistry.LegMismatch.selector);
            registerWith(whoAt(k), oa(whoAt(k), "duplicateLegs"));
        }
    }

    /// Refusal: a stale nonce. The owner signed a revoke at nonce 0; at nonce 1 its leg is not ours.
    function test_aStaleNonceIsRefused() public {
        for (uint256 k = 0; k < 2; k++) {
            string memory who = whoAt(k);
            bytes32 account = v.readBytes32(string.concat(".slots.", who, ".account"));
            registerSlot(who, 0);
            IBLSKeyRegistry.OwnerAuth memory stale = oa(who, "revoke[0]");
            vm.expectRevert(IBLSKeyRegistry.LegMismatch.selector);
            registry.revoke(account, stale, 1);
            vm.expectRevert(IBLSKeyRegistry.BadNonce.selector);
            registry.revoke(account, stale, 0);
            assertEq(registry.liveSlots(account).length, 1);
        }
    }

    /// Refusal: a text with one byte changed. The maker signed a text one byte off the one rebuilt here.
    function test_aTextWithOneByteChangedIsRefused() public {
        IBLSKeyRegistry.OwnerAuth memory auth = oa("makerOnSepolia", "register[0]");
        auth.sig = v.readBytes(".ownerAuth.negative.tamperedText.evmSig");
        assertEq(
            bytes(v.readString(".ownerAuth.negative.tamperedText.signedText")).length,
            bytes(v.readString(string.concat(oaPath("makerOnSepolia", "register[0]"), ".text"))).length
        );
        vm.expectRevert(IBLSKeyRegistry.OwnerMismatch.selector);
        registerWith("makerOnSepolia", auth);
    }

    /// Refusal: a secp256k1 signature on an ed25519 (non-padded) account. The signature is valid and
    /// its signer is the account's low 20 bytes: only the padding rule refuses it.
    function test_aSecp256k1SignatureOnAnEd25519AccountIsRefused() public {
        string memory n = ".ownerAuth.negative.secpOnNonEvmAccount";
        vm.expectRevert(IBLSKeyRegistry.OwnerMismatch.selector);
        registry.register(
            v.readBytes32(string.concat(n, ".account")),
            OwnerAuthVectors.auth(v, n),
            v.readBytes(string.concat(n, ".sepolia.pkNative")),
            v.readBytes(string.concat(n, ".sepolia.pop")),
            0
        );
    }

    /// Refusal: an ed25519 signature on an EVM-shaped (padded) account.
    function test_anEd25519SignatureOnAnEvmAccountIsRefused() public {
        string memory n = ".ownerAuth.negative.sep53OnEvmAccount";
        assertEq(v.readBytes32(string.concat(n, ".account")), v.readBytes32(".slots.bridgerOnSepolia.account"));
        vm.expectRevert(IBLSKeyRegistry.OwnerMismatch.selector);
        registerWith("bridgerOnSepolia", OwnerAuthVectors.auth(v, n));
    }

    /// A retirement names no legs: one that carries any is refused, even when the signature is sound.
    function test_aRetirementWithLegsIsRefused() public {
        bytes32 account = v.readBytes32(".slots.bridgerOnSepolia.account");
        registerSlot("bridgerOnSepolia", 0);
        IBLSKeyRegistry.OwnerAuth memory auth = svuAuth("bridgerOnSepolia", 0, true);
        auth.legs = oa("bridgerOnSepolia", "register[0]").legs;
        vm.expectRevert(IBLSKeyRegistry.LegMismatch.selector);
        registry.setValidUntil(account, auth, fp("bridgerOnSepolia", 0), 1);
    }

    /// A signature the test's own wallet key makes over the vector digest lands: the wallet's rule.
    function test_aFreshSecp256k1SignatureOverTheVectorDigestRegisters() public {
        string memory path = oaPath("bridgerOnSepolia", "register[0]");
        (uint8 sv, bytes32 r, bytes32 ss) =
            vm.sign(uint256(v.readBytes32(".keys.bridgerWallet.sk")), v.readBytes32(string.concat(path, ".digest")));
        IBLSKeyRegistry.OwnerAuth memory auth = oa("bridgerOnSepolia", "register[0]");
        auth.sig = abi.encodePacked(r, ss, sv);
        assertEq(registerWith("bridgerOnSepolia", auth), 0);
    }

    /// The fingerprint map: a key maps to its slot, a revoked key to none (and its retirement fails).
    function test_slotOfKeyFollowsRegistrationAndRevoke() public {
        bytes32 account = v.readBytes32(".slots.makerOnSepolia.account");
        vm.expectRevert(IBLSKeyRegistry.NoSuchSlot.selector);
        registry.slotOfKey(account, fp("makerOnSepolia", 0));
        registerSlot("makerOnSepolia", 0);
        assertEq(registry.slotOfKey(account, fp("makerOnSepolia", 0)), 0);
        registry.revoke(account, oa("makerOnSepolia", "revoke[1]"), 1);
        vm.expectRevert(IBLSKeyRegistry.NoSuchSlot.selector);
        registry.slotOfKey(account, fp("makerOnSepolia", 0));
        assertEq(registerSlot("makerOnSepolia", 2), 1);
        assertEq(registry.slotOfKey(account, fp("makerOnSepolia", 2)), 1);
        vm.expectRevert(IBLSKeyRegistry.NoSuchSlot.selector);
        setValidUntil("makerOnSepolia", 0, true);
    }

    /// D2: on EVM the fingerprint is the stored commitment.
    function test_theFingerprintIsTheStoredCommitment() public view {
        for (uint256 k = 0; k < 2; k++) {
            for (uint256 i = 0; i < 6; i++) {
                assertEq(fp(whoAt(k), i), slotCommitment(whoAt(k), i));
            }
        }
    }

    /// Gas for `register` under a two-leg RegisterKey, each scheme, and for the pre-signed RetireKey.
    /// Measured 2026-09-29: register 420,102 (secp256k1) / 1,000,533 (sep53); setValidUntil
    /// 33,712 / 573,149. The BLS PoP pairing dominates register; ceilings sit ~10% above.
    function test_ownerSigGas() public {
        string[2] memory names = ["bridgerOnSepolia", "makerOnSepolia"];
        uint256[2] memory registerCeil = [REGISTER_SECP_GAS, REGISTER_SEP53_GAS];
        for (uint256 k = 0; k < 2; k++) {
            string memory who = names[k];
            IBLSKeyRegistry.OwnerAuth memory auth = oa(who, "register[0]");
            assertEq(auth.legs.length, 2);
            bytes32 account = v.readBytes32(string.concat(".slots.", who, ".account"));
            bytes memory pk = v.readBytes(string.concat(slotPath(who, 0), ".pkNative"));
            bytes memory pop = v.readBytes(string.concat(slotPath(who, 0), ".pop"));
            uint256 g = gasleft();
            registry.register(account, auth, pk, pop, 0);
            g -= gasleft();
            emit log_named_uint(string.concat("register gas, 2 legs, ", who), g);
            assertLe(g, registerCeil[k]);

            IBLSKeyRegistry.OwnerAuth memory retire = svuAuth(who, 0, true);
            bytes32 key = fp(who, 0);
            g = gasleft();
            registry.setValidUntil(account, retire, key, 1);
            g -= gasleft();
            emit log_named_uint(string.concat("setValidUntil gas, ", who), g);
        }
    }

    uint256 constant REGISTER_SECP_GAS = 462_000;
    uint256 constant REGISTER_SEP53_GAS = 1_100_000;

    function test_domainSeparatorIsTheKeysDomain() public view {
        assertEq(registry.domainSeparator(), v.readBytes32(".ownerAuth._meta.domainSeparator"));
    }
}

/// Exposes `KeyMessages` so the builders can be held to the vectors byte for byte.
contract KeyMessagesHarness {
    function structHash(
        KeyMessages.Kind kind,
        bytes32 account,
        bytes32 key,
        IBLSKeyRegistry.KeyLeg[] calldata legs,
        uint64 validUntil
    ) external pure returns (bytes32) {
        return KeyMessages.structHash(kind, account, key, legs, validUntil);
    }

    function digest(
        KeyMessages.Kind kind,
        bytes32 account,
        bytes32 key,
        IBLSKeyRegistry.KeyLeg[] calldata legs,
        uint64 validUntil
    ) external pure returns (bytes32) {
        return KeyMessages.digest(kind, account, key, legs, validUntil);
    }

    function text(
        KeyMessages.Kind kind,
        bytes32 account,
        bytes32 key,
        IBLSKeyRegistry.KeyLeg[] calldata legs,
        uint64 validUntil
    ) external pure returns (bytes memory) {
        return KeyMessages.text(kind, account, key, legs, validUntil);
    }
}

contract KeyMessagesVectorsTest is Test {
    using stdJson for string;

    string v;
    KeyMessagesHarness h;

    function setUp() public {
        v = vm.readFile("../test-vectors/bls-encodings.json");
        h = new KeyMessagesHarness();
    }

    function test_typehashesMatchTheVectors() public view {
        assertEq(KeyMessages.KEY_LEG_TYPEHASH, v.readBytes32(".ownerAuth._meta.typehashes.keyLeg"));
        assertEq(KeyMessages.REGISTER_KEY_TYPEHASH, v.readBytes32(".ownerAuth._meta.typehashes.registerKey"));
        assertEq(KeyMessages.REVOKE_KEYS_TYPEHASH, v.readBytes32(".ownerAuth._meta.typehashes.revokeKeys"));
        assertEq(KeyMessages.RETIRE_KEY_TYPEHASH, v.readBytes32(".ownerAuth._meta.typehashes.retireKey"));
        assertEq(KeyMessages.DOMAIN_SEPARATOR, v.readBytes32(".ownerAuth._meta.domainSeparator"));
    }

    // Each cheatcode read re-encodes the whole 250 KB vector file into memory, so these readers
    // hand the scratch space back after every read; without it the loop below runs out of memory.
    function r32(string memory path) internal view returns (bytes32 out) {
        uint256 fmp;
        assembly {
            fmp := mload(0x40)
        }
        out = v.readBytes32(path);
        assembly {
            mstore(0x40, fmp)
        }
    }

    function rstr(string memory path) internal view returns (string memory out) {
        uint256 fmp;
        assembly {
            fmp := mload(0x40)
        }
        string memory tmp = v.readString(path);
        assembly {
            let words := add(div(add(mload(tmp), 31), 32), 1)
            for { let i := 0 } lt(i, words) { i := add(i, 1) } {
                mstore(add(fmp, mul(i, 32)), mload(add(tmp, mul(i, 32))))
            }
            out := fmp
            mstore(0x40, add(fmp, mul(words, 32)))
        }
    }

    function exists(string memory path) internal view returns (bool out) {
        uint256 fmp;
        assembly {
            fmp := mload(0x40)
        }
        out = vm.keyExistsJson(v, path);
        assembly {
            mstore(0x40, fmp)
        }
    }

    function legsAt(string memory path) internal view returns (IBLSKeyRegistry.KeyLeg[] memory out) {
        uint256 n;
        while (exists(string.concat(path, ".legs[", vm.toString(n), "]"))) n++;
        out = new IBLSKeyRegistry.KeyLeg[](n);
        for (uint256 i = 0; i < n; i++) {
            string memory l = string.concat(path, ".legs[", vm.toString(i), "]");
            out[i] = IBLSKeyRegistry.KeyLeg(
                vm.parseUint(rstr(string.concat(l, ".chainId"))),
                r32(string.concat(l, ".registry")),
                vm.parseUint(rstr(string.concat(l, ".nonce")))
            );
        }
    }

    function check(string memory path) internal view {
        bytes32 kindName = keccak256(bytes(rstr(string.concat(path, ".kind"))));
        KeyMessages.Kind kind = kindName == keccak256("register")
            ? KeyMessages.Kind.Register
            : kindName == keccak256("revoke") ? KeyMessages.Kind.Revoke : KeyMessages.Kind.Retire;
        bytes32 key = kind == KeyMessages.Kind.Revoke ? bytes32(0) : r32(string.concat(path, ".keyCommitment"));
        uint64 vu = kind == KeyMessages.Kind.Retire ? uint64(vm.parseUint(rstr(string.concat(path, ".validUntil")))) : 0;
        bytes32 account = r32(string.concat(path, ".account"));
        IBLSKeyRegistry.KeyLeg[] memory legs = legsAt(path);
        assertEq(h.structHash(kind, account, key, legs, vu), r32(string.concat(path, ".structHash")), path);
        assertEq(h.digest(kind, account, key, legs, vu), r32(string.concat(path, ".digest")), path);
        assertEq(string(h.text(kind, account, key, legs, vu)), rstr(string.concat(path, ".text")), path);
    }

    function test_everyVectorEntryRebuildsByteForByte() public view {
        string[2] memory actors = ["maker", "bridger"];
        for (uint256 a = 0; a < 2; a++) {
            string memory base = string.concat(".ownerAuth.", actors[a], ".");
            for (uint256 i = 0; i < 6; i++) {
                check(string.concat(base, "register[", vm.toString(i), "]"));
            }
            for (uint256 i = 0; i < 7; i++) {
                check(string.concat(base, "revoke[", vm.toString(i), "]"));
            }
            for (uint256 i = 0; i < 12; i++) {
                check(string.concat(base, "retire[", vm.toString(i), "]"));
            }
            check(string.concat(base, "reuseKey0AtNonce1"));
            check(string.concat(base, "onlySepoliaLeg"));
            check(string.concat(base, "onlyStellarLeg"));
            check(string.concat(base, "duplicateLegs"));
        }
        check(".ownerAuth.negative.secpOnNonEvmAccount");
        check(".ownerAuth.negative.sep53OnEvmAccount");
    }
}
