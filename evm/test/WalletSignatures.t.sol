// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {IBLSKeyRegistry} from "src/interfaces/IBLSKeyRegistry.sol";
import {BLSKeyRegistry} from "../src/BLSKeyRegistry.sol";
import {OwnerAuthVectors} from "./utils/OwnerAuthVectors.sol";

/// Replays the real MetaMask / Freighter signatures of wallet-signatures.json against the registry,
/// placed where the wallet-check page's Anvil deploy put it. The BLS side (test key + PoP) comes
/// from wallet-signatures-pop.json; the Soroban registry suite replays the same two files.
contract WalletSignaturesTest is Test {
    using stdJson for string;

    uint256 constant CHAIN_ID = 31337;
    /// Inside every positive deadline (<= 7 days out) and past both registerExpired deadlines.
    uint64 constant NOW = 1_790_926_000;

    string v;
    string p;
    BLSKeyRegistry testnetReg;
    BLSKeyRegistry localReg;

    function setUp() public {
        v = vm.readFile("../test-vectors/wallet-signatures.json");
        p = vm.readFile("../test-vectors/wallet-signatures-pop.json");
        vm.chainId(CHAIN_ID);
        vm.warp(NOW);
        testnetReg = place(v.readAddress("._meta.registries.testnet.evm"), "testnet");
        localReg = place(v.readAddress("._meta.registries.local.evm"), "local");
    }

    /// Deploy as the CLI does (constructor(admin, env), SCL auto-linked), then move the code to `at`.
    function place(address at, string memory env) internal returns (BLSKeyRegistry) {
        BLSKeyRegistry impl = new BLSKeyRegistry(address(this), env);
        vm.etch(at, address(impl).code);
        vm.store(at, bytes32(0), bytes32(uint256(uint160(address(this))))); // admin
        return BLSKeyRegistry(at);
    }

    // ---- vector readers ----

    function path(string memory w, string memory group) internal pure returns (string memory) {
        return string.concat(".ownerAuth.", w, ".", group, "[0]");
    }

    function auth(string memory w, string memory group) internal view returns (IBLSKeyRegistry.OwnerAuth memory) {
        return OwnerAuthVectors.auth(v, path(w, group));
    }

    function account(string memory w) internal view returns (bytes32) {
        return v.readBytes32(string.concat(".ownerAuth.", w, ".account"));
    }

    function nonceOf(string memory w, string memory group) internal view returns (uint256) {
        return vm.parseUint(v.readString(string.concat(path(w, group), ".legs[0].nonce")));
    }

    function pk(string memory w) internal view returns (bytes memory) {
        return p.readBytes(string.concat(".", w, ".evmPk"));
    }

    function pop(string memory w, string memory env) internal view returns (bytes memory) {
        return p.readBytes(string.concat(".", w, ".pop.", env, ".evm"));
    }

    function register(
        BLSKeyRegistry r,
        string memory w,
        string memory group,
        string memory env,
        IBLSKeyRegistry.OwnerAuth memory a
    ) internal returns (uint32) {
        return r.register(
            account(w), a, pk(w), pop(w, env), nonceOf(w, group), OwnerAuthVectors.deadline(v, path(w, group))
        );
    }

    function registerReal(string memory w) internal returns (uint32 slot) {
        slot = register(testnetReg, w, "register", "testnet", auth(w, "register"));
    }

    function retire(string memory w, IBLSKeyRegistry.OwnerAuth memory a) internal {
        string memory e = path(w, "retire");
        testnetReg.setValidUntil(
            account(w),
            a,
            OwnerAuthVectors.key(v, e),
            uint64(vm.parseUint(v.readString(string.concat(e, ".validUntil"))))
        );
    }

    function flip(IBLSKeyRegistry.OwnerAuth memory a) internal pure returns (IBLSKeyRegistry.OwnerAuth memory) {
        uint256 at = a.sig.length == 65 ? 63 : 0; // secp: the low byte of s; sep53: the first byte of R
        a.sig[at] = a.sig[at] ^ 0x01;
        return a;
    }

    // ---- the sequence, per wallet ----

    function checkRegister(string memory w) internal {
        bytes32 acct = account(w);
        uint32 slot = registerReal(w);
        assertEq(testnetReg.nonceOf(acct), 1);
        assertEq(testnetReg.commitmentAt(acct, slot), keccak256(pk(w)));
        assertEq(testnetReg.slotOfKey(acct, OwnerAuthVectors.key(v, path(w, "register"))), slot);
    }

    /// RetireKey is nonce-free; the page signed it after filing the RegisterKey.
    function checkRetire(string memory w) internal {
        bytes32 acct = account(w);
        uint32 slot = registerReal(w);
        retire(w, auth(w, "retire"));
        uint64 vu = uint64(vm.parseUint(v.readString(string.concat(path(w, "retire"), ".validUntil"))));
        assertEq(testnetReg.lookup(acct, slot).validUntil, vu);
    }

    // CancelPending and RevokeKeys both sign nonce 1 (the page simulated each from the post-register
    // state), so they are alternatives: each test files the register (and the retire) first, then one.
    function checkCancel(string memory w) internal {
        bytes32 acct = account(w);
        uint32 slot = registerReal(w);
        retire(w, auth(w, "retire"));
        assertEq(nonceOf(w, "cancel"), 1);
        testnetReg.cancel(acct, auth(w, "cancel"), 1);
        assertEq(testnetReg.nonceOf(acct), 2);
        assertEq(testnetReg.liveSlots(acct).length, 1); // a cancel leaves live keys
        assertEq(testnetReg.lookup(acct, slot).commitment, keccak256(pk(w)));
    }

    function checkRevoke(string memory w) internal {
        bytes32 acct = account(w);
        uint32 slot = registerReal(w);
        retire(w, auth(w, "retire"));
        assertEq(nonceOf(w, "revoke"), 1);
        testnetReg.revoke(acct, auth(w, "revoke"), 1);
        assertEq(testnetReg.nonceOf(acct), 2);
        assertEq(testnetReg.liveSlots(acct).length, 0);
        vm.expectRevert(IBLSKeyRegistry.NoSuchSlot.selector);
        testnetReg.lookup(acct, slot);
    }

    function checkExpired(string memory w) internal {
        uint64 dl = OwnerAuthVectors.deadline(v, path(w, "registerExpired"));
        assertLt(dl, block.timestamp);
        vm.expectRevert(IBLSKeyRegistry.DeadlineExpired.selector);
        register(testnetReg, w, "registerExpired", "testnet", auth(w, "registerExpired"));
        // the same entry an instant before its deadline: the time check is the only refusal
        vm.warp(dl);
        register(testnetReg, w, "registerExpired", "testnet", auth(w, "registerExpired"));
        assertEq(testnetReg.nonceOf(account(w)), 1);
    }

    /// Signed for testnet, filed at the local-env registry its legs name: the Network line / salt differ.
    function checkOtherEnv(string memory w) internal {
        vm.expectRevert(IBLSKeyRegistry.OwnerMismatch.selector);
        register(localReg, w, "otherEnv", "local", auth(w, "otherEnv"));
        assertEq(localReg.nonceOf(account(w)), 0);
    }

    function checkMutated(string memory w) internal {
        vm.expectRevert(IBLSKeyRegistry.OwnerMismatch.selector);
        register(testnetReg, w, "register", "testnet", flip(auth(w, "register")));
        registerReal(w);
        vm.expectRevert(IBLSKeyRegistry.OwnerMismatch.selector);
        retire(w, flip(auth(w, "retire")));
        vm.expectRevert(IBLSKeyRegistry.OwnerMismatch.selector);
        testnetReg.cancel(account(w), flip(auth(w, "cancel")), 1);
        vm.expectRevert(IBLSKeyRegistry.OwnerMismatch.selector);
        testnetReg.revoke(account(w), flip(auth(w, "revoke")), 1);
    }

    function test_vectorsNameTheseRegistries() public view {
        assertEq(testnetReg.keysEnv(), v.readString("._meta.env"));
        assertEq(testnetReg.domainSeparator(), v.readBytes32("._meta.envs.testnet.domainSeparator"));
        assertEq(localReg.domainSeparator(), v.readBytes32("._meta.envs.local.domainSeparator"));
        assertEq(v.readString(string.concat(path("metamask", "register"), ".scheme")), "secp256k1");
        assertEq(v.readString(string.concat(path("freighter", "register"), ".scheme")), "sep53");
    }

    // ---- MetaMask (secp256k1, EIP-712) ----

    function test_metamask_register() public {
        checkRegister("metamask");
    }

    function test_metamask_retire() public {
        checkRetire("metamask");
    }

    function test_metamask_cancel() public {
        checkCancel("metamask");
    }

    function test_metamask_revoke() public {
        checkRevoke("metamask");
    }

    function test_metamask_registerExpired_isDeadlineExpired() public {
        checkExpired("metamask");
    }

    function test_metamask_otherEnv_isOwnerMismatch() public {
        checkOtherEnv("metamask");
    }

    function test_metamask_oneByteFlip_isOwnerMismatch() public {
        checkMutated("metamask");
    }

    // ---- Freighter (SEP-53 text, ed25519; the 128-byte evmSig form) ----

    function test_freighter_register() public {
        checkRegister("freighter");
    }

    function test_freighter_retire() public {
        checkRetire("freighter");
    }

    function test_freighter_cancel() public {
        checkCancel("freighter");
    }

    function test_freighter_revoke() public {
        checkRevoke("freighter");
    }

    function test_freighter_registerExpired_isDeadlineExpired() public {
        checkExpired("freighter");
    }

    function test_freighter_otherEnv_isOwnerMismatch() public {
        checkOtherEnv("freighter");
    }

    function test_freighter_oneByteFlip_isOwnerMismatch() public {
        checkMutated("freighter");
    }
}
