// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {stdJson} from "forge-std/StdJson.sol";
import {BLSKeyRegistryTest} from "./BLSKeyRegistry.t.sol";
import {BLSKeyRegistry} from "src/BLSKeyRegistry.sol";
import {RootAnchor} from "src/RootAnchor.sol";
import {IRootAnchor} from "src/interfaces/IRootAnchor.sol";
import {HonkVerifier, IVerifier} from "src/Verifier.sol";
import {RegistrationSubject} from "src/libraries/RegistrationSubject.sol";

/// 2.1b (#324), T-67b/c: the registry's proof-accepting `register` path, tested against the real
/// `RootAnchor` (threshold 1, delay 0). The happy-path proof is the committed fixture
/// (`test/fixtures/registration-claim.json`, regenerate with
/// `npx tsx js-scripts/deposits/generateRegistrationFixture.ts`); only the two tests that need a
/// *different* subject build a live proof. Ships flagged off.
contract ProofRegistrationTest is BLSKeyRegistryTest {
    using stdJson for string;

    uint256 internal constant SOURCE_CHAIN = 1_000_002;
    uint256 internal constant OTHER_CHAIN = 1_000_003;
    uint64 internal constant EPOCH = 0; // the vectors' nonce-0 POP doubles as the epoch-0 POP

    RootAnchor internal anchor;
    HonkVerifier internal honk;

    bytes32 internal account;
    bytes internal pk;
    bytes internal pop;
    // The fixture: a domain-4 inclusion proof of the vector maker's epoch-0 subject at this registry.
    bytes internal fxProof;
    bytes32 internal fxRoot;

    function _sources(uint256 chainId) internal pure returns (uint256[] memory s) {
        s = new uint256[](1);
        s[0] = chainId;
    }

    function _wire(bool enabled) internal {
        address[] memory signers = new address[](1);
        signers[0] = address(this);
        anchor = new RootAnchor(address(this), signers, 1);
        honk = new HonkVerifier();
        registry.setProofRegistration(
            IRootAnchor(address(anchor)), IVerifier(address(honk)), _sources(SOURCE_CHAIN), enabled
        );

        account = reg32("makerOnSepolia", "account");
        pk = reg("makerOnSepolia", "pkNative");
        pop = reg("makerOnSepolia", "pop");

        string memory fx = vm.readFile("test/fixtures/registration-claim.json");
        fxProof = fx.readBytes(".proof");
        fxRoot = fx.readBytes32(".root");
        assertEq(fx.readBytes32(".subject"), _subject(account, pk, EPOCH), "fixture is stale: regenerate it");
    }

    /// The subject this registry rebuilds: bound to its own chain and address.
    function _subject(bytes32 acct, bytes memory blsPk, uint64 epoch) internal view returns (bytes32) {
        return RegistrationSubject.subject(
            block.chainid, bytes32(uint256(uint160(address(registry)))), acct, keccak256(blsPk), epoch
        );
    }

    /// A domain-4 inclusion proof for `subject`, built live by the event-claim generator.
    function _leafProof(bytes32 subject) internal returns (bytes memory proof, bytes32 root) {
        string[] memory a = new string[](5);
        a[0] = "npx";
        a[1] = "tsx";
        a[2] = "js-scripts/deposits/generateEventClaim.ts";
        a[3] = "4";
        a[4] = vm.toString(subject);
        bytes32[] memory pub;
        (proof, pub) = abi.decode(vm.ffi(a), (bytes, bytes32[]));
        root = pub[2];
    }

    function _register() internal returns (uint32) {
        return registry.registerByProof(account, pk, pop, EPOCH, SOURCE_CHAIN, fxRoot, fxProof);
    }

    // --- wiring ----------------------------------------------------------------------

    function test_flagOff_reverts() public {
        _wire(false);
        vm.expectRevert(BLSKeyRegistry.ProofRegistrationDisabled.selector);
        registry.registerByProof(account, pk, pop, EPOCH, SOURCE_CHAIN, bytes32(0), "");
    }

    function test_enable_requiresEveryReference() public {
        HonkVerifier v = new HonkVerifier();
        address[] memory signers = new address[](1);
        signers[0] = address(this);
        RootAnchor a = new RootAnchor(address(this), signers, 1);

        vm.expectRevert(BLSKeyRegistry.ProofRegistrationRefsUnset.selector);
        registry.setProofRegistration(IRootAnchor(address(0)), IVerifier(address(v)), _sources(SOURCE_CHAIN), true);
        // A reference without code is as unset as the zero address.
        vm.expectRevert(BLSKeyRegistry.ProofRegistrationRefsUnset.selector);
        registry.setProofRegistration(IRootAnchor(address(a)), IVerifier(address(1)), _sources(SOURCE_CHAIN), true);
        vm.expectRevert(BLSKeyRegistry.ProofRegistrationRefsUnset.selector);
        registry.setProofRegistration(IRootAnchor(address(a)), IVerifier(address(v)), new uint256[](0), true);
        // Disabled needs nothing.
        registry.setProofRegistration(IRootAnchor(address(0)), IVerifier(address(0)), new uint256[](0), false);
    }

    function test_thisChainIsNeverASource() public {
        vm.expectRevert(abi.encodeWithSelector(BLSKeyRegistry.SourceNotAllowed.selector, block.chainid));
        registry.setProofRegistration(IRootAnchor(address(0)), IVerifier(address(0)), _sources(block.chainid), false);
    }

    function test_setProofRegistration_adminOnly() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(BLSKeyRegistry.NotAdmin.selector);
        registry.setProofRegistration(IRootAnchor(address(1)), IVerifier(address(1)), _sources(SOURCE_CHAIN), true);
    }

    function test_enableIsAConfigCall_notARedeploy() public {
        _wire(false);
        anchor.anchor(SOURCE_CHAIN, fxRoot, 1);

        vm.expectRevert(BLSKeyRegistry.ProofRegistrationDisabled.selector);
        _register();

        registry.setProofRegistration(
            IRootAnchor(address(anchor)), IVerifier(address(honk)), _sources(SOURCE_CHAIN), true
        );
        _register();
        assertTrue(registry.hasUsableSlot(account));
        assertEq(registry.proofSources().length, 1);
    }

    // --- the happy path ----------------------------------------------------------------

    function test_anchoredLeafProof_registers() public {
        _wire(true);
        anchor.anchor(SOURCE_CHAIN, fxRoot, 1);

        vm.expectEmit(true, true, false, true);
        emit BLSKeyRegistry.KeyRegisteredByProof(account, 0, pk, EPOCH, SOURCE_CHAIN);
        uint32 slotId = _register();

        assertEq(slotId, 0);
        assertEq(registry.commitmentAt(account, 0), keccak256(pk));
        assertTrue(registry.hasUsableSlot(account));
        // The signature path's nonce is untouched: a proof registration is invisible to nonce-based
        // landing detection (plan §7).
        assertEq(registry.nonceOf(account), 0);
    }

    // --- the anchor ---------------------------------------------------------------------

    function test_unanchoredRoot_reverts() public {
        _wire(true);
        vm.expectRevert(abi.encodeWithSelector(BLSKeyRegistry.RootNotAnchored.selector, SOURCE_CHAIN, fxRoot));
        _register();
    }

    function test_anchoredButInsideDelay_reverts() public {
        _wire(true);
        anchor.setAnchorDelay(SOURCE_CHAIN, 3600);
        anchor.anchor(SOURCE_CHAIN, fxRoot, 1);
        vm.expectRevert(abi.encodeWithSelector(BLSKeyRegistry.RootNotAnchored.selector, SOURCE_CHAIN, fxRoot));
        _register();
    }

    function test_sourceNotAllowed_reverts() public {
        _wire(true);
        // Anchored under a chain the registry was not told to accept leaves from.
        anchor.anchor(OTHER_CHAIN, fxRoot, 1);
        vm.expectRevert(abi.encodeWithSelector(BLSKeyRegistry.SourceNotAllowed.selector, OTHER_CHAIN));
        registry.registerByProof(account, pk, pop, EPOCH, OTHER_CHAIN, fxRoot, fxProof);
    }

    function test_misWiredAnchor_addsNoSlot() public {
        _wire(true);
        // A contract that is not an anchor: the lookup reverts, nothing is added.
        registry.setProofRegistration(
            IRootAnchor(address(honk)), IVerifier(address(honk)), _sources(SOURCE_CHAIN), true
        );
        vm.expectRevert();
        _register();
        assertFalse(registry.hasUsableSlot(account));
    }

    // --- the leaf ------------------------------------------------------------------------

    function test_proofForAnotherSubject_reverts() public {
        _wire(true);
        // A valid POP for the bridger's key, but the leaf proof was built for the maker's subject.
        bytes32 other = reg32("bridgerOnSepolia", "account");
        bytes memory otherPk = reg("bridgerOnSepolia", "pkNative");
        bytes memory otherPop = reg("bridgerOnSepolia", "pop");
        anchor.anchor(SOURCE_CHAIN, fxRoot, 1);

        // The Honk verifier reverts (SumcheckFailed) on a proof for another subject rather than
        // returning false; either way no slot is added.
        vm.expectRevert();
        registry.registerByProof(other, otherPk, otherPop, EPOCH, SOURCE_CHAIN, fxRoot, fxProof);
        assertFalse(registry.hasUsableSlot(other));
    }

    function test_leafForAnotherRegistry_reverts() public {
        _wire(true);
        // The same account, key and epoch, minted for a different registry on this chain (B1).
        bytes32 elsewhere =
            RegistrationSubject.subject(block.chainid, bytes32(uint256(0xBEEF)), account, keccak256(pk), EPOCH);
        (bytes memory proof, bytes32 root) = _leafProof(elsewhere);
        anchor.anchor(SOURCE_CHAIN, root, 1);

        vm.expectRevert();
        registry.registerByProof(account, pk, pop, EPOCH, SOURCE_CHAIN, root, proof);
        assertFalse(registry.hasUsableSlot(account));
    }

    // --- the POP --------------------------------------------------------------------------

    function test_badPop_reverts() public {
        _wire(true);
        bytes memory otherPop = reg("bridgerOnSepolia", "pop");
        anchor.anchor(SOURCE_CHAIN, fxRoot, 1);

        vm.expectRevert(BLSKeyRegistry.InvalidPop.selector);
        registry.registerByProof(account, pk, otherPop, EPOCH, SOURCE_CHAIN, fxRoot, fxProof);
    }

    function test_popBindsTheEpoch() public {
        _wire(true);
        // A genuine epoch-1 leaf, but the key's POP was signed over epoch 0 (D7).
        (bytes memory proof, bytes32 root) = _leafProof(_subject(account, pk, 1));
        anchor.anchor(SOURCE_CHAIN, root, 1);

        vm.expectRevert(BLSKeyRegistry.InvalidPop.selector);
        registry.registerByProof(account, pk, pop, 1, SOURCE_CHAIN, root, proof);
    }

    // --- replay and check order (B3) ----------------------------------------------------------

    function test_replay_reverts_keyPreviouslyUsed() public {
        _wire(true);
        anchor.anchor(SOURCE_CHAIN, fxRoot, 1);
        _register();

        vm.expectRevert(BLSKeyRegistry.KeyPreviouslyUsed.selector);
        _register();
        // The replay guard runs before the anchor lookup: a replay with a stale root still says "used".
        vm.expectRevert(BLSKeyRegistry.KeyPreviouslyUsed.selector);
        registry.registerByProof(account, pk, pop, EPOCH, SOURCE_CHAIN, bytes32(uint256(1)), fxProof);
    }

    function test_cheapChecksRunBeforeThePairing() public {
        _wire(true);
        bytes memory otherPop = reg("bridgerOnSepolia", "pop");
        // Unanchored root *and* a bad POP: the storage read rejects, not the pairing.
        vm.expectRevert(abi.encodeWithSelector(BLSKeyRegistry.RootNotAnchored.selector, SOURCE_CHAIN, fxRoot));
        registry.registerByProof(account, pk, otherPop, EPOCH, SOURCE_CHAIN, fxRoot, fxProof);
    }
}
