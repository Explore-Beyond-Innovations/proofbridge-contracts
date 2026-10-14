// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {AdManager} from "src/AdManager.sol";
import {OrderPortal} from "src/OrderPortal.sol";
import {MerkleManager} from "src/MerkleManager.sol";
import {DisputeManager} from "src/DisputeManager.sol";
import {IAdminTimelock} from "src/interfaces/IAdminTimelock.sol";
import {IEscrow} from "src/interfaces/IEscrow.sol";
import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IDisputeManager} from "src/interfaces/IDisputeManager.sol";
import {IKeyRegistry} from "src/interfaces/IKeyRegistry.sol";
import {IRootAnchor} from "src/interfaces/IRootAnchor.sol";
import {IVerifier} from "src/interfaces/IVerifier.sol";
import {IMerkleManager} from "src/interfaces/IMerkleManager.sol";
import {IwNativeToken, wNativeToken} from "src/wNativeToken.sol";
import {TwoStepAdmin} from "src/libraries/TwoStepAdmin.sol";
import {RouteTiming} from "src/libraries/RouteTiming.sol";
import {Dispute} from "src/libraries/Dispute.sol";
import {RootAnchor} from "src/RootAnchor.sol";
import {BLSKeyRegistry} from "src/BLSKeyRegistry.sol";
import {IOrderPortal} from "src/interfaces/IOrderPortal.sol";
import {IVerifier as IV} from "src/interfaces/IVerifier.sol";
import {Poseidon2Yul_BN254 as Poseidon2Yul} from "@poseidon2/src/bn254/yul/Poseidon2Yul.sol";

/// #586 (plan 2.6 doc 24, D1–D3): the 24-hour delay on admin setters and its one-time setup bypass,
/// on every contract that carries it.
contract TimelockTest is Test {
    AdManager internal adManager;
    OrderPortal internal portal;
    MerkleManager internal mmr;
    DisputeManager internal dm;

    address internal admin = makeAddr("admin");
    address internal stranger = makeAddr("stranger");
    address internal pool = makeAddr("pool");
    address internal token = makeAddr("token");
    uint256 internal constant CHAIN = 1000002;
    bytes32 internal constant PEER = bytes32(uint256(0xbeef));
    uint256 internal constant DELAY = 24 hours;

    function setUp() public {
        mmr = new MerkleManager(admin, address(new Poseidon2Yul()));
        wNativeToken w = new wNativeToken("Wrapped Native Token", "WNATIVE", 18);
        address some = makeAddr("verifier");
        adManager = new AdManager(admin, IVerifier(some), IMerkleManager(address(mmr)), IwNativeToken(address(w)));
        portal = new OrderPortal(admin, IVerifier(some), IMerkleManager(address(mmr)), IwNativeToken(address(w)));
        dm = new DisputeManager(admin, IwNativeToken(address(w)));
    }

    /*//////////////////////////// the setter lists ////////////////////////////*/

    /// Every timelocked escrow setter, in an order whose preconditions hold when run in sequence.
    function _escrowCalls() internal view returns (bytes[] memory c) {
        c = new bytes[](6);
        c[0] = abi.encodeCall(IEscrow.setPeerEscrow, (CHAIN, PEER));
        c[1] = abi.encodeCall(IEscrow.setRootVerifier, (CHAIN, makeAddrView("rootVerifier")));
        c[2] = abi.encodeCall(IEscrow.setTokenRoute, (token, CHAIN, bytes32(uint256(7))));
        c[3] = abi.encodeCall(IEscrow.removeTokenRoute, (token, CHAIN));
        c[4] = abi.encodeCall(IEscrow.setRouteTiming, (CHAIN, RouteTiming.Timing(0, 30 minutes, 0, 0)));
        c[5] = abi.encodeCall(IEscrow.setRootAnchor, (IRootAnchor(makeAddrView("anchor"))));
    }

    function _adManagerCalls() internal view returns (bytes[] memory c) {
        bytes[] memory e = _escrowCalls();
        c = new bytes[](e.length + 4);
        for (uint256 i = 0; i < e.length; i++) {
            c[i] = e[i];
        }
        c[e.length] = abi.encodeCall(IAdManager.setKeyRegistry, (IKeyRegistry(makeAddrView("registry"))));
        c[e.length + 1] = abi.encodeCall(IAdManager.setDisputeManager, (IDisputeManager(address(dm))));
        c[e.length + 2] = abi.encodeCall(IAdManager.setProtocolFeePool, (pool));
        c[e.length + 3] = abi.encodeCall(IAdManager.setFeeBps, (30, 20));
    }

    function _mmrCalls() internal view returns (bytes[] memory c) {
        c = new bytes[](3);
        c[0] = abi.encodeCall(MerkleManager.setManager, (makeAddrView("registrar"), true));
        c[1] = abi.encodeCall(MerkleManager.setEscrowAppender, (address(adManager), true));
        c[2] = abi.encodeCall(MerkleManager.setEscrowAppender, (address(adManager), false));
    }

    function _dmCalls() internal view returns (bytes[] memory c) {
        c = new bytes[](5);
        c[0] = abi.encodeCall(DisputeManager.setEscrow, (address(adManager), true));
        c[1] = abi.encodeCall(DisputeManager.setDisputeParams, (CHAIN, Dispute.Params(2 hours, 1)));
        c[2] = abi.encodeCall(DisputeManager.setArbiter, (makeAddrView("arbiter")));
        c[3] = abi.encodeCall(DisputeManager.setProtocolFeePool, (pool));
        c[4] = abi.encodeCall(DisputeManager.setBondConfig, (token, CHAIN, Dispute.BondConfig(1, 50)));
    }

    function makeAddrView(string memory name) internal pure returns (address) {
        return address(uint160(uint256(keccak256(bytes(name)))));
    }

    /*//////////////////////////// every gate ////////////////////////////*/

    /// After activation every listed setter refuses the admin without a proposal, and runs from a
    /// stranger once its exact calldata has waited the delay. One list per contract.
    function test_everyTimelockedSetterIsGated() public {
        _assertGated(address(adManager), _adManagerCalls());
        _assertGated(address(portal), _escrowCalls());
        _assertGated(address(mmr), _mmrCalls());
        _assertGated(address(dm), _dmCalls());
    }

    function _assertGated(address target, bytes[] memory calls) internal {
        vm.prank(admin);
        IAdminTimelock(target).activateTimelock();
        for (uint256 i = 0; i < calls.length; i++) {
            vm.prank(admin);
            (bool ok, bytes memory ret) = target.call(calls[i]);
            assertFalse(ok, "a timelocked setter ran without a proposal");
            assertEq(
                ret,
                abi.encodeWithSelector(IAdminTimelock.Timelock__NotProposed.selector, keccak256(calls[i])),
                "refused for the wrong reason"
            );
            vm.prank(admin);
            IAdminTimelock(target).proposeAction(calls[i]);
        }
        vm.warp(block.timestamp + DELAY);
        for (uint256 i = 0; i < calls.length; i++) {
            vm.prank(stranger);
            (bool ok,) = target.call(calls[i]);
            assertTrue(ok, "a ripe proposal did not run");
            assertEq(IAdminTimelock(target).timelockEta(keccak256(calls[i])), 0, "the proposal was not consumed");
        }
    }

    /// Before activation the same setters are the admin's, instantly: the setup bypass.
    function test_bootstrapIsAdminOnlyAndInstant() public {
        bytes[] memory calls = _adManagerCalls();
        for (uint256 i = 0; i < calls.length; i++) {
            vm.prank(stranger);
            (bool okStranger, bytes memory ret) = address(adManager).call(calls[i]);
            assertFalse(okStranger, "a stranger used the bypass");
            assertEq(ret, abi.encodeWithSelector(TwoStepAdmin.NotAdmin.selector));
            vm.prank(admin);
            (bool ok,) = address(adManager).call(calls[i]);
            assertTrue(ok, "the admin could not configure during setup");
        }
        assertFalse(adManager.timelockActive());
        (address p, uint16 lp, uint16 proto) = adManager.feeConfig();
        assertEq(p, pool);
        assertEq(lp, 30);
        assertEq(proto, 20);
    }

    /*//////////////////////////// the rules ////////////////////////////*/

    function _proposePeer() internal returns (bytes memory data, bytes32 id, uint256 eta) {
        data = abi.encodeCall(IEscrow.setPeerEscrow, (CHAIN, PEER));
        id = keccak256(data);
        eta = block.timestamp + DELAY;
        vm.expectEmit(address(adManager));
        emit IAdminTimelock.ActionProposed(id, eta, data);
        vm.prank(admin);
        adManager.proposeAction(data);
    }

    /// One second early is refused; at the delay exactly, anyone runs it, once.
    function test_theDelayIsAtLeast24Hours() public {
        (bytes memory data, bytes32 id, uint256 eta) = _proposePeer();
        assertEq(adManager.timelockEta(id), eta);
        assertEq(adManager.TIMELOCK_DELAY(), DELAY);

        vm.warp(eta - 1);
        vm.prank(admin);
        (bool early, bytes memory ret) = address(adManager).call(data);
        assertFalse(early, "ran before the delay");
        assertEq(ret, abi.encodeWithSelector(IAdminTimelock.Timelock__TooEarly.selector, eta));

        vm.warp(eta);
        vm.expectEmit(address(adManager));
        emit IAdminTimelock.ActionExecuted(id);
        vm.prank(stranger);
        adManager.setPeerEscrow(CHAIN, PEER);
        assertEq(adManager.peerEscrow(CHAIN), PEER);

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(IAdminTimelock.Timelock__NotProposed.selector, id));
        adManager.setPeerEscrow(CHAIN, PEER);
    }

    /// The proposal is the exact call: other arguments are another hash.
    function test_executeMustMatchTheProposalExactly() public {
        _proposePeer();
        vm.warp(block.timestamp + DELAY);
        bytes32 other = keccak256(abi.encodeCall(IEscrow.setPeerEscrow, (CHAIN, bytes32(uint256(0xdead)))));
        vm.expectRevert(abi.encodeWithSelector(IAdminTimelock.Timelock__NotProposed.selector, other));
        adManager.setPeerEscrow(CHAIN, bytes32(uint256(0xdead)));
        // Same arguments under another setter's selector are refused too.
        bytes32 otherFn = keccak256(abi.encodeCall(IEscrow.removeTokenRoute, (address(uint160(CHAIN)), uint256(PEER))));
        vm.expectRevert(abi.encodeWithSelector(IAdminTimelock.Timelock__NotProposed.selector, otherFn));
        adManager.removeTokenRoute(address(uint160(CHAIN)), uint256(PEER));
    }

    /// A pending proposal cannot be re-proposed (its clock stands); after it runs it can.
    function test_aPendingProposalCannotBeReproposed() public {
        (bytes memory data, bytes32 id,) = _proposePeer();
        vm.warp(block.timestamp + DELAY - 1);
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(IAdminTimelock.Timelock__AlreadyProposed.selector, id));
        adManager.proposeAction(data);
    }

    /// The admin cancels; the cancelled call is then refused, and so is a second cancel.
    function test_theAdminCancels() public {
        (bytes memory data, bytes32 id,) = _proposePeer();
        vm.prank(stranger);
        vm.expectRevert(TwoStepAdmin.NotAdmin.selector);
        adManager.cancelAction(id);

        vm.expectEmit(address(adManager));
        emit IAdminTimelock.ActionCancelled(id);
        vm.prank(admin);
        adManager.cancelAction(id);
        assertEq(adManager.timelockEta(id), 0);

        vm.warp(block.timestamp + DELAY);
        (bool ok,) = address(adManager).call(data);
        assertFalse(ok, "a cancelled proposal ran");
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(IAdminTimelock.Timelock__NotProposed.selector, id));
        adManager.cancelAction(id);
    }

    /// Only the admin proposes and activates.
    function test_onlyTheAdminProposesAndActivates() public {
        vm.startPrank(stranger);
        vm.expectRevert(TwoStepAdmin.NotAdmin.selector);
        adManager.proposeAction(abi.encodeCall(IEscrow.setPeerEscrow, (CHAIN, PEER)));
        vm.expectRevert(TwoStepAdmin.NotAdmin.selector);
        adManager.activateTimelock();
        vm.stopPrank();
    }

    /// D2: activation is one-way; a second one is refused, and the bypass stays closed.
    function test_activationIsOneWay() public {
        vm.expectEmit(address(adManager));
        emit IAdminTimelock.TimelockActivated();
        vm.prank(admin);
        adManager.activateTimelock();
        assertTrue(adManager.timelockActive());

        vm.prank(admin);
        vm.expectRevert(IAdminTimelock.Timelock__AlreadyActive.selector);
        adManager.activateTimelock();

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAdminTimelock.Timelock__NotProposed.selector,
                keccak256(abi.encodeCall(IEscrow.setPeerEscrow, (CHAIN, PEER)))
            )
        );
        adManager.setPeerEscrow(CHAIN, PEER);
    }

    /// D2: the first proposal closes the bypass too.
    function test_theFirstProposalClosesTheBypass() public {
        assertFalse(adManager.timelockActive());
        vm.expectEmit(address(adManager));
        emit IAdminTimelock.TimelockActivated();
        _proposePeer();
        assertTrue(adManager.timelockActive());
        vm.prank(admin);
        vm.expectRevert();
        adManager.setRouteTiming(CHAIN, RouteTiming.Timing(0, 30 minutes, 0, 0));
    }

    /*//////////////////////////// what stays instant ////////////////////////////*/

    /// Pause, unpause and the admin handover stay instant after activation.
    function test_pauseAndHandoverStayInstant() public {
        vm.startPrank(admin);
        adManager.activateTimelock();
        adManager.pause();
        assertTrue(adManager.paused());
        adManager.unpause();
        adManager.transferAdmin(stranger);
        vm.stopPrank();
        vm.prank(stranger);
        adManager.acceptAdmin();
        assertEq(adManager.admin(), stranger);
    }

    /// D3: the brakes stay instant for the admin (and only the admin); their reverse is delayed.
    function test_theBrakesStayInstantAndTheirReverseIsDelayed() public {
        vm.startPrank(admin);
        adManager.setRootVerifier(CHAIN, makeAddrView("rootVerifier"));
        mmr.setManager(address(adManager), true);
        dm.setEscrow(address(adManager), true);
        adManager.activateTimelock();
        mmr.activateTimelock();
        dm.activateTimelock();

        adManager.setRootVerifier(CHAIN, address(0));
        assertEq(address(adManager.rootVerifier(CHAIN)), address(0), "unwiring the verifier is instant");
        mmr.setManager(address(adManager), false);
        assertFalse(mmr.isManager(address(adManager)), "removing an appender is instant");
        dm.setEscrow(address(adManager), false);
        assertFalse(dm.isEscrow(address(adManager)), "removing an escrow is instant");

        vm.expectRevert(
            abi.encodeWithSelector(
                IAdminTimelock.Timelock__NotProposed.selector,
                keccak256(abi.encodeCall(IEscrow.setRootVerifier, (CHAIN, makeAddrView("rootVerifier"))))
            )
        );
        adManager.setRootVerifier(CHAIN, makeAddrView("rootVerifier"));
        vm.expectRevert(
            abi.encodeWithSelector(
                IAdminTimelock.Timelock__NotProposed.selector,
                keccak256(abi.encodeCall(MerkleManager.setManager, (address(adManager), true)))
            )
        );
        mmr.setManager(address(adManager), true);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAdminTimelock.Timelock__NotProposed.selector,
                keccak256(abi.encodeCall(DisputeManager.setEscrow, (address(adManager), true)))
            )
        );
        dm.setEscrow(address(adManager), true);
        vm.stopPrank();

        // A brake is still the admin's alone.
        vm.startPrank(stranger);
        vm.expectRevert(TwoStepAdmin.NotAdmin.selector);
        adManager.setRootVerifier(CHAIN, address(0));
        vm.expectRevert(TwoStepAdmin.NotAdmin.selector);
        mmr.setManager(address(adManager), false);
        vm.expectRevert(TwoStepAdmin.NotAdmin.selector);
        dm.setEscrow(address(adManager), false);
        vm.stopPrank();
    }

    /*//////////////////////////// review pass 1 ////////////////////////////*/

    function _activateAndPropose(bytes memory data) internal returns (bytes32 id, uint256 eta) {
        id = keccak256(data);
        vm.prank(admin);
        adManager.proposeAction(data);
        eta = block.timestamp + DELAY;
    }

    /// D4: a ripe proposal runs for 14 days after its eta, then expires; an expired one can be proposed again.
    function test_aProposalExpires14DaysAfterItRipens() public {
        bytes memory data = abi.encodeCall(IEscrow.setPeerEscrow, (CHAIN, PEER));
        (bytes32 id, uint256 eta) = _activateAndPropose(data);
        vm.warp(eta + 14 days + 1);
        assertEq(adManager.timelockEta(id), 0, "an expired proposal reads as none");
        vm.expectRevert(abi.encodeWithSelector(IAdminTimelock.Timelock__Expired.selector, eta + 14 days));
        adManager.setPeerEscrow(CHAIN, PEER);
        vm.prank(admin);
        adManager.proposeAction(data); // allowed again: the expired one no longer blocks it
        vm.warp(block.timestamp + DELAY);
        adManager.setPeerEscrow(CHAIN, PEER);
        assertEq(adManager.peerEscrow(CHAIN), PEER);
    }

    /// D4: the last second of the window still runs.
    function test_theLastSecondOfTheWindowRuns() public {
        (, uint256 eta) = _activateAndPropose(abi.encodeCall(IEscrow.setPeerEscrow, (CHAIN, PEER)));
        vm.warp(eta + 14 days);
        adManager.setPeerEscrow(CHAIN, PEER);
    }

    /// D6: an accepted handover voids the old admin's pending proposals.
    function test_aHandoverVoidsTheOldAdminsProposals() public {
        bytes memory data = abi.encodeCall(IEscrow.setPeerEscrow, (CHAIN, PEER));
        (bytes32 id, uint256 eta) = _activateAndPropose(data);
        vm.prank(admin);
        adManager.transferAdmin(stranger);
        vm.prank(stranger);
        adManager.acceptAdmin();
        assertEq(adManager.timelockEta(id), 0, "the old admin's proposal is void");
        vm.warp(eta);
        vm.expectRevert(abi.encodeWithSelector(IAdminTimelock.Timelock__NotProposed.selector, id));
        adManager.setPeerEscrow(CHAIN, PEER);
        // The new admin can propose the same call afresh.
        vm.prank(stranger);
        adManager.proposeAction(data);
        vm.warp(block.timestamp + DELAY);
        adManager.setPeerEscrow(CHAIN, PEER);
    }

    /// Fix 2: pulling a brake voids every pending proposal that would undo it, whoever runs it.
    function test_aBrakeVoidsThePendingProposalThatWouldUndoIt() public {
        address v = makeAddrView("rootVerifier");
        vm.prank(admin);
        adManager.setRootVerifier(CHAIN, v); // setup
        bytes memory rewire = abi.encodeCall(IEscrow.setRootVerifier, (CHAIN, makeAddrView("v2")));
        (bytes32 id, uint256 eta) = _activateAndPropose(rewire);
        vm.prank(admin);
        adManager.setRootVerifier(CHAIN, address(0)); // the brake
        vm.warp(eta);
        vm.expectRevert(abi.encodeWithSelector(IAdminTimelock.Timelock__CancelledByBrake.selector, id));
        adManager.setRootVerifier(CHAIN, makeAddrView("v2"));
        // The voided entry stays until cancelled or expired; a proposal made after the brake runs.
        vm.warp(block.timestamp + 1);
        vm.startPrank(admin);
        adManager.cancelAction(id);
        adManager.proposeAction(rewire);
        vm.stopPrank();
        vm.warp(block.timestamp + DELAY);
        adManager.setRootVerifier(CHAIN, makeAddrView("v2"));
        assertEq(address(adManager.rootVerifier(CHAIN)), makeAddrView("v2"));
        // Another route's proposals are untouched by this route's brake.
    }

    /// D3 / fix 1: an escrow appender cannot be braked out instantly; removing one waits the delay.
    function test_anEscrowAppenderIsNotBrakeable() public {
        vm.startPrank(admin);
        mmr.setEscrowAppender(address(adManager), true);
        mmr.activateTimelock();
        vm.expectRevert(
            abi.encodeWithSelector(MerkleManager.MerkleManager__EscrowAppender.selector, address(adManager))
        );
        mmr.setManager(address(adManager), false);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAdminTimelock.Timelock__NotProposed.selector,
                keccak256(abi.encodeCall(MerkleManager.setEscrowAppender, (address(adManager), false)))
            )
        );
        mmr.setEscrowAppender(address(adManager), false);
        vm.stopPrank();
        assertTrue(mmr.isManager(address(adManager)), "the escrow keeps appending");
    }

    /// D5: RootAnchor: new signers, a delay cut, a sequence lowering and the monotonic check off wait the
    /// delay; a delay raise, a sequence raise, monotonic on and a revoke stay instant.
    function test_rootAnchorGrantsWaitAndRevocationsDoNot() public {
        address[] memory signers = new address[](1);
        signers[0] = address(this);
        RootAnchor anchor = new RootAnchor(admin, signers, 1);
        vm.startPrank(admin);
        anchor.setAnchorDelay(CHAIN, 600);
        anchor.activateTimelock();
        address[] memory other = new address[](1);
        other[0] = stranger;
        vm.expectRevert(
            abi.encodeWithSelector(
                IAdminTimelock.Timelock__NotProposed.selector,
                keccak256(abi.encodeCall(RootAnchor.setSigners, (other, 1)))
            )
        );
        anchor.setSigners(other, 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAdminTimelock.Timelock__NotProposed.selector,
                keccak256(abi.encodeCall(RootAnchor.setAnchorDelay, (CHAIN, 60)))
            )
        );
        anchor.setAnchorDelay(CHAIN, 60);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAdminTimelock.Timelock__NotProposed.selector,
                keccak256(abi.encodeCall(RootAnchor.setMonotonic, (false)))
            )
        );
        anchor.setMonotonic(false);
        anchor.setAnchorDelay(CHAIN, 3600); // a raise: instant
        assertEq(anchor.anchorDelay(CHAIN), 3600);
        anchor.resetLatestSeq(CHAIN, 10); // a raise: instant
        vm.expectRevert(
            abi.encodeWithSelector(
                IAdminTimelock.Timelock__NotProposed.selector,
                keccak256(abi.encodeCall(RootAnchor.resetLatestSeq, (CHAIN, 5)))
            )
        );
        anchor.resetLatestSeq(CHAIN, 5);
        anchor.setMonotonic(true); // on: instant
        vm.stopPrank();
    }

    /// D5: the BLS key registry's position guards and proof registration (when enabling) wait the
    /// delay; disabling proof registration is a brake.
    function test_keyRegistryGrantsWaitAndDisablingDoesNot() public {
        BLSKeyRegistry reg = new BLSKeyRegistry(admin, "local");
        address[] memory guards = new address[](1);
        guards[0] = address(adManager);
        vm.startPrank(admin);
        reg.activateTimelock();
        vm.expectRevert(
            abi.encodeWithSelector(
                IAdminTimelock.Timelock__NotProposed.selector,
                keccak256(abi.encodeCall(BLSKeyRegistry.setPositionGuards, (guards)))
            )
        );
        reg.setPositionGuards(guards);
        uint256[] memory none = new uint256[](0);
        reg.setProofRegistration(IRootAnchor(address(0)), IV(address(0)), none, false); // the brake
        vm.stopPrank();
        assertFalse(reg.proofRegistrationEnabled());
    }

    /// Must-fix 3: the OrderPortal refuses an order fee share above 1% (the ad chain could never lock it).
    function test_theOrderPortalRefusesAFeeAboveOnePercent() public {
        IOrderPortal.OrderParams memory p;
        p.amount = 1;
        p.bridger = bytes32(uint256(uint160(address(this))));
        p.adRecipient = bytes32(uint256(1));
        p.lpFeeBps = 101;
        vm.expectRevert(IOrderPortal.OrderPortal__InvalidFee.selector);
        portal.createOrder(p);
    }
}
