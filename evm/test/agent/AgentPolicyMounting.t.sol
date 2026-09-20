// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {ModuleKitHelpers, UserOpData, PackedUserOperation} from "modulekit/ModuleKit.sol";
import {Execution} from "modulekit/accounts/erc7579/lib/ExecutionLib.sol";

import {ProofBridgeAgentPolicy} from "src/agent/ProofBridgeAgentPolicy.sol";
import {AgentPolicyBase} from "./AgentPolicyBase.t.sol";

/// Installing, uninstalling, and who the hook believes it is working for. The module keeps a note
/// of which of its two halves are mounted, and these are the ways that note — or the account the
/// hook acts for — could be made wrong. (Review findings C1, D2, E2/G2, D10.)
contract AgentPolicyMountingTest is AgentPolicyBase {
    using ModuleKitHelpers for *;

    /// C1. Anyone could nominate the maker's account as *their* forwarder, and an agent could then
    /// pad its calldata so the hook resolved "the account" to that stranger — finding no marker
    /// there, and debiting nothing.
    function test_paddedCalldataCannotPointTheHookAtSomeoneElse() public {
        // Gating the setter is not enough on its own: the squatter simply installs the module on
        // itself first, which anyone may do. So this test does exactly that.
        address stranger = makeAddr("forwarder-squatter");
        vm.startPrank(stranger);
        module.onInstall(bytes.concat(bytes32(TYPE_VALIDATOR)));
        module.setTrustedForwarder(instance.account);
        vm.stopPrank();

        UserOpData memory op = _agentOp(lockCall(MAX_PER_ORDER));
        // The hook reads the last 40 bytes of its own calldata as `forwarder ‖ account`. `msgData`
        // is ABI-padded to a word, so the tail is aligned first or the padding would hide it.
        bytes memory cd = op.userOp.callData;
        uint256 filler = (32 - ((cd.length + 40) % 32)) % 32;
        op.userOp.callData = bytes.concat(cd, new bytes(filler), abi.encodePacked(instance.account, stranger));
        _resign(op).execUserOps();

        assertEq(escrow.locks(), 1, "padding is tolerated by design, so the lock goes through");
        assertEq(
            module.agentBucket(instance.account, agentId, AD_TOKEN).level,
            CAPACITY - MAX_PER_ORDER,
            "and it was debited under the real account, whatever the calldata ended in"
        );
    }

    /// D2. Safe and Nexus swallow a reverting `onUninstall` and remove the hook anyway, so a module
    /// that refused empty de-init data kept believing both halves were mounted.
    function test_aRoutineHookUninstallTurnsTheAgentOff() public {
        instance.uninstallModule(TYPE_HOOK, address(module), "");

        UserOpData memory op = _agentOp(lockCall(1));
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(escrow.locks(), 0, "approving with nothing debiting is the one state that must not exist");
    }

    /// E2, as revised by pass 3 (G2). Pass 2 made "valid but not installed" a no-op so a
    /// half-installed module could be repaired one half at a time — and that let an owner who named
    /// the wrong half keep a hook bit for a hook the account no longer had. Fail shut wins: any
    /// uninstall that does not name an installed type clears both, and the repair is
    /// *uninstall both, install both*.
    function test_anUninstallThatMatchesNothingClearsBoth() public {
        vm.startPrank(instance.account);
        module.onUninstall(bytes.concat(bytes32(TYPE_HOOK)));
        assertTrue(module.isInitialized(instance.account), "one half named and removed: the other stays");
        module.onUninstall(bytes.concat(bytes32(TYPE_HOOK))); // named again, not installed now
        vm.stopPrank();
        assertFalse(module.isInitialized(instance.account), "matches nothing installed: both go");

        // and it still cannot fail, which is what Safe and Nexus need of it
        vm.prank(instance.account);
        module.onUninstall("");
    }

    /// The reviewer's path, step for step. Note says {hook}; the owner removes the hook from the
    /// account with data naming the *validator*; then installs the validator. Under pass 2's no-op
    /// the note read "both" with nothing debiting.
    function test_namingTheWrongHalfCannotLeaveTheAgentApprovedAndUncounted() public {
        vm.startPrank(instance.account);
        module.onUninstall(bytes.concat(bytes32(TYPE_VALIDATOR))); // note: {hook}
        module.onUninstall(bytes.concat(bytes32(TYPE_VALIDATOR))); // wrong half named, hook really gone
        vm.stopPrank();
        assertFalse(module.isInitialized(instance.account), "an uninstall that matches nothing clears both");
    }

    /// D10. Soroban's tombstone is permanent. Keyed by the epoch, this one could be lifted by
    /// uninstalling and reinstalling the module.
    function test_theTombstoneOutlivesAReinstall() public {
        _asAccount(abi.encodeCall(module.revokeAgent, (agentId)));
        instance.uninstallModule(TYPE_HOOK, address(module), bytes.concat(bytes32(TYPE_HOOK)));
        instance.uninstallModule(TYPE_VALIDATOR, address(module), bytes.concat(bytes32(TYPE_VALIDATOR)));
        address[] memory targets = new address[](1);
        targets[0] = address(escrow);
        instance.installModule(
            TYPE_VALIDATOR, address(module), bytes.concat(bytes32(TYPE_VALIDATOR), abi.encode(targets))
        );
        instance.installModule(TYPE_HOOK, address(module), bytes.concat(bytes32(TYPE_HOOK)));

        assertTrue(module.isRevoked(instance.account, agentId), "a revoked key stays dead on this account");
        vm.prank(instance.account);
        vm.expectRevert(ProofBridgeAgentPolicy.AgentPolicy__AgentRevoked.selector);
        module.setAgentPolicy(agentId, defaultPolicy());
    }
}
