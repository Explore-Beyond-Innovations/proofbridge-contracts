// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {stdJson} from "forge-std/StdJson.sol";
import {ModuleKitHelpers, UserOpData} from "modulekit/ModuleKit.sol";

import {IAdManager} from "src/interfaces/IAdManager.sol";
import {ProofBridgeAgentPolicy} from "src/agent/ProofBridgeAgentPolicy.sol";
import {AgentPolicyBase} from "./AgentPolicyBase.t.sol";
import {MockEscrow} from "./mocks/MockEscrow.sol";

/// T-60, layer 2: the module against the shared policy fixture.
///
/// Three implementations decide whether an agent's lock is allowed: this module, the Soroban agent
/// account, and a TypeScript copy the relayer asks first. `test-vectors/agent-policy-parity.json`
/// holds policy + lock → accept or reject, every verdict written by hand, and all three read it. A
/// case carries exactly one fault, because the implementations check in different orders.
///
/// The verdict comes from `preflight`, the one entry point that runs the static rules and the
/// bucket arithmetic with a clock. But `preflight` is a read, and Soroban's check debits as it
/// passes, so a sequence of locks would meet an untouched bucket here and the volume cases would
/// prove nothing. **So every lock is also sent through the EntryPoint**: an accepted one must reach
/// the escrow (and so debits the buckets for the next step), a refused one must not. That holds
/// the enforcing path to the fixture as well as `preflight`'s opinion of it.
///
/// One transaction per `handleOps`, as on a chain: forge otherwise runs a whole test as one, and
/// transient state would leak between operations.
/// forge-config: default.isolate = true
contract AgentPolicyParityTest is AgentPolicyBase {
    using ModuleKitHelpers for *;
    using stdJson for string;

    MockEscrow internal unpinned;
    string internal vectors;

    /// The base rig's account, module and pinned escrow, with no ceilings and no policy: the
    /// fixture brings those, case by case.
    function setUp() public override {
        instance = makeAccountInstance("agent-policy-parity");
        vm.deal(instance.account, 1_000_000 ether);

        module = new ProofBridgeAgentPolicy();
        escrow = new MockEscrow();
        unpinned = new MockEscrow();
        (agent, agentKey) = makeAddrAndKey("agent");
        agentId = bytes32(uint256(uint160(agent)));

        address[] memory targets = new address[](1);
        targets[0] = address(escrow);
        instance.installModule(
            TYPE_VALIDATOR, address(module), bytes.concat(bytes32(TYPE_VALIDATOR), abi.encode(targets))
        );
        instance.installModule(TYPE_HOOK, address(module), bytes.concat(bytes32(TYPE_HOOK)));

        vectors = vm.readFile("../test-vectors/agent-policy-parity.json");
    }

    /// What one step needs, read out of the fixture in a call of its own. Every JSON read copies the
    /// whole file into memory and memory is never freed inside a call, so the reading happens in
    /// `load*` (external, and gone when it returns) and only the acting happens here.
    ///
    /// The acting has to stay at the top level of the test. Isolation makes a test's *top-level*
    /// calls their own transactions; a `handleOps` inside a helper call shares its transaction with
    /// the next one, and the validator's transient bookkeeping leaks from one operation into the
    /// next. That is an artefact of the harness, and it looks exactly like a policy bug.
    struct Loaded {
        bool revoke;
        bool reinstall;
        uint256 warp;
        bool pinned;
        bytes callData;
        bool accept;
        ProofBridgeAgentPolicy.Refusal refusal;
        string at;
    }

    struct Ceiling {
        bytes32 token;
        uint256 capacity;
        uint256 refillPerSecond;
    }

    struct Setup {
        bool mine;
        string name;
        uint256 startTime;
        bytes policy;
        Ceiling[] ceilings;
        uint256 steps;
        bool installs;
        bytes4 installError;
    }

    /// The cases are run in four slices, one test each. A test is one call frame, memory in it is
    /// never freed, and its cost grows with the square of its size: every operation here leaves a
    /// user operation, its logs and a loaded step behind, and the whole table in one frame passes
    /// forge's per-test gas ceiling. Slicing by index keeps each frame small however the table grows.
    uint256 internal constant SLICES = 4;

    function test_theModuleMatchesTheSharedPolicyFixture_slice0() public {
        _runSlice(0);
    }

    function test_theModuleMatchesTheSharedPolicyFixture_slice1() public {
        _runSlice(1);
    }

    function test_theModuleMatchesTheSharedPolicyFixture_slice2() public {
        _runSlice(2);
    }

    function test_theModuleMatchesTheSharedPolicyFixture_slice3() public {
        _runSlice(3);
    }

    /// Zero cases is a failure, and so is some: a reader that stopped half way down the file would
    /// pass every slice. This walks the table with the same `exists` / `loadSetup` the slices use,
    /// executes nothing, and holds what it finds to the fixture's own counts — and to the slices
    /// between them covering every index.
    function test_theSlicesSeeEveryCaseAndStep() public view {
        uint256 cases;
        uint256 steps;
        uint256[] memory perSlice = new uint256[](SLICES);
        uint256 total = vectors.readUint(".counts.total.cases");
        // The count is the table's real length, not a number the fixture could understate.
        assertTrue(this.exists(_case(total - 1, "")) && !this.exists(_case(total, "")), "counts.total.cases");
        for (uint256 c = 0; c < total; ++c) {
            Setup memory setup = this.loadSetup(_case(c, ""), false);
            if (!setup.mine) continue;
            ++cases;
            steps += setup.steps;
            ++perSlice[c % SLICES];
        }
        assertGt(cases, 0, "no case is this reader's");
        assertEq(cases, vectors.readUint(".counts.evm.cases"), "cases seen");
        assertEq(steps, vectors.readUint(".counts.evm.steps"), "steps seen");
        for (uint256 i = 0; i < SLICES; ++i) {
            assertGt(perSlice[i], 0, "a slice with nothing in it proves nothing by passing");
        }
    }

    function _runSlice(uint256 slice) internal {
        uint256 ranCases;
        uint256 total = vectors.readUint(".counts.total.cases");

        // By stride, so a slice reads only its own cases: every read of the fixture copies the whole
        // file out of storage, and that, not the operations, is most of what this test costs.
        for (uint256 c = slice; c < total; c += SLICES) {
            Setup memory setup = this.loadSetup(_case(c, ""), false);
            if (!setup.mine) continue;

            // Each case starts from the bare rig: no case inherits another's buckets or tally.
            uint256 snapshot = vm.snapshotState();
            uint256 nowTs = setup.startTime;
            vm.warp(nowTs);
            _setCeilings(setup.ceilings);
            (bool installed,) = _install(setup.policy);
            assertTrue(installed, string.concat(setup.name, ": did not install"));
            vm.prank(instance.account);
            module.setAgentGasBudget(agentId, type(uint128).max);

            for (uint256 s = 0; s < setup.steps; ++s) {
                Loaded memory step = this.loadStep(c, s, setup.name);
                nowTs += step.warp;
                vm.warp(nowTs);

                if (step.revoke) {
                    vm.prank(instance.account);
                    module.revokeAgent(agentId);
                    continue;
                }
                if (step.reinstall) {
                    // The owner installs the same policy again: a new version, so a fresh bucket for
                    // the agent, while the account's ceiling keeps what was spent.
                    (bool again,) = _install(setup.policy);
                    assertTrue(again, string.concat(step.at, ": did not reinstall"));
                    continue;
                }
                _judge(step);
            }

            vm.revertToState(snapshot);
            ++ranCases;
        }
        assertGt(ranCases, 0, "this slice ran nothing");
    }

    function test_installingAPolicyMatchesTheSharedFixture() public {
        uint256 ran;
        uint256 totalInstalls = vectors.readUint(".counts.total.installs");
        assertTrue(
            this.exists(_install(totalInstalls - 1, "")) && !this.exists(_install(totalInstalls, "")),
            "counts.total.installs"
        );
        for (uint256 i = 0; i < totalInstalls; ++i) {
            Setup memory setup = this.loadSetup(_install(i, ""), true);
            if (!setup.mine) continue;

            uint256 snapshot = vm.snapshotState();
            vm.warp(setup.startTime);
            _setCeilings(setup.ceilings);
            (bool installed, bytes memory err) = _install(setup.policy);

            if (setup.installs) {
                assertTrue(installed, setup.name);
            } else {
                assertFalse(installed, setup.name);
                assertEq(bytes4(err), setup.installError, setup.name);
            }
            vm.revertToState(snapshot);
            ++ran;
        }
        assertGt(ran, 0, "no install ran");
        assertEq(ran, vectors.readUint(".counts.evm.installs"), "installs ran");
    }

    /*//////////////////////////////////////////////////////////////
                                ONE LOCK
    //////////////////////////////////////////////////////////////*/

    function _judge(Loaded memory step) internal {
        MockEscrow target = step.pinned ? escrow : unpinned;
        UserOpData memory op = instance.getExecOps(address(target), 0, step.callData, address(module));
        op.userOp.signature = _sign(op.userOpHash, agentKey);

        (ProofBridgeAgentPolicy.Refusal why,) = module.preflight(instance.account, agentId, op.userOp.callData);
        assertEq(uint8(why), uint8(step.refusal), step.at);

        // ...and the enforcing path, which `preflight` only describes. What a refusal proves depends
        // on which half refuses. The *validator's* no is the EntryPoint's, and is the same on every
        // account type, so it is held to the exact answer: AA24 for a policy refusal, AA22 for an
        // expired one. Anything else reverting (prefund, the gas budget, the pause) would not match.
        // A *volume* refusal is the hook's, which surfaces differently per account type, so there
        // the claim is only what it can be: `preflight` named the reason, and the lock did not land.
        uint256 before = target.locks();
        if (!step.accept) {
            ProofBridgeAgentPolicy.Refusal r = step.refusal;
            if (
                r == ProofBridgeAgentPolicy.Refusal.AgentAllowanceExceeded
                    || r == ProofBridgeAgentPolicy.Refusal.AccountCeilingExceeded
            ) {
                instance.expect4337Revert();
            } else {
                vm.expectRevert(
                    abi.encodeWithSelector(
                        FailedOp.selector,
                        0,
                        r == ProofBridgeAgentPolicy.Refusal.Expired ? "AA22 expired or not due" : "AA24 signature error"
                    )
                );
            }
        }
        op.execUserOps();
        assertEq(target.locks(), before + (step.accept ? 1 : 0), string.concat(step.at, ": through the EntryPoint"));
    }

    /*//////////////////////////////////////////////////////////////
                         READING THE FIXTURE
    //////////////////////////////////////////////////////////////*/

    function exists(string calldata path) external view returns (bool) {
        return vm.keyExistsJson(vectors, path);
    }

    /// @param install true for a row of the `installs` table, which carries an `expect` of its own.
    function loadSetup(string calldata at, bool install) external view returns (Setup memory setup) {
        setup.mine = _reads(string.concat(at, ".readers"));
        if (!setup.mine) return setup;
        setup.name = vectors.readString(string.concat(at, ".name"));
        setup.startTime = vectors.readUint(string.concat(at, ".startTime"));
        setup.policy = vectors.readBytes(string.concat(at, ".evmPolicyHex"));

        string memory ceilings = string.concat(at, ".accountCeilings");
        uint256 n;
        while (vm.keyExistsJson(vectors, _nth(ceilings, n, ""))) ++n;
        setup.ceilings = new Ceiling[](n);
        for (uint256 i = 0; i < n; ++i) {
            setup.ceilings[i] = Ceiling({
                token: vectors.readBytes32(_nth(ceilings, i, ".token")),
                capacity: vectors.readUint(_nth(ceilings, i, ".capacity")),
                refillPerSecond: vectors.readUint(_nth(ceilings, i, ".refillPerSecond"))
            });
        }

        if (install) {
            string memory want = vectors.readString(string.concat(at, ".expect"));
            setup.installs = _eq(want, "installs");
            if (!setup.installs) {
                setup.installError = _installError(vectors.readString(string.concat(".installReasons.", want, ".evm")));
            }
        } else {
            while (vm.keyExistsJson(vectors, _nth(string.concat(at, ".steps"), setup.steps, ""))) ++setup.steps;
        }
    }

    function loadStep(uint256 c, uint256 s, string calldata name) external view returns (Loaded memory step) {
        step.at = string.concat(name, " [step ", vm.toString(s), "]");
        step.warp = vectors.readUint(_step(c, s, ".warp"));
        string memory op = vectors.readString(_step(c, s, ".op"));
        step.revoke = _eq(op, "revoke");
        step.reinstall = _eq(op, "reinstall");
        if (step.revoke || step.reinstall) return step;
        require(_eq(op, "lock"), string.concat("an op this reader does not know: ", op));

        string memory lock = _step(c, s, ".lock");
        step.pinned = _eq(vectors.readString(string.concat(lock, ".target")), "pinned");
        step.callData = _callData(lock);

        string memory want = _expected(_step(c, s, ".expect"));
        step.accept = _eq(want, "accept");
        step.refusal = step.accept
            ? ProofBridgeAgentPolicy.Refusal.None
            : _refusal(vectors.readString(string.concat(".reasons.", want, ".evm")));
        if (!step.accept) step.at = string.concat(step.at, ": want ", want);
    }

    function _callData(string memory lock) internal view returns (bytes memory) {
        IAdManager.OrderParams memory p = orderParams(
            vectors.readUint(string.concat(lock, ".amount")),
            vectors.readBytes32(string.concat(lock, ".adChainToken")),
            vectors.readBytes32(string.concat(lock, ".orderChainToken")),
            vectors.readString(string.concat(lock, ".adId")),
            _eq(vectors.readString(string.concat(lock, ".signer")), "policy")
                ? vectors.readBytes32(".constants.evmSettlementSigner")
                : vectors.readBytes32(".constants.otherSigner")
        );
        p.orderDecimals = uint8(vectors.readUint(string.concat(lock, ".orderDecimals")));
        p.adDecimals = uint8(vectors.readUint(string.concat(lock, ".adDecimals")));

        string memory action = vectors.readString(string.concat(lock, ".action"));
        if (_eq(action, "lock_for_order")) return abi.encodeCall(IAdManager.lockForOrder, (p));
        // A real function of the escrow's, and one no policy can list.
        if (_eq(action, "other")) {
            return abi.encodeWithSignature("withdrawFromAd(string,uint256,address)", p.adId, 1, agent);
        }
        revert(string.concat("action: ", action));
    }

    /*//////////////////////////////////////////////////////////////
                              CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    function _setCeilings(Ceiling[] memory ceilings) internal {
        for (uint256 i = 0; i < ceilings.length; ++i) {
            vm.prank(instance.account);
            module.setAccountLimit(ceilings[i].token, ceilings[i].capacity, ceilings[i].refillPerSecond);
        }
    }

    /// @dev By low-level call, so a refusal comes back as data rather than ending the test.
    function _install(bytes memory policy) internal returns (bool ok, bytes memory err) {
        vm.prank(instance.account);
        (ok, err) = address(module).call(abi.encodeCall(module.setAgentPolicy, (agentId, policy)));
    }

    /*//////////////////////////////////////////////////////////////
                               VOCABULARY
    //////////////////////////////////////////////////////////////*/

    /// @dev The fixture's word for a refusal, as this module's. An unknown word has to fail here
    ///      rather than match nothing.
    function _refusal(string memory word) internal pure returns (ProofBridgeAgentPolicy.Refusal) {
        if (_eq(word, "TargetNotPinned")) return ProofBridgeAgentPolicy.Refusal.TargetNotPinned;
        if (_eq(word, "ActionNotAllowed")) return ProofBridgeAgentPolicy.Refusal.ActionNotAllowed;
        if (_eq(word, "TokenNotAllowed")) return ProofBridgeAgentPolicy.Refusal.TokenNotAllowed;
        if (_eq(word, "OverPerOrderCap")) return ProofBridgeAgentPolicy.Refusal.OverPerOrderCap;
        if (_eq(word, "AmountNotScalable")) return ProofBridgeAgentPolicy.Refusal.AmountNotScalable;
        if (_eq(word, "AgentAllowanceExceeded")) return ProofBridgeAgentPolicy.Refusal.AgentAllowanceExceeded;
        if (_eq(word, "AccountCeilingExceeded")) return ProofBridgeAgentPolicy.Refusal.AccountCeilingExceeded;
        if (_eq(word, "Expired")) return ProofBridgeAgentPolicy.Refusal.Expired;
        if (_eq(word, "NoPolicy")) return ProofBridgeAgentPolicy.Refusal.NoPolicy;
        if (_eq(word, "SettlementSignerMismatch")) return ProofBridgeAgentPolicy.Refusal.SettlementSignerMismatch;
        if (_eq(word, "AdNotInScope")) return ProofBridgeAgentPolicy.Refusal.AdNotInScope;
        revert(string.concat("a refusal this reader does not know: ", word));
    }

    function _installError(string memory word) internal pure returns (bytes4) {
        if (_eq(word, "AgentPolicy__NoAccountCeiling")) {
            return ProofBridgeAgentPolicy.AgentPolicy__NoAccountCeiling.selector;
        }
        if (_eq(word, "AgentPolicy__BadExpiry")) return ProofBridgeAgentPolicy.AgentPolicy__BadExpiry.selector;
        revert(string.concat("an install error this reader does not know: ", word));
    }

    /// @dev One word for everyone, or a word per reader where the implementations differ by design.
    function _expected(string memory path) internal view returns (string memory) {
        string memory mine = string.concat(path, ".evm");
        return vm.keyExistsJson(vectors, mine) ? vectors.readString(mine) : vectors.readString(path);
    }

    function _reads(string memory path) internal view returns (bool) {
        string[] memory readers = vectors.readStringArray(path);
        for (uint256 i = 0; i < readers.length; ++i) {
            if (_eq(readers[i], "evm")) return true;
        }
        return false;
    }

    /*//////////////////////////////////////////////////////////////
                                  PATHS
    //////////////////////////////////////////////////////////////*/

    function _case(uint256 c, string memory field) internal pure returns (string memory) {
        return string.concat(".cases[", vm.toString(c), "]", field);
    }

    function _step(uint256 c, uint256 s, string memory field) internal pure returns (string memory) {
        return string.concat(".cases[", vm.toString(c), "].steps[", vm.toString(s), "]", field);
    }

    function _install(uint256 i, string memory field) internal pure returns (string memory) {
        return string.concat(".installs[", vm.toString(i), "]", field);
    }

    function _nth(string memory path, uint256 i, string memory field) internal pure returns (string memory) {
        return string.concat(path, "[", vm.toString(i), "]", field);
    }

    function _eq(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }
}
