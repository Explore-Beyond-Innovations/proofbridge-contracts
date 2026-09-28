// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {stdJson} from "forge-std/StdJson.sol";
import {ModuleKitHelpers, UserOpData} from "modulekit/ModuleKit.sol";
import {Execution} from "modulekit/accounts/erc7579/lib/ExecutionLib.sol";

import {IAdManager} from "src/interfaces/IAdManager.sol";
import {ProofBridgeAgentPolicy} from "src/agent/ProofBridgeAgentPolicy.sol";
import {AgentPolicyBase} from "./AgentPolicyBase.t.sol";
import {MockEscrow} from "./mocks/MockEscrow.sol";

/// T-60, layer 2: the module against the shared policy fixture.
///
/// Three implementations decide whether an agent's lock is allowed: this module, the Soroban agent
/// account, and a TypeScript copy the relayer asks first. `test-vectors/agent-policy-parity.json`
/// holds policy + lock → accept or reject, every verdict written by hand, and all three read it. A
/// case carries exactly one fault, except the precedence cases, which pin the one order all three
/// share. A case this reader does not run names the reason in `skips.evm`, and the enumeration test
/// asserts it. A `request` step is a batch UserOperation: this chain's "several locks, one
/// authorization".
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
    /// The fixture is read from disk into *memory* by each external helper, never kept in storage:
    /// a storage string is copied out whole on every `vm.readX`, and at 116 KB that copy costs about
    /// 8M gas, which was most of what these tests spent. `vm.readFile` is a cheat and costs nothing.
    string internal constant VECTORS = "../test-vectors/agent-policy-parity.json";

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
        /// A re-install the chain must refuse (a revoked id), or zero when it must install.
        bytes4 reinstallError;
        bool setCeiling;
        bool dropCeiling;
        bytes32 token;
        uint256 capacity;
        uint256 refillPerSecond;
        uint256 warp;
        /// One entry for a single lock; several for a `request`, which goes as one batch.
        bool[] pinned;
        bytes[] callData;
        bool request;
        uint256 refusedAt;
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

    /// @dev `_accountLimit`'s slot in the module's layout, for the one step that has to reach under
    ///      the module: a ceiling going missing. `_dropCeiling` checks the configured capacity is
    ///      there before zeroing it, so a layout change fails loudly rather than zeroing nothing.
    uint256 internal constant ACCOUNT_LIMIT_SLOT = 12;

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
        string memory vectors = vm.readFile(VECTORS);
        uint256 cases;
        uint256 steps;
        uint256 skipped;
        uint256[] memory perSlice = new uint256[](SLICES);
        uint256 total = vectors.readUint(".counts.total.cases");
        // The count is the table's real length, not a number the fixture could understate.
        assertTrue(this.exists(_case(total - 1, "")) && !this.exists(_case(total, "")), "counts.total.cases");
        assertEq(vectors.readUint(".counts.evm.slices"), SLICES, "the fixture and this reader agree on the slice count");
        for (uint256 c = 0; c < total; ++c) {
            (bool mine, uint256 stepCount, uint256 slice) = this.loadCount(c);
            if (!mine) {
                // Not a silent skip: the fixture has to say why this implementation cannot run it.
                ++skipped;
                continue;
            }
            ++cases;
            steps += stepCount;
            ++perSlice[slice];
        }
        assertGt(cases, 0, "no case is this reader's");
        assertEq(cases, vectors.readUint(".counts.evm.cases"), "cases seen");
        assertEq(steps, vectors.readUint(".counts.evm.steps"), "steps seen");
        assertEq(cases + skipped, total, "every case run or skipped with a reason");
        for (uint256 i = 0; i < SLICES; ++i) {
            assertGt(perSlice[i], 0, "a slice with nothing in it proves nothing by passing");
        }
    }

    function _runSlice(uint256 slice) internal {
        string memory vectors = vm.readFile(VECTORS);
        uint256 ranCases;
        uint256 total = vectors.readUint(".counts.total.cases");

        // The fixture assigns cases to slices, balanced by step count, so skipping another slice's
        // case is one small read: every read of the fixture copies the whole file out of storage,
        // and that, not the operations, is most of what this test costs.
        for (uint256 c = 0; c < total; ++c) {
            if (!this.inSlice(c, slice)) continue;
            Setup memory setup = this.loadSetup(_case(c, ""), false);
            assertTrue(setup.mine, "a case assigned to an EVM slice is not this reader's");

            // Each case starts from the bare rig: no case inherits another's buckets or tally.
            uint256 snapshot = vm.snapshotState();
            uint256 nowTs = setup.startTime;
            vm.warp(nowTs);
            _setCeilings(setup.ceilings);
            (bool installed,) = _install(setup.policy);
            assertTrue(installed, string.concat(setup.name, ": did not install"));
            vm.prank(instance.account);
            module.setAgentGasBudget(agentId, type(uint128).max);

            uint256 ranSteps;
            for (uint256 s = 0; s < setup.steps; ++s) {
                Loaded memory step = this.loadStep(c, s, setup.name);
                nowTs += step.warp;
                vm.warp(nowTs);
                ++ranSteps;

                if (step.revoke) {
                    vm.prank(instance.account);
                    module.revokeAgent(agentId);
                    continue;
                }
                if (step.reinstall) {
                    // The owner installs the same policy again: a new version, so a fresh bucket for
                    // the agent, while the account's ceiling keeps what was spent. Or, for a revoked
                    // id, a refusal: the tombstone.
                    (bool again, bytes memory err) = _install(setup.policy);
                    if (step.reinstallError == bytes4(0)) {
                        assertTrue(again, string.concat(step.at, ": did not reinstall"));
                    } else {
                        assertFalse(again, string.concat(step.at, ": re-installed"));
                        assertEq(bytes4(err), step.reinstallError, step.at);
                    }
                    continue;
                }
                if (step.setCeiling) {
                    vm.prank(instance.account);
                    module.setAccountLimit(step.token, step.capacity, step.refillPerSecond);
                    continue;
                }
                if (step.dropCeiling) {
                    _dropCeiling(step.token, setup.ceilings, step.at);
                    continue;
                }
                _judge(step);
            }
            // Every step, not most of them: a loop that stopped one early in each case would
            // otherwise pass, and did once, when the single-frame test's step count went with it.
            assertEq(ranSteps, setup.steps, string.concat(setup.name, ": steps ran"));

            vm.revertToState(snapshot);
            ++ranCases;
        }
        assertGt(ranCases, 0, "this slice ran nothing");
    }

    function test_installingAPolicyMatchesTheSharedFixture() public {
        string memory vectors = vm.readFile(VECTORS);
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
        UserOpData memory op;
        if (step.request) {
            // One authorization for several locks: a batch, judged whole.
            Execution[] memory calls = new Execution[](step.callData.length);
            for (uint256 i = 0; i < calls.length; ++i) {
                calls[i] = Execution({
                    target: address(step.pinned[i] ? escrow : unpinned), value: 0, callData: step.callData[i]
                });
            }
            op = instance.getExecOps(calls, address(module));
        } else {
            op = instance.getExecOps(address(step.pinned[0] ? escrow : unpinned), 0, step.callData[0], address(module));
        }
        op.userOp.signature = _sign(op.userOpHash, agentKey);

        (ProofBridgeAgentPolicy.Refusal why, uint256 callIndex) =
            module.preflight(instance.account, agentId, op.userOp.callData);
        assertEq(uint8(why), uint8(step.refusal), step.at);
        // In a request, which lock was refused: the second of two means the first's debit counted.
        if (step.request && !step.accept) {
            assertEq(callIndex, step.refusedAt, string.concat(step.at, ": the lock refused"));
        }

        // ...and the enforcing path, which `preflight` only describes. What a refusal proves depends
        // on which half refuses. The *validator's* no is the EntryPoint's, and is the same on every
        // account type, so it is held to the exact answer: AA24 for a policy refusal, AA22 for an
        // expired one. Anything else reverting (prefund, the gas budget, the pause) would not match.
        // A *volume* refusal is the hook's, which surfaces differently per account type, so there
        // the claim is only what it can be: `preflight` named the reason, and the lock did not land.
        uint256 before = escrow.locks() + unpinned.locks();
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
        assertEq(
            escrow.locks() + unpinned.locks(),
            before + (step.accept ? step.callData.length : 0),
            string.concat(step.at, ": through the EntryPoint")
        );
    }

    /// @dev A ceiling row gone from under a live policy. Soroban reaches this by an idle entry
    ///      archiving; EVM storage does not expire and no call removes a ceiling, so this zeroes the
    ///      stored row to reach the module's own refusal for it (`_floors`, `_acquireCeiling`).
    function _dropCeiling(bytes32 token, Ceiling[] memory ceilings, string memory at) internal {
        bytes32 ceilKey = keccak256(abi.encode(module.epochOf(instance.account), "ceiling", token));
        bytes32 slot = keccak256(abi.encode(instance.account, keccak256(abi.encode(ceilKey, ACCOUNT_LIMIT_SLOT))));
        uint256 configured;
        for (uint256 i = 0; i < ceilings.length; ++i) {
            if (ceilings[i].token == token) configured = ceilings[i].capacity;
        }
        assertGt(configured, 0, string.concat(at, ": the case configured no ceiling to drop"));
        assertEq(uint256(vm.load(address(module), slot)), configured, string.concat(at, ": not the ceiling's slot"));
        vm.store(address(module), slot, bytes32(0));
        vm.store(address(module), bytes32(uint256(slot) + 1), bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                         READING THE FIXTURE
    //////////////////////////////////////////////////////////////*/

    function exists(string calldata path) external view returns (bool) {
        string memory vectors = vm.readFile(VECTORS);
        return vm.keyExistsJson(vectors, path);
    }

    /// @param install true for a row of the `installs` table, which carries an `expect` of its own.
    function loadSetup(string calldata at, bool install) external view returns (Setup memory setup) {
        string memory vectors = vm.readFile(VECTORS);
        setup.mine = _reads(vectors, string.concat(at, ".readers"));
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
            setup.steps = vectors.readUint(string.concat(at, ".stepCount"));
        }
    }

    /// @dev The two numbers the enumeration needs, and nothing else: `loadSetup` also reads the policy
    ///      bytes and every ceiling, which for counting is most of the cost.
    /// @dev Whether case `c` is in EVM slice `slice`: one read. A case with no slice is not this
    ///      reader's, which the enumeration test holds to `readers`.
    function inSlice(uint256 c, uint256 slice) external view returns (bool) {
        string memory vectors = vm.readFile(VECTORS);
        string memory at = _case(c, ".evmSlice");
        return vm.keyExistsJson(vectors, at) && vectors.readUint(at) == slice;
    }

    function loadCount(uint256 c) external view returns (bool mine, uint256 steps, uint256 slice) {
        string memory vectors = vm.readFile(VECTORS);
        mine = _reads(vectors, _case(c, ".readers"));
        // A case is this reader's exactly when the fixture gave it a slice.
        assertEq(vm.keyExistsJson(vectors, _case(c, ".evmSlice")), mine, "evmSlice present iff evm reads the case");
        // ...and it is not this reader's exactly when the fixture says why not.
        string memory why = _case(c, ".skips.evm");
        assertEq(vm.keyExistsJson(vectors, why), !mine, "skips.evm present iff evm does not read the case");
        if (!mine) {
            assertGt(bytes(vectors.readString(why)).length, 0, "an empty reason is no reason");
            return (false, 0, 0);
        }
        steps = vectors.readUint(_case(c, ".stepCount"));
        slice = vectors.readUint(_case(c, ".evmSlice"));
        // Stated by the fixture; held to the array's real end, or an understated count would let a
        // reader skip the tail of every case.
        string memory tail = _case(c, ".steps");
        assertTrue(
            steps > 0 && vm.keyExistsJson(vectors, _nth(tail, steps - 1, ""))
                && !vm.keyExistsJson(vectors, _nth(tail, steps, "")),
            "stepCount"
        );
    }

    function loadStep(uint256 c, uint256 s, string calldata name) external view returns (Loaded memory step) {
        string memory vectors = vm.readFile(VECTORS);
        step.at = string.concat(name, " [step ", vm.toString(s), "]");
        step.warp = vectors.readUint(_step(c, s, ".warp"));
        string memory op = vectors.readString(_step(c, s, ".op"));
        step.revoke = _eq(op, "revoke");
        step.reinstall = _eq(op, "reinstall");
        if (step.revoke) return step;
        if (step.reinstall) {
            string memory refused = _step(c, s, ".expect");
            if (vm.keyExistsJson(vectors, refused)) {
                step.reinstallError = _installError(
                    vectors.readString(string.concat(".installReasons.", vectors.readString(refused), ".evm"))
                );
            }
            return step;
        }
        step.setCeiling = _eq(op, "setCeiling");
        step.dropCeiling = _eq(op, "dropCeiling");
        if (step.setCeiling || step.dropCeiling) {
            step.token = vectors.readBytes32(_step(c, s, ".token"));
            if (step.setCeiling) {
                step.capacity = vectors.readUint(_step(c, s, ".capacity"));
                step.refillPerSecond = vectors.readUint(_step(c, s, ".refillPerSecond"));
            }
            return step;
        }
        step.request = _eq(op, "request");
        require(step.request || _eq(op, "lock"), string.concat("an op this reader does not know: ", op));

        if (step.request) {
            string memory locks = _step(c, s, ".locks");
            uint256 n;
            while (vm.keyExistsJson(vectors, _nth(locks, n, ""))) ++n;
            step.pinned = new bool[](n);
            step.callData = new bytes[](n);
            for (uint256 i = 0; i < n; ++i) {
                (step.pinned[i], step.callData[i]) = _readLock(vectors, _nth(locks, i, ""));
            }
            string memory at = _step(c, s, ".refusedAt");
            if (vm.keyExistsJson(vectors, at)) step.refusedAt = vectors.readUint(at);
        } else {
            step.pinned = new bool[](1);
            step.callData = new bytes[](1);
            (step.pinned[0], step.callData[0]) = _readLock(vectors, _step(c, s, ".lock"));
        }

        string memory want = _expected(vectors, _step(c, s, ".expect"));
        step.accept = _eq(want, "accept");
        step.refusal = step.accept
            ? ProofBridgeAgentPolicy.Refusal.None
            : _refusal(vectors.readString(string.concat(".reasons.", want, ".evm")));
        if (!step.accept) step.at = string.concat(step.at, ": want ", want);
    }

    function _readLock(string memory vectors, string memory lock)
        internal
        view
        returns (bool pinned, bytes memory data)
    {
        // This module has no rule about the order's maker (`AdManager` reverts `NotMaker` itself), so
        // a lock naming a stranger is never this reader's: the fixture marks such cases Soroban's.
        require(
            _eq(vectors.readString(string.concat(lock, ".maker")), "account"),
            "a lock with a foreign maker reached the EVM reader"
        );
        pinned = _eq(vectors.readString(string.concat(lock, ".target")), "pinned");
        data = _callData(vectors, lock);
    }

    function _callData(string memory vectors, string memory lock) internal view returns (bytes memory) {
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
        if (_eq(word, "NoAccountCeiling")) return ProofBridgeAgentPolicy.Refusal.NoAccountCeiling;
        if (_eq(word, "OverStoredAllowance")) return ProofBridgeAgentPolicy.Refusal.OverStoredAllowance;
        revert(string.concat("a refusal this reader does not know: ", word));
    }

    function _installError(string memory word) internal pure returns (bytes4) {
        if (_eq(word, "AgentPolicy__NoAccountCeiling")) {
            return ProofBridgeAgentPolicy.AgentPolicy__NoAccountCeiling.selector;
        }
        if (_eq(word, "AgentPolicy__BadExpiry")) return ProofBridgeAgentPolicy.AgentPolicy__BadExpiry.selector;
        if (_eq(word, "AgentPolicy__AgentRevoked")) return ProofBridgeAgentPolicy.AgentPolicy__AgentRevoked.selector;
        revert(string.concat("an install error this reader does not know: ", word));
    }

    /// @dev One word for everyone, or a word per reader where the implementations differ by design.
    function _expected(string memory vectors, string memory path) internal view returns (string memory) {
        string memory mine = string.concat(path, ".evm");
        return vm.keyExistsJson(vectors, mine) ? vectors.readString(mine) : vectors.readString(path);
    }

    function _reads(string memory vectors, string memory path) internal view returns (bool) {
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
