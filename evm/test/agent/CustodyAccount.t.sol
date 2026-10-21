// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {Poseidon2Yul_BN254 as Poseidon2Yul} from "@poseidon2/src/bn254/yul/Poseidon2Yul.sol";

import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IVerifier} from "src/interfaces/IVerifier.sol";
import {IMerkleManager} from "src/interfaces/IMerkleManager.sol";
import {IwNativeToken, wNativeToken} from "src/wNativeToken.sol";
import {AdManager} from "src/AdManager.sol";
import {MerkleManager} from "src/MerkleManager.sol";
import {RouteTiming} from "src/libraries/RouteTiming.sol";
import {AgentPolicyCodec} from "src/agent/AgentPolicyCodec.sol";
import {ProofBridgeAgentPolicy} from "src/agent/ProofBridgeAgentPolicy.sol";
import {IAgentPolicyDirect, ProofBridgeCustodyAccount} from "src/agent/ProofBridgeCustodyAccount.sol";
import {CustodyAccountFactory} from "src/agent/CustodyAccountFactory.sol";
import {MockVerifier} from "../mocks/MockVerifier.sol";
import {MockKeyRegistry} from "../mocks/MockKeyRegistry.sol";
import {MockRootVerifier} from "../mocks/MockRootVerifier.sol";

/// Plan 45: a maker's custody account on the real `AdManager`. The maker's wallet owns it and acts through
/// `execute`; the pod's key calls `executeAsAgent`, which the policy module checks and counts (`authorizeDirect`)
/// with the same rules as a 7702 account's UserOps — so every refusal here is also `preflight`'s answer.
contract CustodyAccountTest is Test {
    uint256 internal constant ORDER_CHAIN_ID = 11155111;
    string internal constant AD = "custody-ad";
    string internal constant OTHER_AD = "custody-ad-2";
    uint256 internal constant AD_FUNDS = 10_000_000;
    uint256 internal constant MAX_PER_ORDER = 1_000_000;
    uint256 internal constant CAPACITY = 5_000_000;
    uint256 internal constant REFILL = 10;
    uint64 internal constant EXPIRY_IN = 30 days;

    ProofBridgeAgentPolicy internal module;
    CustodyAccountFactory internal factory;
    ProofBridgeCustodyAccount internal account;
    AdManager internal adManager;
    MockKeyRegistry internal keys;
    ERC20Mock internal adToken;

    address internal admin = makeAddr("escrow-admin");
    address internal orderPortal = makeAddr("order-portal");
    address internal orderToken = makeAddr("order-token");
    address internal adRecipient = makeAddr("ad-recipient");
    address internal owner = makeAddr("maker-wallet");
    address internal agent = makeAddr("pod");
    bytes32 internal agentId;
    bytes32 internal signer;
    uint64 internal validUntil;

    function setUp() public {
        module = new ProofBridgeAgentPolicy();
        factory = new CustodyAccountFactory(IAgentPolicyDirect(address(module)));
        MerkleManager merkleManager = new MerkleManager(admin, address(new Poseidon2Yul()));
        adManager = new AdManager(
            admin,
            IVerifier(address(new MockVerifier(true))),
            IMerkleManager(address(merkleManager)),
            IwNativeToken(address(new wNativeToken("Wrapped Native Token", "WNATIVE", 18)))
        );
        keys = new MockKeyRegistry();
        vm.startPrank(admin);
        merkleManager.setManager(address(adManager), true);
        adManager.setKeyRegistry(keys);
        adManager.setRootVerifier(ORDER_CHAIN_ID, address(new MockRootVerifier(true)));
        adManager.setRouteTiming(ORDER_CHAIN_ID, RouteTiming.Timing(0, 30 minutes, 0, 0));
        adManager.setPeerEscrow(ORDER_CHAIN_ID, _b32(orderPortal));
        adToken = new ERC20Mock();
        adManager.setTokenRoute(address(adToken), ORDER_CHAIN_ID, _b32(orderToken));
        vm.stopPrank();

        agentId = _b32(agent);
        // The browser path: the maker's own wallet is the settlement signer (plan 44 D1), and it approves the
        // account as a maker of its key.
        signer = _b32(owner);
        keys.set(signer, true);
        validUntil = uint64(block.timestamp) + EXPIRY_IN;

        vm.prank(owner);
        account = ProofBridgeCustodyAccount(payable(factory.deploy(0, _targets())));
        keys.approve(signer, _b32(address(account)), true);

        // The owner opens two ads from the account and gives the agent a policy for the first only.
        adToken.mint(address(account), 2 * AD_FUNDS);
        _asOwner(address(adToken), abi.encodeCall(adToken.approve, (address(adManager), 2 * AD_FUNDS)));
        _createAd(AD);
        _createAd(OTHER_AD);
        _asOwner(
            address(module), abi.encodeCall(module.setAccountLimit, (_b32(address(adToken)), 2 * CAPACITY, REFILL))
        );
        _asOwner(address(module), abi.encodeCall(module.setAgentPolicy, (agentId, _policy(AD))));
    }

    /*//////////////////////////////////////////////////////////////
                               THE AGENT
    //////////////////////////////////////////////////////////////*/

    function test_theAgentLocksAnOrderOnItsAd() public {
        IAdManager.OrderParams memory p = _order(AD, 100_000, 1);
        vm.prank(agent);
        account.executeAsAgent(address(adManager), _lock(p));
        assertEq(adManager.availableLiquidity(AD), AD_FUNDS - 100_000, "the ad's liquidity is locked");
        assertEq(module.agentBucket(address(account), agentId, _b32(address(adToken))).level, CAPACITY - 100_000);
        assertEq(module.accountBucket(address(account), _b32(address(adToken))).level, 2 * CAPACITY - 100_000);
    }

    /// Every way out of the policy is refused with the module's reason, which is `preflight`'s answer for the
    /// same request; nothing reaches the escrow and the buckets don't move.
    function test_everyRefusalIsPreflightsAndLeavesTheBucketsAlone() public {
        _refused(
            agent,
            address(adManager),
            _lock(_order(AD, MAX_PER_ORDER + 1, 2)),
            0,
            ProofBridgeAgentPolicy.Refusal.OverPerOrderCap
        );
        _refused(
            agent, address(adManager), _lock(_order(OTHER_AD, 100, 3)), 0, ProofBridgeAgentPolicy.Refusal.AdNotInScope
        );
        _refused(
            agent,
            address(adManager),
            abi.encodeCall(IAdManager.withdrawFromAd, (AD, AD_FUNDS, agent)),
            0,
            ProofBridgeAgentPolicy.Refusal.ActionNotAllowed
        );
        _refused(
            agent,
            address(adToken),
            abi.encodeCall(adToken.transfer, (agent, 1)),
            0,
            ProofBridgeAgentPolicy.Refusal.TargetNotPinned
        );
        IAdManager.OrderParams memory wrongSigner = _order(AD, 100, 4);
        wrongSigner.adSettlementSigner = _b32(makeAddr("someone-else"));
        _refused(
            agent, address(adManager), _lock(wrongSigner), 0, ProofBridgeAgentPolicy.Refusal.SettlementSignerMismatch
        );
        // An address with no policy here.
        _refused(
            makeAddr("stranger"),
            address(adManager),
            _lock(_order(AD, 100, 5)),
            type(uint256).max,
            ProofBridgeAgentPolicy.Refusal.NoPolicy
        );
    }

    function test_anExpiredPolicyIsRefused() public {
        vm.warp(validUntil);
        _refused(
            agent,
            address(adManager),
            _lock(_order(AD, 100, 6)),
            type(uint256).max,
            ProofBridgeAgentPolicy.Refusal.Expired
        );
    }

    function test_aRevokedAgentIsRefused() public {
        _asOwner(address(module), abi.encodeCall(module.revokeAgent, (agentId)));
        _refused(
            agent,
            address(adManager),
            _lock(_order(AD, 100, 7)),
            type(uint256).max,
            ProofBridgeAgentPolicy.Refusal.NoPolicy
        );
    }

    /// The module passes the lock and the escrow then refuses it: the debit goes with the revert.
    function test_aLockTheEscrowRefusesIsNotCounted() public {
        IAdManager.OrderParams memory p = _order(AD, 100_000, 8);
        p.deadline = block.timestamp - 1;
        vm.prank(agent);
        vm.expectRevert();
        account.executeAsAgent(address(adManager), _lock(p));
        assertEq(module.agentBucket(address(account), agentId, _b32(address(adToken))).lastTs, 0, "never debited");
        assertEq(adManager.availableLiquidity(AD), AD_FUNDS);
    }

    /// `authorizeDirect` takes a single call only: the batch rules exist for the 4337 split it doesn't have.
    function test_authorizeDirectRefusesABatch() public {
        // A well-formed one-call batch, which the walk itself would accept: only the single-call rule stops it.
        ProofBridgeAgentPolicy.Execution[] memory calls = new ProofBridgeAgentPolicy.Execution[](1);
        calls[0] = ProofBridgeAgentPolicy.Execution(address(adManager), 0, _lock(_order(AD, 100, 9)));
        bytes memory batch = abi.encodeWithSelector(0xe9ae5c53, bytes32(uint256(1) << 248), abi.encode(calls));
        vm.prank(address(account));
        vm.expectRevert(
            abi.encodeWithSelector(
                ProofBridgeAgentPolicy.AgentPolicy__RefusedAtExecution.selector,
                type(uint256).max,
                ProofBridgeAgentPolicy.Refusal.MalformedRequest
            )
        );
        module.authorizeDirect(agentId, batch);
    }

    /// A caller that never mounted the module (a wallet, a contract) is refused before anything is read.
    function test_authorizeDirectRefusesAnUnmountedCaller() public {
        vm.prank(makeAddr("not-an-account"));
        vm.expectRevert(
            abi.encodeWithSelector(
                ProofBridgeAgentPolicy.AgentPolicy__RefusedAtExecution.selector,
                type(uint256).max,
                ProofBridgeAgentPolicy.Refusal.NotMounted
            )
        );
        module.authorizeDirect(agentId, _execute(address(adManager), _lock(_order(AD, 100, 10))));
    }

    /*//////////////////////////////////////////////////////////////
                               THE OWNER
    //////////////////////////////////////////////////////////////*/

    function test_onlyTheOwnerExecutes() public {
        address stranger = makeAddr("stranger");
        vm.startPrank(stranger);
        vm.expectRevert(ProofBridgeCustodyAccount.CustodyAccount__NotOwner.selector);
        account.execute(address(adManager), 0, abi.encodeCall(IAdManager.withdrawFromAd, (AD, 1, stranger)));
        ProofBridgeCustodyAccount.Call[] memory calls = new ProofBridgeCustodyAccount.Call[](1);
        calls[0] = ProofBridgeCustodyAccount.Call(address(adToken), 0, abi.encodeCall(adToken.transfer, (stranger, 1)));
        vm.expectRevert(ProofBridgeCustodyAccount.CustodyAccount__NotOwner.selector);
        account.executeBatch(calls);
        vm.expectRevert(ProofBridgeCustodyAccount.CustodyAccount__NotOwner.selector);
        account.transferOwnership(stranger);
        vm.stopPrank();
    }

    function test_theOwnerWithdrawsAndClosesThroughTheAccount() public {
        _asOwner(address(adManager), abi.encodeCall(IAdManager.withdrawFromAd, (AD, 1_000, owner)));
        assertEq(adToken.balanceOf(owner), 1_000);
        _asOwner(address(adManager), abi.encodeCall(IAdManager.closeAd, (OTHER_AD, owner)));
        assertEq(adToken.balanceOf(owner), 1_000 + AD_FUNDS);
    }

    function test_ownershipMovesInTwoSteps() public {
        address next = makeAddr("next-owner");
        vm.prank(owner);
        account.transferOwnership(next);
        assertEq(account.owner(), owner, "not until accepted");
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(ProofBridgeCustodyAccount.CustodyAccount__NotPendingOwner.selector);
        account.acceptOwnership();
        vm.prank(next);
        account.acceptOwnership();
        assertEq(account.owner(), next);
        assertEq(account.pendingOwner(), address(0));
    }

    /// The maker's signer must approve the account, or the escrow refuses the ad.
    function test_anAdNeedsTheSignersApprovalOfTheAccount() public {
        keys.approve(signer, _b32(address(account)), false);
        vm.prank(owner);
        vm.expectRevert();
        account.execute(
            address(adManager),
            0,
            abi.encodeCall(
                adManager.createAd, ("unapproved", address(adToken), 1, ORDER_CHAIN_ID, _b32(adRecipient), signer)
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                        INITIALISING, THE FACTORY
    //////////////////////////////////////////////////////////////*/

    function test_neitherTheCloneNorTheImplementationCanBeInitialisedAgain() public {
        ProofBridgeCustodyAccount implementation = ProofBridgeCustodyAccount(payable(factory.implementation()));
        vm.startPrank(address(factory));
        vm.expectRevert(ProofBridgeCustodyAccount.CustodyAccount__AlreadyInitialized.selector);
        account.initialize(makeAddr("thief"), _targets());
        vm.expectRevert(ProofBridgeCustodyAccount.CustodyAccount__AlreadyInitialized.selector);
        implementation.initialize(makeAddr("thief"), _targets());
        vm.stopPrank();
        vm.prank(makeAddr("thief"));
        vm.expectRevert(ProofBridgeCustodyAccount.CustodyAccount__NotFactory.selector);
        account.initialize(makeAddr("thief"), _targets());
    }

    function test_theFactoryKnowsItsOwnAccountsOnly() public {
        assertEq(factory.predict(owner, 0), address(account), "predict matches");
        assertEq(account.owner(), owner);
        assertTrue(factory.isAccount(address(account)));
        assertFalse(factory.isAccount(factory.implementation()), "the implementation is not an account");
        assertFalse(factory.isAccount(owner));
        // The same owner and salt again: the address is taken.
        vm.prank(owner);
        vm.expectRevert();
        factory.deploy(0, _targets());
    }

    /// The caller is the owner: someone else deploying with the same salt gets their own address, never the
    /// owner's, so nobody can open an owner's account first or with targets of their choosing.
    function test_nobodyCanTakeAnOwnersAddressFirst() public {
        address thief = makeAddr("thief");
        vm.prank(thief);
        address theirs = factory.deploy(1, _targets());
        assertTrue(theirs != factory.predict(owner, 1));
        assertEq(ProofBridgeCustodyAccount(payable(theirs)).owner(), thief);
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _refused(
        address caller,
        address target,
        bytes memory data,
        uint256 callIndex,
        ProofBridgeAgentPolicy.Refusal reason
    ) internal {
        (ProofBridgeAgentPolicy.Refusal pre, uint256 preIndex) =
            module.preflight(address(account), _b32(caller), _execute(target, data));
        assertEq(uint8(pre), uint8(reason), "preflight agrees");
        assertEq(preIndex, callIndex, "preflight blames the same call");
        uint256 liquidity = adManager.availableLiquidity(AD);
        vm.prank(caller);
        vm.expectRevert(
            abi.encodeWithSelector(ProofBridgeAgentPolicy.AgentPolicy__RefusedAtExecution.selector, callIndex, reason)
        );
        account.executeAsAgent(target, data);
        assertEq(adManager.availableLiquidity(AD), liquidity, "the escrow never saw it");
        assertEq(module.agentBucket(address(account), agentId, _b32(address(adToken))).lastTs, 0, "never debited");
    }

    function _execute(address target, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(0xe9ae5c53, bytes32(0), abi.encodePacked(target, uint256(0), data));
    }

    function _asOwner(address target, bytes memory data) internal {
        vm.prank(owner);
        account.execute(target, 0, data);
    }

    function _createAd(string memory adId) internal {
        _asOwner(
            address(adManager),
            abi.encodeCall(
                adManager.createAd, (adId, address(adToken), AD_FUNDS, ORDER_CHAIN_ID, _b32(adRecipient), signer)
            )
        );
    }

    function _targets() internal view returns (address[] memory t) {
        t = new address[](1);
        t[0] = address(adManager);
    }

    function _lock(IAdManager.OrderParams memory p) internal pure returns (bytes memory) {
        return abi.encodeCall(IAdManager.lockForOrder, (p, uint32(0)));
    }

    function _order(string memory adId, uint256 amount, uint256 salt)
        internal
        view
        returns (IAdManager.OrderParams memory)
    {
        return IAdManager.OrderParams({
            orderChainToken: _b32(orderToken),
            adChainToken: _b32(address(adToken)),
            amount: amount,
            bridger: bytes32(uint256(0xb1)),
            orderChainId: ORDER_CHAIN_ID,
            srcOrderPortal: _b32(orderPortal),
            orderRecipient: bytes32(uint256(0xb2)),
            adId: adId,
            adCreator: _b32(address(account)),
            adRecipient: _b32(adRecipient),
            salt: salt,
            orderDecimals: 18,
            adDecimals: 18,
            deadline: block.timestamp + 1 days,
            adSettlementSigner: signer,
            lpFeeBps: 0,
            protocolFeeBps: 0
        });
    }

    /// The canonical policy: one lock action, the ad token with its limits, the order token, one ad in scope.
    function _policy(string memory adId) internal view returns (bytes memory) {
        bytes memory ad = bytes(adId);
        bytes memory tokens = bytes.concat(
            AgentPolicyCodec.DOMAIN,
            bytes1(AgentPolicyCodec.ACTION_LOCK_FOR_ORDER),
            bytes1(uint8(1)),
            _b32(address(adToken)),
            bytes32(MAX_PER_ORDER),
            bytes32(CAPACITY),
            bytes32(REFILL),
            bytes1(uint8(1)),
            _b32(orderToken)
        );
        return bytes.concat(
            tokens, bytes1(uint8(1)), bytes1(uint8(1)), bytes2(uint16(ad.length)), ad, bytes8(validUntil), signer
        );
    }

    function _b32(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }
}
