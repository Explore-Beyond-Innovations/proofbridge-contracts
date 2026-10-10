// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {ModuleKitHelpers, UserOpData} from "modulekit/ModuleKit.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {Poseidon2Yul_BN254 as Poseidon2Yul} from "@poseidon2/src/bn254/yul/Poseidon2Yul.sol";

import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IEscrow} from "src/interfaces/IEscrow.sol";
import {IVerifier} from "src/interfaces/IVerifier.sol";
import {IMerkleManager} from "src/interfaces/IMerkleManager.sol";
import {IwNativeToken, wNativeToken} from "src/wNativeToken.sol";
import {AdManager} from "src/AdManager.sol";
import {MerkleManager} from "src/MerkleManager.sol";
import {RouteTiming} from "src/libraries/RouteTiming.sol";
import {OrderHash} from "src/libraries/OrderHash.sol";
import {AgentPolicyCodec} from "src/agent/AgentPolicyCodec.sol";
import {MockVerifier} from "../mocks/MockVerifier.sol";
import {MockKeyRegistry} from "../mocks/MockKeyRegistry.sol";
import {MockRootVerifier} from "../mocks/MockRootVerifier.sol";
import {AgentPolicyBase} from "./AgentPolicyBase.t.sol";

/// C-26: the agent module against the real `AdManager`, not the stand-in. The account is the ad's
/// maker, the agent's UserOp passes the module and then every check the escrow makes of a lock.
/// Runs on every mount CI covers (ACCOUNT_TYPE = DEFAULT / SAFE / KERNEL / NEXUS).
contract AgentPolicyRealEscrowTest is AgentPolicyBase {
    using ModuleKitHelpers for *;

    uint256 internal constant ORDER_CHAIN_ID = 11155111;
    string internal constant REAL_AD = "real-ad";
    uint256 internal constant AD_FUNDS = 10_000_000;

    AdManager internal adManager;
    MerkleManager internal merkleManager;
    ERC20Mock internal adToken;
    address internal admin = makeAddr("escrow-admin");
    address internal orderPortal = makeAddr("order-portal");
    address internal orderToken = makeAddr("order-token");
    address internal adRecipient = makeAddr("ad-recipient");

    function setUp() public override {
        super.setUp();

        merkleManager = new MerkleManager(admin, address(new Poseidon2Yul()));
        adManager = new AdManager(
            admin,
            IVerifier(address(new MockVerifier(true))),
            IMerkleManager(address(merkleManager)),
            IwNativeToken(address(new wNativeToken("Wrapped Native Token", "WNATIVE", 18)))
        );
        MockKeyRegistry keys = new MockKeyRegistry();
        keys.set(settlementSigner, true);

        vm.startPrank(admin);
        merkleManager.setManager(address(adManager), true);
        adManager.setKeyRegistry(keys);
        adManager.setRootVerifier(ORDER_CHAIN_ID, address(new MockRootVerifier(true)));
        adManager.setRouteTiming(ORDER_CHAIN_ID, RouteTiming.Timing(0, 30 minutes, 0, 1 days, 0));
        adManager.setPeerEscrow(ORDER_CHAIN_ID, _b32(orderPortal));
        adToken = new ERC20Mock();
        adManager.setTokenRoute(address(adToken), ORDER_CHAIN_ID, _b32(orderToken));
        vm.stopPrank();

        // The account opens its own ad, through its owner's validator.
        adToken.mint(instance.account, AD_FUNDS);
        instance.exec(address(adToken), 0, abi.encodeCall(adToken.approve, (address(adManager), AD_FUNDS)));
        instance.exec(
            address(adManager),
            0,
            abi.encodeCall(
                adManager.createAd,
                (REAL_AD, address(adToken), AD_FUNDS, ORDER_CHAIN_ID, _b32(adRecipient), settlementSigner)
            )
        );

        // Point the agent at the real escrow and the real tokens.
        address[] memory targets = new address[](1);
        targets[0] = address(adManager);
        _asAccount(abi.encodeCall(module.setTargets, (targets, true)));
        _asAccount(abi.encodeCall(module.setAccountLimit, (_b32(address(adToken)), ACCOUNT_CAPACITY, ACCOUNT_REFILL)));
        _asAccount(abi.encodeCall(module.setAccountLimit, (_b32(orderToken), ACCOUNT_CAPACITY, ACCOUNT_REFILL)));
        _asAccount(abi.encodeCall(module.setAgentPolicy, (agentId, _realPolicy())));
    }

    /// The agent locks for an order on the maker's real ad: the lock lands, the liquidity moves, the
    /// order leaf is appended, and the module debits the agent.
    function test_c26_anAgentLockPassesTheRealAdManager() public {
        IAdManager.OrderParams memory p = _realOrder(100_000, 1);
        _realOp(abi.encodeCall(IAdManager.lockForOrder, (p))).execUserOps();

        assertEq(uint8(adManager.orders(_hashOf(p))), uint8(IEscrow.Status.Open), "the order is open on the escrow");
        assertEq(adManager.availableLiquidity(REAL_AD), AD_FUNDS - 100_000, "the ad's liquidity is locked");
        assertEq(merkleManager.getWidth(), 1, "the lock appended its leaf");
        assertEq(
            module.agentBucket(instance.account, agentId, _b32(address(adToken))).level,
            CAPACITY - 100_000,
            "the agent was debited for it"
        );
    }

    /// The same real escrow, a call the policy does not allow: the agent tries to withdraw the
    /// maker's liquidity. It never reaches the escrow.
    function test_c26_theAgentCannotWithdrawFromTheRealAd() public {
        bytes memory withdraw = abi.encodeCall(IAdManager.withdrawFromAd, (REAL_AD, AD_FUNDS, makeAddr("agent-pocket")));
        UserOpData memory op = _realOp(withdraw);
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(adManager.availableLiquidity(REAL_AD), AD_FUNDS, "the ad is untouched");
        assertEq(adToken.balanceOf(makeAddr("agent-pocket")), 0);
    }

    /// Over the per-order cap on the real escrow: refused by the module, the escrow never sees it.
    function test_c26_overTheCapIsRefusedBeforeTheRealAdManager() public {
        UserOpData memory op = _realOp(abi.encodeCall(IAdManager.lockForOrder, (_realOrder(MAX_PER_ORDER + 1, 2))));
        instance.expect4337Revert();
        op.execUserOps();
        assertEq(adManager.availableLiquidity(REAL_AD), AD_FUNDS);
        assertEq(merkleManager.getWidth(), 0, "no leaf");
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _b32(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    function _realOp(bytes memory callData) internal returns (UserOpData memory op) {
        op = instance.getExecOps(address(adManager), 0, callData, address(module));
        op.userOp.signature = _sign(op.userOpHash, agentKey);
    }

    function _realOrder(uint256 amount, uint256 salt) internal view returns (IAdManager.OrderParams memory p) {
        p = IAdManager.OrderParams({
            orderChainToken: _b32(orderToken),
            adChainToken: _b32(address(adToken)),
            amount: amount,
            bridger: bytes32(uint256(0xb1)),
            orderChainId: ORDER_CHAIN_ID,
            srcOrderPortal: _b32(orderPortal),
            orderRecipient: bytes32(uint256(0xb2)),
            adId: REAL_AD,
            adCreator: _b32(instance.account),
            adRecipient: _b32(adRecipient),
            salt: salt,
            orderDecimals: 18,
            adDecimals: 18,
            deadline: block.timestamp + 1 days,
            adSettlementSigner: settlementSigner
        });
    }

    /// The order hash the escrow computes: this chain, this AdManager.
    function _hashOf(IAdManager.OrderParams memory p) internal view returns (bytes32) {
        return OrderHash.digest(
            OrderHash.Order({
                orderChainToken: p.orderChainToken,
                adChainToken: p.adChainToken,
                amount: p.amount,
                bridger: p.bridger,
                orderChainId: p.orderChainId,
                orderPortal: p.srcOrderPortal,
                orderRecipient: p.orderRecipient,
                adChainId: block.chainid,
                adManager: _b32(address(adManager)),
                adId: p.adId,
                adCreator: p.adCreator,
                adRecipient: p.adRecipient,
                salt: p.salt,
                orderDecimals: p.orderDecimals,
                adDecimals: p.adDecimals,
                deadline: p.deadline,
                adSettlementSigner: p.adSettlementSigner
            })
        );
    }

    /// The canonical policy, one lock action, the real ad token and order token.
    function _realPolicy() internal view returns (bytes memory out) {
        bytes32 a = _b32(address(adToken));
        bytes32 b = _b32(orderToken);
        (bytes32 lo, bytes32 hi) = uint256(a) < uint256(b) ? (a, b) : (b, a);
        out = bytes.concat(
            AgentPolicyCodec.DOMAIN,
            bytes1(uint8(1)),
            bytes1(AgentPolicyCodec.ACTION_LOCK_FOR_ORDER),
            bytes1(uint8(2)),
            lo,
            bytes32(MAX_PER_ORDER),
            bytes32(CAPACITY),
            bytes32(REFILL),
            hi,
            bytes32(MAX_PER_ORDER),
            bytes32(CAPACITY),
            bytes32(REFILL)
        );
        out = bytes.concat(out, bytes1(uint8(0)), bytes1(uint8(0)), bytes8(uint64(0)), settlementSigner);
    }
}
