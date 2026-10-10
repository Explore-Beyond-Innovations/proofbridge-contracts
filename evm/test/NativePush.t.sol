// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {IEscrow} from "src/interfaces/IEscrow.sol";
import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IDisputeManager} from "src/interfaces/IDisputeManager.sol";
import {Dispute} from "src/libraries/Dispute.sol";
import {TestField} from "test/utils/TestField.sol";
import {DisputeTest} from "./Dispute.t.sol";

/// The logic behind a proxy wallet: receiving costs a delegatecall plus storage writes.
contract WalletImpl {
    bool public accepting;
    uint256 public received;

    function setAccepting(bool ok) external {
        accepting = ok;
    }

    function claimTo(IEscrow escrow, address token, address to) external {
        escrow.claimTo(token, to);
    }

    receive() external payable {
        require(accepting, "wallet closed");
        received += msg.value;
    }
}

/// A smart-account-like receiver: bumps a nonce, emits, and calls out on receive.
contract Ledger {
    mapping(address => uint256) public deposits;

    function record(uint256 amount) external {
        deposits[msg.sender] += amount;
    }
}

contract SmartAccountLike {
    event Received(address from, uint256 amount);

    Ledger internal immutable ledger;
    uint256 public nonce;

    constructor(Ledger l) {
        ledger = l;
    }

    receive() external payable {
        nonce += 1;
        ledger.record(msg.value);
        emit Received(msg.sender, msg.value);
    }
}

/// A maker contract whose receive hook tries to withdraw again from inside the push.
contract ReentrantMaker {
    IAdManager internal immutable am;
    address internal immutable token;
    string internal adId;
    bool public reentryRefused;
    uint256 public hooks;

    constructor(IAdManager am_, address token_) {
        am = am_;
        token = token_;
    }

    function create(string calldata id, uint256 amount, uint256 chainId, bytes32 signer) external payable {
        adId = id;
        am.createAd{value: msg.value}(id, token, amount, chainId, bytes32(uint256(uint160(address(this)))), signer);
    }

    function withdraw(uint256 amount) external {
        am.withdrawFromAd(adId, amount, address(this));
    }

    receive() external payable {
        hooks += 1;
        if (hooks > 1) return;
        try am.withdrawFromAd(adId, 1 ether, address(this)) {}
        catch (bytes memory err) {
            reentryRefused = bytes4(err) == ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector;
        }
    }
}

/// Reads the order and dispute state from inside its receive hook.
contract StateProbe {
    IEscrow internal immutable escrow;
    IDisputeManager internal immutable dm;
    bytes32 public orderHash;
    uint8 public statusSeen;
    bool public disputedSeen;
    bool public hooked;

    constructor(IEscrow e, IDisputeManager d) {
        escrow = e;
        dm = d;
    }

    function watch(bytes32 h) external {
        orderHash = h;
    }

    receive() external payable {
        hooked = true;
        statusSeen = uint8(escrow.orders(orderHash));
        disputedSeen = dm.isDisputed(orderHash);
    }
}

/// The native push through the escrow doors (October security review): with all gas forwarded,
/// proxy and smart-account wallets receive; a settlement push that fails still credits; a hook that
/// re-enters is refused; and finalizeDispute pays only after the dispute is closed.
contract NativePushTest is DisputeTest {
    WalletImpl internal wallet; // the proxy, typed as its logic
    SmartAccountLike internal account;

    function setUp() public override {
        super.setUp();
        wallet = WalletImpl(payable(address(new ERC1967Proxy(address(new WalletImpl()), ""))));
        account = new SmartAccountLike(new Ledger());
    }

    function test_withdrawFromAd_paysAProxyWallet() public {
        test_createAd_with_native_token_success();
        wallet.setAccepting(true);
        vm.prank(maker);
        adManager.withdrawFromAd("nativeAd", 3 ether, address(wallet));
        assertEq(address(wallet).balance, 3 ether);
        assertEq(wallet.received(), 3 ether, "the proxy's logic ran");
    }

    function test_withdrawFromAd_paysASmartAccount() public {
        test_createAd_with_native_token_success();
        vm.prank(maker);
        adManager.withdrawFromAd("nativeAd", 2 ether, address(account));
        assertEq(address(account).balance, 2 ether);
        assertEq(account.nonce(), 1);
    }

    function test_closeAd_paysAProxyWallet() public {
        test_createAd_with_native_token_success();
        wallet.setAccepting(true);
        vm.prank(maker);
        adManager.closeAd("nativeAd", address(wallet));
        assertEq(address(wallet).balance, initAmt);
        assertEq(wallet.received(), initAmt);
    }

    /// A refusing proxy wallet is credited on the settlement push; `claim` later pays it in full.
    function test_settlementCreditsARefusingWallet_thenClaimPaysIt() public {
        test_createAd_with_native_token_success();
        (IAdManager.OrderParams memory p,) =
            _openOrder("nativeAd", NATIVE_TOKEN_ADDRESS, 50 ether, 801, bridger, address(wallet));
        vm.prank(bridger);
        adManager.unlock(p, TestField.fe("NP1"), bytes32(uint256(71)), hex"", hex"");
        assertEq(address(wallet).balance, 0, "the push failed");
        assertEq(adManager.claimable(address(wallet), NATIVE_TOKEN_ADDRESS), 50 ether, "credited instead");

        wallet.setAccepting(true);
        adManager.claim(address(wallet), NATIVE_TOKEN_ADDRESS);
        assertEq(address(wallet).balance, 50 ether);
        assertEq(wallet.received(), 50 ether);
    }

    /// The credited wallet redirects its credit to a smart account with `claimTo`.
    function test_claimTo_paysASmartAccount() public {
        test_createAd_with_native_token_success();
        (IAdManager.OrderParams memory p,) =
            _openOrder("nativeAd", NATIVE_TOKEN_ADDRESS, 40 ether, 802, bridger, address(wallet));
        vm.prank(bridger);
        adManager.unlock(p, TestField.fe("NP2"), bytes32(uint256(72)), hex"", hex"");
        assertEq(adManager.claimable(address(wallet), NATIVE_TOKEN_ADDRESS), 40 ether);

        wallet.claimTo(IEscrow(address(adManager)), NATIVE_TOKEN_ADDRESS, address(account));
        assertEq(address(account).balance, 40 ether);
        assertEq(account.nonce(), 1);
        assertEq(adManager.claimable(address(wallet), NATIVE_TOKEN_ADDRESS), 0);
    }

    /// With all gas forwarded the receive hook can call back in; the escrow's guard refuses it, and
    /// the ad is debited exactly once.
    function test_reentryFromTheReceiveHook_isRefused() public {
        test_createAd_with_native_token_success(); // wires the route
        ReentrantMaker rm = new ReentrantMaker(IAdManager(address(adManager)), NATIVE_TOKEN_ADDRESS);
        vm.deal(address(this), 10 ether);
        rm.create{value: 10 ether}("rmAd", 10 ether, orderChainId, _b32(maker));

        rm.withdraw(4 ether);
        assertTrue(rm.reentryRefused(), "the nested withdraw hit the reentrancy guard");
        assertEq(address(rm).balance, 4 ether, "paid once");
        (,,,,,,, uint256 balance,) = adManager.ads("rmAd");
        assertEq(balance, 6 ether, "debited once");
    }

    /// finalizeDispute pays a maker forfeit after the order is resolved and the dispute record is
    /// gone, so the recipient's hook never sees the order mid-transition.
    function test_finalizeDispute_paysAfterTheDisputeCloses() public {
        test_createAd_with_native_token_success();
        StateProbe probe = new StateProbe(IEscrow(address(adManager)), IDisputeManager(address(dm)));
        (IAdManager.OrderParams memory p, bytes32 h) =
            _openOrder("nativeAd", NATIVE_TOKEN_ADDRESS, 60 ether, 803, bridger, address(probe));
        probe.watch(h);
        _file(p, maker);
        vm.prank(arbiter);
        dm.resolveDispute(h, Dispute.Outcome.MakerForfeit);
        _warpPastWindow(h);

        adManager.finalizeDispute(p);
        assertTrue(probe.hooked(), "paid directly");
        assertEq(address(probe).balance, 60 ether);
        assertEq(probe.statusSeen(), uint8(IEscrow.Status.Resolved), "order resolved before the push");
        assertFalse(probe.disputedSeen(), "dispute record gone before the push");
    }
}
