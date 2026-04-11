// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {AdManager} from "src/AdManager.sol";
import {MockVerifier} from "src/mocks/MockVerifier.sol";
import {MerkleManager} from "src/MerkleManager.sol";
import {IVerifier} from "src/Verifier.sol";
import {IMerkleManager} from "src/MerkleManager.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IwNativeToken, wNativeToken} from "src/wNativeToken.sol";

contract MockAdManager is AdManager {
    constructor(address admin, IVerifier v, IMerkleManager m, IwNativeToken t) AdManager(admin, v, m, t) {}

    function hashOrderPublic(OrderParams calldata p) external view returns (bytes32) {
        return _hashOrder(p, block.chainid, address(this));
    }
}

contract AdManagerTest is Test {
    MockAdManager internal adManager;
    MockVerifier internal verifier;
    MerkleManager internal merkleManager;
    ERC20Mock internal adToken;
    wNativeToken internal _wNativeToken;
    uint256 constant W_DECIMALS = 18;

    address admin;
    uint256 adminPk;

    address nonAdmin = makeAddr("nonAdmin");
    address maker = makeAddr("maker");
    address nonMaker = makeAddr("nonMaker");
    address bridger = makeAddr("bridger");
    address orderRecipient = makeAddr("orderRecipient");
    address adRecipient = makeAddr("adRecipient");
    address recipient = makeAddr("recipient");
    address other = makeAddr("other");

    address internal constant NATIVE_TOKEN_ADDRESS = address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);

    // Common addresses
    address internal orderPortal = makeAddr("orderPortal");
    address internal orderToken = makeAddr("orderToken");

    uint256 internal orderChainId = 111_55111; // e.g., Sepolia
    uint256 internal adChainId; // block.chainid at runtime
    uint256 internal unsupportedChainId = 25_000_001;

    uint256 internal minted = 1_000 ether;
    uint256 internal fundAmt = 300 ether;
    uint256 internal initAmt = 100 ether;

    string internal lastAdId;

    // auth variables
    bytes signature;
    bytes32 authToken;
    uint256 timeToLive;

    function setUp() public {
        (admin, adminPk) = makeAddrAndKey("admin");
        verifier = new MockVerifier(true);
        merkleManager = new MerkleManager(admin);
        _wNativeToken = new wNativeToken("Wrapped Native Token", "WNATIVE", W_DECIMALS);

        adManager = new MockAdManager(
            admin,
            IVerifier(address(verifier)),
            IMerkleManager(address(merkleManager)),
            IwNativeToken(address(_wNativeToken))
        );

        vm.startPrank(admin);
        merkleManager.grantRole(merkleManager.MANAGER_ROLE(), address(adManager));
        vm.stopPrank();

        adChainId = block.chainid;
        adToken = new ERC20Mock();
        adToken.mint(maker, minted);
    }

    /*//////////////////////////////////////////////////////////////
           HELPER
    //////////////////////////////////////////////////////////////*/

    function _defaultParams(string memory adId) internal view returns (AdManager.OrderParams memory p) {
        p.orderChainToken = orderToken;
        p.adChainToken = address(adToken);
        p.amount = 100 ether;
        p.bridger = bridger;
        p.orderChainId = orderChainId;
        p.srcOrderPortal = orderPortal;
        p.orderRecipient = recipient;
        p.adId = adId;
        p.adCreator = maker;
        p.adRecipient = adRecipient;
        p.salt = 123;
    }

    function generateCreateAdRequestParams(string memory adId, address adTokenAddr)
        internal
        view
        returns (bytes32 token, uint256 ttl, bytes memory sig)
    {
        token = bytes32(vm.randomBytes(32));
        ttl = block.timestamp + 1 hours;
        bytes32 message =
            adManager.createAdRequestHash(adId, adTokenAddr, initAmt, orderChainId, adRecipient, token, ttl);

        sig = sign(message, adminPk);
    }

    function generateFundAdRequestParams(string memory adId, uint256 amount)
        internal
        view
        returns (bytes32 token, uint256 ttl, bytes memory sig)
    {
        token = bytes32(vm.randomBytes(32));
        ttl = block.timestamp + 1 hours;
        bytes32 message = adManager.fundAdRequestHash(adId, amount, token, ttl);
        sig = sign(message, adminPk);
    }

    function generateCloseAdRequestParams(string memory adId, address to)
        internal
        view
        returns (bytes32 token, uint256 ttl, bytes memory sig)
    {
        token = bytes32(vm.randomBytes(32));
        ttl = block.timestamp + 1 hours;

        bytes32 message = adManager.closeAdRequestHash(adId, to, token, ttl);
        sig = sign(message, adminPk);
    }

    function generateWithdrawFromAdRequestParams(string memory adId, uint256 amount, address to)
        internal
        view
        returns (bytes32 token, uint256 ttl, bytes memory sig)
    {
        token = bytes32(vm.randomBytes(32));
        ttl = block.timestamp + 1 hours;

        bytes32 message = adManager.withdrawFromAdRequestHash(adId, amount, to, token, ttl);
        sig = sign(message, adminPk);
    }

    function generateLockForOrderRequestHash(string memory adId, bytes32 orderHash)
        internal
        view
        returns (bytes32 token, uint256 ttl, bytes memory sig)
    {
        token = bytes32(vm.randomBytes(32));
        ttl = block.timestamp + 1 hours;

        bytes32 message = adManager.lockForOrderRequestHash(adId, orderHash, token, ttl);
        sig = sign(message, adminPk);
    }

    function generateUnlockOrderRequestHash(string memory adId, bytes32 orderHash, bytes32 targetRoot)
        internal
        view
        returns (bytes32 token, uint256 ttl, bytes memory sig)
    {
        token = bytes32(vm.randomBytes(32));
        ttl = block.timestamp + 1 hours;

        bytes32 message = adManager.unlockOrderRequestHash(adId, orderHash, targetRoot, token, ttl);
        sig = sign(message, adminPk);
    }

    function sign(bytes32 message, uint256 pk) public pure returns (bytes memory sig) {
        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        sig = abi.encodePacked(r, s, v);
    }

    /*//////////////////////////////////////////////////////////////
             ACCESS CONTROL: ROLES
    //////////////////////////////////////////////////////////////*/

    // Test that only the admin can call functions restricted by the admin role
    function test_AdminRoleAssignedOnDeploy() public {
        // nonAdmin should revert when calling onlyRole function
        vm.prank(nonAdmin);
        vm.expectRevert();
        adManager.setChain(orderChainId, orderPortal, true);

        // admin should succeed
        vm.prank(admin);
        adManager.setChain(orderChainId, orderPortal, true); // should succeed
    }

    /*//////////////////////////////////////////////////////////////
               setChain / removeChain
    //////////////////////////////////////////////////////////////*/

    // Test that only admin can call setChain
    function test_setChain_onlyAdmin() public {
        vm.prank(nonAdmin);
        vm.expectRevert();
        adManager.setChain(orderChainId, orderPortal, true);
    }

    // Test that setChain updates state and emits the correct event
    function test_setChain_updatesStateAndEmits() public {
        vm.prank(admin);
        vm.expectEmit(true, true, true, true);
        emit AdManager.ChainSet(orderChainId, orderPortal, true);
        adManager.setChain(orderChainId, orderPortal, true);

        (bool supported, address portal) = adManager.chains(orderChainId);
        assertTrue(supported, "chain not supported");
        assertEq(portal, orderPortal, "portal mismatch");
    }

    // Test that only admin can call removeChain
    function test_removeChain_onlyAdmin() public {
        vm.startPrank(admin);
        adManager.setChain(orderChainId, orderPortal, true);
        vm.stopPrank();

        vm.prank(nonAdmin);
        vm.expectRevert();
        adManager.removeChain(orderChainId);
    }

    // Test that removeChain clears state and emits the correct event
    function test_removeChain_clearsStateAndEmits() public {
        vm.startPrank(admin);
        adManager.setChain(orderChainId, orderPortal, true);

        vm.expectEmit(true, true, true, true);
        emit AdManager.ChainSet(orderChainId, address(0), false);
        adManager.removeChain(orderChainId);
        vm.stopPrank();

        (bool supported, address portal) = adManager.chains(orderChainId);
        assertTrue(!supported, "chain still supported");
        assertEq(portal, address(0), "portal not cleared");
    }

    /*//////////////////////////////////////////////////////////////
             setTokenRoute / removeTokenRoute
    //////////////////////////////////////////////////////////////*/

    // Test that only admin can call setTokenRoute
    function test_setTokenRoute_onlyAdmin() public {
        vm.prank(nonAdmin);
        vm.expectRevert();
        adManager.setTokenRoute(address(adToken), orderToken, orderChainId);
    }

    // Test that setTokenRoute rejects zero addresses
    function test_setTokenRoute_rejectsZeroAddresses() public {
        vm.prank(admin);
        vm.expectRevert(AdManager.AdManager__TokenZeroAddress.selector);
        adManager.setTokenRoute(address(0), orderToken, orderChainId);

        vm.prank(admin);
        vm.expectRevert(AdManager.AdManager__TokenZeroAddress.selector);
        adManager.setTokenRoute(address(adToken), address(0), orderChainId);
    }

    // Test that setTokenRoute rejects unsupported chain
    function test_setTokenRoute_rejectsUnsupportedChain() public {
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(AdManager.AdManager__ChainNotSupported.selector, orderChainId));
        adManager.setTokenRoute(address(adToken), orderToken, orderChainId);
    }

    // Test that setTokenRoute sets the route and emits the correct event
    function test_setTokenRoute_setsAndEmits() public {
        vm.startPrank(admin);
        adManager.setChain(orderChainId, orderPortal, true);

        vm.expectEmit(true, true, true, true);
        emit AdManager.TokenRouteSet(orderToken, orderChainId, address(adToken));
        adManager.setTokenRoute(address(adToken), orderToken, orderChainId);
        vm.stopPrank();

        address routed = adManager.tokenRoute(address(adToken), orderChainId);
        assertEq(routed, orderToken, "route not set");
    }

    // Test that only admin can call removeTokenRoute
    function test_removeTokenRoute_onlyAdmin() public {
        vm.startPrank(admin);
        adManager.setChain(orderChainId, orderPortal, true);
        adManager.setTokenRoute(address(adToken), orderToken, orderChainId);
        vm.stopPrank();

        vm.prank(nonAdmin);
        vm.expectRevert();
        adManager.removeTokenRoute(address(adToken), orderChainId);
    }

    // Test that removeTokenRoute clears the route and emits the correct event
    function test_removeTokenRoute_clearsAndEmits() public {
        vm.startPrank(admin);
        adManager.setChain(orderChainId, orderPortal, true);
        adManager.setTokenRoute(address(adToken), orderToken, orderChainId);

        vm.expectEmit(true, true, true, true);
        emit AdManager.TokenRouteRemoved(address(adToken), orderToken, orderChainId);
        adManager.removeTokenRoute(address(adToken), orderChainId);
        vm.stopPrank();

        address routed = adManager.tokenRoute(address(adToken), orderChainId);
        assertEq(routed, address(0), "route not removed");
    }

    /*//////////////////////////////////////////////////////////////
                createAd setup
    //////////////////////////////////////////////////////////////*/

    // Test that createAd rejects zero adToken address
    function test_createAd_rejectsZeroAdToken() public {
        string memory adId = "1";
        // get auth
        (authToken, timeToLive, signature) = generateCreateAdRequestParams(adId, address(adToken));

        vm.prank(maker);
        adToken.approve(address(adManager), initAmt);

        vm.prank(maker);
        vm.expectRevert(AdManager.AdManager__TokenZeroAddress.selector);
        adManager.createAd(signature, authToken, timeToLive, adId, address(0), initAmt, orderChainId, address(0xDEAD));
    }

    // Test that createAd rejects when no route exists for the chain
    function test_createAd_rejectsWhenNoRoute() public {
        string memory adId = "1";
        // get auth
        (authToken, timeToLive, signature) = generateCreateAdRequestParams(adId, address(adToken));

        vm.prank(maker);
        adToken.approve(address(adManager), initAmt);

        vm.prank(maker);
        vm.expectRevert(abi.encodeWithSelector(AdManager.AdManager__ChainNotSupported.selector, orderChainId));
        adManager.createAd(
            signature, authToken, timeToLive, adId, address(adToken), initAmt, orderChainId, address(0xDEAD)
        );
    }

    // Test that createAd succeeds when route exists, emits event, and stores ad data
    function test_createAd_succeedsWhenRouteExists_emitsAndStores() public {
        string memory adId = "1";

        vm.startPrank(admin);
        adManager.setChain(orderChainId, orderPortal, true);
        adManager.setTokenRoute(address(adToken), orderToken, orderChainId);
        vm.stopPrank();

        (authToken, timeToLive, signature) = generateCreateAdRequestParams(adId, address(adToken));

        vm.prank(maker);
        adToken.approve(address(adManager), initAmt);

        vm.prank(maker);
        vm.expectEmit(true, true, true, true);
        emit AdManager.AdCreated("1", maker, address(adToken), initAmt, orderChainId);
        adManager.createAd(signature, authToken, timeToLive, adId, address(adToken), initAmt, orderChainId, adRecipient);

        (
            uint256 linkedOrderChainId,
            address _adRecipient,
            address owner,
            address token,
            uint256 balance,
            uint256 locked,
            bool open
        ) = adManager.ads(adId);

        lastAdId = adId;

        assertEq(linkedOrderChainId, orderChainId);
        assertEq(_adRecipient, adRecipient);
        assertEq(owner, maker);
        assertEq(token, address(adToken));
        assertEq(balance, initAmt);
        assertEq(locked, 0);
        assertTrue(open);
    }

    function test_createAd_with_native_token_success() public {
        string memory adId = "nativeAd";

        vm.startPrank(admin);
        adManager.setChain(orderChainId, orderPortal, true);
        adManager.setTokenRoute(NATIVE_TOKEN_ADDRESS, orderToken, orderChainId);
        vm.stopPrank();

        (authToken, timeToLive, signature) = generateCreateAdRequestParams(adId, NATIVE_TOKEN_ADDRESS);

        vm.deal(maker, initAmt);

        vm.prank(maker);
        vm.expectEmit(true, true, true, true);
        emit AdManager.AdCreated(adId, maker, NATIVE_TOKEN_ADDRESS, initAmt, orderChainId);
        adManager.createAd{
            value: initAmt
        }(signature, authToken, timeToLive, adId, NATIVE_TOKEN_ADDRESS, initAmt, orderChainId, adRecipient);

        (
            uint256 linkedOrderChainId,
            address _adRecipient,
            address owner,
            address token,
            uint256 balance,
            uint256 locked,
            bool open
        ) = adManager.ads(adId);

        assertEq(linkedOrderChainId, orderChainId);
        assertEq(_adRecipient, adRecipient);
        assertEq(owner, maker);
        assertEq(token, NATIVE_TOKEN_ADDRESS);
        assertEq(balance, initAmt);
        assertEq(locked, 0);
        assertTrue(open);

        uint256 wNativeBalance = _wNativeToken.balanceOf(address(adManager));
        assertEq(wNativeBalance, initAmt);
    }

    function test_createAd_with_native_token_fails_if_no_token_is_supplied() public {
        string memory adId = "nativeAdFail";

        vm.startPrank(admin);
        adManager.setChain(orderChainId, orderPortal, true);
        adManager.setTokenRoute(NATIVE_TOKEN_ADDRESS, orderToken, orderChainId);
        vm.stopPrank();

        (authToken, timeToLive, signature) = generateCreateAdRequestParams(adId, NATIVE_TOKEN_ADDRESS);

        vm.deal(maker, initAmt);

        vm.prank(maker);
        vm.expectRevert(AdManager.AdManager__InsufficientLiquidity.selector);
        adManager.createAd(
            signature, authToken, timeToLive, adId, NATIVE_TOKEN_ADDRESS, initAmt, orderChainId, adRecipient
        );
    }

    /*//////////////////////////////////////////////////////////////
                        fundAd: maker only
    ////////////////////////////////////////////////////////////////*/
    function test_fundAd_makerOnly() public {
        test_createAd_succeedsWhenRouteExists_emitsAndStores();
        string memory adId = lastAdId;

        // get auth
        (authToken, timeToLive, signature) = generateFundAdRequestParams(adId, fundAmt);

        vm.prank(nonMaker);
        vm.expectRevert(AdManager.AdManager__NotMaker.selector);
        adManager.fundAd(signature, authToken, timeToLive, adId, fundAmt);

        vm.prank(maker);
        adToken.approve(address(adManager), fundAmt);

        // another auth
        (authToken, timeToLive, signature) = generateFundAdRequestParams(adId, fundAmt);

        vm.prank(maker);
        adManager.fundAd(signature, authToken, timeToLive, adId, fundAmt);

        (,,,, uint256 balance,,) = adManager.ads(adId);
        assertEq(balance, initAmt + fundAmt);
    }

    /*//////////////////////////////////////////////////////////////
                   fundAd: rejects when ad closed
    ////////////////////////////////////////////////////////////////*/
    function test_fundAd_rejects_whenAdClosed() public {
        test_createAd_succeedsWhenRouteExists_emitsAndStores();
        string memory adId = lastAdId;

        (authToken, timeToLive, signature) = generateCloseAdRequestParams(adId, maker);

        // Close first (no locked funds, balance 0)
        vm.prank(maker);
        adManager.closeAd(signature, authToken, timeToLive, adId, maker);

        uint256 amount = 1 ether;

        (bytes32 token2, uint256 ttl2, bytes memory sig2) = generateFundAdRequestParams(adId, amount);

        vm.prank(maker);
        vm.expectRevert(AdManager.AdManager__AdClosed.selector);
        adManager.fundAd(sig2, token2, ttl2, adId, amount);
    }

    /*//////////////////////////////////////////////////////////////
                       fundAd: rejects zero amount
    ////////////////////////////////////////////////////////////////*/
    function test_fundAd_rejects_zeroAmount() public {
        test_createAd_succeedsWhenRouteExists_emitsAndStores();

        string memory adId = lastAdId;

        (authToken, timeToLive, signature) = generateFundAdRequestParams(adId, 0);

        vm.prank(maker);
        vm.expectRevert(AdManager.AdManager__ZeroAmount.selector);
        adManager.fundAd(signature, authToken, timeToLive, adId, 0);
    }

    /*//////////////////////////////////////////////////////////////
                       fundAd: with native token
    ////////////////////////////////////////////////////////////////*/
    function test_fundAd_withNativeToken() public {
        test_createAd_with_native_token_success();
        string memory adId = "nativeAd";
        vm.deal(maker, fundAmt);
        (authToken, timeToLive, signature) = generateFundAdRequestParams(adId, fundAmt);
        vm.prank(maker);
        adManager.fundAd{value: fundAmt}(signature, authToken, timeToLive, adId, fundAmt);
        (,,,, uint256 balance,,) = adManager.ads(adId);

        assertEq(balance, initAmt + fundAmt);
    }

    // ─────────────────────────────────────────────────────────────
    // lockForOrder: rejects when order chain not supported
    // ─────────────────────────────────────────────────────────────
    function test_lock_rejects_orderChainNotSupported() public {
        test_fundAd_makerOnly();
        string memory adId = lastAdId;
        AdManager.OrderParams memory p = _defaultParams(adId);
        p.orderChainId = unsupportedChainId;

        bytes32 orderHash = adManager.hashOrderPublic(p);

        (authToken, timeToLive, signature) = generateLockForOrderRequestHash(adId, orderHash);

        vm.prank(maker);
        vm.expectRevert(abi.encodeWithSelector(AdManager.AdManager__ChainNotSupported.selector, p.orderChainId));
        adManager.lockForOrder(signature, authToken, timeToLive, p);
    }

    // ─────────────────────────────────────────────────────────────
    // lockForOrder: rejects when param chain mismatch
    // ─────────────────────────────────────────────────────────────
    function test_lock_rejects_orderChainMismatch() public {
        uint256 anotherSupportedChainId = 5;
        address anotherOrderPortal = makeAddr("anotherOrderPortal");
        vm.startPrank(admin);
        adManager.setChain(anotherSupportedChainId, anotherOrderPortal, true);
        adManager.setTokenRoute(makeAddr("randomAdToken"), makeAddr("randomOrderToken"), anotherSupportedChainId);
        vm.stopPrank();

        test_fundAd_makerOnly();
        string memory adId = lastAdId;
        AdManager.OrderParams memory p = _defaultParams(adId);
        p.orderChainId = anotherSupportedChainId;
        p.srcOrderPortal = anotherOrderPortal;

        bytes32 orderHash = adManager.hashOrderPublic(p);

        (authToken, timeToLive, signature) = generateLockForOrderRequestHash(adId, orderHash);

        vm.prank(maker);
        vm.expectRevert(
            abi.encodeWithSelector(AdManager.AdManager__OrderChainMismatch.selector, orderChainId, p.orderChainId)
        );
        adManager.lockForOrder(signature, authToken, timeToLive, p);
    }

    // ─────────────────────────────────────────────────────────────
    // lockForOrder: rejects when srcOrderPortal mismatch
    // ─────────────────────────────────────────────────────────────
    function test_lock_rejects_srcOrderPortalMismatch() public {
        test_fundAd_makerOnly();
        string memory adId = lastAdId;
        AdManager.OrderParams memory p = _defaultParams(adId);
        p.srcOrderPortal = address(0xBEEF);

        bytes32 orderHash = adManager.hashOrderPublic(p);

        (authToken, timeToLive, signature) = generateLockForOrderRequestHash(adId, orderHash);

        vm.prank(maker);
        vm.expectRevert(
            abi.encodeWithSelector(AdManager.AdManager__OrderPortalMismatch.selector, orderPortal, p.srcOrderPortal)
        );
        adManager.lockForOrder(signature, authToken, timeToLive, p);
    }

    // ─────────────────────────────────────────────────────────────
    // lockForOrder: rejects when missing token route
    // ─────────────────────────────────────────────────────────────
    function test_lock_rejects_missingTokenRoute() public {
        test_fundAd_makerOnly();

        vm.prank(admin);
        adManager.removeTokenRoute(address(adToken), orderChainId);

        string memory adId = lastAdId;
        AdManager.OrderParams memory p = _defaultParams(adId);

        bytes32 orderHash = adManager.hashOrderPublic(p);

        (authToken, timeToLive, signature) = generateLockForOrderRequestHash(adId, orderHash);

        vm.prank(maker);
        vm.expectRevert(
            abi.encodeWithSelector(AdManager.AdManager__MissingRoute.selector, p.orderChainToken, block.chainid)
        );
        adManager.lockForOrder(signature, authToken, timeToLive, p);
    }

    // ─────────────────────────────────────────────────────────────
    // lockForOrder: rejects when route token != orderChainToken
    // ─────────────────────────────────────────────────────────────
    function test_lock_rejects_routeTokenMismatch() public {
        test_fundAd_makerOnly();
        string memory adId = lastAdId;
        AdManager.OrderParams memory p = _defaultParams(adId);

        address otherOrderToken = other;
        vm.prank(admin);
        adManager.setTokenRoute(address(adToken), otherOrderToken, orderChainId);

        bytes32 orderHash = adManager.hashOrderPublic(p);

        (authToken, timeToLive, signature) = generateLockForOrderRequestHash(adId, orderHash);

        vm.prank(maker);
        vm.expectRevert(
            abi.encodeWithSelector(
                AdManager.AdManager__OrderTokenMismatch.selector,
                otherOrderToken, // expected routed token
                p.orderChainToken // provided in params
            )
        );
        adManager.lockForOrder(signature, authToken, timeToLive, p);
    }

    // ─────────────────────────────────────────────────────────────
    // lockForOrder: rejects when params.adCreator != ad.maker
    // ─────────────────────────────────────────────────────────────
    function test_lock_rejects_wrongAdCreator() public {
        test_fundAd_makerOnly();
        string memory adId = lastAdId;
        AdManager.OrderParams memory p = _defaultParams(adId);
        p.adCreator = other;

        bytes32 orderHash = adManager.hashOrderPublic(p);

        (authToken, timeToLive, signature) = generateLockForOrderRequestHash(adId, orderHash);

        vm.prank(maker);
        vm.expectRevert(AdManager.AdManager__NotMaker.selector);
        adManager.lockForOrder(signature, authToken, timeToLive, p);
    }

    // ─────────────────────────────────────────────────────────────
    // lockForOrder: rejects when adChainToken != ad.token
    // ─────────────────────────────────────────────────────────────
    function test_lock_rejects_adTokenMismatch() public {
        test_fundAd_makerOnly();
        string memory adId = lastAdId;
        AdManager.OrderParams memory p = _defaultParams(adId);

        // Create another ad-chain token and route so route check passes first
        ERC20Mock otherAdToken = new ERC20Mock();
        vm.prank(admin);
        adManager.setTokenRoute(address(otherAdToken), orderToken, orderChainId);

        p.adChainToken = address(otherAdToken);

        bytes32 orderHash = adManager.hashOrderPublic(p);

        (authToken, timeToLive, signature) = generateLockForOrderRequestHash(adId, orderHash);

        vm.prank(maker);
        vm.expectRevert(
            abi.encodeWithSelector(
                AdManager.AdManager__AdTokenMismatch.selector, address(adToken), address(otherAdToken)
            )
        );
        adManager.lockForOrder(signature, authToken, timeToLive, p);
    }

    // ─────────────────────────────────────────────────────────────
    // lockForOrder: rejects when adRecipient != ad.adRecipient
    // ─────────────────────────────────────────────────────────────
    function test_lock_rejects_adRecipientMismatch() public {
        test_fundAd_makerOnly();
        string memory adId = lastAdId;
        AdManager.OrderParams memory p = _defaultParams(adId);

        p.adRecipient = recipient;

        (, address expected,,,,,) = adManager.ads(p.adId);

        bytes32 orderHash = adManager.hashOrderPublic(p);

        (authToken, timeToLive, signature) = generateLockForOrderRequestHash(adId, orderHash);

        vm.prank(maker);
        vm.expectRevert(
            abi.encodeWithSelector(AdManager.AdManager__AdRecipientMismatch.selector, expected, p.adRecipient)
        );
        adManager.lockForOrder(signature, authToken, timeToLive, p);
    }

    // ─────────────────────────────────────────────────────────────
    // lockForOrder: rejects zero bridger
    // ─────────────────────────────────────────────────────────────
    function test_lock_rejects_zeroBridger() public {
        test_fundAd_makerOnly();
        string memory adId = lastAdId;
        AdManager.OrderParams memory p = _defaultParams(adId);
        p.bridger = address(0);

        bytes32 orderHash = adManager.hashOrderPublic(p);

        (authToken, timeToLive, signature) = generateLockForOrderRequestHash(adId, orderHash);

        vm.prank(maker);
        vm.expectRevert(AdManager.AdManager__BridgerZero.selector);
        adManager.lockForOrder(signature, authToken, timeToLive, p);
    }

    // ─────────────────────────────────────────────────────────────
    // lockForOrder: rejects zero orderRecipient
    // ─────────────────────────────────────────────────────────────
    function test_lock_rejects_zeroOrderRecipient() public {
        test_fundAd_makerOnly();
        string memory adId = lastAdId;
        AdManager.OrderParams memory p = _defaultParams(adId);
        p.orderRecipient = address(0);

        bytes32 orderHash = adManager.hashOrderPublic(p);

        (authToken, timeToLive, signature) = generateLockForOrderRequestHash(adId, orderHash);

        vm.prank(maker);
        vm.expectRevert(AdManager.AdManager__RecipientZero.selector);
        adManager.lockForOrder(signature, authToken, timeToLive, p);
    }

    // ─────────────────────────────────────────────────────────────
    // lockForOrder: rejects zero amount
    // ─────────────────────────────────────────────────────────────
    function test_lock_rejects_zeroAmount() public {
        test_fundAd_makerOnly();
        string memory adId = lastAdId;
        AdManager.OrderParams memory p = _defaultParams(adId);
        p.amount = 0;

        bytes32 orderHash = adManager.hashOrderPublic(p);

        (authToken, timeToLive, signature) = generateLockForOrderRequestHash(adId, orderHash);

        vm.prank(maker);
        vm.expectRevert(AdManager.AdManager__ZeroAmount.selector);
        adManager.lockForOrder(signature, authToken, timeToLive, p);
    }

    // ─────────────────────────────────────────────────────────────
    // lockForOrder: rejects when amount > available
    // ─────────────────────────────────────────────────────────────
    function test_lock_rejects_amountExceedsAvailable() public {
        test_fundAd_makerOnly();
        string memory adId = lastAdId;
        AdManager.OrderParams memory p = _defaultParams(adId);
        p.amount = initAmt + fundAmt + 1;

        bytes32 orderHash = adManager.hashOrderPublic(p);

        (authToken, timeToLive, signature) = generateLockForOrderRequestHash(adId, orderHash);

        vm.prank(maker);
        vm.expectRevert(AdManager.AdManager__InsufficientLiquidity.selector);
        adManager.lockForOrder(signature, authToken, timeToLive, p);
    }

    // ─────────────────────────────────────────────────────────────
    // lockForOrder: opens order, locks balance, emits OrderLocked
    // ─────────────────────────────────────────────────────────────
    function test_lock_opensOrder_updatesLocked_emitsEvent() public {
        test_fundAd_makerOnly();
        string memory adId = lastAdId;
        AdManager.OrderParams memory p = _defaultParams(adId);

        (,, address adMaker, address token,, uint256 lockedBefore, bool open) = adManager.ads(adId);
        assertTrue(open);
        assertEq(lockedBefore, 0);

        bytes32 expectedHash = adManager.hashOrderPublic(p);

        vm.expectEmit(true, true, true, true);
        emit AdManager.OrderLocked(adId, expectedHash, adMaker, token, p.amount, p.bridger, p.orderRecipient);

        (authToken, timeToLive, signature) = generateLockForOrderRequestHash(adId, expectedHash);

        vm.prank(maker);
        bytes32 orderHash = adManager.lockForOrder(signature, authToken, timeToLive, p);
        assertEq(orderHash, expectedHash, "order hash mismatch");

        (,,,,, uint256 lockedAfter,) = adManager.ads(adId);
        assertEq(lockedAfter, lockedBefore + p.amount, "locked not incremented");

        (AdManager.Status status) = adManager.orders(orderHash);
        assertEq(uint256(status), uint256(AdManager.Status.Open), "order not open");
    }

    // ─────────────────────────────────────────────────────────────
    // lockForOrder: idempotency—same params (same salt) -> OrderExists
    // ─────────────────────────────────────────────────────────────
    function test_lock_idempotency_sameParamsSameSalt_revertsOrderExists() public {
        test_fundAd_makerOnly();
        string memory adId = lastAdId;

        AdManager.OrderParams memory p = _defaultParams(adId);

        bytes32 orderHash = adManager.hashOrderPublic(p);

        (authToken, timeToLive, signature) = generateLockForOrderRequestHash(adId, orderHash);

        vm.prank(maker);
        bytes32 h1 = adManager.lockForOrder(signature, authToken, timeToLive, p);

        vm.prank(maker);
        vm.expectRevert(abi.encodeWithSelector(AdManager.AdManager__OrderExists.selector, h1));
        adManager.lockForOrder(signature, authToken, timeToLive, p);
    }

    /*//////////////////////////////////////////////////////////////
                       withdrawFromAd: maker only
    ////////////////////////////////////////////////////////////////*/
    function test_withdrawAd_makerOnly() public {
        test_fundAd_makerOnly();
        string memory adId = lastAdId;

        uint256 amount = 3 ether;

        (authToken, timeToLive, signature) = generateWithdrawFromAdRequestParams(adId, amount, recipient);

        vm.prank(nonMaker);
        vm.expectRevert(AdManager.AdManager__NotMaker.selector);
        adManager.withdrawFromAd(signature, authToken, timeToLive, adId, amount, recipient);

        vm.prank(maker);
        adManager.withdrawFromAd(signature, authToken, timeToLive, adId, amount, recipient);
    }

    /*//////////////////////////////////////////////////////////////
                     withdrawFromAd: rejects zero amount
    ////////////////////////////////////////////////////////////////*/
    function test_withdrawAd_rejects_zeroAmount() public {
        test_fundAd_makerOnly();

        string memory adId = lastAdId;

        (authToken, timeToLive, signature) = generateWithdrawFromAdRequestParams(adId, 0, recipient);

        vm.startPrank(maker);
        vm.expectRevert(AdManager.AdManager__ZeroAmount.selector);
        adManager.withdrawFromAd(signature, authToken, timeToLive, adId, 0, recipient);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    withdrawFromAd: rejects > available
    ////////////////////////////////////////////////////////////////*/
    function test_withdrawAd_rejects_gtAvailable() public {
        test_fundAd_makerOnly();

        string memory adId = lastAdId;
        uint256 available = initAmt + fundAmt;

        (authToken, timeToLive, signature) = generateWithdrawFromAdRequestParams(adId, available + 1, recipient);

        vm.startPrank(maker);
        // available = fundAmt, ask for fundAmt + 1
        vm.expectRevert(AdManager.AdManager__InsufficientLiquidity.selector);
        adManager.withdrawFromAd(signature, authToken, timeToLive, adId, available + 1, recipient);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    withdrawFromAd: with native token
    ////////////////////////////////////////////////////////////////*/
    function test_withdrawAd_withNativeToken() public {
        test_fundAd_withNativeToken();
        string memory adId = "nativeAd";
        uint256 amount = 5 ether;
        uint256 balBefore = recipient.balance;
        (authToken, timeToLive, signature) = generateWithdrawFromAdRequestParams(adId, amount, recipient);

        vm.prank(maker);
        adManager.withdrawFromAd(signature, authToken, timeToLive, adId, amount, recipient);

        uint256 balAfter = recipient.balance;
        assertEq(balAfter - balBefore, amount);
    }

    /*//////////////////////////////////////////////////////////////
                    withdrawFromAd: with native token fails when > available
    ////////////////////////////////////////////////////////////////*/
    function test_withdrawAd_native_fails_when_gtAvailable() public {
        test_fundAd_withNativeToken();
        string memory adId = "nativeAd";
        uint256 available = initAmt + fundAmt;

        (authToken, timeToLive, signature) = generateWithdrawFromAdRequestParams(adId, available + 1, recipient);

        vm.prank(maker);
        vm.expectRevert(AdManager.AdManager__InsufficientLiquidity.selector);
        adManager.withdrawFromAd(signature, authToken, timeToLive, adId, available + 1, recipient);
    }

    /*//////////////////////////////////////////////////////////////
                          closeAd: maker only
    ////////////////////////////////////////////////////////////////*/
    function test_closeAd_makerOnly() public {
        test_createAd_succeedsWhenRouteExists_emitsAndStores();

        string memory adId = lastAdId;

        (authToken, timeToLive, signature) = generateCloseAdRequestParams(adId, recipient);

        vm.prank(nonMaker);
        vm.expectRevert(AdManager.AdManager__NotMaker.selector);
        adManager.closeAd(signature, authToken, timeToLive, adId, recipient);
    }

    /*//////////////////////////////////////////////////////////////
                 closeAd: rejects when locked > 0
    ////////////////////////////////////////////////////////////////*/
    function test_closeAd_rejects_whenLocked_gt0() public {
        test_fundAd_makerOnly();

        string memory adId = lastAdId;

        // Prepare a minimal valid lock to set locked > 0
        AdManager.OrderParams memory p = _defaultParams(adId);
        bytes32 orderHash = adManager.hashOrderPublic(p);
        (authToken, timeToLive, signature) = generateLockForOrderRequestHash(adId, orderHash);

        (bytes32 tokenCloseAd, uint256 ttlCloseAd, bytes memory sigCloseAd) =
            generateCloseAdRequestParams(adId, recipient);

        vm.startPrank(maker);

        // Lock succeeds -> increases ad.locked
        adManager.lockForOrder(signature, authToken, timeToLive, p);

        vm.expectRevert(AdManager.Admanager__ActiveLocks.selector);
        adManager.closeAd(sigCloseAd, tokenCloseAd, ttlCloseAd, adId, recipient);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
           closeAd: transfers remaining and marks closed
    ////////////////////////////////////////////////////////////////*/
    function test_closeAd_transfersRemaining_andMarksClosed() public {
        test_fundAd_makerOnly();

        string memory adId = lastAdId;

        uint256 balBefore = adToken.balanceOf(recipient);

        (authToken, timeToLive, signature) = generateCloseAdRequestParams(adId, recipient);

        // Close (no locks)
        vm.prank(maker);
        adManager.closeAd(signature, authToken, timeToLive, adId, recipient);

        // Remaining transferred to recipient
        uint256 balAfter = adToken.balanceOf(recipient);
        assertEq(balAfter - balBefore, fundAmt + initAmt, "remaining not transferred");

        // Ad is closed, balance set to 0
        (,,,, uint256 balance, uint256 locked, bool open) = adManager.ads(adId);
        assertEq(balance, 0, "balance not zeroed");
        assertEq(locked, 0, "locked should be zero (no open locks)");
        assertFalse(open, "ad not closed");
    }

    /*//////////////////////////////////////////////////////////////
           closeAd: with native token transfers remaining and marks closed
    ////////////////////////////////////////////////////////////////*/
    function test_closeAd_withNativeToken_transfersRemaining_andMarksClosed() public {
        test_createAd_with_native_token_success();

        string memory adId = "nativeAd";
        uint256 balBefore = recipient.balance;
        (authToken, timeToLive, signature) = generateCloseAdRequestParams(adId, recipient);

        vm.prank(maker);
        adManager.closeAd(signature, authToken, timeToLive, adId, recipient);

        uint256 balAfter = recipient.balance;
        assertEq(balAfter - balBefore, initAmt, "remaining not transferred");

        (,,,, uint256 balance, uint256 locked, bool open) = adManager.ads(adId);

        assertEq(balance, 0, "balance not zeroed");
        assertEq(locked, 0, "locked should be zero (no open locks)");
        assertFalse(open, "ad not closed");
    }

    /*//////////////////////////////////////////////////////////////
     * unlock: rejects when order not open
     //////////////////////////////////////////////////////////////*/
    function test_unlock_rejects_orderNotOpen() public {
        test_fundAd_makerOnly();

        string memory adId = lastAdId;

        AdManager.OrderParams memory p = _defaultParams(adId);
        bytes32 expected = adManager.hashOrderPublic(p);

        (authToken, timeToLive, signature) = generateUnlockOrderRequestHash(adId, expected, bytes32(0));

        vm.prank(bridger);
        vm.expectRevert(abi.encodeWithSelector(AdManager.AdManager__OrderNotOpen.selector, expected));
        adManager.unlock(signature, authToken, timeToLive, p, bytes32(uint256(1)), bytes32(0), hex"");
    }

    function _openOrder(
        string memory adId,
        address _adToken,
        uint256 amount,
        uint256 salt,
        address _bridger,
        address _recipient
    ) internal returns (AdManager.OrderParams memory p, bytes32 orderHash) {
        p = _defaultParams(adId);
        p.adChainToken = _adToken;
        p.amount = amount;
        p.salt = salt;
        p.bridger = _bridger;
        p.orderRecipient = _recipient;

        bytes32 orderHashExpected = adManager.hashOrderPublic(p);
        (authToken, timeToLive, signature) = generateLockForOrderRequestHash(adId, orderHashExpected);

        vm.prank(maker);
        orderHash = adManager.lockForOrder(signature, authToken, timeToLive, p);
    }

    /*//////////////////////////////////////////////////////////////
     * unlock: rejects when nullifier already used
     *  - Unlock order A with N
     *  - Try to unlock distinct order B (still Open) with same N -> NullifierUsed
     //////////////////////////////////////////////////////////////*/
    function test_unlock_rejects_nullifierAlreadyUsed_onDifferentOpenOrder() public {
        test_fundAd_makerOnly();
        string memory adId = lastAdId;

        // Open two orders with different salts
        (AdManager.OrderParams memory p1, bytes32 oh1) =
            _openOrder(adId, address(adToken), 80 ether, 777, bridger, recipient);
        (AdManager.OrderParams memory p2, bytes32 oh2) =
            _openOrder(adId, address(adToken), 90 ether, 778, other, recipient);

        bytes32 nullifier = keccak256("N");

        bytes32 t_root = bytes32(uint256(0));

        // get auth
        (authToken, timeToLive, signature) = generateUnlockOrderRequestHash(adId, oh1, t_root);

        // First unlock succeeds
        vm.prank(bridger);
        adManager.unlock(signature, authToken, timeToLive, p1, nullifier, t_root, hex"");

        /// get auth
        (authToken, timeToLive, signature) = generateUnlockOrderRequestHash(adId, oh2, t_root);

        // Second unlock with the same nullifier on a different (still open) order
        vm.prank(bridger);
        vm.expectRevert(abi.encodeWithSelector(AdManager.AdManager__NullifierUsed.selector, nullifier));
        adManager.unlock(signature, authToken, timeToLive, p2, nullifier, t_root, hex"");
    }

    /*//////////////////////////////////////////////////////////////
     * unlock: verifier false -> InvalidProof (state unchanged)
     //////////////////////////////////////////////////////////////*/
    function test_unlock_verifierFalse_revertsInvalidProof_andNoStateChange() public {
        test_fundAd_makerOnly();
        string memory adId = lastAdId;

        (AdManager.OrderParams memory p, bytes32 orderHash) =
            _openOrder(adId, address(adToken), 70 ether, 999, bridger, recipient);

        // Snapshot state
        (,,,,, uint256 lockedBefore,) = adManager.ads(p.adId);
        (AdManager.Status statusBefore) = adManager.orders(orderHash);
        assertEq(uint256(statusBefore), uint256(AdManager.Status.Open));

        // Flip verifier to fail
        verifier.setResult(false);

        bytes32 t_root = bytes32(uint256(0));

        (authToken, timeToLive, signature) = generateUnlockOrderRequestHash(adId, orderHash, t_root);

        vm.prank(bridger);
        vm.expectRevert(AdManager.AdManager__InvalidProof.selector);
        adManager.unlock(signature, authToken, timeToLive, p, keccak256("X"), t_root, hex"");

        // State unchanged
        (AdManager.Status statusAfter) = adManager.orders(orderHash);
        assertEq(uint256(statusAfter), uint256(AdManager.Status.Open), "status changed");
        (,,,,, uint256 lockedAfter,) = adManager.ads(p.adId);
        assertEq(lockedAfter, lockedBefore, "locked changed");
    }

    /*//////////////////////////////////////////////////////////////
     * unlock: verifier true -> status Filled, reduces locked
     * unlock: transfers ad.token to orderRecipient
     * unlock: emits OrderUnlocked
     * unlock: cannot unlock twice with same nullifier (same order -> OrderNotOpen on 2nd call)
     //////////////////////////////////////////////////////////////*/
    function test_unlock_success_flow_updatesState_transfers_emits_andPreventsRepeat() public {
        test_fundAd_makerOnly();
        string memory adId = lastAdId;
        (AdManager.OrderParams memory p, bytes32 orderHash) =
            _openOrder(adId, address(adToken), 60 ether, 111, bridger, recipient);

        // Balances and locked snapshot
        uint256 balBefore = adToken.balanceOf(p.orderRecipient);
        (,,,,, uint256 lockedBefore,) = adManager.ads(p.adId);

        // Expect event
        vm.expectEmit(true, true, true, true);
        emit AdManager.OrderUnlocked(orderHash, p.orderRecipient, bytes32("N1"));

        bytes32 targetRoot = bytes32(uint256(5));
        (authToken, timeToLive, signature) = generateUnlockOrderRequestHash(adId, orderHash, targetRoot);

        // Verify success
        vm.prank(bridger);
        adManager.unlock(signature, authToken, timeToLive, p, bytes32("N1"), targetRoot, hex"");

        // Status -> Filled
        (AdManager.Status status) = adManager.orders(orderHash);
        assertEq(uint256(status), uint256(AdManager.Status.Filled), "status not filled");

        // Locked reduced
        (,,,,, uint256 lockedAfter,) = adManager.ads(p.adId);
        assertEq(lockedAfter, lockedBefore - p.amount, "locked not reduced");

        // Tokens transferred to orderRecipient
        uint256 balAfter = adToken.balanceOf(p.orderRecipient);
        assertEq(balAfter - balBefore, p.amount, "recipient not paid");

        // Second call (same order) should fail (order not open anymore)

        // get auth
        (authToken, timeToLive, signature) = generateUnlockOrderRequestHash(adId, orderHash, targetRoot);

        vm.prank(bridger);
        vm.expectRevert(abi.encodeWithSelector(AdManager.AdManager__OrderNotOpen.selector, orderHash));
        adManager.unlock(signature, authToken, timeToLive, p, bytes32("N1"), targetRoot, hex"");
    }

    /*//////////////////////////////////////////////////////////////
     * unlock: with native token transfers ad.token to orderRecipient
     //////////////////////////////////////////////////////////////*/
    function test_unlock_withNativeToken_transfersToOrderRecipient() public {
        test_createAd_with_native_token_success();
        string memory adId = "nativeAd";
        (AdManager.OrderParams memory p, bytes32 orderHash) =
            _openOrder(adId, NATIVE_TOKEN_ADDRESS, 50 ether, 222, bridger, recipient);

        uint256 balBefore = recipient.balance;
        (,,,,, uint256 lockedBefore,) = adManager.ads(p.adId);

        bytes32 targetRoot = bytes32(uint256(10));
        (authToken, timeToLive, signature) = generateUnlockOrderRequestHash(adId, orderHash, targetRoot);

        // get contract wrapped token balance before
        uint256 contractBalBefore = _wNativeToken.balanceOf(address(adManager));

        // Verify success
        vm.prank(bridger);
        adManager.unlock(signature, authToken, timeToLive, p, bytes32("N2"), targetRoot, hex"");

        // status
        (AdManager.Status status) = adManager.orders(orderHash);
        assertEq(uint256(status), uint256(AdManager.Status.Filled), "status not filled");

        // locked reduced
        (,,,,, uint256 lockedAfter,) = adManager.ads(p.adId);
        assertEq(lockedAfter, lockedBefore - p.amount, "locked not reduced");

        uint256 balAfter = recipient.balance;
        assertEq(balAfter - balBefore, p.amount, "recipient not paid");

        uint256 contractBalAfter = _wNativeToken.balanceOf(address(adManager));
        assertEq(contractBalBefore - contractBalAfter, p.amount, "contract balance not reduced");
    }
}
