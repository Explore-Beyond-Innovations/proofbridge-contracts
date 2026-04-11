// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {OrderPortal} from "src/OrderPortal.sol";
import {MockVerifier} from "src/mocks/MockVerifier.sol";
import {MerkleManager} from "src/MerkleManager.sol";
import {IVerifier} from "src/Verifier.sol";
import {IMerkleManager} from "src/MerkleManager.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IwNativeToken, wNativeToken} from "src/wNativeToken.sol";

// Expose internal hash for assertions
contract MockOrderPortal is OrderPortal {
    constructor(address admin, IVerifier v, IMerkleManager m, IwNativeToken t) OrderPortal(admin, v, m, t) {}

    function hashOrderPublic(OrderParams calldata p) external view returns (bytes32) {
        return _hashOrder(p, getChainID(), address(this));
    }
}

contract OrderPortalTest is Test {
    MockOrderPortal internal portal;
    MockVerifier internal verifier;
    MerkleManager internal merkleManager;
    ERC20Mock internal orderToken;
    wNativeToken internal _wNativeToken;
    uint256 constant W_DECIMALS = 18;

    address internal constant NATIVE_TOKEN_ADDRESS = address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);

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

    // Common addresses
    address internal adManager = makeAddr("adManager");
    address internal adToken = makeAddr("adToken");

    uint256 internal adChainId = 111_55111; // e.g., Sepolia-style id
    uint256 internal orderChainId; // block.chainid at runtime
    uint256 internal unsupportedChainId = 25_000_000;

    uint256 internal minted = 1_000 ether;
    uint256 internal fundAmt = 300 ether;

    // auth variables
    bytes signature;
    bytes32 authToken;
    uint256 timeToLive;

    function setUp() public {
        (admin, adminPk) = makeAddrAndKey("admin");
        verifier = new MockVerifier(true);
        merkleManager = new MerkleManager(admin);
        _wNativeToken = new wNativeToken("Wrapped Native Token", "WNT", W_DECIMALS);
        portal = new MockOrderPortal(
            admin,
            IVerifier(address(verifier)),
            IMerkleManager(address(merkleManager)),
            IwNativeToken(address(_wNativeToken))
        );

        vm.startPrank(admin);
        merkleManager.grantRole(merkleManager.MANAGER_ROLE(), address(portal));
        vm.stopPrank();

        orderToken = new ERC20Mock();
        orderToken.mint(bridger, minted);
    }

    /*//////////////////////////////////////////////////////////////
           HELPER
    //////////////////////////////////////////////////////////////*/
    function _defaultParams() internal view returns (OrderPortal.OrderParams memory p) {
        p.orderChainToken = address(orderToken);
        p.adChainToken = adToken;
        p.amount = 100 ether;
        p.bridger = bridger;
        p.orderRecipient = orderRecipient;
        p.adChainId = adChainId;
        p.adManager = adManager;
        p.adId = "777";
        p.adCreator = address(0xACAC);
        p.adRecipient = adRecipient;
        p.salt = 12345;
    }

    function generateCreateOrderRequestParams(string memory adId, bytes32 orderHash)
        internal
        view
        returns (bytes32 token, uint256 ttl, bytes memory sig)
    {
        token = bytes32(vm.randomBytes(32));
        ttl = block.timestamp + 1 hours;
        bytes32 message = portal.createOrderRequestHash(adId, orderHash, token, ttl);
        sig = sign(message, adminPk);
    }

    function generateUnlockOrderRequestHash(string memory adId, bytes32 orderHash, bytes32 targetRoot)
        internal
        view
        returns (bytes32 token, uint256 ttl, bytes memory sig)
    {
        token = bytes32(vm.randomBytes(32));
        ttl = block.timestamp + 1 hours;

        bytes32 message = portal.unlockOrderRequestHash(adId, orderHash, targetRoot, token, ttl);
        sig = sign(message, adminPk);
    }

    function sign(bytes32 message, uint256 pk) public pure returns (bytes memory sig) {
        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        sig = abi.encodePacked(r, s, v);
    }

    /*//////////////////////////////////////////////////////////////
                        setChain: only admin can set
    //////////////////////////////////////////////////////////////*/
    function test_setChain_onlyAdmin() public {
        vm.prank(nonAdmin);
        vm.expectRevert();
        portal.setChain(adChainId, adManager, true);
    }

    function test_setChain_setsAndEmits() public {
        vm.prank(admin);
        vm.expectEmit(true, true, true, true);
        emit OrderPortal.ChainSet(adChainId, adManager, true);
        portal.setChain(adChainId, adManager, true);

        (bool supported, address storedManager) = portal.chains(adChainId);
        assertTrue(supported, "chain not supported");
        assertEq(storedManager, adManager, "adManager mismatch");
    }

    /*//////////////////////////////////////////////////////////////
                       removeChain: only admin can remove
    //////////////////////////////////////////////////////////////*/
    function test_removeChain_onlyAdmin() public {
        vm.startPrank(admin);
        portal.setChain(adChainId, adManager, true);
        vm.stopPrank();

        vm.prank(nonAdmin);
        vm.expectRevert();
        portal.removeChain(adChainId);
    }

    function test_removeChain_clearsAndEmits() public {
        vm.startPrank(admin);
        portal.setChain(adChainId, adManager, true);
        vm.expectEmit(true, true, true, true);
        // Contract emits ChainSet(chainId, address(0), false) on removal
        emit OrderPortal.ChainSet(adChainId, address(0), false);
        portal.removeChain(adChainId);
        vm.stopPrank();

        (bool supported, address storedManager) = portal.chains(adChainId);
        assertFalse(supported, "chain still supported");
        assertEq(storedManager, address(0), "adManager not cleared");
    }

    /*//////////////////////////////////////////////////////////////
          setTokenRoute: only admin; rejects zero addresses
    //////////////////////////////////////////////////////////////*/
    function test_setTokenRoute_onlyAdmin() public {
        vm.prank(nonAdmin);
        vm.expectRevert();
        portal.setTokenRoute(address(orderToken), adChainId, adToken);
    }

    function test_setTokenRoute_rejectsZeroAddresses() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(OrderPortal.OrderPortal__RoutesZeroAddress.selector, address(0), adToken)
        );
        portal.setTokenRoute(address(0), adChainId, adToken);

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(OrderPortal.OrderPortal__RoutesZeroAddress.selector, address(orderToken), address(0))
        );
        portal.setTokenRoute(address(orderToken), adChainId, address(0));
    }

    /*//////////////////////////////////////////////////////////////
           setTokenRoute: rejects unsupported dstChainId
    //////////////////////////////////////////////////////////////*/
    function test_setTokenRoute_rejectsUnsupportedDstChainId() public {
        // dstChainId not set via setChain => unsupported
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(OrderPortal.OrderPortal__AdChainNotSupported.selector, adChainId));
        portal.setTokenRoute(address(orderToken), adChainId, adToken);
    }

    /*//////////////////////////////////////////////////////////////
           setTokenRoute: orderToken path
    ///////////////////////////////////////////////////////////////*/

    function test_setTokenRoute_setsAndEmits_whenSupported() public {
        vm.startPrank(admin);
        portal.setChain(adChainId, adManager, true);

        vm.expectEmit(true, true, true, true);
        emit OrderPortal.TokenRouteSet(address(orderToken), adChainId, adToken);
        portal.setTokenRoute(address(orderToken), adChainId, adToken);
        vm.stopPrank();

        address routed = portal.tokenRoute(address(orderToken), adChainId);
        assertEq(routed, adToken, "route not set");
    }

    /*//////////////////////////////////////////////////////////////
           setTokenRoute: wNativeToken path
    //////////////////////////////////////////////////////////////*/

    function test_setNativeTokenRoute_setsAndEmits_whenSupported() public {
        vm.startPrank(admin);
        portal.setChain(adChainId, adManager, true);

        vm.expectEmit(true, true, true, true);
        emit OrderPortal.TokenRouteSet(NATIVE_TOKEN_ADDRESS, adChainId, adToken);
        portal.setTokenRoute(NATIVE_TOKEN_ADDRESS, adChainId, adToken);
        vm.stopPrank();

        address routed = portal.tokenRoute(NATIVE_TOKEN_ADDRESS, adChainId);
        assertEq(routed, adToken, "route not set");
    }

    /*//////////////////////////////////////////////////////////////
                    removeTokenRoute: only admin
    //////////////////////////////////////////////////////////////*/
    function test_removeTokenRoute_onlyAdmin() public {
        vm.startPrank(admin);
        portal.setChain(adChainId, adManager, true);
        portal.setTokenRoute(address(orderToken), adChainId, adToken);
        vm.stopPrank();

        vm.prank(nonAdmin);
        vm.expectRevert();
        portal.removeTokenRoute(address(orderToken), adChainId);
    }

    function test_removeTokenRoute_clearsAndEmits() public {
        vm.startPrank(admin);
        portal.setChain(adChainId, adManager, true);
        portal.setTokenRoute(address(orderToken), adChainId, adToken);

        vm.expectEmit(true, true, true, true);
        emit OrderPortal.TokenRouteRemoved(address(orderToken), adChainId);
        portal.removeTokenRoute(address(orderToken), adChainId);
        vm.stopPrank();

        address routed = portal.tokenRoute(address(orderToken), adChainId);
        assertEq(routed, address(0), "route not removed");
    }

    /*//////////////////////////////////////////////////////////////
                      createOrder: rejects zero amount
    //////////////////////////////////////////////////////////////*/
    function test_createOrder_rejects_zeroAmount() public {
        test_setTokenRoute_setsAndEmits_whenSupported();
        OrderPortal.OrderParams memory p = _defaultParams();
        p.amount = 0;

        bytes32 orderHash = portal.hashOrderPublic(p);
        (authToken, timeToLive, signature) = generateCreateOrderRequestParams(p.adId, orderHash);

        vm.prank(bridger);
        vm.expectRevert(OrderPortal.OrderPortal__ZeroAmount.selector);
        portal.createOrder(signature, authToken, timeToLive, p);
    }

    /*//////////////////////////////////////////////////////////////
                 createOrder: rejects when dstChain unsupported
    //////////////////////////////////////////////////////////////*/
    function test_createOrder_rejects_dstChainUnsupported() public {
        test_setTokenRoute_setsAndEmits_whenSupported();
        OrderPortal.OrderParams memory p = _defaultParams();
        p.adChainId = 9_999_999; // not configured

        bytes32 orderHash = portal.hashOrderPublic(p);
        (authToken, timeToLive, signature) = generateCreateOrderRequestParams(p.adId, orderHash);

        vm.prank(bridger);
        vm.expectRevert(abi.encodeWithSelector(OrderPortal.OrderPortal__AdChainNotSupported.selector, p.adChainId));
        portal.createOrder(signature, authToken, timeToLive, p);
    }

    /*//////////////////////////////////////////////////////////////
              createOrder: rejects when dstAdManager mismatch
    //////////////////////////////////////////////////////////////*/
    function test_createOrder_rejects_adManagerMismatch() public {
        test_setTokenRoute_setsAndEmits_whenSupported();
        OrderPortal.OrderParams memory p = _defaultParams();
        address otherAdMgr = makeAddr("otherAdMgr");
        p.adManager = otherAdMgr; // differs from configured dstAdMgr

        bytes32 orderHash = portal.hashOrderPublic(p);
        (authToken, timeToLive, signature) = generateCreateOrderRequestParams(p.adId, orderHash);

        vm.prank(bridger);
        vm.expectRevert(abi.encodeWithSelector(OrderPortal.OrderPortal__AdManagerMismatch.selector, adManager));
        portal.createOrder(signature, authToken, timeToLive, p);
    }

    /*//////////////////////////////////////////////////////////////
      createOrder: rejects when no token route for (token1, dstChainId)
    //////////////////////////////////////////////////////////////*/
    function test_createOrder_rejects_missingTokenRoute() public {
        test_setTokenRoute_setsAndEmits_whenSupported();
        // No tokenRoute set yet
        OrderPortal.OrderParams memory p = _defaultParams();
        p.orderChainToken = other;

        bytes32 orderHash = portal.hashOrderPublic(p);
        (authToken, timeToLive, signature) = generateCreateOrderRequestParams(p.adId, orderHash);

        vm.prank(bridger);
        vm.expectRevert(OrderPortal.OrderPortal__MissingRoute.selector);
        portal.createOrder(signature, authToken, timeToLive, p);
    }

    /*//////////////////////////////////////////////////////////////
        createOrder: rejects when token2 != routed dst token
    //////////////////////////////////////////////////////////////*/
    function test_createOrder_rejects_dstTokenMismatch() public {
        test_setTokenRoute_setsAndEmits_whenSupported();
        // Route points to token2Other, but params.token2 is token2
        vm.prank(admin);
        portal.setTokenRoute(address(orderToken), adChainId, other);

        OrderPortal.OrderParams memory p = _defaultParams();

        bytes32 orderHash = portal.hashOrderPublic(p);
        (authToken, timeToLive, signature) = generateCreateOrderRequestParams(p.adId, orderHash);

        vm.prank(bridger);
        vm.expectRevert(OrderPortal.OrderPortal__AdTokenMismatch.selector);
        portal.createOrder(signature, authToken, timeToLive, p);
    }

    /*//////////////////////////////////////////////////////////////
    createOrder: computes orderHash; stores Status.Open; pulls token1; emits
    //////////////////////////////////////////////////////////////*/
    function test_createOrder_success_storesOpen_pullsFunds_emitsEvent() public {
        test_setTokenRoute_setsAndEmits_whenSupported();

        OrderPortal.OrderParams memory p = _defaultParams();

        // Approvals & balances
        vm.startPrank(bridger);
        orderToken.approve(address(portal), p.amount);
        uint256 balSenderBefore = orderToken.balanceOf(bridger);
        uint256 balPortalBefore = orderToken.balanceOf(address(portal));

        // Expected hash (uses struct, chainid, and address(this))
        bytes32 expectedHash = portal.hashOrderPublic(p);

        vm.expectEmit(true, true, true, true);
        emit OrderPortal.OrderCreated(
            expectedHash,
            bridger,
            address(orderToken),
            p.amount,
            p.adChainId,
            p.adChainToken,
            p.adManager,
            p.adId,
            p.adCreator,
            p.adRecipient
        );

        (authToken, timeToLive, signature) = generateCreateOrderRequestParams(p.adId, expectedHash);
        bytes32 orderHash = portal.createOrder(signature, authToken, timeToLive, p);
        vm.stopPrank();

        // Hash returned matches expected
        assertEq(orderHash, expectedHash, "orderHash mismatch");

        // Status is Open
        (OrderPortal.Status status) = portal.orders(orderHash);
        assertEq(uint256(status), uint256(OrderPortal.Status.Open), "status not Open");

        // Funds moved
        uint256 balSenderAfter = orderToken.balanceOf(bridger);
        uint256 balPortalAfter = orderToken.balanceOf(address(portal));
        assertEq(balSenderBefore - balSenderAfter, p.amount, "sender not debited");
        assertEq(balPortalAfter - balPortalBefore, p.amount, "portal not credited");
    }

    /*//////////////////////////////////////////////////////////////
            createOrder: computes orderHash; stores Status.Open; pulls wNativeToken; emits
    //////////////////////////////////////////////////////////////*/
    function test_createOrder_with_NativeToken_success_storesOpen_pullsFunds_emitsEvent() public {
        test_setNativeTokenRoute_setsAndEmits_whenSupported();

        OrderPortal.OrderParams memory p = _defaultParams();
        p.orderChainToken = NATIVE_TOKEN_ADDRESS;

        vm.deal(bridger, p.amount);

        // Balances
        vm.startPrank(bridger);
        uint256 balSenderBefore = bridger.balance;
        uint256 balPortalBefore = _wNativeToken.balanceOf(address(portal));

        // Expected hash (uses struct, chainid, and address(this))
        bytes32 expectedHash = portal.hashOrderPublic(p);

        vm.expectEmit(true, true, true, true);
        emit OrderPortal.OrderCreated(
            expectedHash,
            bridger,
            NATIVE_TOKEN_ADDRESS,
            p.amount,
            p.adChainId,
            p.adChainToken,
            p.adManager,
            p.adId,
            p.adCreator,
            p.adRecipient
        );

        (authToken, timeToLive, signature) = generateCreateOrderRequestParams(p.adId, expectedHash);
        bytes32 orderHash = portal.createOrder{value: p.amount}(signature, authToken, timeToLive, p);
        vm.stopPrank();

        // Hash returned matches expected
        assertEq(orderHash, expectedHash, "orderHash mismatch");

        // Status is Open
        (OrderPortal.Status status) = portal.orders(orderHash);
        assertEq(uint256(status), uint256(OrderPortal.Status.Open), "status not Open");

        // Funds moved
        uint256 balSenderAfter = bridger.balance;
        uint256 balPortalAfter = _wNativeToken.balanceOf(address(portal));
        assertEq(balSenderBefore - balSenderAfter, p.amount, "sender not debited");
        assertEq(balPortalAfter - balPortalBefore, p.amount, "portal not credited");
    }

    /*//////////////////////////////////////////////////////////////
             createOrder: duplicate (same params) -> OrderExists
    //////////////////////////////////////////////////////////////*/
    function test_createOrder_duplicate_sameParams_revertsOrderExists() public {
        test_setTokenRoute_setsAndEmits_whenSupported();

        OrderPortal.OrderParams memory p = _defaultParams();

        vm.startPrank(bridger);
        orderToken.approve(address(portal), p.amount * 2);

        bytes32 orderHash = portal.hashOrderPublic(p);
        (authToken, timeToLive, signature) = generateCreateOrderRequestParams(p.adId, orderHash);

        bytes32 h1 = portal.createOrder(signature, authToken, timeToLive, p);

        vm.expectRevert(abi.encodeWithSelector(OrderPortal.OrderPortal__OrderExists.selector, h1));
        portal.createOrder(signature, authToken, timeToLive, p);
        vm.stopPrank();
    }

    // Create an order from `bridger` and return its hash + params used
    function _openOrder(uint256 _amount, uint256 _salt)
        internal
        returns (OrderPortal.OrderParams memory p, bytes32 orderHash)
    {
        p = _defaultParams();
        p.amount = _amount;
        p.salt = _salt;

        bytes32 exHash = portal.hashOrderPublic(p);
        (authToken, timeToLive, signature) = generateCreateOrderRequestParams(p.adId, exHash);

        vm.startPrank(bridger);
        orderToken.approve(address(portal), _amount);
        orderHash = portal.createOrder(signature, authToken, timeToLive, p);
        vm.stopPrank();
    }

    // createOrder with Native token
    function _openOrderWithNativeToken(uint256 _amount, uint256 _salt)
        internal
        returns (OrderPortal.OrderParams memory p, bytes32 orderHash)
    {
        p = _defaultParams();
        p.amount = _amount;
        p.salt = _salt;
        p.orderChainToken = NATIVE_TOKEN_ADDRESS;
        vm.deal(bridger, _amount);

        bytes32 exHash = portal.hashOrderPublic(p);
        (authToken, timeToLive, signature) = generateCreateOrderRequestParams(p.adId, exHash);

        vm.startPrank(bridger);
        orderHash = portal.createOrder{value: _amount}(signature, authToken, timeToLive, p);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
     * unlock: rejects when order not open
     //////////////////////////////////////////////////////////////*/
    function test_unlock_rejects_whenOrderNotOpen() public {
        OrderPortal.OrderParams memory p = _defaultParams();
        bytes32 orderHash = portal.hashOrderPublic(p); // no order created

        bytes32 t_root = bytes32(uint256(0));

        // get auth
        (authToken, timeToLive, signature) = generateUnlockOrderRequestHash(p.adId, orderHash, t_root);

        vm.expectRevert(abi.encodeWithSelector(OrderPortal.OrderPortal__OrderNotOpen.selector, orderHash));
        portal.unlock(signature, authToken, timeToLive, p, bytes32("N"), t_root, hex"");
    }

    /*//////////////////////////////////////////////////////////////
     * unlock: rejects when nullifier used
     //////////////////////////////////////////////////////////////*/
    function test_unlock_rejects_whenNullifierAlreadyUsed() public {
        test_setTokenRoute_setsAndEmits_whenSupported();

        (OrderPortal.OrderParams memory p,) = _openOrder(80 ether, 777);
        bytes32 orderHash = portal.hashOrderPublic(p);

        bytes32 t_root = bytes32(uint256(0));

        // get auth
        (authToken, timeToLive, signature) = generateUnlockOrderRequestHash(p.adId, orderHash, t_root);

        // First unlock OK
        vm.expectEmit(true, true, true, true);
        emit OrderPortal.OrderUnlocked(
            portal.hashOrderPublic(p),
            p.adRecipient, // NOTE: contract emits dstRecipient in 2nd arg
            bytes32("N")
        );
        portal.unlock(signature, authToken, timeToLive, p, bytes32("N"), t_root, hex"AA");

        // get auth again
        (authToken, timeToLive, signature) = generateUnlockOrderRequestHash(p.adId, orderHash, t_root);

        // Second unlock with same nullifier reverts
        vm.expectRevert(abi.encodeWithSelector(OrderPortal.OrderPortal__NullifierUsed.selector, bytes32("N")));
        portal.unlock(signature, authToken, timeToLive, p, bytes32("N"), t_root, hex"BB");
    }

    /*//////////////////////////////////////////////////////////////
     * unlock: verifier false -> InvalidProof (state unchanged)
     //////////////////////////////////////////////////////////////*/
    function test_unlock_verifierFalse_revertsInvalidProof_andNoStateChange() public {
        test_setTokenRoute_setsAndEmits_whenSupported();
        (OrderPortal.OrderParams memory p, bytes32 orderHash) = _openOrder(70 ether, 999);

        // Balances before
        uint256 balPortalBefore = orderToken.balanceOf(address(portal));
        uint256 balRecipientBefore = orderToken.balanceOf(p.adRecipient);

        // Fail regardless of inputs
        verifier.setResult(false); // not strict, return false

        bytes32 t_root = bytes32(uint256(0));

        (authToken, timeToLive, signature) = generateUnlockOrderRequestHash(p.adId, orderHash, t_root);

        vm.expectRevert(OrderPortal.OrderPortal__InvalidProof.selector);
        portal.unlock(signature, authToken, timeToLive, p, bytes32("X"), t_root, hex"");

        // Status & balances unchanged
        (OrderPortal.Status status) = portal.orders(orderHash);
        assertEq(uint256(status), uint256(OrderPortal.Status.Open), "status changed unexpectedly");

        assertEq(orderToken.balanceOf(address(portal)), balPortalBefore, "portal balance changed");
        assertEq(orderToken.balanceOf(p.adRecipient), balRecipientBefore, "recipient balance changed");
    }

    /*//////////////////////////////////////////////////////////////
     * unlock: verifier true -> status Filled; transfers token1 to adRecipient
     * unlock: emits OrderUnlocked
     //////////////////////////////////////////////////////////////*/
    function test_unlock_success_setsFilled_transfers_emits() public {
        test_setTokenRoute_setsAndEmits_whenSupported();
        (OrderPortal.OrderParams memory p, bytes32 orderHash) = _openOrder(65 ether, 123);

        uint256 balPortalBefore = orderToken.balanceOf(address(portal));
        uint256 balRecipientBefore = orderToken.balanceOf(p.adRecipient);

        bytes memory proof = hex"ABCD";
        bytes32 nullifier = bytes32("NOK");

        bytes32 t_root = bytes32(uint256(0));

        (authToken, timeToLive, signature) = generateUnlockOrderRequestHash(p.adId, orderHash, t_root);

        vm.expectEmit(true, true, true, true);
        emit OrderPortal.OrderUnlocked(orderHash, p.adRecipient, nullifier);

        portal.unlock(signature, authToken, timeToLive, p, nullifier, t_root, proof);

        // Status moved to Filled
        (OrderPortal.Status status) = portal.orders(orderHash);
        assertEq(uint256(status), uint256(OrderPortal.Status.Filled), "status not Filled");

        // Funds transferred from portal to dstRecipient
        assertEq(orderToken.balanceOf(address(portal)), balPortalBefore - p.amount, "portal not debited");
        assertEq(orderToken.balanceOf(p.adRecipient), balRecipientBefore + p.amount, "recipient not credited");
    }

    /*//////////////////////////////////////////////////////////////
     * unlock: emits OrderUnlocked (covered above) + cannot unlock again
     //////////////////////////////////////////////////////////////*/
    function test_unlock_cannotUnlockTwice_sameOrder() public {
        test_setTokenRoute_setsAndEmits_whenSupported();
        (OrderPortal.OrderParams memory p, bytes32 orderHash) = _openOrder(40 ether, 321);
        bytes32 t_root = bytes32(uint256(0));

        (authToken, timeToLive, signature) = generateUnlockOrderRequestHash(p.adId, orderHash, t_root);

        portal.unlock(signature, authToken, timeToLive, p, bytes32("one"), t_root, hex"");

        (authToken, timeToLive, signature) = generateUnlockOrderRequestHash(p.adId, orderHash, t_root);

        vm.expectRevert(abi.encodeWithSelector(OrderPortal.OrderPortal__OrderNotOpen.selector, orderHash));
        portal.unlock(signature, authToken, timeToLive, p, bytes32("two"), t_root, hex"");
    }

    /*//////////////////////////////////////////////////////////////
     * unlock: verifier true -> status Filled; transfers native token to adRecipient
     * unlock: emits OrderUnlocked
     //////////////////////////////////////////////////////////////*/
    function test_unlock_with_NativeToken_success_setsFilled_transfers_emits() public {
        test_setNativeTokenRoute_setsAndEmits_whenSupported();
        (OrderPortal.OrderParams memory p, bytes32 orderHash) = _openOrderWithNativeToken(55 ether, 456);

        uint256 balPortalBefore = _wNativeToken.balanceOf(address(portal));
        uint256 balRecipientBefore = p.adRecipient.balance;

        bytes memory proof = hex"ABCD";
        bytes32 nullifier = bytes32("NATIVE");

        bytes32 t_root = bytes32(uint256(0));

        (authToken, timeToLive, signature) = generateUnlockOrderRequestHash(p.adId, orderHash, t_root);

        vm.expectEmit(true, true, true, true);
        emit OrderPortal.OrderUnlocked(orderHash, p.adRecipient, nullifier);

        portal.unlock(signature, authToken, timeToLive, p, nullifier, t_root, proof);

        // Status moved to Filled
        (OrderPortal.Status status) = portal.orders(orderHash);
        assertEq(uint256(status), uint256(OrderPortal.Status.Filled), "status not Filled");

        // Funds transferred from portal to dstRecipient
        assertEq(_wNativeToken.balanceOf(address(portal)), balPortalBefore - p.amount, "portal not debited");
        assertEq(p.adRecipient.balance, balRecipientBefore + p.amount, "recipient not credited");
    }
}
