// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {AdManager} from "src/AdManager.sol";
import {OrderPortal} from "src/OrderPortal.sol";
import {HonkVerifier} from "src/Verifier.sol";
import {IVerifier} from "src/Verifier.sol";
import {MerkleManager, IMerkleManager} from "src/MerkleManager.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IwNativeToken, wNativeToken} from "src/wNativeToken.sol";

contract MockAdManager is AdManager {
    constructor(address admin, IVerifier v, IMerkleManager m, IwNativeToken t) AdManager(admin, v, m, t) {}

    string public lastId;

    function setLastId(string memory id) public {
        lastId = id;
    }

    function hashOrderPublic(OrderParams calldata p) external view returns (bytes32) {
        return _hashOrder(p, block.chainid, address(this));
    }
}

contract MockOrderPortal is OrderPortal {
    constructor(address admin, IVerifier v, IMerkleManager m, IwNativeToken t) OrderPortal(admin, v, m, t) {}

    function hashOrderPublic(OrderParams calldata p) external view returns (bytes32) {
        return _hashOrder(p, block.chainid, address(this));
    }
}

contract ProofBridge is Test {
    MockAdManager internal adManager;
    MockOrderPortal internal orderPortal;
    HonkVerifier internal adChainVerifier;
    HonkVerifier internal orderChainVerifier;
    MerkleManager internal adChainMerkleManager;
    MerkleManager internal orderChainMerkleManager;
    ERC20Mock internal orderToken;
    ERC20Mock internal adToken;
    IwNativeToken internal adChainWNativeToken;
    IwNativeToken internal orderChainWNativeToken;
    address public constant NATIVE_TOKEN_ADDRESS = address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);
    uint256 public constant W_DECIMALS = 18;

    address admin;
    uint256 adminPk;

    address nonAdmin = makeAddr("nonAdmin");
    address maker;
    uint256 makerPk;
    address bridger;
    uint256 bridgerPk;
    address nonMaker = makeAddr("nonMaker");

    address orderRecipient = makeAddr("orderRecipient");
    address adRecipient = makeAddr("adRecipient");
    address recipient = makeAddr("recipient");
    address other = makeAddr("other");

    uint256 internal adChainId = 111_55_111;
    uint256 internal orderChainId = 296;

    uint256 internal unsupportedChainId = 25_000_000;

    uint256 internal minted = 2_000 ether;
    uint256 internal initAmt = 5_00 ether;
    uint256 internal fundAmt = 1_000 ether;
    uint256 internal orderAmt = 100 ether;

    // auth variables
    bytes signature;
    bytes32 authToken;
    uint256 timeToLive;

    struct Order {
        address orderToken;
        address adToken;
        uint256 amount;
        address bridger;
        uint256 orderChainId;
        address orderPortal;
        address orderRecipient;
        uint256 adChainId;
        address adManager;
        string adId;
        address adCreator;
        address adRecipient;
        uint256 salt;
    }

    function setUp() public {
        uint256 neutral = block.chainid;

        // setup addresses
        (admin, adminPk) = makeAddrAndKey("admin");
        (maker, makerPk) = makeAddrAndKey("maker");
        (bridger, bridgerPk) = makeAddrAndKey("bridger");

        // Initialize the contracts
        // AdChain contracts
        vm.chainId(adChainId);
        adChainVerifier = new HonkVerifier();
        adChainMerkleManager = new MerkleManager(admin);
        adChainWNativeToken = new wNativeToken("Wrapped Native Token", "WNATIVE", W_DECIMALS);
        adManager = new MockAdManager(admin, adChainVerifier, adChainMerkleManager, adChainWNativeToken);
        adToken = new ERC20Mock();
        // assign manager role
        vm.startPrank(admin);
        adChainMerkleManager.grantRole(adChainMerkleManager.MANAGER_ROLE(), address(adManager));
        vm.stopPrank();

        // Order chain Contracts
        vm.chainId(orderChainId);
        orderChainVerifier = new HonkVerifier();
        orderChainMerkleManager = new MerkleManager(admin);
        orderChainWNativeToken = new wNativeToken("Wrapped Native Token", "WNATIVE", W_DECIMALS);
        orderPortal = new MockOrderPortal(admin, orderChainVerifier, orderChainMerkleManager, orderChainWNativeToken);
        orderToken = new ERC20Mock();
        // assign manager role
        vm.startPrank(admin);
        orderChainMerkleManager.grantRole(orderChainMerkleManager.MANAGER_ROLE(), address(orderPortal));
        vm.stopPrank();

        // Set Ad Chain configs
        vm.chainId(adChainId);
        // Mint ad tokens to the maker
        adToken.mint(maker, minted);
        // Set up AdManager configs
        vm.startPrank(admin);
        // Register the order chain
        adManager.setChain(orderChainId, address(orderPortal), true);
        // Set token route
        adManager.setTokenRoute(address(adToken), address(orderToken), orderChainId);
        // Set native token route
        adManager.setTokenRoute(NATIVE_TOKEN_ADDRESS, address(orderToken), orderChainId);
        vm.stopPrank();

        // Setup Ads
        vm.startPrank(maker);
        // Create an ad
        string memory adId = "1";
        // Generate request params
        (authToken, timeToLive, signature) = generateCreateAdRequestParams(adId, address(adToken));
        // Approve with initial tokens
        adToken.approve(address(adManager), initAmt);
        // Create the ad
        adManager.createAd(signature, authToken, timeToLive, adId, address(adToken), initAmt, orderChainId, adRecipient);
        // Set last id to the created ad
        adManager.setLastId(adId);
        // Approve the ad with tokens
        adToken.approve(address(adManager), fundAmt);
        // Generate request params
        (authToken, timeToLive, signature) = generateFundAdRequestParams(adId, fundAmt);
        // Fund the ad
        adManager.fundAd(signature, authToken, timeToLive, adId, fundAmt);

        // Create native ad
        adId = "native-ad";
        (authToken, timeToLive, signature) = generateCreateAdRequestParams(adId, NATIVE_TOKEN_ADDRESS);
        vm.deal(maker, initAmt);
        adManager.createAd{
            value: initAmt
        }(signature, authToken, timeToLive, adId, NATIVE_TOKEN_ADDRESS, initAmt, orderChainId, adRecipient);

        vm.stopPrank();

        // Set Order Chain configs
        vm.chainId(orderChainId);
        // mint order tokens to bridger
        orderToken.mint(bridger, minted);
        // Set up OrderPortal configs
        vm.startPrank(admin);
        orderPortal.setChain(adChainId, address(adManager), true);
        orderPortal.setTokenRoute(address(orderToken), adChainId, address(adToken));
        vm.stopPrank();

        vm.chainId(neutral);
    }

    /*//////////////////////////////////////////////////////////////
           HELPERS
    //////////////////////////////////////////////////////////////*/
    function _defaultAdChainParams(string memory adId, address adTokenAddr, uint256 amount, uint256 salt)
        internal
        view
        returns (AdManager.OrderParams memory p)
    {
        p.orderChainToken = address(orderToken);
        p.adChainToken = adTokenAddr;
        p.amount = amount;
        p.bridger = bridger;
        p.orderChainId = orderChainId;
        p.srcOrderPortal = address(orderPortal);
        p.orderRecipient = orderRecipient;
        p.adId = adId;
        p.adCreator = maker;
        p.adRecipient = adRecipient;
        p.salt = salt;
    }

    function _defaultOrderChainParams(string memory adId, address adTokenAddr, uint256 amount, uint256 salt)
        internal
        view
        returns (OrderPortal.OrderParams memory p)
    {
        p.orderChainToken = address(orderToken);
        p.adChainToken = adTokenAddr;
        p.amount = amount;
        p.bridger = bridger;
        p.orderRecipient = orderRecipient;
        p.adChainId = adChainId;
        p.adManager = address(adManager);
        p.adId = adId;
        p.adCreator = maker;
        p.adRecipient = adRecipient;
        p.salt = salt;
    }

    function _adId() internal returns (string memory adId) {
        uint256 prevChain = block.chainid;
        vm.chainId(adChainId);
        adId = adManager.lastId();
        vm.chainId(prevChain);
    }

    function ethSign(bytes32 message, uint256 pk) public pure returns (bytes memory sig) {
        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        sig = abi.encodePacked(r, s, v);
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

        sig = ethSign(message, adminPk);
    }

    function generateFundAdRequestParams(string memory adId, uint256 amount)
        internal
        view
        returns (bytes32 token, uint256 ttl, bytes memory sig)
    {
        token = bytes32(vm.randomBytes(32));
        ttl = block.timestamp + 1 hours;
        bytes32 message = adManager.fundAdRequestHash(adId, amount, token, ttl);
        sig = ethSign(message, adminPk);
    }

    function generateLockForOrderRequestHash(string memory adId, bytes32 orderHash)
        internal
        view
        returns (bytes32 token, uint256 ttl, bytes memory sig)
    {
        token = bytes32(vm.randomBytes(32));
        ttl = block.timestamp + 1 hours;

        bytes32 message = adManager.lockForOrderRequestHash(adId, orderHash, token, ttl);
        sig = ethSign(message, adminPk);
    }

    function generateCreateOrderRequestParams(string memory adId, bytes32 orderHash)
        internal
        view
        returns (bytes32 token, uint256 ttl, bytes memory sig)
    {
        token = bytes32(vm.randomBytes(32));
        ttl = block.timestamp + 1 hours;
        bytes32 message = orderPortal.createOrderRequestHash(adId, orderHash, token, ttl);
        sig = ethSign(message, adminPk);
    }

    function generateUnlockOrderRequestHash(string memory adId, bytes32 orderHash, bytes32 targetRoot)
        internal
        view
        returns (bytes32 token, uint256 ttl, bytes memory sig)
    {
        token = bytes32(vm.randomBytes(32));
        ttl = block.timestamp + 1 hours;

        bytes32 message = adManager.unlockOrderRequestHash(adId, orderHash, targetRoot, token, ttl);
        sig = ethSign(message, adminPk);
    }

    function generateOrderChainUnlockOrderRequestHash(string memory adId, bytes32 orderHash, bytes32 targetRoot)
        internal
        view
        returns (bytes32 token, uint256 ttl, bytes memory sig)
    {
        token = bytes32(vm.randomBytes(32));
        ttl = block.timestamp + 1 hours;

        bytes32 message = orderPortal.unlockOrderRequestHash(adId, orderHash, targetRoot, token, ttl);
        sig = ethSign(message, adminPk);
    }

    /*//////////////////////////////////////////////////////////////
            check that order hashes matches for same data
    //////////////////////////////////////////////////////////////*/
    function test_orderHashMatchesOnBothChains() public {
        uint256 neutral = block.chainid;

        string memory adId = _adId();

        // get order chain params
        OrderPortal.OrderParams memory orderChainParams =
            _defaultOrderChainParams(adId, address(adToken), 100 ether, 777);

        // get ad chain params
        AdManager.OrderParams memory adChainParams = _defaultAdChainParams(adId, address(adToken), 100 ether, 777);

        bytes32 orderChainOrderHash;
        bytes32 adChainOrderHash;

        vm.chainId(orderChainId);
        orderChainOrderHash = orderPortal.hashOrderPublic(orderChainParams);

        vm.chainId(adChainId);
        adChainOrderHash = adManager.hashOrderPublic(adChainParams);

        assertEq(orderChainOrderHash, adChainOrderHash);

        vm.chainId(neutral);
    }

    /*//////////////////////////////////////////////////////////////
            check that order hashes not match for different data
    //////////////////////////////////////////////////////////////*/
    function test_orderHashNotMatchesOnBothChainsIfParamsDifferent() public {
        uint256 neutral = block.chainid;

        string memory adId = _adId();

        // get order chain params
        OrderPortal.OrderParams memory orderChainParams =
            _defaultOrderChainParams(adId, address(adToken), 90 ether, 777);

        // get ad chain params
        AdManager.OrderParams memory adChainParams = _defaultAdChainParams(adId, address(adToken), 100 ether, 777);

        vm.chainId(orderChainId);
        bytes32 orderChainOrderHash = orderPortal.hashOrderPublic(orderChainParams);

        vm.chainId(adChainId);
        bytes32 adChainOrderHash = adManager.hashOrderPublic(adChainParams);

        assertNotEq(orderChainOrderHash, adChainOrderHash);

        vm.chainId(neutral);
    }

    function getTypedHash(Order memory order) public returns (bytes32 typedHash) {
        string[] memory inputs = new string[](16);

        inputs[0] = "npx";
        inputs[1] = "tsx";
        inputs[2] = "js-scripts/hashTypedData.ts";
        inputs[3] = vm.toString(order.orderToken);
        inputs[4] = vm.toString(order.adToken);
        inputs[5] = vm.toString(order.amount);
        inputs[6] = vm.toString(order.bridger);
        inputs[7] = vm.toString(order.orderChainId);
        inputs[8] = vm.toString(order.orderPortal);
        inputs[9] = vm.toString(order.orderRecipient);
        inputs[10] = vm.toString(order.adChainId);
        inputs[11] = vm.toString(order.adManager);
        inputs[12] = order.adId;
        inputs[13] = vm.toString(order.adCreator);
        inputs[14] = vm.toString(order.adRecipient);
        inputs[15] = vm.toString(order.salt);

        bytes memory result = vm.ffi(inputs);

        typedHash = abi.decode(result, (bytes32));
    }

    function getNullfierHashes(bytes32 orderHash)
        public
        returns (bytes32 adCreatorNullifierHash, bytes32 bridgerNullifierHash, bytes32 secret)
    {
        string[] memory inputs = new string[](4);

        inputs[0] = "npx";
        inputs[1] = "tsx";
        inputs[2] = "js-scripts/deposits/getNullifierHash.ts";
        inputs[3] = vm.toString(orderHash);

        bytes memory result = vm.ffi(inputs);
        (adCreatorNullifierHash, bridgerNullifierHash, secret) = abi.decode(result, (bytes32, bytes32, bytes32));
    }

    function getProof(
        bytes32[] memory leaves,
        bytes32 orderHash,
        bytes32 nullifierHash,
        bytes32 secret,
        bool isAdContract
    ) public returns (bytes memory proof, bytes32[] memory publicInputs) {
        string[] memory inputs = new string[](7 + leaves.length);

        inputs[0] = "npx";
        inputs[1] = "tsx";
        inputs[2] = "js-scripts/deposits/generateProof.ts";
        inputs[3] = vm.toString(nullifierHash); // nullifierHash
        inputs[4] = vm.toString(orderHash); // order hash
        inputs[5] = vm.toString(isAdContract); // location where proof is generated
        inputs[6] = vm.toString(secret); // secret

        for (uint256 i = 0; i < leaves.length; i++) {
            inputs[7 + i] = vm.toString(leaves[i]);
        }

        bytes memory result = vm.ffi(inputs);
        (proof, publicInputs) = abi.decode(result, (bytes, bytes32[]));
    }

    function sign(bytes32 hash, uint256 pk) public pure returns (bytes memory sig) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        sig = abi.encodePacked(r, s, v);
    }

    // Test that EIP712 hash matches onchain hashes
    function test_onChainHashesMatchesTypedDataHash() public {
        uint256 neutral = block.chainid;

        string memory adId = _adId();

        // get order chain params
        OrderPortal.OrderParams memory orderChainParams =
            _defaultOrderChainParams(adId, address(adToken), 100 ether, 777);

        // get ad chain params
        AdManager.OrderParams memory adChainParams = _defaultAdChainParams(adId, address(adToken), 100 ether, 777);

        // order chain params for typed data hash
        Order memory order = Order({
            orderToken: orderChainParams.orderChainToken,
            adToken: orderChainParams.adChainToken,
            amount: orderChainParams.amount,
            bridger: orderChainParams.bridger,
            orderChainId: adChainParams.orderChainId,
            orderPortal: adChainParams.srcOrderPortal,
            orderRecipient: orderChainParams.orderRecipient,
            adChainId: orderChainParams.adChainId,
            adManager: orderChainParams.adManager,
            adId: orderChainParams.adId,
            adCreator: orderChainParams.adCreator,
            adRecipient: orderChainParams.adRecipient,
            salt: orderChainParams.salt
        });

        // get on-chain hashes
        vm.chainId(orderChainId);
        bytes32 orderChainOrderHash = orderPortal.hashOrderPublic(orderChainParams);

        vm.chainId(adChainId);
        bytes32 adChainOrderHash = adManager.hashOrderPublic(adChainParams);

        vm.chainId(neutral);

        // get typed data hash
        bytes32 typedHash = getTypedHash(order);
        assertEq(orderChainOrderHash, adChainOrderHash);
        assertEq(typedHash, orderChainOrderHash);
        assertEq(typedHash, adChainOrderHash);
    }

    // Test that proof verifies offchain if maker is on order chain
    function test_makerCanVerifyWithMakerSecret() public {
        uint256 neutral = block.chainid;

        string memory adId = _adId();

        // get order chain params
        OrderPortal.OrderParams memory orderChainParams =
            _defaultOrderChainParams(adId, address(adToken), 100 ether, 777);

        vm.chainId(orderChainId);
        // since both hashes match, we can just use any chain's
        bytes32 orderHash = orderPortal.hashOrderPublic(orderChainParams);

        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = orderChainMerkleManager.fieldMod(orderHash);

        vm.chainId(neutral);

        // get maker nullifier hash
        (bytes32 makerNullifierHash,, bytes32 secret) = getNullfierHashes(orderHash);

        (bytes memory proof, bytes32[] memory publicInputs) =
            getProof(leaves, orderHash, makerNullifierHash, secret, false);

        vm.chainId(orderChainId);

        bool res = orderChainVerifier.verify(proof, publicInputs);
        assertTrue(res);

        vm.chainId(neutral);
    }

    // Test that maker proof verifies on order chain and fulfills the order
    function test_makerCanVerifyWithMakerSecretOnOrderChainAndOrderFulfills() public {
        uint256 neutral = block.chainid;
        string memory adId = _adId();

        // Setup Params
        OrderPortal.OrderParams memory orderChainParams =
            _defaultOrderChainParams(adId, address(adToken), orderAmt, 777);
        AdManager.OrderParams memory adChainParams = _defaultAdChainParams(adId, address(adToken), orderAmt, 777);

        // Create order on order chain
        vm.chainId(orderChainId);
        bytes32 expectedHash = orderPortal.hashOrderPublic(orderChainParams);
        (authToken, timeToLive, signature) = generateCreateOrderRequestParams(adId, expectedHash);

        vm.startPrank(bridger);
        orderToken.approve(address(orderPortal), orderAmt);
        bytes32 orderHash = orderPortal.createOrder(signature, authToken, timeToLive, orderChainParams);
        assertEq(orderHash, expectedHash);
        vm.stopPrank();

        // Lock order on ad chain
        vm.chainId(adChainId);
        vm.startPrank(maker);
        (authToken, timeToLive, signature) = generateLockForOrderRequestHash(adId, orderHash);
        adManager.lockForOrder(signature, authToken, timeToLive, adChainParams);
        vm.stopPrank();

        // Get Merkle tree state from ad chain
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = adChainMerkleManager.fieldMod(orderHash);
        bytes32 adChainRoot = adChainMerkleManager.getRoot();

        // Generate proof
        vm.chainId(neutral);
        (bytes32 makerNullifierHash,, bytes32 secret) = getNullfierHashes(orderHash);
        (bytes memory proof,) = getProof(leaves, orderHash, makerNullifierHash, secret, false);

        // Unlock and verify on order chain
        vm.chainId(orderChainId);

        // Check initial balances
        uint256 orderPortalBalanceBefore = orderToken.balanceOf(address(orderPortal));
        uint256 recipientBalBefore = orderToken.balanceOf(adRecipient);

        // Execute unlock
        (authToken, timeToLive, signature) = generateOrderChainUnlockOrderRequestHash(adId, orderHash, adChainRoot);

        vm.prank(maker);
        orderPortal.unlock(signature, authToken, timeToLive, orderChainParams, makerNullifierHash, adChainRoot, proof);

        // Verify final balances
        uint256 orderPortalBalanceAfter = orderToken.balanceOf(address(orderPortal));
        uint256 recipientBalAfter = orderToken.balanceOf(adRecipient);
        assertEq(orderPortalBalanceBefore - orderPortalBalanceAfter, orderAmt);
        assertEq(recipientBalAfter - recipientBalBefore, orderAmt);
    }

    // Test that maker secret cannot be user to unlock on ad chain even if they know the right proof
    function test_makerCannotUnlockOnAdChain() public {
        uint256 neutral = block.chainid;

        string memory adId = _adId();

        // Setup Params
        OrderPortal.OrderParams memory orderChainParams =
            _defaultOrderChainParams(adId, address(adToken), orderAmt, 777);
        AdManager.OrderParams memory adChainParams = _defaultAdChainParams(adId, address(adToken), orderAmt, 777);

        // Create order on order chain
        vm.chainId(orderChainId);
        bytes32 expectedHash = orderPortal.hashOrderPublic(orderChainParams);
        (authToken, timeToLive, signature) = generateCreateOrderRequestParams(adId, expectedHash);

        vm.startPrank(bridger);
        orderToken.approve(address(orderPortal), orderAmt);
        bytes32 orderHash = orderPortal.createOrder(signature, authToken, timeToLive, orderChainParams);
        assertEq(orderHash, expectedHash);
        vm.stopPrank();

        // Get Merkle tree state from order chain
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = orderChainMerkleManager.fieldMod(orderHash);
        bytes32 orderChainRoot = orderChainMerkleManager.getRoot();

        // Lock order on ad chain
        vm.chainId(adChainId);
        vm.startPrank(maker);
        (authToken, timeToLive, signature) = generateLockForOrderRequestHash(adId, orderHash);
        adManager.lockForOrder(signature, authToken, timeToLive, adChainParams);
        vm.stopPrank();

        vm.chainId(neutral);

        // get bridger nullifier hash
        (bytes32 makerNullifierHash, bytes32 bridgerNullifierHash, bytes32 secret) = getNullfierHashes(orderHash);

        // get proof
        (bytes memory proof,) = getProof(leaves, orderHash, bridgerNullifierHash, secret, true);

        vm.chainId(adChainId);

        // get auth
        (authToken, timeToLive, signature) = generateUnlockOrderRequestHash(adId, orderHash, orderChainRoot);

        // verify and fulfill order
        vm.prank(maker);
        vm.expectRevert(); // should revert because the nullifier is not for the bridger
        adManager.unlock(signature, authToken, timeToLive, adChainParams, makerNullifierHash, orderChainRoot, proof);

        vm.chainId(neutral);
    }

    // Test that proof verifies offchain if bridger is on ad chain
    function test_bridgerCanVerifyWithBridgerSecret() public {
        uint256 neutral = block.chainid;

        string memory adId = _adId();

        // get order chain params
        OrderPortal.OrderParams memory orderChainParams =
            _defaultOrderChainParams(adId, address(adToken), 100 ether, 777);

        vm.chainId(orderChainId);

        // since both hashes match, we can just use any chain's
        bytes32 orderHash = orderPortal.hashOrderPublic(orderChainParams);

        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = orderChainMerkleManager.fieldMod(orderHash);
        vm.chainId(neutral);

        // get maker nullifier hash
        (, bytes32 bridgerNullifierHash, bytes32 secret) = getNullfierHashes(orderHash);

        // get proof
        (bytes memory proof, bytes32[] memory publicInputs) =
            getProof(leaves, orderHash, bridgerNullifierHash, secret, true);

        vm.chainId(adChainId);

        bool res = adChainVerifier.verify(proof, publicInputs);
        assertTrue(res);

        vm.chainId(neutral);
    }

    // Test that bridger proof verifies on ad chain and fulfills the order
    function test_bridgerCanVerifyWithBridgerSecretOnAdChainAndOrderFulfills() public {
        uint256 neutral = block.chainid;
        string memory adId = _adId();

        // Setup Params
        OrderPortal.OrderParams memory orderChainParams =
            _defaultOrderChainParams(adId, address(adToken), orderAmt, 777);
        AdManager.OrderParams memory adChainParams = _defaultAdChainParams(adId, address(adToken), orderAmt, 777);

        // Create order on order chain
        vm.chainId(orderChainId);
        bytes32 expectedHash = orderPortal.hashOrderPublic(orderChainParams);
        (authToken, timeToLive, signature) = generateCreateOrderRequestParams(adId, expectedHash);

        vm.startPrank(bridger);
        orderToken.approve(address(orderPortal), orderAmt);
        bytes32 orderHash = orderPortal.createOrder(signature, authToken, timeToLive, orderChainParams);
        assertEq(orderHash, expectedHash);
        vm.stopPrank();

        // Get Merkle tree state from ad chain
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = orderChainMerkleManager.fieldMod(orderHash);
        bytes32 orderChainRoot = orderChainMerkleManager.getRoot();

        // Lock order on ad chain
        vm.chainId(adChainId);
        vm.startPrank(maker);
        (authToken, timeToLive, signature) = generateLockForOrderRequestHash(adId, orderHash);
        adManager.lockForOrder(signature, authToken, timeToLive, adChainParams);
        vm.stopPrank();

        // Generate proof
        vm.chainId(neutral);
        (, bytes32 bridgerNullifierHash, bytes32 secret) = getNullfierHashes(orderHash);
        (bytes memory proof,) = getProof(leaves, orderHash, bridgerNullifierHash, secret, true);

        vm.chainId(adChainId);

        // Check balances before
        uint256 adManagerBalanceBefore = adToken.balanceOf(address(adManager));
        uint256 recipientBalBefore = adToken.balanceOf(orderRecipient);

        // Get auth
        (authToken, timeToLive, signature) = generateUnlockOrderRequestHash(adId, orderHash, orderChainRoot);

        // Verify and fulfill order
        vm.prank(bridger);
        adManager.unlock(signature, authToken, timeToLive, adChainParams, bridgerNullifierHash, orderChainRoot, proof);

        // Check balances after
        uint256 adManagerBalanceAfter = adToken.balanceOf(address(adManager));
        uint256 recipientBalAfter = adToken.balanceOf(orderRecipient);
        assertEq(adManagerBalanceBefore - adManagerBalanceAfter, orderAmt);
        assertEq(recipientBalAfter - recipientBalBefore, orderAmt);
    }

    // Test that bridger secret cannot be user to unlock on order chain even if they know the right proof
    function test_bridgerCannotUnlockOnOrderChain() public {
        uint256 neutral = block.chainid;
        string memory adId = _adId();

        // Setup Params
        OrderPortal.OrderParams memory orderChainParams =
            _defaultOrderChainParams(adId, address(adToken), orderAmt, 777);
        AdManager.OrderParams memory adChainParams = _defaultAdChainParams(adId, address(adToken), orderAmt, 777);

        // Create order on order chain
        vm.chainId(orderChainId);
        bytes32 expectedHash = orderPortal.hashOrderPublic(orderChainParams);
        (authToken, timeToLive, signature) = generateCreateOrderRequestParams(adId, expectedHash);

        vm.startPrank(bridger);
        orderToken.approve(address(orderPortal), orderAmt);
        bytes32 orderHash = orderPortal.createOrder(signature, authToken, timeToLive, orderChainParams);
        assertEq(orderHash, expectedHash);
        vm.stopPrank();

        // Lock order on ad chain
        vm.chainId(adChainId);
        vm.startPrank(maker);
        (authToken, timeToLive, signature) = generateLockForOrderRequestHash(adId, orderHash);
        adManager.lockForOrder(signature, authToken, timeToLive, adChainParams);
        vm.stopPrank();

        // Get Merkle tree state from ad chain
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = adChainMerkleManager.fieldMod(orderHash);
        bytes32 adChainRoot = adChainMerkleManager.getRoot();

        // Generate proof
        vm.chainId(neutral);
        (bytes32 makerNullifierHash, bytes32 bridgerNullifierHash, bytes32 secret) = getNullfierHashes(orderHash);
        (bytes memory proof,) = getProof(leaves, orderHash, makerNullifierHash, secret, false);
        vm.chainId(orderChainId);

        // Unlock and verify on order chain
        vm.chainId(orderChainId);

        // get auth
        (authToken, timeToLive, signature) = generateUnlockOrderRequestHash(adId, orderHash, adChainRoot);

        // verify and fulfill order
        vm.prank(bridger);
        vm.expectRevert(); // should revert because the nullifier is not for the maker
        orderPortal.unlock(signature, authToken, timeToLive, orderChainParams, bridgerNullifierHash, adChainRoot, proof);

        vm.chainId(neutral);
    }

    // Test that nullifier hash cannot be used twice on order chain
    function test_nullifierCannotBeUsedTwiceOnOrderChain() public {
        uint256 neutral = block.chainid;
        string memory adId = _adId();

        // Setup Params
        OrderPortal.OrderParams memory orderChainParams =
            _defaultOrderChainParams(adId, address(adToken), orderAmt, 777);
        AdManager.OrderParams memory adChainParams = _defaultAdChainParams(adId, address(adToken), orderAmt, 777);

        // Create order on order chain
        vm.chainId(orderChainId);
        bytes32 expectedHash = orderPortal.hashOrderPublic(orderChainParams);
        (authToken, timeToLive, signature) = generateCreateOrderRequestParams(adId, expectedHash);

        vm.startPrank(bridger);
        orderToken.approve(address(orderPortal), orderAmt);
        bytes32 orderHash = orderPortal.createOrder(signature, authToken, timeToLive, orderChainParams);
        assertEq(orderHash, expectedHash);
        vm.stopPrank();

        // Lock order on ad chain
        vm.chainId(adChainId);
        vm.startPrank(maker);
        (authToken, timeToLive, signature) = generateLockForOrderRequestHash(adId, orderHash);
        adManager.lockForOrder(signature, authToken, timeToLive, adChainParams);
        vm.stopPrank();

        // Get Merkle tree state from ad chain
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = adChainMerkleManager.fieldMod(orderHash);
        bytes32 adChainRoot = adChainMerkleManager.getRoot();

        // Generate proof
        vm.chainId(neutral);
        (bytes32 makerNullifierHash,, bytes32 secret) = getNullfierHashes(orderHash);
        (bytes memory proof,) = getProof(leaves, orderHash, makerNullifierHash, secret, false);
        vm.chainId(orderChainId);

        // Unlock and verify on order chain
        vm.chainId(orderChainId);

        // get auth
        (authToken, timeToLive, signature) = generateOrderChainUnlockOrderRequestHash(adId, orderHash, adChainRoot);

        // verify and fulfill order
        vm.prank(maker);
        orderPortal.unlock(signature, authToken, timeToLive, orderChainParams, makerNullifierHash, adChainRoot, proof);

        // get another auth
        (authToken, timeToLive, signature) = generateOrderChainUnlockOrderRequestHash(adId, orderHash, adChainRoot);

        vm.prank(maker);
        vm.expectRevert();
        orderPortal.unlock(signature, authToken, timeToLive, orderChainParams, makerNullifierHash, adChainRoot, proof);

        vm.chainId(neutral);
    }

    // Test that nullifier hash cannot be used twice on ad chain
    function test_nullifierCannotBeUsedTwiceOnAdChain() public {
        uint256 neutral = block.chainid;
        string memory adId = _adId();

        // Setup Params
        OrderPortal.OrderParams memory orderChainParams =
            _defaultOrderChainParams(adId, address(adToken), orderAmt, 777);
        AdManager.OrderParams memory adChainParams = _defaultAdChainParams(adId, address(adToken), orderAmt, 777);

        // Create order on order chain
        vm.chainId(orderChainId);
        bytes32 expectedHash = orderPortal.hashOrderPublic(orderChainParams);
        (authToken, timeToLive, signature) = generateCreateOrderRequestParams(adId, expectedHash);

        vm.startPrank(bridger);
        orderToken.approve(address(orderPortal), orderAmt);
        bytes32 orderHash = orderPortal.createOrder(signature, authToken, timeToLive, orderChainParams);
        assertEq(orderHash, expectedHash);
        vm.stopPrank();

        // Get Merkle tree state from ad chain
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = orderChainMerkleManager.fieldMod(orderHash);
        bytes32 orderChainRoot = orderChainMerkleManager.getRoot();

        // Lock order on ad chain
        vm.chainId(adChainId);
        vm.startPrank(maker);
        (authToken, timeToLive, signature) = generateLockForOrderRequestHash(adId, orderHash);
        adManager.lockForOrder(signature, authToken, timeToLive, adChainParams);
        vm.stopPrank();

        // Generate proof
        vm.chainId(neutral);
        (, bytes32 bridgerNullifierHash, bytes32 secret) = getNullfierHashes(orderHash);
        (bytes memory proof,) = getProof(leaves, orderHash, bridgerNullifierHash, secret, true);

        vm.chainId(adChainId);

        // Get auth
        (authToken, timeToLive, signature) = generateUnlockOrderRequestHash(adId, orderHash, orderChainRoot);

        // Verify and fulfill order
        vm.prank(bridger);
        adManager.unlock(signature, authToken, timeToLive, adChainParams, bridgerNullifierHash, orderChainRoot, proof);

        // Get another auth
        (authToken, timeToLive, signature) = generateUnlockOrderRequestHash(adId, orderHash, orderChainRoot);

        vm.prank(bridger);
        vm.expectRevert();
        adManager.unlock(signature, authToken, timeToLive, adChainParams, bridgerNullifierHash, orderChainRoot, proof);
    }
}
