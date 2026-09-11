// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test, console} from "forge-std/Test.sol";
import {AdManager} from "src/AdManager.sol";
import {OrderPortal} from "src/OrderPortal.sol";
import {HonkVerifier} from "src/Verifier.sol";
import {IVerifier} from "src/Verifier.sol";
import {MerkleManager, IMerkleManager} from "src/MerkleManager.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {MockRootVerifier} from "./mocks/MockRootVerifier.sol";
import {IwNativeToken, wNativeToken} from "src/wNativeToken.sol";
import {Poseidon2Yul_BN254 as Poseidon2Yul} from "@poseidon2/src/bn254/yul/Poseidon2Yul.sol";

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

    struct Order {
        bytes32 orderToken;
        bytes32 adToken;
        uint256 amount;
        bytes32 bridger;
        uint256 orderChainId;
        bytes32 orderPortal;
        bytes32 orderRecipient;
        uint256 adChainId;
        bytes32 adManager;
        string adId;
        bytes32 adCreator;
        bytes32 adRecipient;
        uint256 salt;
        uint8 orderDecimals;
        uint8 adDecimals;
        uint256 deadline;
        bytes32 adSettlementSigner;
    }

    function _b32(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    function _toAddr(bytes32 b) internal pure returns (address) {
        return address(uint160(uint256(b)));
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
        adChainMerkleManager = new MerkleManager(admin, address(new Poseidon2Yul()));
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
        orderChainMerkleManager = new MerkleManager(admin, address(new Poseidon2Yul()));
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
        adManager.setChain(orderChainId, _b32(address(orderPortal)), true);
        // Set token route
        adManager.setTokenRoute(address(adToken), _b32(address(orderToken)), orderChainId);
        // Set native token route
        adManager.setTokenRoute(NATIVE_TOKEN_ADDRESS, _b32(address(orderToken)), orderChainId);
        // Root authenticity is mandatory at unlock: wire a permissive mock.
        adManager.setRootVerifier(orderChainId, address(new MockRootVerifier(true)));
        vm.stopPrank();

        // Setup Ads
        vm.startPrank(maker);
        // Create an ad
        string memory adId = "1";
        // Generate request params
        // Approve with initial tokens
        adToken.approve(address(adManager), initAmt);
        // Create the ad
        adManager.createAd(adId, address(adToken), initAmt, orderChainId, _b32(adRecipient));
        // Set last id to the created ad
        adManager.setLastId(adId);
        // Approve the ad with tokens
        adToken.approve(address(adManager), fundAmt);
        // Generate request params
        // Fund the ad
        adManager.fundAd(adId, fundAmt);

        // Create native ad
        adId = "native-ad";
        vm.deal(maker, initAmt);
        adManager.createAd{value: initAmt}(adId, NATIVE_TOKEN_ADDRESS, initAmt, orderChainId, _b32(adRecipient));

        vm.stopPrank();

        // Set Order Chain configs
        vm.chainId(orderChainId);
        // mint order tokens to bridger
        orderToken.mint(bridger, minted);
        // Set up OrderPortal configs
        vm.startPrank(admin);
        orderPortal.setChain(adChainId, _b32(address(adManager)), true);
        orderPortal.setTokenRoute(address(orderToken), adChainId, _b32(address(adToken)));
        orderPortal.setRootVerifier(adChainId, address(new MockRootVerifier(true)));
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
        p.orderChainToken = _b32(address(orderToken));
        p.adChainToken = _b32(adTokenAddr);
        p.amount = amount;
        p.bridger = _b32(bridger);
        p.orderChainId = orderChainId;
        p.srcOrderPortal = _b32(address(orderPortal));
        p.orderRecipient = _b32(orderRecipient);
        p.adId = adId;
        p.adCreator = _b32(maker);
        p.adRecipient = _b32(adRecipient);
        p.salt = salt;
        p.orderDecimals = 18;
        p.adDecimals = 18;
        p.deadline = block.timestamp + 1 days;
        p.adSettlementSigner = p.adCreator;
    }

    function _defaultOrderChainParams(string memory adId, address adTokenAddr, uint256 amount, uint256 salt)
        internal
        view
        returns (OrderPortal.OrderParams memory p)
    {
        p.orderChainToken = _b32(address(orderToken));
        p.adChainToken = _b32(adTokenAddr);
        p.amount = amount;
        p.bridger = _b32(bridger);
        p.orderRecipient = _b32(orderRecipient);
        p.adChainId = adChainId;
        p.adManager = _b32(address(adManager));
        p.adId = adId;
        p.adCreator = _b32(maker);
        p.adRecipient = _b32(adRecipient);
        p.salt = salt;
        p.orderDecimals = 18;
        p.adDecimals = 18;
        p.deadline = block.timestamp + 1 days;
        p.adSettlementSigner = p.adCreator;
    }

    function _adId() internal returns (string memory adId) {
        uint256 prevChain = block.chainid;
        vm.chainId(adChainId);
        adId = adManager.lastId();
        vm.chainId(prevChain);
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
        string[] memory inputs = new string[](20);

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
        inputs[16] = vm.toString(uint256(order.orderDecimals));
        inputs[17] = vm.toString(uint256(order.adDecimals));
        inputs[18] = vm.toString(order.deadline);
        inputs[19] = vm.toString(order.adSettlementSigner);

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
            salt: orderChainParams.salt,
            orderDecimals: orderChainParams.orderDecimals,
            adDecimals: orderChainParams.adDecimals,
            deadline: orderChainParams.deadline,
            adSettlementSigner: orderChainParams.adSettlementSigner
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

        vm.startPrank(bridger);
        orderToken.approve(address(orderPortal), orderAmt);
        bytes32 orderHash = orderPortal.createOrder(orderChainParams);
        assertEq(orderHash, expectedHash);
        vm.stopPrank();

        // Lock order on ad chain
        vm.chainId(adChainId);
        vm.startPrank(maker);
        adManager.lockForOrder(adChainParams);
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

        vm.prank(maker);
        orderPortal.unlock(orderChainParams, makerNullifierHash, adChainRoot, proof, hex"");

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

        vm.startPrank(bridger);
        orderToken.approve(address(orderPortal), orderAmt);
        bytes32 orderHash = orderPortal.createOrder(orderChainParams);
        assertEq(orderHash, expectedHash);
        vm.stopPrank();

        // Get Merkle tree state from order chain
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = orderChainMerkleManager.fieldMod(orderHash);
        bytes32 orderChainRoot = orderChainMerkleManager.getRoot();

        // Lock order on ad chain
        vm.chainId(adChainId);
        vm.startPrank(maker);
        adManager.lockForOrder(adChainParams);
        vm.stopPrank();

        vm.chainId(neutral);

        // get bridger nullifier hash
        (bytes32 makerNullifierHash, bytes32 bridgerNullifierHash, bytes32 secret) = getNullfierHashes(orderHash);

        // get proof
        (bytes memory proof,) = getProof(leaves, orderHash, bridgerNullifierHash, secret, true);

        vm.chainId(adChainId);

        // verify and fulfill order
        vm.prank(maker);
        vm.expectRevert(); // should revert because the nullifier is not for the bridger
        adManager.unlock(adChainParams, makerNullifierHash, orderChainRoot, proof, hex"");

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

        vm.startPrank(bridger);
        orderToken.approve(address(orderPortal), orderAmt);
        bytes32 orderHash = orderPortal.createOrder(orderChainParams);
        assertEq(orderHash, expectedHash);
        vm.stopPrank();

        // Get Merkle tree state from ad chain
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = orderChainMerkleManager.fieldMod(orderHash);
        bytes32 orderChainRoot = orderChainMerkleManager.getRoot();

        // Lock order on ad chain
        vm.chainId(adChainId);
        vm.startPrank(maker);
        adManager.lockForOrder(adChainParams);
        vm.stopPrank();

        // Generate proof
        vm.chainId(neutral);
        (, bytes32 bridgerNullifierHash, bytes32 secret) = getNullfierHashes(orderHash);
        (bytes memory proof,) = getProof(leaves, orderHash, bridgerNullifierHash, secret, true);

        vm.chainId(adChainId);

        // Check balances before
        uint256 adManagerBalanceBefore = adToken.balanceOf(address(adManager));
        uint256 recipientBalBefore = adToken.balanceOf(orderRecipient);

        // Verify and fulfill order
        vm.prank(bridger);
        adManager.unlock(adChainParams, bridgerNullifierHash, orderChainRoot, proof, hex"");

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

        vm.startPrank(bridger);
        orderToken.approve(address(orderPortal), orderAmt);
        bytes32 orderHash = orderPortal.createOrder(orderChainParams);
        assertEq(orderHash, expectedHash);
        vm.stopPrank();

        // Lock order on ad chain
        vm.chainId(adChainId);
        vm.startPrank(maker);
        adManager.lockForOrder(adChainParams);
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

        // verify and fulfill order
        vm.prank(bridger);
        vm.expectRevert(); // should revert because the nullifier is not for the maker
        orderPortal.unlock(orderChainParams, bridgerNullifierHash, adChainRoot, proof, hex"");

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

        vm.startPrank(bridger);
        orderToken.approve(address(orderPortal), orderAmt);
        bytes32 orderHash = orderPortal.createOrder(orderChainParams);
        assertEq(orderHash, expectedHash);
        vm.stopPrank();

        // Lock order on ad chain
        vm.chainId(adChainId);
        vm.startPrank(maker);
        adManager.lockForOrder(adChainParams);
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

        // verify and fulfill order
        vm.prank(maker);
        orderPortal.unlock(orderChainParams, makerNullifierHash, adChainRoot, proof, hex"");

        vm.prank(maker);
        vm.expectRevert();
        orderPortal.unlock(orderChainParams, makerNullifierHash, adChainRoot, proof, hex"");

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

        vm.startPrank(bridger);
        orderToken.approve(address(orderPortal), orderAmt);
        bytes32 orderHash = orderPortal.createOrder(orderChainParams);
        assertEq(orderHash, expectedHash);
        vm.stopPrank();

        // Get Merkle tree state from ad chain
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = orderChainMerkleManager.fieldMod(orderHash);
        bytes32 orderChainRoot = orderChainMerkleManager.getRoot();

        // Lock order on ad chain
        vm.chainId(adChainId);
        vm.startPrank(maker);
        adManager.lockForOrder(adChainParams);
        vm.stopPrank();

        // Generate proof
        vm.chainId(neutral);
        (, bytes32 bridgerNullifierHash, bytes32 secret) = getNullfierHashes(orderHash);
        (bytes memory proof,) = getProof(leaves, orderHash, bridgerNullifierHash, secret, true);

        vm.chainId(adChainId);

        // Verify and fulfill order
        vm.prank(bridger);
        adManager.unlock(adChainParams, bridgerNullifierHash, orderChainRoot, proof, hex"");

        vm.prank(bridger);
        vm.expectRevert();
        adManager.unlock(adChainParams, bridgerNullifierHash, orderChainRoot, proof, hex"");
    }
}
