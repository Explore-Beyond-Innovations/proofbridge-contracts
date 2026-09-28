// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {IEscrow} from "src/interfaces/IEscrow.sol";
import {IAdManager} from "src/interfaces/IAdManager.sol";
import {IOrderPortal} from "src/interfaces/IOrderPortal.sol";
import {IMerkleManager} from "src/interfaces/IMerkleManager.sol";
import {MerkleManager} from "src/MerkleManager.sol";
import {Registrar} from "src/Registrar.sol";
import {IRegistrar} from "src/interfaces/IRegistrar.sol";
import {HonkVerifier, BaseHonkVerifier} from "src/Verifier.sol";
import {BLS} from "src/libraries/BLS.sol";
import {DecimalScaling} from "src/libraries/DecimalScaling.sol";
import {AdManagerTest} from "./Admanager.t.sol";
import {OrderPortalTest} from "./OrderPortal.t.sol";
import {Poseidon2Yul_BN254 as Poseidon2Yul} from "@poseidon2/src/bn254/yul/Poseidon2Yul.sol";

/*//////////////////////////////////////////////////////////////
       C-19 — errors no other test named, each triggered here
//////////////////////////////////////////////////////////////*/

/// A token with transfers but no `decimals()`, which EIP-20 allows.
contract NoDecimalsToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract AdManagerErrorCoverageTest is AdManagerTest {
    function test_c19_lockOnAnUnknownAdIsAdNotFound() public {
        test_fundAd_makerOnly();
        IAdManager.OrderParams memory p = _defaultParams("no-such-ad");
        vm.prank(maker);
        vm.expectRevert(IAdManager.AdManager__AdNotFound.selector);
        adManager.lockForOrder(p);
    }

    function test_c19_aReusedAdIdIsUsedAdId() public {
        test_createAd_succeedsWhenRouteExists_emitsAndStores();
        vm.startPrank(maker);
        adToken.approve(address(adManager), initAmt);
        vm.expectRevert(IAdManager.AdManager__UsedAdId.selector);
        adManager.createAd(lastAdId, address(adToken), initAmt, orderChainId, _b32(adRecipient), _b32(maker));
        vm.stopPrank();
    }

    function test_c19_resumeWithoutAHaltIsNotHalted() public {
        vm.prank(maker);
        vm.expectRevert(IAdManager.AdManager__NotHalted.selector);
        adManager.resumeSettlement();
        // Halted, the same call goes through.
        vm.startPrank(maker);
        adManager.haltSettlement();
        adManager.resumeSettlement();
        vm.stopPrank();
    }

    /// No dispute module wired: filing fails closed and the order stays `Open`.
    function test_c19_disputeWithNoModuleIsNoDisputeManager() public {
        test_fundAd_makerOnly();
        (IAdManager.OrderParams memory p, bytes32 h) =
            _openOrder(lastAdId, address(adToken), 60 ether, 1, bridger, recipient);
        vm.prank(maker);
        vm.expectRevert(IEscrow.Escrow__NoDisputeManager.selector);
        adManager.dispute(p, bytes32("evidence"));
        assertEq(uint8(adManager.orders(h)), uint8(IEscrow.Status.Open));
    }

    /// The signed ad-side decimals must match the token's own.
    function test_c19_lockWithTheWrongAdDecimalsIsDecimalsMismatch() public {
        test_fundAd_makerOnly();
        IAdManager.OrderParams memory p = _defaultParams(lastAdId);
        p.adDecimals = 6;
        vm.prank(maker);
        vm.expectRevert(abi.encodeWithSelector(DecimalScaling.DecimalScaling__DecimalsMismatch.selector, 18, 6));
        adManager.lockForOrder(p);
    }

    /// A token without `decimals()` cannot be locked against: the escrow cannot check the scaling.
    function test_c19_lockOnATokenWithNoDecimalsIsDecimalsUnavailable() public {
        NoDecimalsToken bare = new NoDecimalsToken();
        bare.mint(maker, 10 ether);
        vm.startPrank(admin);
        adManager.setPeerEscrow(orderChainId, _b32(orderPortal));
        adManager.setTokenRoute(address(bare), orderChainId, _b32(orderToken));
        vm.stopPrank();
        vm.startPrank(maker);
        bare.approve(address(adManager), 10 ether);
        adManager.createAd("bare", address(bare), 10 ether, orderChainId, _b32(adRecipient), _b32(maker));
        IAdManager.OrderParams memory p = _defaultParams("bare");
        p.adChainToken = _b32(address(bare));
        p.amount = 1 ether;
        vm.expectRevert(
            abi.encodeWithSelector(DecimalScaling.DecimalScaling__DecimalsUnavailable.selector, address(bare))
        );
        adManager.lockForOrder(p);
        vm.stopPrank();
    }

    /// A MerkleManager that answers `false` fails the lock rather than leaving it without a leaf.
    function test_c19_anAppendThatReturnsFalseRevertsTheLock() public {
        test_fundAd_makerOnly();
        IAdManager.OrderParams memory p = _defaultParams(lastAdId);
        vm.mockCall(
            address(merkleManager), abi.encodeWithSelector(IMerkleManager.appendOrderHash.selector), abi.encode(false)
        );
        vm.prank(maker);
        vm.expectRevert(IEscrow.Escrow__MerkleManagerAppendFailed.selector);
        adManager.lockForOrder(p);
    }
}

contract OrderPortalErrorCoverageTest is OrderPortalTest {
    function _wire() internal {
        vm.startPrank(admin);
        portal.setPeerEscrow(adChainId, _b32(adManager));
        portal.setTokenRoute(address(orderToken), adChainId, adToken);
        vm.stopPrank();
    }

    /// Only the bridger named in the order may create it.
    function test_c19_createOrderBySomeoneElseIsBridgerMustBeSender() public {
        _wire();
        IOrderPortal.OrderParams memory p = _defaultParams();
        orderToken.mint(other, p.amount);
        vm.startPrank(other);
        orderToken.approve(address(portal), p.amount);
        vm.expectRevert(IOrderPortal.OrderPortal__BridgerMustBeSender.selector);
        portal.createOrder(p);
        vm.stopPrank();
    }

    function test_c19_createOrderWithTheWrongOrderDecimalsIsDecimalsMismatch() public {
        _wire();
        IOrderPortal.OrderParams memory p = _defaultParams();
        p.orderDecimals = 6;
        vm.startPrank(bridger);
        orderToken.approve(address(portal), p.amount);
        vm.expectRevert(abi.encodeWithSelector(DecimalScaling.DecimalScaling__DecimalsMismatch.selector, 18, 6));
        portal.createOrder(p);
        vm.stopPrank();
    }

    function test_c19_createOrderOnATokenWithNoDecimalsIsDecimalsUnavailable() public {
        NoDecimalsToken bare = new NoDecimalsToken();
        vm.startPrank(admin);
        portal.setPeerEscrow(adChainId, _b32(adManager));
        portal.setTokenRoute(address(bare), adChainId, adToken);
        vm.stopPrank();
        IOrderPortal.OrderParams memory p = _defaultParams();
        p.orderChainToken = _b32(address(bare));
        vm.prank(bridger);
        vm.expectRevert(
            abi.encodeWithSelector(DecimalScaling.DecimalScaling__DecimalsUnavailable.selector, address(bare))
        );
        portal.createOrder(p);
    }
}

/// Calls the BLS library from outside, so a revert inside it can be expected.
contract BLSHarness {
    function verifySingle(bytes memory pk, bytes memory msgG2, bytes memory sig) external view returns (bool) {
        return BLS.verifySingle(pk, msgG2, sig);
    }
}

contract StandaloneErrorCoverageTest is Test {
    function test_c19_merkleManagerRefusesZeroAddresses() public {
        address hasher = address(new Poseidon2Yul());
        vm.expectRevert(MerkleManager.MerkleManager__ZeroAddress.selector);
        new MerkleManager(address(0), hasher);
        vm.expectRevert(MerkleManager.MerkleManager__ZeroAddress.selector);
        new MerkleManager(address(this), address(0));
    }

    function test_c19_registrarRefusesZeroAndAFalseAppend() public {
        vm.expectRevert(IRegistrar.Registrar__ZeroAddress.selector);
        new Registrar(IMerkleManager(address(0)));

        MerkleManager mm = new MerkleManager(address(this), address(new Poseidon2Yul()));
        Registrar registrar = new Registrar(IMerkleManager(address(mm)));
        mm.grantRole(mm.MANAGER_ROLE(), address(registrar));
        vm.mockCall(address(mm), abi.encodeWithSelector(IMerkleManager.appendOrderHash.selector), abi.encode(false));
        bytes32 account = bytes32(uint256(uint160(address(this))));
        vm.expectRevert(IRegistrar.Registrar__AppendFailed.selector);
        registrar.registerLeaf(account, keccak256("pk"), 0, 1, bytes32(uint256(1)), "");
    }

    /// A key that is not a field element makes the pairing precompile fail, and the library says so.
    function test_c19_aMalformedKeyIsBlsPrecompileFailed() public {
        BLSHarness h = new BLSHarness();
        bytes memory junkPk = new bytes(128);
        for (uint256 i = 0; i < 128; i++) {
            junkPk[i] = 0xff;
        }
        vm.expectRevert(BLS.BlsPrecompileFailed.selector);
        h.verifySingle(junkPk, new bytes(256), new bytes(256));
    }

    /*//////////////////// the generated verifier ////////////////////*/

    function _base() internal view returns (bytes memory proof, bytes32[] memory pub) {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), "/../test-vectors/verifier-negative.json"));
        proof = vm.parseJsonBytes(json, ".bases.event.proof");
        pub = vm.parseJsonBytes32Array(json, ".vectors[9].publicInputs");
        assertEq(vm.parseJsonString(json, ".vectors[9].name"), "event/valid", "vector order moved");
    }

    function test_c19_verifierNamesItsLengthErrors() public {
        HonkVerifier v = new HonkVerifier();
        (bytes memory proof, bytes32[] memory pub) = _base();
        assertTrue(v.verify(proof, pub), "the base proof is valid");

        bytes memory short = new bytes(proof.length - 32);
        for (uint256 i = 0; i < short.length; i++) {
            short[i] = proof[i];
        }
        vm.expectRevert(BaseHonkVerifier.ProofLengthWrong.selector);
        v.verify(short, pub);

        bytes32[] memory three = new bytes32[](3);
        for (uint256 i = 0; i < 3; i++) {
            three[i] = pub[i];
        }
        vm.expectRevert(BaseHonkVerifier.PublicInputsLengthWrong.selector);
        v.verify(proof, three);
    }

    /// The final KZG commitment replaced by another valid point from the same proof: the sumcheck
    /// never reads it, so only the Shplemini pairing can refuse it.
    function test_c19_aSwappedFinalCommitmentIsShpleminiFailed() public {
        HonkVerifier v = new HonkVerifier();
        (bytes memory proof, bytes32[] memory pub) = _base();
        uint256 last = proof.length - 128;
        for (uint256 i = 0; i < 128; i++) {
            proof[last + i] = proof[512 + i];
        }
        vm.expectRevert(BaseHonkVerifier.ShpleminiFailed.selector);
        v.verify(proof, pub);
    }
}
