// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "forge-std/console2.sol";

import {HonkVerifier, IVerifier} from "src/Verifier.sol";
import {AdManager} from "src/AdManager.sol";
import {OrderPortal} from "src/OrderPortal.sol";
import {IMerkleManager, MerkleManager} from "src/MerkleManager.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {IwNativeToken, wNativeToken} from "src/wNativeToken.sol";

contract DeployProofbridge is Script {
    uint256 constant W_DECIMALS = 18;

    function _envOrAddress(string memory key, address fallback_) internal view returns (address out) {
        try vm.envAddress(key) returns (address v) {
            out = v;
        } catch {
            out = fallback_;
        }
    }

    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");

    function run() external {
        // --- Load deployer ---
        uint256 pk = vm.envUint("PRIVATE_KEY");
        require(pk != 0, "PRIVATE_KEY not set");
        address deployer = vm.addr(pk);

        // --- Choose admin (defaults to deployer, can override via ADMIN env var) ---
        address adminDefault = deployer;
        address admin = _envOrAddress("ADMIN", adminDefault);

        vm.startBroadcast(pk);

        // --- Verifier: reuse or deploy ---
        address verifierMaybe = _envOrAddress("VERIFIER", address(0));
        IVerifier verifier;
        if (verifierMaybe == address(0)) {
            verifier = IVerifier(address(new HonkVerifier()));
            console2.log("Deployed Verifier    :", address(verifier));
        } else {
            verifier = IVerifier(verifierMaybe);
            console2.log("Reusing Verifier     :", address(verifier));
        }

        // // --- MerkleManager: reuse or deploy ---
        address merkleManagerMaybe = _envOrAddress("MERKLE_MANAGER", address(0));

        IMerkleManager merkleManager;

        if (merkleManagerMaybe == address(0)) {
            merkleManager = new MerkleManager(admin);
            console2.log("Deployed MerkleManager    :", address(merkleManager));
        } else {
            merkleManager = IMerkleManager(merkleManagerMaybe);
            console2.log("Reusing MerkleManager    :", address(merkleManager));
        }

        IwNativeToken _wNativeToken;
        address wNativeTokenMaybe = _envOrAddress("WNATIVE_TOKEN", address(0));
        if (wNativeTokenMaybe == address(0)) {
            _wNativeToken = new wNativeToken("Wrapped Native Token", "WNATIVE", W_DECIMALS);
            console2.log("Deployed WNATIVE Token :", address(_wNativeToken), W_DECIMALS);
        } else {
            _wNativeToken = IwNativeToken(wNativeTokenMaybe);
            console2.log("Reusing WNATIVE Token     :", wNativeTokenMaybe);
        }

        // --- Deploy AdManager & OrderPortal ---
        address adManagerMaybe = _envOrAddress("ADMANAGER", address(0));
        if (adManagerMaybe != address(0)) {
            console2.log("Reusing AdManager     :", adManagerMaybe);
        } else {
            AdManager adManager = new AdManager(admin, verifier, merkleManager, _wNativeToken);
            console2.log("Deployed AdManager    :", address(adManager));
            adManagerMaybe = address(adManager);
        }

        address orderPortalMaybe = _envOrAddress("ORDER_PORTAL", address(0));
        if (orderPortalMaybe != address(0)) {
            console2.log("Reusing OrderPortal     :", orderPortalMaybe);
        } else {
            OrderPortal orderPortal = new OrderPortal(admin, verifier, merkleManager, _wNativeToken);
            console2.log("Deployed OrderPortal :", address(orderPortal));
            orderPortalMaybe = address(orderPortal);
        }

        // --- Assign Manager role to deployed contrats ---

        IAccessControl merkleManagerAsAccessControl = IAccessControl(address(merkleManager));
        bytes32 DEFAULT_ADMIN_ROLE = 0x00;
        if (merkleManagerAsAccessControl.hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            console2.log("Granting MANAGER_ROLE to AdManager and OrderPortal");
            merkleManagerAsAccessControl.grantRole(MANAGER_ROLE, adManagerMaybe);
            merkleManagerAsAccessControl.grantRole(MANAGER_ROLE, orderPortalMaybe);
        } else {
            console2.log("WARN: Skipping grantRole: sender lacks DEFAULT_ADMIN_ROLE");
        }

        ERC20Mock testToken = new ERC20Mock();

        console2.log("Deployed TestTOken : ", address(testToken));

        vm.stopBroadcast();
    }
}
