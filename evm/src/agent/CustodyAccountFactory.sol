// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IAgentPolicyDirect, ProofBridgeCustodyAccount} from "./ProofBridgeCustodyAccount.sol";

/**
 * @title CustodyAccountFactory
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice Makes makers' custody accounts (plan 45): EIP-1167 clones of one implementation, at an address fixed by
 *         the owner and a salt. The caller is the owner, so nobody can open an account at another owner's address
 *         first, or with targets of their choosing.
 */
contract CustodyAccountFactory {
    address public immutable implementation;
    /// @notice The accounts this factory made: what the relayer and the agent runtime check before treating an
    ///         ad's creator as a custody account.
    mapping(address account => bool) public isAccount;

    event AccountDeployed(address indexed account, address indexed owner, uint256 salt);

    constructor(IAgentPolicyDirect module) {
        implementation = address(new ProofBridgeCustodyAccount(module, address(this)));
    }

    /// @notice The caller's account for `salt`, with the module mounted and `targets` (the escrows) pinned.
    function deploy(uint256 salt, address[] calldata targets) external returns (address account) {
        account = Clones.cloneDeterministic(implementation, _salt(msg.sender, salt));
        isAccount[account] = true;
        ProofBridgeCustodyAccount(payable(account)).initialize(msg.sender, targets);
        emit AccountDeployed(account, msg.sender, salt);
    }

    function predict(address owner, uint256 salt) external view returns (address) {
        return Clones.predictDeterministicAddress(implementation, _salt(owner, salt));
    }

    function _salt(address owner, uint256 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode(owner, salt));
    }
}
