// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {IMerkleManager} from "./MerkleManager.sol";
import {AddressCast} from "./libraries/AddressCast.sol";
import {LeafDomain} from "./libraries/LeafDomain.sol";

/**
 * @title Registrar (Proofbridge)
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice The home-chain half of proof-carried registration (2.1b, contracts/proof-carried-registration).
 *         A keyless account (a Safe, a 4337 wallet) cannot sign a registration for the other chain,
 *         so it approves one *here*, under its own authorization, and the registrar appends a
 *         `REGISTERED` leaf to the home MMR. The foreign registry then accepts the key on an
 *         inclusion proof of that leaf against an anchored home-chain root. Nothing consumes the
 *         leaves until the registry's flag is turned on (T3).
 * @dev Authorization is the account's own: a direct call (`msg.sender` is the account, so its auth
 *      logic already ran) or a signature over the EIP-712 `RegistrationLeaf` — EIP-1271 for a
 *      contract account, ecrecover for an EOA. The subject is `keccak256(account32 ‖ blsCommitment ‖
 *      epoch)` with `epoch` as 8 big-endian bytes, so both chains hash identical bytes.
 */
contract Registrar is EIP712 {
    using AddressCast for address;
    using AddressCast for bytes32;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant REGISTRATION_LEAF_TYPEHASH =
        keccak256("RegistrationLeaf(bytes32 account32,bytes32 blsCommitment,uint64 epoch)");

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice The home chain's MMR; the registrar holds its `MANAGER_ROLE`.
    IMerkleManager public immutable i_merkleManager;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event RegistrationLeaf(bytes32 indexed account32, bytes32 indexed blsCommitment, uint64 epoch, bytes32 subject);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error Registrar__ZeroAddress();
    error Registrar__NotAccount();
    error Registrar__BadAuth();
    error Registrar__AppendFailed();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(IMerkleManager merkleManager) EIP712("ProofBridge Registrar", "1") {
        if (address(merkleManager) == address(0)) revert Registrar__ZeroAddress();
        i_merkleManager = merkleManager;
    }

    /*//////////////////////////////////////////////////////////////
                                REGISTER
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Append the registration leaf for `account32` after the account's own authorization.
     * @param sig Empty for a direct call by the account; otherwise an EIP-712 signature over
     *        {leafDigest} — EIP-1271 for a contract account, ecrecover for an EOA.
     * @return subject The leaf's subject, `keccak256(account32 ‖ blsCommitment ‖ epoch)`.
     */
    function registerLeaf(bytes32 account32, bytes32 blsCommitment, uint64 epoch, bytes calldata sig)
        external
        returns (bytes32 subject)
    {
        if (sig.length == 0) {
            if (msg.sender.toBytes32() != account32) revert Registrar__NotAccount();
        } else {
            address account = account32.toAddressChecked();
            if (!SignatureChecker.isValidSignatureNow(account, leafDigest(account32, blsCommitment, epoch), sig)) {
                revert Registrar__BadAuth();
            }
        }

        subject = subjectOf(account32, blsCommitment, epoch);
        if (!i_merkleManager.appendOrderHash(subject, LeafDomain.REGISTERED)) revert Registrar__AppendFailed();
        emit RegistrationLeaf(account32, blsCommitment, epoch, subject);
    }

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @notice The leaf subject both chains derive: 32 + 32 + 8 bytes, `epoch` big-endian.
    function subjectOf(bytes32 account32, bytes32 blsCommitment, uint64 epoch) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(account32, blsCommitment, epoch));
    }

    /// @notice The EIP-712 digest a relayed registration signs.
    function leafDigest(bytes32 account32, bytes32 blsCommitment, uint64 epoch) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(REGISTRATION_LEAF_TYPEHASH, account32, blsCommitment, epoch)));
    }
}
