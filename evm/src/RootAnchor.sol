// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IRootAnchor} from "./interfaces/IRootAnchor.sol";
import {TwoStepAdmin} from "./libraries/TwoStepAdmin.sol";

/**
 * @title RootAnchor (Proofbridge)
 * @author Proofbridge
 * @custom:security-contact security@proofbridge.xyz
 * @notice The protocol's authenticator for proofs about facts no counterparty co-signed
 *         (cancellation-proofs §5). A signer set notarizes "the source chain's MMR root was `root`
 *         at ledger `ledgerSeq`"; the anchor becomes usable only `anchorDelay[chainId]` later, so a
 *         fraudulent anchor must survive the watchtower's inspection window before any refund can
 *         cite it. Consumers only ever call {isAnchored}: the writer is swapped up the ladder
 *         (admin key → listener quorum → light client) with {setSigners}, never by redeploying this
 *         module or the escrows. Settlement never touches this — co-signed roots keep their own oracle.
 * @dev Approvals accumulate per authenticated signer up to `threshold` (2.3f D1). Monotonicity is
 *      enforced when a root's first approval fixes its sequence. {isAnchored} is never pausable: it
 *      sits on the refund path, and a pause must not be able to freeze a claim (D4).
 */
contract RootAnchor is IRootAnchor, TwoStepAdmin, Pausable {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Admin role identifier.
    bytes32 public constant ADMIN_ROLE = DEFAULT_ADMIN_ROLE;

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice One notarized root of one source chain.
     * @param ledgerSeq The source-chain ledger / block the root was read at; fixed by the first approval.
     * @param anchoredAt When the threshold was reached; 0 while approvals are still accumulating.
     * @param approvals Distinct signers who approved this (chain, root, ledgerSeq).
     */
    struct Anchor {
        uint64 ledgerSeq;
        uint64 anchoredAt;
        uint32 approvals;
    }

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    mapping(uint256 => mapping(bytes32 => Anchor)) private _anchors;

    /// @notice Whether `signer` has approved `(chainId, root)`; one approval per signer per root.
    mapping(uint256 => mapping(bytes32 => mapping(address => bool))) public approved;

    /// @notice The current notary set. Every ladder rung is a {setSigners} call.
    mapping(address => bool) public isSigner;
    address[] private _signers;

    /// @notice Approvals needed before a root counts as anchored.
    uint32 public threshold;

    /// @notice Seconds after `anchoredAt` before an anchor is usable, per source chain.
    mapping(uint256 => uint64) public anchorDelay;

    /// @notice When true, a new root's `ledgerSeq` must exceed the chain's latest anchored one.
    bool public monotonic = true;

    /// @notice The highest `ledgerSeq` anchored per source chain.
    mapping(uint256 => uint64) public latestSeq;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event AnchorApproved(uint256 indexed chainId, bytes32 indexed root, address indexed signer, uint32 approvals);
    event Anchored(uint256 indexed chainId, bytes32 indexed root, uint64 ledgerSeq, uint64 anchoredAt);
    event SignersSet(address[] signers, uint32 threshold);
    event AnchorDelaySet(uint256 indexed chainId, uint64 delay);
    event MonotonicSet(bool monotonic);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error RootAnchor__ZeroAddress();
    error RootAnchor__NotSigner();
    error RootAnchor__BadThreshold();
    error RootAnchor__DuplicateSigner(address signer);
    error RootAnchor__SeqNotMonotonic(uint64 latest, uint64 given);
    error RootAnchor__SeqMismatch(uint64 pending, uint64 given);

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address admin, address[] memory signers_, uint32 threshold_) {
        if (admin == address(0)) revert RootAnchor__ZeroAddress();
        _initAdmin(admin);
        _setSigners(signers_, threshold_);
    }

    /*//////////////////////////////////////////////////////////////
                             NOTARY: ANCHOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Approve `root` as the source chain's MMR root at `ledgerSeq`. Reaching the threshold
     *         stamps `anchoredAt`; the anchor is usable `anchorDelay[sourceChainId]` later.
     * @dev Re-anchoring an anchored root is a no-op so a retrying publisher never reverts. The first
     *      approval fixes the sequence; later approvals must agree with it.
     */
    function anchor(uint256 sourceChainId, bytes32 root, uint64 ledgerSeq) external whenNotPaused {
        if (!isSigner[msg.sender]) revert RootAnchor__NotSigner();

        Anchor storage a = _anchors[sourceChainId][root];
        if (a.anchoredAt != 0) return;

        if (a.approvals == 0) {
            uint64 latest = latestSeq[sourceChainId];
            if (monotonic && ledgerSeq <= latest) revert RootAnchor__SeqNotMonotonic(latest, ledgerSeq);
            a.ledgerSeq = ledgerSeq;
        } else if (ledgerSeq != a.ledgerSeq) {
            revert RootAnchor__SeqMismatch(a.ledgerSeq, ledgerSeq);
        }

        if (approved[sourceChainId][root][msg.sender]) return;
        approved[sourceChainId][root][msg.sender] = true;
        a.approvals += 1;
        emit AnchorApproved(sourceChainId, root, msg.sender, a.approvals);

        if (a.approvals >= threshold) {
            a.anchoredAt = uint64(block.timestamp);
            if (ledgerSeq > latestSeq[sourceChainId]) latestSeq[sourceChainId] = ledgerSeq;
            emit Anchored(sourceChainId, root, ledgerSeq, a.anchoredAt);
        }
    }

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IRootAnchor
    /// @dev Deliberately not gated by pause (D4).
    function isAnchored(uint256 sourceChainId, bytes32 root) external view returns (bool) {
        Anchor storage a = _anchors[sourceChainId][root];
        return a.anchoredAt != 0 && block.timestamp >= a.anchoredAt + anchorDelay[sourceChainId];
    }

    /// @notice The anchor record, for the watchtower's cross-check against real history.
    function anchorOf(uint256 sourceChainId, bytes32 root) external view returns (Anchor memory) {
        return _anchors[sourceChainId][root];
    }

    function signers() external view returns (address[] memory) {
        return _signers;
    }

    /*//////////////////////////////////////////////////////////////
                                 ADMIN
    //////////////////////////////////////////////////////////////*/

    /// @notice Replace the notary set — the ladder rung (admin key → quorum → light client).
    function setSigners(address[] calldata signers_, uint32 threshold_) external onlyRole(ADMIN_ROLE) {
        _setSigners(signers_, threshold_);
    }

    function setAnchorDelay(uint256 sourceChainId, uint64 delay) external onlyRole(ADMIN_ROLE) {
        anchorDelay[sourceChainId] = delay;
        emit AnchorDelaySet(sourceChainId, delay);
    }

    function setMonotonic(bool monotonic_) external onlyRole(ADMIN_ROLE) {
        monotonic = monotonic_;
        emit MonotonicSet(monotonic_);
    }

    /// @notice Gates {anchor} only; {isAnchored} keeps answering.
    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                               INTERNALS
    //////////////////////////////////////////////////////////////*/

    function _setSigners(address[] memory signers_, uint32 threshold_) private {
        if (threshold_ == 0 || threshold_ > signers_.length) revert RootAnchor__BadThreshold();

        for (uint256 i = 0; i < _signers.length; i++) {
            isSigner[_signers[i]] = false;
        }
        delete _signers;

        for (uint256 i = 0; i < signers_.length; i++) {
            address s = signers_[i];
            if (s == address(0)) revert RootAnchor__ZeroAddress();
            if (isSigner[s]) revert RootAnchor__DuplicateSigner(s);
            isSigner[s] = true;
            _signers.push(s);
        }
        threshold = threshold_;
        emit SignersSet(signers_, threshold_);
    }
}
