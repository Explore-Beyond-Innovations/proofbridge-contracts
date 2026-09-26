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
 *         cite it — and the admin can {revokeAnchor} what the watchtower catches, during the delay
 *         or after. Consumers only ever call {isAnchored}: the writer is swapped up the ladder
 *         (admin key → listener quorum → light client) with {setSigners}, never by redeploying this
 *         module or the escrows. Settlement never touches this — co-signed roots keep their own oracle.
 * @dev Approvals accumulate per authenticated signer up to `threshold` (2.3f D1) and count only under
 *      the current signer set and the root's current generation, so rotating a compromised notary
 *      out or revoking a root discards its work. Any ledger sequence is accepted for a pending root
 *      and the highest is recorded (independent publishers read a quiet chain's root at different
 *      ledgers); monotonicity is checked at the first approval and again when the threshold is
 *      reached. {isAnchored} is never pausable: it sits on the refund path, and a pause must not be
 *      able to freeze a claim (D4). The delay is read at query time, so lowering it un-delays anchored
 *      roots retroactively — an admin power, deliberately.
 */
contract RootAnchor is IRootAnchor, TwoStepAdmin, Pausable {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Upper bound on a route's delay: keeps {isAnchored} arithmetic trivially safe and an
    ///         incident stopgap from becoming a silent brick. 7 days (#453): the escrows' evidence grace
    ///         adds it to the route buffer, and the sum must stay inside the key registry's 30-day
    ///         memory of a dead slot.
    uint64 public constant MAX_ANCHOR_DELAY = 7 days;

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    mapping(uint256 => mapping(bytes32 => Anchor)) private _anchors;

    /// @dev (setEpoch << 32 | gen) at the time `signer` approved `(chainId, root)`; counts iff it matches now.
    mapping(uint256 => mapping(bytes32 => mapping(address => uint64))) private _approvalStamp;

    /// @notice The current notary set. Every ladder rung is a {setSigners} call.
    mapping(address => bool) public isSigner;
    address[] private _signers;

    /// @notice Approvals needed before a root counts as anchored.
    uint32 public threshold;

    /// @notice Bumped on every {setSigners}; approvals from an earlier epoch do not count.
    uint32 public signerSetEpoch;

    /// @notice Seconds after `anchoredAt` before an anchor is usable, per source chain.
    mapping(uint256 => uint64) public anchorDelay;

    /// @notice When true, a new root's `ledgerSeq` must exceed the chain's latest anchored one.
    bool public monotonic = true;

    /// @notice The highest `ledgerSeq` anchored per source chain; admin-resettable after an incident.
    mapping(uint256 => uint64) public latestSeq;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

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
     * @dev Re-anchoring an anchored root is a no-op so a retrying publisher never reverts. A repeat
     *      approval by the same signer adds nothing but still evaluates the threshold, so a lowered
     *      threshold can complete a pending root.
     */
    function anchor(uint256 sourceChainId, bytes32 root, uint64 ledgerSeq) external whenNotPaused {
        if (!isSigner[msg.sender]) revert RootAnchor__NotSigner();

        Anchor storage a = _anchors[sourceChainId][root];
        if (a.anchoredAt != 0) return;

        // Approvals from an earlier signer set do not carry over (A1).
        if (a.setEpoch != signerSetEpoch) {
            a.setEpoch = signerSetEpoch;
            a.approvals = 0;
        }

        uint64 latest = latestSeq[sourceChainId];
        if (a.approvals == 0) {
            if (monotonic && ledgerSeq <= latest) revert RootAnchor__SeqNotMonotonic(latest, ledgerSeq);
            a.ledgerSeq = ledgerSeq;
        } else if (ledgerSeq > a.ledgerSeq) {
            // Independent publishers read the same root at different ledgers on a quiet chain (A6).
            a.ledgerSeq = ledgerSeq;
        }

        uint64 stamp = _stamp(a.setEpoch, a.gen);
        if (_approvalStamp[sourceChainId][root][msg.sender] != stamp) {
            _approvalStamp[sourceChainId][root][msg.sender] = stamp;
            a.approvals += 1;
            emit AnchorApproved(sourceChainId, root, msg.sender, a.approvals);
        }

        if (a.approvals >= threshold) {
            // A newer root may have anchored while this one was pending (A2).
            if (monotonic && a.ledgerSeq <= latest) revert RootAnchor__SeqNotMonotonic(latest, a.ledgerSeq);
            a.anchoredAt = uint64(block.timestamp);
            if (a.ledgerSeq > latest) latestSeq[sourceChainId] = a.ledgerSeq;
            emit Anchored(sourceChainId, root, a.ledgerSeq, a.anchoredAt);
        }
    }

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IRootAnchor
    /// @dev Deliberately not gated by pause (D4), and can never revert: the delay is bounded and the
    ///      age is computed by subtraction.
    function isAnchored(uint256 sourceChainId, bytes32 root) external view returns (bool) {
        Anchor storage a = _anchors[sourceChainId][root];
        if (a.anchoredAt == 0 || block.timestamp < a.anchoredAt) return false;
        return block.timestamp - a.anchoredAt >= anchorDelay[sourceChainId];
    }

    /// @inheritdoc IRootAnchor
    function anchoredAt(uint256 sourceChainId, bytes32 root) external view returns (uint64) {
        return _anchors[sourceChainId][root].anchoredAt;
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

    /// @notice Replace the notary set — the ladder rung (admin key → quorum → light client). Pending
    ///         approvals from the previous set stop counting.
    function setSigners(address[] calldata signers_, uint32 threshold_) external onlyAdmin {
        _setSigners(signers_, threshold_);
    }

    /**
     * @notice Discard a root's record — the response to an anchor the watchtower proves absent from
     *         real history, usable during the delay or after. Its approvals never count again; a fresh
     *         anchoring needs a fresh threshold. `latestSeq` is left for {resetLatestSeq}.
     */
    function revokeAnchor(uint256 sourceChainId, bytes32 root) external onlyAdmin {
        Anchor storage a = _anchors[sourceChainId][root];
        if (a.approvals == 0 && a.anchoredAt == 0) revert RootAnchor__NoSuchAnchor();
        a.gen += 1;
        a.approvals = 0;
        a.anchoredAt = 0;
        a.ledgerSeq = 0;
        emit AnchorRevoked(sourceChainId, root, a.gen);
    }

    /// @notice Recover a route whose sequence was pinned wrongly (a buggy or compromised publisher).
    function resetLatestSeq(uint256 sourceChainId, uint64 seq) external onlyAdmin {
        latestSeq[sourceChainId] = seq;
        emit LatestSeqReset(sourceChainId, seq);
    }

    function setAnchorDelay(uint256 sourceChainId, uint64 delay) external onlyAdmin {
        if (delay > MAX_ANCHOR_DELAY) revert RootAnchor__DelayTooLong(MAX_ANCHOR_DELAY, delay);
        anchorDelay[sourceChainId] = delay;
        emit AnchorDelaySet(sourceChainId, delay);
    }

    function setMonotonic(bool monotonic_) external onlyAdmin {
        monotonic = monotonic_;
        emit MonotonicSet(monotonic_);
    }

    /// @notice Gates {anchor} only; {isAnchored} keeps answering.
    function pause() external onlyAdmin {
        _pause();
    }

    function unpause() external onlyAdmin {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                               INTERNALS
    //////////////////////////////////////////////////////////////*/

    function _stamp(uint32 setEpoch, uint32 gen) private pure returns (uint64) {
        return (uint64(setEpoch) << 32) | uint64(gen);
    }

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
        signerSetEpoch += 1;
        emit SignersSet(signers_, threshold_, signerSetEpoch);
    }
}
