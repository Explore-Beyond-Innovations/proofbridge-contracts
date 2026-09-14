// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/**
 * @title Termination
 * @notice The claim record behind the one termination primitive (2.3e D1/D9): a `claim*` opens a
 *         presentation window, a `present*` settles the leg by evidence inside it, and an unchallenged
 *         `finalize*` refunds after it. The `entry` tag records which clock opened the window so 2.3g's
 *         dispute entry (and its bond routing) hangs off the same record without restructuring.
 */
library Termination {
    enum ClaimEntry {
        None,
        Deadline,
        Backstop,
        Dispute
    }

    /// @dev One slot: 8 + 8 + 1 bytes.
    struct Claim {
        uint64 openedAt;
        uint64 finalizeAt;
        ClaimEntry entry;
    }
}
