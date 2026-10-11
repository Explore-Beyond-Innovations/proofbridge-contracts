// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/**
 * @title Termination
 * @notice The claim record behind the one termination primitive (2.3e D1/D9): `claimCancel` opens a
 *         presentation window, a `present*` settles the leg by evidence inside it, and an unchallenged
 *         `finalizeCancel` releases the lock after it. Only the primary opens one.
 */
library Termination {
    /// @dev One slot. `finalizeAt` is written once, from the order's own timing version.
    struct Claim {
        uint64 openedAt;
        uint64 finalizeAt;
    }
}
