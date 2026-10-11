// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IEscrow} from "src/interfaces/IEscrow.sol";

/// The leg's status alone, from the widened `orders` view (status, timing version).
function statusOf(address escrow, bytes32 orderHash) view returns (IEscrow.Status s) {
    (s,,,) = IEscrow(escrow).orders(orderHash);
}
