// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {stdJson} from "forge-std/StdJson.sol";
import {BLS} from "src/libraries/BLS.sol";
import {CounterpartyVerifier} from "src/CounterpartyVerifier.sol";

/// Test-only: co-signs a `SettlementAuth` with the vector parties' BLS secret keys, so a fixture can
/// settle an order whose hash the vector never signed (#433 binds the co-signature to the order).
library CoSign {
    address internal constant G2_ADD = address(0x0d);
    address internal constant G2_MSM = address(0x0e);
    bytes32 internal constant SETTLE_TAG = keccak256("ProofBridge.Settlement.v1");
    string internal constant DST_SIG = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    /// The message point both parties sign: the same preimage `CounterpartyVerifier` verifies.
    function messagePoint(CounterpartyVerifier.SettlementAuth memory a) internal view returns (bytes memory) {
        bytes memory preimage = bytes.concat(
            SETTLE_TAG, bytes32(a.orderChainId), bytes32(a.adChainId), a.orderHash, a.orderChainRoot, a.adChainRoot
        );
        return BLS.hashToG2(preimage, bytes(DST_SIG));
    }

    /// sk · H(m) on G2 via the EIP-2537 MSM precompile.
    function sign(bytes memory msgPoint, uint256 sk) internal view returns (bytes memory sig) {
        (bool ok, bytes memory out) = G2_MSM.staticcall(bytes.concat(msgPoint, bytes32(sk)));
        require(ok && out.length == 256, "CoSign: G2 MSM");
        return out;
    }

    function add(bytes memory p, bytes memory q) internal view returns (bytes memory) {
        (bool ok, bytes memory out) = G2_ADD.staticcall(bytes.concat(p, q));
        require(ok && out.length == 256, "CoSign: G2 add");
        return out;
    }

    /// Both vector parties' aggregate signature over `a`.
    function aggregate(string memory vjson, CounterpartyVerifier.SettlementAuth memory a)
        internal
        view
        returns (bytes memory)
    {
        bytes memory h = messagePoint(a);
        return add(
            sign(h, uint256(stdJson.readBytes32(vjson, ".keys.makerBls.sk"))),
            sign(h, uint256(stdJson.readBytes32(vjson, ".keys.bridgerBls.sk")))
        );
    }

    /// The vector's auth with `orderHash` swapped in: same chains, same roots.
    function authFor(string memory vjson, bytes32 orderHash)
        internal
        pure
        returns (CounterpartyVerifier.SettlementAuth memory)
    {
        return CounterpartyVerifier.SettlementAuth({
            orderChainId: stdJson.readUint(vjson, ".settlement.auth.orderChainId"),
            adChainId: stdJson.readUint(vjson, ".settlement.auth.adChainId"),
            orderHash: orderHash,
            orderChainRoot: stdJson.readBytes32(vjson, ".settlement.auth.orderChainRoot"),
            adChainRoot: stdJson.readBytes32(vjson, ".settlement.auth.adChainRoot")
        });
    }

    /// Module data v2, both settlement keys in slot 0, co-signed over `orderHash`.
    function moduleDataFor(string memory vjson, bytes32 orderHash) internal view returns (bytes memory) {
        CounterpartyVerifier.SettlementAuth memory a = authFor(vjson, orderHash);
        return abi.encode(
            uint8(2),
            a,
            uint32(0),
            uint32(0),
            stdJson.readBytes(vjson, ".keys.makerBls.pk.eip2537"),
            stdJson.readBytes(vjson, ".keys.bridgerBls.pk.eip2537"),
            aggregate(vjson, a)
        );
    }
}
