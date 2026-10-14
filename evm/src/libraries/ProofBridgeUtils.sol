// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {DecimalScaling} from "./DecimalScaling.sol";
import {OrderHash} from "./OrderHash.sol";
import {IKeyRegistry} from "../interfaces/IKeyRegistry.sol";
import {IAdManager} from "../interfaces/IAdManager.sol";
import {IEscrow} from "../interfaces/IEscrow.sol";
import {RouteTiming} from "./RouteTiming.sol";
import {Timelock} from "./Timelock.sol";
import {AddressCast} from "./AddressCast.sol";

/// @title ProofBridgeUtils — the one deployed library both escrows link: today the order digest, the
///        width check and the decimal scaling, i.e. what both escrows must agree on about one order,
///        plus the AdManager's settlement-signer gate.
/// @dev EIP-170 headroom: these entry points are `public`, so the escrows DELEGATECALL one copy per
///      chain instead of inlining `DecimalScaling` and `OrderHash`. The logic stays in those two
///      (internal, still inlined into tests and the agent module); this is only the deployed door.
library ProofBridgeUtils {
    function scale(uint256 amount, uint8 fromDec, uint8 toDec) public pure returns (uint256) {
        return DecimalScaling.scale(amount, fromDec, toDec);
    }

    function assertInRange(uint8 decimals) public pure {
        DecimalScaling.assertInRange(decimals);
    }

    function assertMatchesOnChain(address token, uint8 signed) public view {
        DecimalScaling.assertMatchesOnChain(token, signed);
    }

    function checkWidths(uint256 amount, uint256 orderChainId, uint256 adChainId, uint256 deadline) public pure {
        OrderHash.checkWidths(amount, orderChainId, adChainId, deadline);
    }

    function digest(OrderHash.Order memory o) public pure returns (bytes32) {
        return OrderHash.digest(o);
    }

    /// The ad leg's order hash: the canonical 19-field order from its params plus the ad-chain
    /// context, here for EIP-170 headroom.
    function adOrderHash(IAdManager.OrderParams calldata p, uint256 adChainId, address adManager)
        public
        pure
        returns (bytes32)
    {
        return OrderHash.digest(
            OrderHash.Order({
                orderChainToken: p.orderChainToken,
                adChainToken: p.adChainToken,
                amount: p.amount,
                bridger: p.bridger,
                orderChainId: p.orderChainId,
                orderPortal: p.srcOrderPortal,
                orderRecipient: p.orderRecipient,
                adChainId: adChainId,
                adManager: bytes32(uint256(uint160(adManager))),
                adId: p.adId,
                adCreator: p.adCreator,
                adRecipient: p.adRecipient,
                salt: p.salt,
                orderDecimals: p.orderDecimals,
                adDecimals: p.adDecimals,
                deadline: p.deadline,
                adSettlementSigner: p.adSettlementSigner,
                lpFeeBps: p.lpFeeBps,
                protocolFeeBps: p.protocolFeeBps
            })
        );
    }

    /// The AdManager's lock-time rules, cheapest first, the registry read last; here for EIP-170
    /// headroom. `peer` and `routed` are the AdManager's wired peer escrow and token route.
    function validateLock(
        IAdManager.Ad storage ad,
        IAdManager.OrderParams calldata params,
        bytes32 peer,
        bytes32 routed,
        IKeyRegistry registry,
        uint32 signerSlot,
        IAdManager.FeeConfig storage fees,
        address verifier
    ) public view returns (uint256 adAmount) {
        if (!ad.open) revert IAdManager.AdManager__AdClosed();
        // #586: the fee the bridger deposited against is the one live now; a change since the deposit
        // refuses the lock (the trade cancels at no cost) rather than charging a rate nobody agreed to.
        if (params.lpFeeBps != fees.lpBps || params.protocolFeeBps != fees.protocolBps) {
            revert IAdManager.AdManager__FeeMismatch(fees.lpBps, fees.protocolBps);
        }
        if (params.amount == 0) revert IEscrow.Escrow__ZeroAmount();
        if (params.bridger == bytes32(0)) revert IAdManager.AdManager__BridgerZero();
        if (params.orderRecipient == bytes32(0)) revert IAdManager.AdManager__RecipientZero();
        AddressCast.assertEvmAddress(params.orderRecipient);
        DecimalScaling.assertInRange(params.orderDecimals);
        DecimalScaling.assertInRange(params.adDecimals);

        // The peer OrderPortal named in the order must be the one wired for that chain.
        if (peer == bytes32(0)) revert IEscrow.Escrow__ChainNotSupported(params.orderChainId);
        if (peer != params.srcOrderPortal) {
            revert IAdManager.AdManager__OrderPortalMismatch(peer, params.srcOrderPortal);
        }

        // The ad serves exactly one chain and one route, committed at creation and still live.
        if (params.orderChainId != ad.orderChainId) {
            revert IAdManager.AdManager__OrderChainMismatch(ad.orderChainId, params.orderChainId);
        }
        if (params.orderChainToken != ad.orderChainToken) {
            revert IAdManager.AdManager__RouteMismatch(ad.orderChainToken, params.orderChainToken);
        }
        if (routed == bytes32(0)) revert IEscrow.Escrow__MissingRoute(params.orderChainToken, params.orderChainId);
        if (routed != params.orderChainToken) revert IEscrow.Escrow__PeerTokenMismatch(routed, params.orderChainToken);

        // Identity: custody (adCreator == maker) and the settlement identity the ad declared (2.3c).
        // A lock naming any other signer is refused here, not left to the maker's account policy.
        bytes32 maker = AddressCast.toBytes32(ad.maker);
        if (params.adCreator != maker) revert IAdManager.AdManager__NotMaker();
        if (params.adSettlementSigner != ad.settlementSigner) {
            revert IAdManager.AdManager__SettlementSignerMismatch(ad.settlementSigner, params.adSettlementSigner);
        }
        bytes32 token = AddressCast.toBytes32(ad.token);
        if (params.adChainToken != token) revert IAdManager.AdManager__AdTokenMismatch(token, params.adChainToken);
        if (params.adRecipient != ad.adRecipient) {
            revert IAdManager.AdManager__AdRecipientMismatch(ad.adRecipient, params.adRecipient);
        }
        DecimalScaling.assertMatchesOnChain(ad.token, params.adDecimals);
        OrderHash.checkWidths(params.amount, params.orderChainId, block.chainid, params.deadline);

        // A key retired after the ad was pointed at it (setValidUntil, a watchtower retirement) must
        // not take new locks: the bridger's deposit could never be unlocked (2.3c D2). Plan 12 C: the
        // slot the lock pins must be the signer's and usable now, in the registry the order records.
        _requireSettlementSigner(registry, ad.settlementSigner, maker);
        _requireUsableSlot(registry, ad.settlementSigner, signerSlot);

        // #464: no new order while the order chain's verifier reads another key registry.
        (bool split, address verifierRegistry) = registrySplit(verifier, address(registry));
        if (split) {
            revert IAdManager.AdManager__RegistrySplit(params.orderChainId, address(registry), verifierRegistry);
        }
        // The signed amount is in order-chain units; the pool accounts in ad-chain units.
        adAmount = DecimalScaling.scale(params.amount, params.orderDecimals, params.adDecimals);
        if (adAmount > ad.balance - ad.locked) revert IEscrow.Escrow__InsufficientLiquidity();
    }

    /// The AdManager's settlement-signer gate, here for EIP-170 headroom: a registry is wired, the
    /// signer is non-zero with a usable key, and it is the maker itself or has approved the maker.
    function requireSettlementSigner(IKeyRegistry registry, bytes32 signer, bytes32 maker) public view {
        _requireSettlementSigner(registry, signer, maker);
    }

    /// The AdManager's re-pin (2.7 plan 12 D12, Q2), here for EIP-170 headroom: the order is `Open` and
    /// not past `deadline - claimStagger` (its own timing version; the AdManager's own table, since
    /// the ad chain cannot read the OrderPortal's, and the two are linked from one manifest), the
    /// signer's consent in the order's registry (`registryAt[o.registryEpoch]`) names this order and
    /// its current pin, and the new slot is usable now. The pin being left may have expired: the
    /// answer to a leaked key is kill, then re-pin, and the stamp below denies either way. Moves the
    /// pin and stamps the order re-pinned, which the denial rule counts from then on: a re-pin is a
    /// lever the maker's side holds, and it refuses every pair signed under the old pin.
    function repin(
        IEscrow.Order storage o,
        mapping(uint32 => IKeyRegistry) storage registryAt,
        RouteTiming.Timing storage t,
        bytes32 signer,
        bytes32 orderHash,
        uint256 deadline
    ) public {
        IKeyRegistry registry = registryAt[o.registryEpoch];
        uint256 cutoff = deadline - t.claimStagger;
        if (o.status != IEscrow.Status.Open) revert IEscrow.Escrow__OrderNotOpen(orderHash);
        if (block.timestamp > cutoff) revert IEscrow.Escrow__OrderExpired(cutoff);
        uint32 from = o.pinnedSlot;
        (uint32 fromSlot, uint32 to, uint64 nonce) = registry.repinApproval(signer, orderHash);
        if (nonce == 0 || fromSlot != from) revert IAdManager.AdManager__NoRepin(orderHash);
        _requireUsableSlot(registry, signer, to);
        o.pinnedSlot = to;
        o.repinned = true;
        emit IAdManager.OrderRepinned(orderHash, from, to);
    }

    /// #464: does `verifier` verify against a registry other than `expected`? A verifier that does not
    /// answer `registry()` is not a BLS co-signature verifier: no split. No verifier: no split.
    function registrySplit(address verifier, address expected)
        public
        view
        returns (bool split, address verifierRegistry)
    {
        if (verifier == address(0)) return (false, address(0));
        (bool ok, bytes memory ret) = verifier.staticcall(abi.encodeWithSignature("registry()"));
        if (!ok || ret.length != 32) return (false, address(0));
        verifierRegistry = abi.decode(ret, (address));
        split = verifierRegistry != expected;
    }

    /// The denial rule's registry and verifier half (#464, #465, plan 12 C, plan 14 e), here for
    /// EIP-170 headroom: an unwired verifier refuses every co-signed unlock, and one changed after the
    /// order's lock second (`verifierChangedAt`: unset, rewired or repointed) opened a gap that counts
    /// for the rest of the order's life; a re-pinned order is denied for the rest of its life (the
    /// re-pin refused every pair under the old pin, and the slot left behind may be dead); with no
    /// registry wired nothing else denies; a verifier on another registry denies; else the order's
    /// pinned slot expiring at or before `until` denies.
    function registryDenies(
        IKeyRegistry registry,
        address verifier,
        uint64 verifierChangedAt,
        bytes32 signer,
        IEscrow.Order storage o,
        uint256 until
    ) public view returns (bool) {
        if (verifier == address(0) || verifierChangedAt > o.lockedAt || o.repinned) return true;
        if (address(registry) == address(0)) return false;
        (bool split,) = registrySplit(verifier, address(registry));
        if (split) return true;
        uint64 e = registry.expiredAt(signer, o.pinnedSlot);
        return e != 0 && e <= until;
    }

    /// The ceiling on each fee, in bps (1%).
    uint16 internal constant MAX_FEE_BPS = 100;

    /// The fee split on `amount`, each fee rounded down, so the rounding dust stays with the
    /// recipient: `lpFee = amount × lpBps / 10,000`, `protocolFee = amount × protocolBps / 10,000`.
    function splitFee(uint256 amount, uint16 lpBps, uint16 protocolBps)
        public
        pure
        returns (uint256 lpFee, uint256 protocolFee)
    {
        lpFee = amount * lpBps / 10_000;
        protocolFee = amount * protocolBps / 10_000;
    }

    /// The AdManager's `setFeeBps` (EIP-170 headroom): each at most `MAX_FEE_BPS`, and a protocol
    /// fee only with a pool to pay it to (the pool can never be unset again).
    function setFeeBps(IAdManager.FeeConfig storage f, uint16 lpBps, uint16 protocolBps) public {
        if (lpBps > MAX_FEE_BPS || protocolBps > MAX_FEE_BPS || (protocolBps != 0 && f.pool == address(0))) {
            revert IAdManager.AdManager__InvalidFee();
        }
        f.lpBps = lpBps;
        f.protocolBps = protocolBps;
        emit IAdManager.FeeBpsSet(lpBps, protocolBps);
    }

    /// The AdManager's fee on a released lock (EIP-170 headroom), at the bps the bridger deposited
    /// against (in the order, so in its hash): the LP fee stays in the ad's balance, the rest of
    /// `adAmount` leaves it. On a maker forfeit the LP share goes to the bridger instead (the maker
    /// found at fault keeps nothing). Returns the recipient's net and the protocol's fee.
    function chargeFee(
        IAdManager.Ad storage ad,
        IAdManager.OrderParams calldata p,
        bytes32 orderHash,
        uint256 adAmount,
        bool forfeit
    ) public returns (uint256 net, uint256 protocolFee) {
        uint256 lpFee;
        (lpFee, protocolFee) = splitFee(adAmount, forfeit ? 0 : p.lpFeeBps, p.protocolFeeBps);
        ad.balance -= adAmount - lpFee;
        net = adAmount - lpFee - protocolFee;
        emit IAdManager.FeeCharged(orderHash, lpFee, protocolFee);
    }

    /// The escrows' timelock doors (EIP-170 headroom); the rules are `Timelock`'s.
    function timelockActivate(Timelock.State storage s) public {
        Timelock.activate(s);
    }

    function timelockPropose(Timelock.State storage s, bytes calldata data) public {
        Timelock.propose(s, data);
    }

    function timelockCancel(Timelock.State storage s, bytes32 id) public {
        Timelock.cancel(s, id);
    }

    function timelockConsume(Timelock.State storage s, bytes32 id, bytes32 key) public {
        Timelock.consume(s, id, key);
    }

    function timelockEta(Timelock.State storage s, bytes32 id) public view returns (uint256) {
        return Timelock.liveEta(s, id);
    }

    function _requireUsableSlot(IKeyRegistry registry, bytes32 signer, uint32 slot) private view {
        try registry.commitmentAt(signer, slot) returns (bytes32) {}
        catch {
            revert IAdManager.AdManager__SlotNotUsable(signer, slot);
        }
    }

    function _requireSettlementSigner(IKeyRegistry registry, bytes32 signer, bytes32 maker) private view {
        if (address(registry) == address(0)) revert IAdManager.AdManager__NoKeyRegistry();
        if (signer == bytes32(0)) revert IAdManager.AdManager__SettlementSignerZero();
        if (!registry.hasUsableSlot(signer)) revert IAdManager.AdManager__SignerNotRegistered(signer);
        if (signer != maker && !registry.isApprovedMaker(signer, maker)) {
            revert IAdManager.AdManager__SignerNotApproved(signer, maker);
        }
    }
}
