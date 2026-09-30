// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Vm} from "forge-std/Vm.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {IBLSKeyRegistry} from "src/interfaces/IBLSKeyRegistry.sol";

/// Test-only: an `ownerAuth` entry of bls-encodings.json (2.6) as the registry's `OwnerAuth`.
library OwnerAuthVectors {
    using stdJson for string;

    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    /// `path` is an entry such as ".ownerAuth.maker.register[0]": legs, then the EVM form of the sig.
    function auth(string memory json, string memory path) internal view returns (IBLSKeyRegistry.OwnerAuth memory a) {
        a.legs = legs(json, path);
        if (keccak256(bytes(json.readString(string.concat(path, ".scheme")))) == keccak256("sep53")) {
            a.scheme = IBLSKeyRegistry.Scheme.Sep53;
            a.sig = json.readBytes(string.concat(path, ".evmSig"));
        } else {
            a.scheme = IBLSKeyRegistry.Scheme.Secp256k1;
            a.sig = json.readBytes(string.concat(path, ".sig"));
        }
    }

    function legs(string memory json, string memory path) internal view returns (IBLSKeyRegistry.KeyLeg[] memory out) {
        uint256 n;
        while (vm.keyExistsJson(json, string.concat(path, ".legs[", vm.toString(n), "]"))) n++;
        out = new IBLSKeyRegistry.KeyLeg[](n);
        for (uint256 i = 0; i < n; i++) {
            string memory l = string.concat(path, ".legs[", vm.toString(i), "]");
            out[i] = IBLSKeyRegistry.KeyLeg(
                vm.parseUint(json.readString(string.concat(l, ".chainId"))),
                json.readBytes32(string.concat(l, ".registry")),
                vm.parseUint(json.readString(string.concat(l, ".nonce")))
            );
        }
    }

    /// `.ownerAuth.<who>.register[i]`, or `registerLate[i]` once the clock reaches `slots.graceTs`:
    /// each family is signed for its own clock (review D2).
    function registerPath(string memory json, string memory who, uint256 i) internal view returns (string memory) {
        bool late = block.timestamp >= vm.parseUint(json.readString(".slots.graceTs"));
        return string.concat(".ownerAuth.", who, late ? ".registerLate[" : ".register[", vm.toString(i), "]");
    }

    /// Moves the clock to the one `register[...]` entries are signed for; returns the clock to
    /// restore, for suites whose registrations are setup, not the subject (review D2).
    function enterRegisterClock(string memory json) internal returns (uint256 prev) {
        prev = block.timestamp;
        vm.warp(vm.parseUint(json.readString(".ownerAuth._meta.deadline.registerChainTime")));
    }

    function restoreClock(uint256 t) internal {
        vm.warp(t);
    }

    /// A RegisterKey entry's deadline (review D2).
    function deadline(string memory json, string memory path) internal pure returns (uint64) {
        return uint64(vm.parseUint(json.readString(string.concat(path, ".deadline"))));
    }

    /// The key fingerprint an entry names (`keyCommitment`).
    function key(string memory json, string memory path) internal pure returns (bytes32) {
        return json.readBytes32(string.concat(path, ".keyCommitment"));
    }
}
