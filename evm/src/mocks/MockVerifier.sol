// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IVerifier} from "../Verifier.sol";

contract MockVerifier is IVerifier {
    bool public pass;

    constructor(bool _pass) {
        pass = _pass;
    }

    function setResult(bool _pass) external {
        pass = _pass;
    }

    function verify(bytes calldata, bytes32[] calldata) external view returns (bool) {
        return pass;
    }
}
