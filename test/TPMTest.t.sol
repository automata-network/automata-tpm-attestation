// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.15;

import "./SetupBase.sol";

contract TPMTest is SetupBase {
    function setUp() public override {
        super.setUp();
    }

    function testTpm() public pure {
        // TODO: you may refer to test cases found at:
        // https://github.com/automata-network/tee-workload-measurement/tree/main/contracts/test
        // to see tests for TpmAttestation
        assertTrue(true);
    }
}
