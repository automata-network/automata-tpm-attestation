// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.15;

import {console} from "forge-std/console.sol";
import {P256Configuration} from "./utils/P256Configuration.sol";
import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import "./utils/Salt.sol";

import {TpmAttestation} from "../src/TpmAttestation.sol";

contract Deploy is DeploymentConfig, P256Configuration {
    address owner = vm.envAddress("OWNER");

    modifier broadcast() {
        vm.startBroadcast(owner);
        _;
        vm.stopBroadcast();
    }

    function deployTpmAttestation() public broadcast {
        // deploy the TpmAttestation implementation
        TpmAttestation tpmAttestation = new TpmAttestation{salt: TPM_ATTESTATION_SALT}(owner, simulateVerify());

        console.log("TpmAttestation deployed at:", address(tpmAttestation));

        // write the implementation address to JSON
        writeToJson("TpmAttestation", address(tpmAttestation));
    }
}
