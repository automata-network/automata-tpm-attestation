// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.0;

struct MeasureablePcr {
    // pcr index
    uint256 index;
    // pcr value, must not be zero
    bytes32 pcr;
    // if allEvents.length > 0; extend_sha256(events) = pcr
    bytes32[] allEvents;
    // the index of events wants to measure
    uint256[] measureEventsIdx;
    bool measurePcr;
}

/// PCR Golden Measurement
struct Pcr {
    // pcr index
    uint256 index;
    // sanity check: require(pcr!=0 || measureEvents.length>0)
    // this value is zero if we don't intend to include PCR value as part of the golden measurement
    bytes32 pcr;
    // the subset of events to measure
    bytes32[] measureEvents;
    // the index of events to measure
    uint256[] measureEventsIdx;
}

import {ICertChainRegistry, Pubkey} from "./ICertChainRegistry.sol";

/**
 * @title Trusted Platform Module (TPM) Onchain Attestation Interface
 * @notice This interface defines the functions for verifying TPM quotes and checking correctness of user data and PCR measurements
 * @notice It extends the ICertChainRegistry to include the ability to configure trusted CA issuers for TPM Attestation Keys
 */
interface ITpmAttestation is ICertChainRegistry {
    /**
     * @notice Verifies a TPM quote
     * @param tpmQuote - The TPM quote to verify
     * @param tpmSignature - The signature of the TPM quote
     * @param akCertchain - The attestation key certificate chain
     * @return success - Whether the verification was successful
     * @return errorMessage - An error message if the verification failed
     */
    function verifyTpmQuote(bytes calldata tpmQuote, bytes calldata tpmSignature, bytes[] calldata akCertchain)
        external
        returns (bool, string memory);

    /**
     * @notice Verifies a TPM quote using pre-verified / trusted public AK
     * @dev is responsible for ensuring akPub is valid (saves gas from verifying the entire cert chain)
     * @param tpmQuote - The TPM quote to verify
     * @param tpmSignature - The signature of the TPM quote
     * @param akPub - A pre-verified attestation public key
     * @return success - Whether the verification was successful
     * @return errorMessage - An error message if the verification failed
     */
    function verifyTpmQuote(bytes calldata tpmQuote, bytes calldata tpmSignature, Pubkey calldata akPub)
        external
        returns (bool, string memory);

    /**
     * Extracts extra data from the TPM quote
     * @param tpmQuote - TPM quote
     * @return success - Whether the extraction was successful
     * @return extraData - The extracted extra data from the TPM quote, otherwise an error message
     */
    function extractExtraData(bytes calldata tpmQuote) external pure returns (bool success, bytes memory extraData);

    /**
     * @notice Checks the PCR measurements against the TPM quote
     * @param tpmQuote - The TPM quote to check
     * @param tpmPcrs - The PCR measurements to validate against the PCR digest in the TPM quote
     * @return success - Whether the check was successful
     * @return returnData - if success is true, this returns the extracted user data from the TPM quote
     * @dev if success is false, returnData will contain an error message
     */
    function checkPcrMeasurements(bytes calldata tpmQuote, MeasureablePcr[] calldata tpmPcrs)
        external
        returns (bool, bytes memory);

    /**
     * @notice Converts the PCR measurements to a golden measurement format
     * @param tpmPcrs - The PCR measurements to convert
     * @return pcrs - The converted PCR measurements in golden measurement format
     */
    function toGoldenMeasurement(MeasureablePcr[] calldata tpmPcrs) external returns (Pcr[] memory);
}
