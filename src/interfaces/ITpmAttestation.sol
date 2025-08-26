// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.0;

/**
 * @title Measureable PCR Object
 * @notice This object contains the PCR value, and a list of event traces that
 * can be extended to compute the PCR value.
 * @notice This object also contains a list of log indices to select a sub-set of (or all) events
 * to be included in the final measurement.
 * @notice Generally, when the event indices are provided, the final PCR value
 * to include for measurement should be zero.
 */
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

/**
 * @title PCR Object
 * @notice This object represents the intended measurement of a PCR.
 * @notice Applications often use this object to define its golden measurement.
 */
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
     * @notice Verifies a TPM quote using the attestation key certificate chain
     * @param tpmQuote - The TPM quote to verify
     * @param tpmSignature - The signature of the TPM quote
     * @param akCertchain - The attestation key certificate chain
     * @return success - Whether the verification was successful
     * @return akPubkey - The Attestation Key abi-encoded in Pubkey type; otherwise the raw bytes of error message
     */
    function verifyTpmQuote(bytes calldata tpmQuote, bytes calldata tpmSignature, bytes[] calldata akCertchain)
        external
        returns (bool, bytes memory);

    /**
     * @notice Verifies a TPM quote using pre-verified / trusted public AK
     * @dev is responsible for ensuring akPub is trusted (saves gas from verifying the entire cert chain)
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
     * @notice Converts Measurable PCRs to the final PCR Measurement format
     * @param tpmPcrs - The PCR measurements to convert
     * @return pcrs - The final PCR measurement format
     */
    function toFinalMeasurement(MeasureablePcr[] calldata tpmPcrs) external returns (Pcr[] memory);
}
