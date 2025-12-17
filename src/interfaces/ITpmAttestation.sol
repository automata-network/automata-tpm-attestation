// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.0;

/// @title Measureable PCR Object
/// @notice This object contains the PCR value, and a list of event traces that
/// can be extended to compute the PCR value.
/// @notice This object also contains a list of log indices to select a sub-set of (or all) events
/// to be included in the final measurement.
/// @notice Generally, when the event indices are provided, the final PCR value
/// to include for measurement should be zero.
/// @custom:security-contact security@ata.network
struct MeasureablePcr {
    // pcr index
    uint256 index;
    // pcr value
    bytes32 pcr;
    // if allEvents.length > 0; extend_sha256(events) = pcr
    bytes32[] allEvents;
    // the index of events wants to measure
    uint256[] measureEventsIdx;
    bool measurePcr;
}

/// @title PCR Object
/// @notice This object represents the intended measurement of a PCR.
/// @notice Applications often use this object to define its golden measurement.
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

import {ICertChainRegistry, CertPubkey} from "./ICertChainRegistry.sol";

/// @title TPMS_CLOCK_INFO structure from TPM quote
/// @notice Can be used by callers for their own replay detection logic
/// @dev To check if a new ClockInfo is fresher than a previous one, compare in this order:
///      1. resetCount: If current > lastSeen, TPM was reset (valid even if clock is smaller)
///      2. restartCount: If current > lastSeen (same resetCount), TPM was restarted (valid)
///      3. clock: If same reset/restart counts, clock must be strictly greater
///      If any counter is less than lastSeen, it indicates rollback (reject).
///      If all values are equal, it indicates replay (reject).
struct ClockInfo {
    uint64 clock; // TPM clock value in milliseconds
    uint32 resetCount; // TPM reset count since manufacture
    uint32 restartCount; // Restart count since last reset
    bool safe; // Whether the TPM clock is in a safe state
}

/// @title Trusted Platform Module (TPM) Onchain Attestation Interface
/// @notice This interface defines the functions for verifying TPM quotes and checking correctness of user data and PCR
/// measurements
/// @notice It extends the ICertChainRegistry to include the ability to configure trusted CA issuers for TPM Attestation
/// Keys
/// @dev IMPORTANT: This contract does NOT include replay protection. Callers MUST implement their own freshness checks.
interface ITpmAttestation is ICertChainRegistry {
    event TpmSignatureVerified(bytes32 indexed tpmQuoteHash);
    event TpmMeasurementChecked(bytes32 indexed tpmQuoteHash, bytes32 pcrDigest, bytes userData);

    /// @notice Verifies a TPM quote using the attestation key certificate chain
    /// @param tpmQuote - The TPM quote to verify
    /// @param tpmSignature - The signature of the TPM quote
    /// @param akCertchain - The attestation key certificate chain
    /// @return success - Whether the verification was successful
    /// @return akPubkey - The Attestation Key abi-encoded in Pubkey type; otherwise the raw bytes of error message
    function verifyTpmQuote(bytes calldata tpmQuote, bytes calldata tpmSignature, bytes[] calldata akCertchain)
        external
        returns (bool, bytes memory);

    /// @notice Verifies a TPM quote using pre-verified / trusted public AK
    /// @dev is responsible for ensuring akPub is trusted (saves gas from verifying the entire cert chain)
    /// @param tpmQuote - The TPM quote to verify
    /// @param tpmSignature - The signature of the TPM quote
    /// @param akPub - A pre-verified attestation public key
    /// @return success - Whether the verification was successful
    /// @return errorMessage - An error message if the verification failed
    function verifyTpmQuoteWithTrustedAkPub(
        bytes calldata tpmQuote,
        bytes calldata tpmSignature,
        CertPubkey calldata akPub
    ) external returns (bool, string memory);

    /// Extracts extra data from the TPM quote
    /// @param tpmQuote - TPM quote
    /// @return success - Whether the extraction was successful
    /// @return extraData - The extracted extra data from the TPM quote, otherwise an error message
    function extractExtraData(bytes calldata tpmQuote) external pure returns (bool success, bytes memory extraData);

    /// @notice Checks the PCR measurements against the TPM quote
    /// @param tpmQuote - The TPM quote to check
    /// @param tpmPcrs - The PCR measurements to validate against the PCR digest in the TPM quote
    /// @return success - Whether the check was successful
    /// @return returnData - if success is true, this returns the extracted user data from the TPM quote
    /// @dev if success is false, returnData will contain an error message
    function checkPcrMeasurements(bytes calldata tpmQuote, MeasureablePcr[] calldata tpmPcrs)
        external
        returns (bool, bytes memory);

    /// @notice Converts Measurable PCRs to the final PCR Measurement format
    /// @param tpmPcrs - The PCR measurements to convert
    /// @return pcrs - The final PCR measurement format
    function toFinalMeasurement(MeasureablePcr[] calldata tpmPcrs) external pure returns (Pcr[] memory);

    /// @notice Extract ClockInfo from TPM quote for caller's own replay protection
    /// @dev Callers are responsible for implementing their own replay logic if needed.
    /// @param tpmQuote - The TPM quote bytes
    /// @return info - The parsed ClockInfo struct including safe flag
    function extractClockInfo(bytes calldata tpmQuote) external pure returns (ClockInfo memory info);
}
