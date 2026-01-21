// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.27;

import {ITpmAttestation, MeasureablePcr, Pcr} from "./interfaces/ITpmAttestation.sol";
import {CertPubkey, SignatureAlgorithm, LibX509} from "./lib/LibX509.sol";
import {LibX509Verify} from "./lib/LibX509Verify.sol";
import {LibTpm} from "./lib/LibTpm.sol";
import {TPMConstants} from "./types/TPMConstants.sol";
import {CertChainRegistry} from "./bases/CertChainRegistry.sol";
import {
    InvalidCertChainLength,
    InvalidCertificateChain,
    TpmQuoteTooShort,
    InvalidTpmAttType,
    InvalidTpmMagic,
    InvalidTpmsPcrCount,
    InvalidEcdsaSignature,
    InvalidSignature,
    TpmSignatureVerificationFailed,
    CertifiedNameMismatch,
    ExtraDataMismatch,
    PcrDigestMismatch,
    InvalidPcrDigestSize,
    UnsupportedHashAlgorithm,
    PcrSelectionMismatch,
    InvalidPcrEvents,
    InvalidPcrEventIndex,
    TpmSignatureTooShort,
    InvalidRsaSignatureSize,
    PcrIndexOutOfRange
} from "./types/Errors.sol";

/// @title TpmAttestation
/// @notice Verifies TPM 2.0 quotes and their certificate chains for TEE workload attestation
/// @dev This contract handles TPM quote verification including:
///      - Certificate chain verification for Attestation Key (AK) certificates
///      - TPM quote signature verification using RSA or ECDSA
///      - PCR (Platform Configuration Register) measurement validation
///
///      TPM Quote Layout:
///      =================
///      magic: [0..4]
///      att_type: [4..6] - Must be 0x8018 for TPM2_ST_ATTEST_QUOTE
///      qualified_signer_len: [6..8]
///      qualified_signer: [8..8+qualified_signer_len]
///      extra_data_len: [8+qualified_signer_len..10+qualified_signer_len]
///      extra_data: [10+qualified_signer_len..10+qualified_signer_len+extra_data_len]
///      clock_info: [10+qualified_signer_len+extra_data_len..27+qualified_signer_len+extra_data_len]
///      firmware_version: [27+qualified_signer_len+extra_data_len..35+qualified_signer_len+extra_data_len]
///      TPMSQuoteInfo (if att_type == 0x8018):
///        count: 4 bytes (must be 1)
///        pcr_selections: TPMSPCRSelection array
///          hash: 2 bytes (algorithm ID, e.g., TPM_ALG_SHA256)
///          pcr_size: 1 byte
///          pcrs: pcr_size bytes (PCR selection bitmap)
///        pcr_digest_size: 2 bytes
///        pcr_digest: pcr_digest_size bytes
///
/// @custom:security-contact security@ata.network
/// @custom:security PCR values are critical for workload integrity verification.
///                  The contract validates that provided PCR values match the digest in the quote.
contract TpmAttestation is CertChainRegistry, ITpmAttestation {
    using LibX509Verify for CertPubkey;

    constructor(address _intitialOwner, address _p256) CertChainRegistry(_intitialOwner, _p256) {}

    /// @notice Verifies TPM quote signature and certificate chain
    /// @dev IMPORTANT: This function does NOT include replay protection.
    ///       Callers MUST implement their own freshness checks, for example:
    ///       - Include block number/hash in extraData
    ///       - Validate extraData contains recent block reference
    /// @param tpmQuote The TPM quote bytes
    /// @param tpmSignature The TPM signature bytes
    /// @param akCertchain Array of DER-encoded certificates [leaf, intermediate..., root]
    /// @return success Whether the verification succeeded
    /// @return akPubEncoded ABI-encoded CertPubkey of the attestation key
    function verifyTpmQuote(bytes calldata tpmQuote, bytes calldata tpmSignature, bytes[] calldata akCertchain)
        external
        override
        returns (bool, bytes memory)
    {
        require(akCertchain.length > 0, InvalidCertChainLength());

        CertPubkey memory akPub = verifyCertChain(akCertchain);
        require(akPub.data.length > 0, InvalidCertificateChain());

        _verifyTpmQuote(tpmQuote, tpmSignature, akPub);
        return (true, abi.encode(akPub));
    }

    /// @notice Verifies a TPM quote using a pre-trusted attestation key public key
    /// @dev Skips certificate chain verification since the AK public key is already trusted.
    ///      This is used when the AK public key was previously verified or is embedded in TEE report data.
    /// @dev IMPORTANT: This function does NOT include replay protection.
    ///       Callers MUST implement their own freshness checks.
    /// @param tpmQuote The raw TPM quote data structure (TPMS_ATTEST)
    /// @param tpmSignature The TPM signature over the quote (TPMT_SIGNATURE)
    /// @param akPub The pre-trusted attestation key public key
    /// @return success True if verification succeeded
    /// @return errorMessage Empty string on success, error description on failure
    function verifyTpmQuoteWithTrustedAkPub(
        bytes calldata tpmQuote,
        bytes calldata tpmSignature,
        CertPubkey calldata akPub
    ) external override returns (bool, string memory) {
        _verifyTpmQuote(tpmQuote, tpmSignature, akPub);
        return (true, "");
    }

    /// @notice Validates PCR measurements in a TPM quote against expected values
    /// @dev Performs the following validations:
    ///      1. Parses the TPM quote structure to extract PCR selection and digest
    ///      2. Verifies the hash algorithm is SHA-256 (TPM_ALG_SHA256)
    ///      3. Checks that provided PCR indices match the selection bitmap in the quote
    ///      4. Computes the expected PCR digest from provided values and compares with quote
    ///
    ///      PCR values can be provided directly or reconstructed from event logs.
    ///      If a PCR value is zero and events are provided, the value is calculated
    ///      by extending the events into an initially-zero register.
    ///
    /// @param tpmQuote The raw TPM quote data structure (TPMS_ATTEST)
    /// @param tpmPcrs Array of PCR measurements to validate, including indices and values
    /// @return success True if all PCR measurements match
    /// @return extraData The extra data field extracted from the quote
    /// @custom:security Critical for workload integrity - ensures the TPM measured expected values
    function checkPcrMeasurements(bytes calldata tpmQuote, MeasureablePcr[] calldata tpmPcrs)
        external
        override
        returns (bool, bytes memory extraData)
    {
        uint256 offset;
        {
            uint16 qualifiedSignerLen;
            uint16 extraDataLen;
            (qualifiedSignerLen, extraDataLen, extraData) =
                LibTpm.parseAttestHeaders(tpmQuote, TPMConstants.TPM_ST_ATTEST_QUOTE);
            offset = 35 + qualifiedSignerLen + extraDataLen;
        }

        // Upfront check for minimum fixed-size fields: 4 (count) + 2 (hash) + 1 (size)
        require(tpmQuote.length >= offset + 7, TpmQuoteTooShort());

        uint32 tpmsPCRCount = uint32(bytes4(tpmQuote[offset:offset + 4]));
        require(tpmsPCRCount == 1, InvalidTpmsPcrCount());
        offset += 4;

        uint16 tpmPcrHash = uint16(bytes2(tpmQuote[offset:offset + 2]));
        require(tpmPcrHash == TPMConstants.TPM_ALG_SHA256, UnsupportedHashAlgorithm());
        offset += 2;

        uint8 pcrsSize = uint8(tpmQuote[offset]);
        offset += 1;

        // Check for remaining data: pcrsSize + 2 (digest size field) + 32 (digest bytes)
        require(tpmQuote.length >= offset + pcrsSize + 34, TpmQuoteTooShort());

        bytes4 pcrSelection = bytes4(tpmQuote[offset:offset + pcrsSize]);
        require(pcrSelection == _compactSelections(tpmPcrs), PcrSelectionMismatch());
        offset += pcrsSize;

        uint16 pcrDigestSize = uint16(bytes2(tpmQuote[offset:offset + 2]));
        require(pcrDigestSize == 32, InvalidPcrDigestSize());
        offset += 2;
        bytes32 pcrDigest = bytes32(tpmQuote[offset:offset + pcrDigestSize]);
        bytes32 expectedDigest = _digest(tpmPcrs);
        require(pcrDigest == expectedDigest, PcrDigestMismatch());

        emit TpmMeasurementChecked(keccak256(tpmQuote), pcrDigest, extraData);

        return (true, extraData);
    }

    /// @notice Converts MeasureablePcr array to final Pcr measurements for workload identification
    /// @dev Filters PCR data based on measureEventsIdx to include only the events that should
    ///      be part of the final measurement. This allows selective measurement of specific
    ///      boot events while ignoring transient or non-deterministic values.
    ///
    ///      For each MeasureablePcr:
    ///      - If measurePcr is true, the raw PCR value is included
    ///      - measureEventsIdx specifies which events from allEvents to include
    ///      - Events are verified to match the calculated PCR value
    ///
    /// @param mpcrs Array of MeasureablePcr containing raw PCR values and event logs
    /// @return Array of Pcr structs with filtered measurements for golden measurement comparison
    function toFinalMeasurement(MeasureablePcr[] calldata mpcrs) external pure override returns (Pcr[] memory) {
        // Cache array length to avoid multiple storage reads
        uint256 mpcrsLength = mpcrs.length;
        Pcr[] memory pcrs = new Pcr[](mpcrsLength);

        // Use unchecked to save gas on bounds checking where we know it's safe
        unchecked {
            for (uint256 i = 0; i < mpcrsLength; i++) {
                // Cache the current MeasureablePcr to avoid multiple calldata accesses
                MeasureablePcr calldata currentMpcr = mpcrs[i];

                // Verify events before allocating memory for arrays
                require(_verifyEvents(currentMpcr), InvalidPcrEvents());

                // Cache the measureEventsIdx length
                uint256 eventsIdxLength = currentMpcr.measureEventsIdx.length;

                // Only allocate memory if there are events to process
                bytes32[] memory measureEvents = new bytes32[](eventsIdxLength);
                uint256[] memory measureEventsIdx = new uint256[](eventsIdxLength);

                // Process events only if there are any
                if (eventsIdxLength > 0) {
                    uint256 allEventsLength = currentMpcr.allEvents.length;

                    for (uint256 j = 0; j < eventsIdxLength; j++) {
                        uint256 eventIdx = currentMpcr.measureEventsIdx[j];
                        require(eventIdx < allEventsLength, InvalidPcrEventIndex());
                        measureEvents[j] = currentMpcr.allEvents[eventIdx];
                        measureEventsIdx[j] = eventIdx;
                    }
                }

                // Create the PCR with the correct values
                pcrs[i] = Pcr({
                    index: currentMpcr.index,
                    pcr: currentMpcr.measurePcr ? currentMpcr.pcr : bytes32(0),
                    measureEvents: measureEvents,
                    measureEventsIdx: measureEventsIdx
                });
            }
        }

        return pcrs;
    }

    function verifyTpmKeyCertification(
        bytes calldata certifyInfo,
        bytes calldata akSignature,
        bytes calldata tpmtPublic,
        CertPubkey calldata akPub,
        bytes calldata expectedExtraData
    ) external view override returns (CertPubkey memory certifiedPubkey) {
        // Step 1: Parse and verify AK signature over certifyInfo
        (SignatureAlgorithm memory akSigAlgo, bytes memory sig) = LibTpm.parseTpmSignature(akSignature);
        address verifier = akSigAlgo.scheme == TPMConstants.TPM_ALG_ECDSA ? p256 : address(0);
        require(akPub.verifySignature(akSigAlgo, certifyInfo, sig, verifier), TpmSignatureVerificationFailed());

        // Step 2: Parse certifyInfo and extract fields
        (bytes memory extraData, bytes memory certifiedName) = LibTpm.parseCertifyInfo(certifyInfo);

        // Step 3: Compare KEY_NAME
        bytes memory expectedName = LibTpm.computeKeyName(tpmtPublic);
        require(keccak256(certifiedName) == keccak256(expectedName), CertifiedNameMismatch());

        // Step 4: Validate extraData if provided
        if (expectedExtraData.length != 0) {
            require(keccak256(extraData) == keccak256(expectedExtraData), ExtraDataMismatch());
        }

        // Step 5: Extract and return certified public key
        certifiedPubkey = LibTpm.extractCertPubkey(tpmtPublic);
    }

    function _verifyTpmQuote(bytes calldata tpmQuote, bytes calldata tpmSignature, CertPubkey memory akPub) private {
        // Use library function for signature parsing (fixes ECDSA length bug: 40 -> 72)
        (SignatureAlgorithm memory sigAlgo, bytes memory sig) = LibTpm.parseTpmSignature(tpmSignature);

        // Validate hash algorithm is SHA256
        require(sigAlgo.hashAlgo == TPMConstants.TPM_ALG_SHA256, UnsupportedHashAlgorithm());

        address verifier = sigAlgo.scheme == TPMConstants.TPM_ALG_ECDSA ? p256 : address(0);
        bool result = akPub.verifySignature(sigAlgo, tpmQuote, sig, verifier);

        require(result, TpmSignatureVerificationFailed());

        emit TpmSignatureVerified(keccak256(tpmQuote));
    }

    function _compactSelections(MeasureablePcr[] calldata tpmPcrs) private pure returns (bytes4) {
        // Use a single uint32 instead of an array to reduce memory operations
        uint32 bitmap;
        uint256 len = tpmPcrs.length;

        // Cache array length and use unchecked for loop operations to save gas
        unchecked {
            for (uint256 i = 0; i < len && i < 32; i++) {
                uint256 idx = tpmPcrs[i].index;
                // Enforce that PCR index is within valid range for 32-bit bitmap
                require(idx < 32, PcrIndexOutOfRange());
                // Set bit directly in the bitmap using a single operation
                bitmap |= uint32(1 << idx);
            }
        }

        // Convert to bytes4 in a single operation
        return bytes4(
            ((bitmap & 0xFF000000) >> 24) | ((bitmap & 0x00FF0000) >> 8) | ((bitmap & 0x0000FF00) << 8)
                | ((bitmap & 0x000000FF) << 24)
        );
    }

    function _digest(MeasureablePcr[] calldata tpmPcrs) private pure returns (bytes32) {
        bytes memory concatenated;

        for (uint256 i = 0; i < tpmPcrs.length; i++) {
            bytes32 pcrValue = tpmPcrs[i].pcr;
            // If a PCR value is zero, calculate it from events (if provided)
            if (pcrValue == bytes32(0)) {
                pcrValue = _calculatePcrFromEvents(tpmPcrs[i].allEvents);
            }
            concatenated = abi.encodePacked(concatenated, pcrValue);
        }

        return sha256(concatenated);
    }

    function _calculatePcrFromEvents(bytes32[] calldata events) private pure returns (bytes32) {
        bytes32 pcr = bytes32(0);
        for (uint256 i = 0; i < events.length; i++) {
            pcr = sha256(abi.encodePacked(pcr, events[i]));
        }
        return pcr;
    }

    function _verifyEvents(MeasureablePcr calldata mpcr) private pure returns (bool) {
        // If a PCR value is provided, it must match the calculated value from its events.
        // If no PCR value is provided, this check is skipped (it's calculated in _digest).
        if (mpcr.pcr != bytes32(0) && mpcr.allEvents.length > 0) {
            return _calculatePcrFromEvents(mpcr.allEvents) == mpcr.pcr;
        }
        // If no events are provided, or no pcr is provided, there's nothing to verify here.
        return true;
    }
}
