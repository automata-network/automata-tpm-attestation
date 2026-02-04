// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.0;

import {ICertChainRegistry, CertPubkey} from "./ICertChainRegistry.sol";
import {SignatureAlgorithm} from "../lib/LibX509.sol";
import {PcrValue} from "../types/Types.sol";

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
    /// @return extraData - The extraData field from the TPM quote (for caller's replay protection)
    function verifyTpmQuote(bytes calldata tpmQuote, bytes calldata tpmSignature, bytes[] calldata akCertchain)
        external
        returns (bool success, bytes memory akPubkey, bytes memory extraData);

    /// @notice Verifies a TPM quote using pre-verified / trusted public AK
    /// @dev is responsible for ensuring akPub is trusted (saves gas from verifying the entire cert chain)
    /// @param tpmQuote - The TPM quote to verify
    /// @param tpmSignature - The signature of the TPM quote
    /// @param akPub - A pre-verified attestation public key
    /// @return success - Whether the verification was successful
    /// @return extraData - The extraData field from the TPM quote (for caller's replay protection); otherwise the raw bytes of error message
    function verifyTpmQuoteWithTrustedAkPub(
        bytes calldata tpmQuote,
        bytes calldata tpmSignature,
        CertPubkey calldata akPub
    ) external returns (bool success, bytes memory extraData);

    /// @notice Verifies a TPM2_Certify attestation proving a key is bound to the same TPM as the AK
    /// @param certifyInfo Raw TPMS_ATTEST bytes from TPM2_Certify
    /// @param akSignature TPMT_SIGNATURE bytes from TPM2_Certify
    /// @param tpmtPublic Marshalled TPMT_PUBLIC of the certified key
    /// @param akPub The trusted Attestation Key public key
    /// @param tpmaObjectBitMask Required attribute bits (pass 0 to skip attribute validation)
    /// @dev TPMA_OBJECT bit layout (TPM 2.0 Part 2, Table 31):
    ///      Bit  1  — fixedTPM             (0x00002) — Key cannot be duplicated outside the TPM
    ///      Bit  2  — stClear              (0x00004) — Cleared on TPM2_Startup(CLEAR)
    ///      Bit  4  — fixedParent          (0x00010) — Key cannot be moved to a different parent
    ///      Bit  5  — sensitiveDataOrigin  (0x00020) — TPM generated all sensitive data
    ///      Bit  6  — userWithAuth         (0x00040) — User role auth via HMAC/password
    ///      Bit  7  — adminWithPolicy      (0x00080) — Admin role requires policy session
    ///      Bit 10  — noDA                 (0x00400) — Not subject to dictionary attack lockout
    ///      Bit 11  — encryptedDuplication (0x00800) — May be duplicated with symmetric encryption
    ///      Bit 16  — restricted           (0x10000) — Usage restricted to known-format structures
    ///      Bit 17  — decrypt              (0x20000) — Private portion may decrypt
    ///      Bit 18  — sign/encrypt         (0x40000) — Private portion may sign / encrypt
    ///
    ///      Example: requiring `fixedTPM | fixedParent | sensitiveDataOrigin | sign/encrypt` → 0x40032
    /// @return certifiedPubkey The certified key extracted as CertPubkey
    /// @return extraData The extraData field from the certifyInfo (for caller's replay protection)
    function verifyTpmKeyCertification(
        bytes calldata certifyInfo,
        bytes calldata akSignature,
        bytes calldata tpmtPublic,
        CertPubkey calldata akPub,
        uint32 tpmaObjectBitMask
    ) external view returns (CertPubkey memory certifiedPubkey, bytes memory extraData);

    /// Extracts extra data from the TPM quote
    /// @param tpmQuote - TPM quote
    /// @return success - Whether the extraction was successful
    /// @return extraData - The extracted extra data from the TPM quote, otherwise an error message
    function extractExtraData(bytes calldata tpmQuote) external pure returns (bool success, bytes memory extraData);

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
    function checkPcrMeasurements(bytes calldata tpmQuote, PcrValue[] calldata tpmPcrs)
        external
        returns (bool success, bytes memory extraData);
}
