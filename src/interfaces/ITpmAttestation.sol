// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.0;

import {ICertChainRegistry, CertPubkey} from "./ICertChainRegistry.sol";
import {SignatureAlgorithm} from "../lib/LibX509.sol";
import {MeasureablePcr, Pcr} from "../types/Types.sol";

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

    /// @notice Verifies a TPM2_Certify attestation proving a key is bound to the same TPM as the AK
    /// @param certifyInfo Raw TPMS_ATTEST bytes from TPM2_Certify
    /// @param akSignature TPMT_SIGNATURE bytes from TPM2_Certify
    /// @param tpmtPublic Marshalled TPMT_PUBLIC of the certified key
    /// @param akPub The trusted Attestation Key public key
    /// @param expectedExtraData Optional: Expected extraData for replay protection (empty to skip)
    /// @return certifiedPubkey The certified key extracted as CertPubkey
    function verifyTpmKeyCertification(
        bytes calldata certifyInfo,
        bytes calldata akSignature,
        bytes calldata tpmtPublic,
        CertPubkey calldata akPub,
        bytes calldata expectedExtraData
    ) external view returns (CertPubkey memory certifiedPubkey);
}
