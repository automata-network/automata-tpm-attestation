// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.27;

import {ITpmAttestation, PcrValue} from "./interfaces/ITpmAttestation.sol";
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
    MismatchedTpmtObjAttributes,
    PcrDigestMismatch,
    InvalidPcrDigestSize,
    UnsupportedHashAlgorithm,
    PcrSelectionMismatch,
    InvalidPcrEvents,
    InvalidPcrEventIndex,
    TpmSignatureTooShort,
    InvalidRsaSignatureSize,
    PcrIndexOutOfRange,
    PcrNotSorted
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

    function verifyTpmQuote(bytes calldata tpmQuote, bytes calldata tpmSignature, bytes[] calldata akCertchain)
        external
        override
        returns (bool, bytes memory, bytes memory)
    {
        require(akCertchain.length > 0, InvalidCertChainLength());

        CertPubkey memory akPub = verifyCertChain(akCertchain);
        require(akPub.data.length > 0, InvalidCertificateChain());

        bytes memory extraData = _verifyTpmQuote(tpmQuote, tpmSignature, akPub);
        return (true, abi.encode(akPub), extraData);
    }

    function verifyTpmQuoteWithTrustedAkPub(
        bytes calldata tpmQuote,
        bytes calldata tpmSignature,
        CertPubkey calldata akPub
    ) external override returns (bool, bytes memory) {
        bytes memory extraData = _verifyTpmQuote(tpmQuote, tpmSignature, akPub);
        return (true, extraData);
    }

    function verifyTpmKeyCertification(
        bytes calldata certifyInfo,
        bytes calldata akSignature,
        bytes calldata tpmtPublic,
        CertPubkey calldata akPub,
        uint32 tpmaObjectBitMask
    ) external view override returns (CertPubkey memory certifiedPubkey, bytes memory extraData) {
        // Step 1: Parse and verify AK signature over certifyInfo
        (SignatureAlgorithm memory akSigAlgo, bytes memory sig) = LibTpm.parseTpmSignature(akSignature);
        address verifier = akSigAlgo.scheme == TPMConstants.TPM_ALG_ECDSA ? p256 : address(0);
        require(akPub.verifySignature(akSigAlgo, certifyInfo, sig, verifier), TpmSignatureVerificationFailed());

        // Step 2: Parse certifyInfo and extract fields
        bytes memory certifiedName;
        (extraData, certifiedName) = LibTpm.parseCertifyInfo(certifyInfo);

        // Step 3: Compare KEY_NAME
        bytes memory expectedName = LibTpm.computeKeyName(tpmtPublic);
        require(keccak256(certifiedName) == keccak256(expectedName), CertifiedNameMismatch());

        // Step 4: Validate objectAttributes if mask is non-zero
        if (tpmaObjectBitMask != 0) {
            uint32 attributes = LibTpm.extractKeyAttributes(tpmtPublic);
            if ((attributes & tpmaObjectBitMask) != tpmaObjectBitMask) {
                revert MismatchedTpmtObjAttributes(attributes, tpmaObjectBitMask);
            }
        }

        // Step 5: Extract and return certified public key
        certifiedPubkey = LibTpm.extractCertPubkey(tpmtPublic);
    }

    function extractExtraData(bytes calldata tpmQuote) external pure returns (bool success, bytes memory extraData) {
        extraData = LibTpm.extractExtraData(tpmQuote);
        success = true;
    }

    function checkPcrMeasurements(bytes calldata tpmQuote, PcrValue[] calldata tpmPcrs)
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

    function _verifyTpmQuote(bytes calldata tpmQuote, bytes calldata tpmSignature, CertPubkey memory akPub)
        private
        returns (bytes memory extraData)
    {
        // Parse and validate attestation headers (validates TPM_ST_ATTEST_QUOTE and extracts extraData)
        (,, extraData) = LibTpm.parseAttestHeaders(tpmQuote, TPMConstants.TPM_ST_ATTEST_QUOTE);

        // Use library function for signature parsing (fixes ECDSA length bug: 40 -> 72)
        (SignatureAlgorithm memory sigAlgo, bytes memory sig) = LibTpm.parseTpmSignature(tpmSignature);

        // Validate hash algorithm is SHA256
        require(sigAlgo.hashAlgo == TPMConstants.TPM_ALG_SHA256, UnsupportedHashAlgorithm());

        address verifier = sigAlgo.scheme == TPMConstants.TPM_ALG_ECDSA ? p256 : address(0);
        bool result = akPub.verifySignature(sigAlgo, tpmQuote, sig, verifier);

        require(result, TpmSignatureVerificationFailed());

        emit TpmSignatureVerified(keccak256(tpmQuote));
    }

    function _compactSelections(PcrValue[] calldata tpmPcrs) private pure returns (bytes4) {
        // Use a single uint32 instead of an array to reduce memory operations
        uint32 bitmap;
        uint256 len = tpmPcrs.length;

        // Cache array length and use unchecked for loop operations to save gas
        unchecked {
            for (uint256 i = 0; i < len && i < 32; i++) {
                uint256 idx = uint256(tpmPcrs[i].pcrIndex);
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

    function _digest(PcrValue[] calldata tpmPcrs) private pure returns (bytes32) {
        bytes memory concatenated;

        for (uint256 i = 0; i < tpmPcrs.length; i++) {
            if (i > 0) {
                require(tpmPcrs[i].pcrIndex > tpmPcrs[i - 1].pcrIndex, PcrNotSorted());
            }
            bytes32 pcrValue = tpmPcrs[i].value;
            bytes32[] calldata events = tpmPcrs[i].eventLogHashes;

            // only verify the value if event logs are provided.
            if (events.length > 0) {
                bytes32 computed = _calculatePcrFromEvents(events);
                require(pcrValue == bytes32(0) || pcrValue == computed, InvalidPcrEvents());
                pcrValue = computed;
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
}
