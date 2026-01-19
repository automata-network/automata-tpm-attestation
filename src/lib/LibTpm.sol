// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.15;

import {CertPubkey, SignatureAlgorithm, LibX509} from "./LibX509.sol";
import {LibX509Verify} from "./LibX509Verify.sol";
import {TPMConstants} from "../types/TPMConstants.sol";
import {ClockInfo} from "../interfaces/ITpmAttestation.sol";
import {
    InvalidTpmMagic,
    InvalidCertifyAttestType,
    InvalidTpmAttType,
    CertifiedNameMismatch,
    ExtraDataMismatch,
    TpmtPublicTooShort,
    UnsupportedNameAlgorithm,
    InvalidTpmtPublicType,
    ParseOffsetOutOfBounds,
    TpmSignatureTooShort,
    InvalidRsaSignatureSize,
    InvalidEcdsaSignature,
    TpmSignatureVerificationFailed,
    UnsupportedSignatureScheme
} from "../types/Errors.sol";

/// @title LibTpm
/// @notice TPM utility library
library LibTpm {
    using LibX509Verify for CertPubkey;

    /// @notice Parses a TPM signature (TPMT_SIGNATURE format)
    /// @dev Handles both RSASSA and ECDSA signature formats:
    ///      - RSASSA: scheme(2) + hashAlg(2) + sig.size(2) + sig(variable)
    ///      - ECDSA: scheme(2) + hashAlg(2) + r.size(2) + r(32) + s.size(2) + s(32)
    /// @param tpmSignature The raw TPMT_SIGNATURE bytes from TPM
    /// @return sigAlgo The parsed signature algorithm (scheme + hash algorithm)
    /// @return signature The signature bytes (raw for RSA, DER-encoded for ECDSA)
    function parseTpmSignature(bytes calldata tpmSignature)
        internal
        pure
        returns (SignatureAlgorithm memory sigAlgo, bytes memory signature)
    {
        require(tpmSignature.length >= 6, TpmSignatureTooShort());

        // Extract signature scheme and hash algorithm
        sigAlgo.scheme = uint16(bytes2(tpmSignature[0:2]));
        sigAlgo.hashAlgo = uint16(bytes2(tpmSignature[2:4]));

        if (sigAlgo.scheme == TPMConstants.TPM_ALG_RSASSA) {
            // RSA signature format: [scheme][hashAlg][size][signature]
            uint16 sigSize = uint16(bytes2(tpmSignature[4:6]));
            require(sigSize >= 256 && sigSize <= 512, InvalidRsaSignatureSize());
            require(tpmSignature.length >= 6 + sigSize, TpmSignatureTooShort());
            signature = tpmSignature[6:6 + sigSize];
        } else if (sigAlgo.scheme == TPMConstants.TPM_ALG_ECDSA) {
            // ECDSA signature format: [scheme][hashAlg][r.size][r][s.size][s]
            require(tpmSignature.length >= 72, InvalidEcdsaSignature());

            uint16 rSize = uint16(bytes2(tpmSignature[4:6]));
            require(rSize == 32, InvalidEcdsaSignature());

            uint16 sSize = uint16(bytes2(tpmSignature[38:40]));
            require(sSize == 32, InvalidEcdsaSignature());

            // Extract r and s components
            bytes32 r = bytes32(tpmSignature[6:38]);
            bytes32 s = bytes32(tpmSignature[40:72]);

            // Convert to DER-encoded ECDSA signature for verification
            signature = LibX509.encodeEcdsaSignature(r, s);
        } else {
            revert UnsupportedSignatureScheme(sigAlgo.scheme, 0);
        }
    }

    /// @notice Generic parser for TPMS_ATTEST header (works for all attestation types)
    /// @dev Parses the common header fields present in all TPMS_ATTEST structures:
    ///      magic(4) + type(2) + qualifiedSigner(TPM2B) + extraData(TPM2B)
    /// @param attest The raw TPMS_ATTEST bytes (quote, certify, etc.)
    /// @param expectedType The expected attestation type (0 to skip validation)
    /// @return qualifiedSignerLen Length of qualifiedSigner field
    /// @return extraDataLen Length of extraData field
    /// @return extraData The extracted extraData bytes
    function parseAttestHeaders(bytes calldata attest, uint16 expectedType)
        internal
        pure
        returns (uint16 qualifiedSignerLen, uint16 extraDataLen, bytes memory extraData)
    {
        require(attest.length >= 10, TpmtPublicTooShort());

        // Validate TPM_MAGIC
        uint32 magic = uint32(bytes4(attest[0:4]));
        require(magic == TPMConstants.TPM_MAGIC, InvalidTpmMagic());

        // Optionally validate type (pass 0 to skip)
        if (expectedType != 0) {
            uint16 attType = uint16(bytes2(attest[4:6]));
            require(attType == expectedType, InvalidTpmAttType());
        }

        // Parse common fields (works for ALL TPMS_ATTEST types)
        qualifiedSignerLen = uint16(bytes2(attest[6:8]));
        require(attest.length >= 10 + qualifiedSignerLen, TpmtPublicTooShort());

        extraDataLen = uint16(bytes2(attest[8 + qualifiedSignerLen:10 + qualifiedSignerLen]));
        require(attest.length >= 10 + qualifiedSignerLen + extraDataLen, TpmtPublicTooShort());

        // Ensure clockInfo + firmwareVersion are present (25 bytes minimum)
        require(attest.length >= 35 + qualifiedSignerLen + extraDataLen, TpmtPublicTooShort());

        extraData = attest[10 + qualifiedSignerLen:10 + qualifiedSignerLen + extraDataLen];
    }

    /// @notice Extracts extraData from any TPMS_ATTEST structure
    /// @dev Works for all attestation types (quote, certify, etc.)
    /// @param attest The raw TPMS_ATTEST bytes
    /// @return extraData The extracted extraData field for replay protection
    function extractExtraData(bytes calldata attest) internal pure returns (bytes memory extraData) {
        (,, extraData) = parseAttestHeaders(attest, 0);
    }

    /// @notice Extracts ClockInfo from any TPMS_ATTEST structure
    /// @dev Works for all attestation types (quote, certify, etc.)
    ///      TPMS_CLOCK_INFO layout (17 bytes, big-endian):
    ///      [0:8]   clock (uint64)
    ///      [8:12]  resetCount (uint32)
    ///      [12:16] restartCount (uint32)
    ///      [16:17] safe (uint8: 0 or 1)
    /// @param attest The raw TPMS_ATTEST bytes
    /// @return info The parsed ClockInfo struct including safe flag
    function extractClockInfo(bytes calldata attest) internal pure returns (ClockInfo memory info) {
        (uint16 qualifiedSignerLen, uint16 extraDataLen,) = parseAttestHeaders(attest, 0);

        // Calculate clock_info offset: 10 + qualifiedSignerLen + extraDataLen
        uint256 clockInfoOffset = 10 + qualifiedSignerLen + extraDataLen;

        // TPM uses big-endian encoding
        info.clock = uint64(bytes8(attest[clockInfoOffset:clockInfoOffset + 8]));
        info.resetCount = uint32(bytes4(attest[clockInfoOffset + 8:clockInfoOffset + 12]));
        info.restartCount = uint32(bytes4(attest[clockInfoOffset + 12:clockInfoOffset + 16]));
        info.safe = uint8(attest[clockInfoOffset + 16]) == 1;
    }

    /// @notice Parse TPMS_ATTEST structure for CERTIFY type (0x8017)
    /// @dev TPMS_ATTEST layout:
    ///      magic(4) + type(2) + qualifiedSigner(TPM2B) + extraData(TPM2B) +
    ///      clockInfo(17) + firmwareVersion(8) + attested.name(TPM2B) + ...
    /// @param certifyInfo The raw TPMS_ATTEST bytes
    /// @return extraData The extraData field for replay protection
    /// @return certifiedName The certified key's name (nameAlg || hash)
    function parseCertifyInfo(bytes calldata certifyInfo)
        internal
        pure
        returns (bytes memory extraData, bytes memory certifiedName)
    {
        // Use generic parser to validate and extract common fields
        uint16 qualifiedSignerLen;
        uint16 extraDataLen;
        (qualifiedSignerLen, extraDataLen, extraData) =
            parseAttestHeaders(certifyInfo, TPMConstants.TPM_ST_ATTEST_CERTIFY);

        // Calculate offset to attested.name (after clockInfo + firmwareVersion)
        uint256 offset = 10 + qualifiedSignerLen + extraDataLen + 25;

        // Extract attested.name (TPM2B_NAME)
        require(offset + 2 <= certifyInfo.length, ParseOffsetOutOfBounds());
        uint16 nameLen = uint16(bytes2(certifyInfo[offset:offset + 2]));
        offset += 2;
        require(offset + nameLen <= certifyInfo.length, ParseOffsetOutOfBounds());
        certifiedName = certifyInfo[offset:offset + nameLen];
    }

    /// @notice Computes the TPM KEY_NAME for a TPMT_PUBLIC structure
    /// @dev name = nameAlg || Hash(tpmtPublic)
    ///      For SHA256: name = 0x000b || sha256(tpmtPublic)
    /// @param tpmtPublic The marshalled TPMT_PUBLIC bytes
    /// @return name The computed KEY_NAME (typically 34 bytes: 2-byte alg + 32-byte hash)
    function computeKeyName(bytes calldata tpmtPublic) internal pure returns (bytes memory name) {
        require(tpmtPublic.length >= 4, TpmtPublicTooShort());

        // Extract nameAlg from bytes [2:4]
        uint16 nameAlg = uint16(bytes2(tpmtPublic[2:4]));

        require(nameAlg == TPMConstants.TPM_ALG_SHA256, UnsupportedNameAlgorithm());
        bytes32 hash = sha256(tpmtPublic);
        name = abi.encodePacked(nameAlg, hash);
    }

    /// @notice Extracts CertPubkey from TPMT_PUBLIC
    /// @dev Handles both ECC and RSA key types
    /// @param tpmtPublic The marshalled TPMT_PUBLIC bytes
    /// @return pubkey The public key as CertPubkey
    function extractCertPubkey(bytes calldata tpmtPublic) internal pure returns (CertPubkey memory pubkey) {
        require(tpmtPublic.length >= 10, TpmtPublicTooShort());

        uint16 keyType = uint16(bytes2(tpmtPublic[0:2]));

        // Skip: type(2) + nameAlg(2) + objectAttributes(4) = 8 bytes
        uint256 offset = 8;

        // Skip authPolicy (TPM2B)
        require(offset + 2 <= tpmtPublic.length, ParseOffsetOutOfBounds());
        uint16 apLen = uint16(bytes2(tpmtPublic[offset:offset + 2]));
        offset += 2 + apLen;

        if (keyType == TPMConstants.TPM_ALG_ECC) {
            pubkey = _parseEccPublic(tpmtPublic, offset);
        } else if (keyType == TPMConstants.TPM_ALG_RSA) {
            pubkey = _parseRsaPublic(tpmtPublic, offset);
        } else {
            revert InvalidTpmtPublicType();
        }
    }

    /// @dev Parses ECC TPMT_PUBLIC to extract public key
    /// @param tpmtPublic The full TPMT_PUBLIC bytes
    /// @param offset The offset to start of TPMS_ECC_PARMS
    /// @return pubkey The EC public key in uncompressed format (0x04 || x || y)
    function _parseEccPublic(bytes calldata tpmtPublic, uint256 offset)
        private
        pure
        returns (CertPubkey memory pubkey)
    {
        // TPMS_ECC_PARMS: symmetric(2+) + scheme(2+) + curveID(2) + kdf(2+)
        require(offset + 2 <= tpmtPublic.length, ParseOffsetOutOfBounds());

        // Skip symmetric
        uint16 symmetricAlgo = uint16(bytes2(tpmtPublic[offset:offset + 2]));
        offset += 2;
        if (symmetricAlgo != TPMConstants.TPM_ALG_NULL) {
            // Skip keyBits(2) + mode(2)
            offset += 4;
        }

        // Skip scheme
        require(offset + 2 <= tpmtPublic.length, ParseOffsetOutOfBounds());
        uint16 scheme = uint16(bytes2(tpmtPublic[offset:offset + 2]));
        offset += 2;

        if (scheme != TPMConstants.TPM_ALG_NULL) {
            // Skip hashAlg
            offset += 2;
        }

        // Extract curveID
        require(offset + 2 <= tpmtPublic.length, ParseOffsetOutOfBounds());
        uint16 curveID = uint16(bytes2(tpmtPublic[offset:offset + 2]));
        offset += 2;

        // Skip kdf
        require(offset + 2 <= tpmtPublic.length, ParseOffsetOutOfBounds());
        uint16 kdfScheme = uint16(bytes2(tpmtPublic[offset:offset + 2]));
        offset += 2;
        if (kdfScheme != TPMConstants.TPM_ALG_NULL) {
            offset += 2; // skip kdf.hashAlg
        }

        // Extract x coordinate (TPM2B)
        require(offset + 2 <= tpmtPublic.length, ParseOffsetOutOfBounds());
        uint16 xLen = uint16(bytes2(tpmtPublic[offset:offset + 2]));
        offset += 2;
        require(offset + xLen <= tpmtPublic.length, ParseOffsetOutOfBounds());
        bytes memory xBytes = tpmtPublic[offset:offset + xLen];
        offset += xLen;

        // Extract y coordinate (TPM2B)
        require(offset + 2 <= tpmtPublic.length, ParseOffsetOutOfBounds());
        uint16 yLen = uint16(bytes2(tpmtPublic[offset:offset + 2]));
        offset += 2;
        require(offset + yLen <= tpmtPublic.length, ParseOffsetOutOfBounds());
        bytes memory yBytes = tpmtPublic[offset:offset + yLen];

        // Build uncompressed EC point (0x04 || x || y)
        require(xLen == 32 && yLen == 32, InvalidTpmtPublicType());
        bytes memory ecPoint = abi.encodePacked(uint8(0x04), xBytes, yBytes);

        pubkey = CertPubkey({algo: TPMConstants.TPM_ALG_ECC, params: curveID, data: ecPoint});
    }

    /// @dev Parses RSA TPMT_PUBLIC to extract public key
    /// @param tpmtPublic The full TPMT_PUBLIC bytes
    /// @param offset The offset to start of TPMS_RSA_PARMS
    /// @return pubkey The RSA public key as DER-encoded RSAPublicKey
    function _parseRsaPublic(bytes calldata tpmtPublic, uint256 offset)
        private
        pure
        returns (CertPubkey memory pubkey)
    {
        // TPMS_RSA_PARMS: symmetric(2+) + scheme(2+) + keyBits(2) + exponent(4)
        require(offset + 2 <= tpmtPublic.length, ParseOffsetOutOfBounds());

        // Skip symmetric
        uint16 symmetricAlgo = uint16(bytes2(tpmtPublic[offset:offset + 2]));
        offset += 2;
        if (symmetricAlgo != TPMConstants.TPM_ALG_NULL) {
            offset += 4; // skip keyBits + mode
        }

        // Skip scheme
        require(offset + 2 <= tpmtPublic.length, ParseOffsetOutOfBounds());
        uint16 scheme = uint16(bytes2(tpmtPublic[offset:offset + 2]));
        offset += 2;

        if (scheme != TPMConstants.TPM_ALG_NULL) {
            // Skip hashAlg
            offset += 2;
        }

        // Skip keyBits (not needed for CertPubkey)
        offset += 2;

        // Parse exponent (uint32, 0 means 65537)
        require(offset + 4 <= tpmtPublic.length, ParseOffsetOutOfBounds());
        uint32 exponentValue = uint32(bytes4(tpmtPublic[offset:offset + 4]));
        offset += 4;

        if (exponentValue == 0) {
            exponentValue = 65537;
        }

        // Convert exponent to bytes
        bytes memory e;
        if (exponentValue == 65537) {
            e = hex"010001"; // Common case: 65537 = 0x010001
        } else {
            // Handle other exponent values - convert uint32 to minimal bytes
            e = _uint32ToBytes(exponentValue);
        }

        // Extract modulus (TPM2B_PUBLIC_KEY_RSA)
        require(offset + 2 <= tpmtPublic.length, ParseOffsetOutOfBounds());
        uint16 nLen = uint16(bytes2(tpmtPublic[offset:offset + 2]));
        offset += 2;
        require(offset + nLen <= tpmtPublic.length, ParseOffsetOutOfBounds());
        bytes memory n = tpmtPublic[offset:offset + nLen];

        // Use LibX509.newRsaPubkey to create DER-encoded public key
        pubkey = LibX509.newRsaPubkey(n, e);
    }

    /// @dev Converts uint32 to minimal big-endian bytes
    /// @param value The uint32 value to convert
    /// @return result The minimal byte representation
    function _uint32ToBytes(uint32 value) private pure returns (bytes memory result) {
        if (value == 0) return hex"00";

        // Find the number of bytes needed
        uint256 temp = value;
        uint256 length = 0;
        while (temp > 0) {
            length++;
            temp >>= 8;
        }

        result = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            result[length - 1 - i] = bytes1(uint8(value >> (i * 8)));
        }
    }
}
