// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.15;

import {CertPubkey, SignatureAlgorithm, LibX509} from "./LibX509.sol";
import {LibX509Verify} from "./LibX509Verify.sol";
import {TPMConstants} from "../types/TPMConstants.sol";
import {
    InvalidTpmMagic,
    InvalidCertifyAttestType,
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

/// @title LibTpmCertify
/// @notice Library for verifying TPM2_Certify attestations
/// @dev Implements verification that a key is certified by a TPM's Attestation Key,
///      proving the key is bound to the same TPM hardware and cannot be exported.
/// @custom:security-contact security@ata.network
library LibTpmCertify {
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
        if (tpmSignature.length < 6) revert TpmSignatureTooShort();

        // Extract signature scheme and hash algorithm
        sigAlgo.scheme = uint16(bytes2(tpmSignature[0:2]));
        sigAlgo.hashAlgo = uint16(bytes2(tpmSignature[2:4]));

        if (sigAlgo.scheme == TPMConstants.TPM_ALG_RSASSA) {
            // RSA signature format: [scheme][hashAlg][size][signature]
            uint16 sigSize = uint16(bytes2(tpmSignature[4:6]));
            if (sigSize < 256 || sigSize > 512) revert InvalidRsaSignatureSize();
            if (tpmSignature.length < 6 + sigSize) revert TpmSignatureTooShort();
            signature = tpmSignature[6:6 + sigSize];
        } else if (sigAlgo.scheme == TPMConstants.TPM_ALG_ECDSA) {
            // ECDSA signature format: [scheme][hashAlg][r.size][r][s.size][s]
            if (tpmSignature.length < 72) revert InvalidEcdsaSignature();

            uint16 rSize = uint16(bytes2(tpmSignature[4:6]));
            if (rSize != 32) revert InvalidEcdsaSignature();

            uint16 sSize = uint16(bytes2(tpmSignature[38:40]));
            if (sSize != 32) revert InvalidEcdsaSignature();

            // Extract r and s components
            bytes32 r = bytes32(tpmSignature[6:38]);
            bytes32 s = bytes32(tpmSignature[40:72]);

            // Convert to DER-encoded ECDSA signature for verification
            signature = LibX509.encodeEcdsaSignature(r, s);
        } else {
            revert UnsupportedSignatureScheme(sigAlgo.scheme, 0);
        }
    }

    /// @notice Verifies a TPM2_Certify attestation proving a key is bound to the same TPM as the AK
    /// @dev Performs 4-step verification:
    ///      1. Verify AK signature over certifyInfo
    ///      2. Parse certifyInfo and validate magic/type
    ///      3. Validate extraData and compare KEY_NAME
    ///      4. Extract and return certified public key + signature algorithm
    /// @param certifyInfo Raw TPMS_ATTEST bytes from TPM2_Certify
    /// @param akSignature TPMT_SIGNATURE bytes from TPM2_Certify
    /// @param tpmtPublic Marshalled TPMT_PUBLIC of the certified key
    /// @param akPub The trusted Attestation Key public key
    /// @param expectedExtraData Optional: Expected extraData for replay protection
    /// @param ecdsaP256Verifier Address of P256 verifier contract
    /// @return certifiedPubkey The certified key extracted as CertPubkey
    /// @return certifiedSigAlgo The signature algorithm for the certified key
    function verifyTpmKeyCertification(
        bytes calldata certifyInfo,
        bytes calldata akSignature,
        bytes calldata tpmtPublic,
        CertPubkey memory akPub,
        bytes calldata expectedExtraData,
        address ecdsaP256Verifier
    ) internal view returns (CertPubkey memory certifiedPubkey, SignatureAlgorithm memory certifiedSigAlgo) {
        // Step 1: Parse and verify AK signature over certifyInfo
        (SignatureAlgorithm memory akSigAlgo, bytes memory sig) = parseTpmSignature(akSignature);
        bool sigValid = akPub.verifySignature(akSigAlgo, certifyInfo, sig, ecdsaP256Verifier);
        if (!sigValid) revert TpmSignatureVerificationFailed();

        // Step 2: Parse certifyInfo and extract fields
        (bytes memory extraData, bytes memory certifiedName) = parseCertifyInfo(certifyInfo);

        // Step 3: Compare KEY_NAME
        bytes memory expectedName = computeKeyName(tpmtPublic);
        if (keccak256(certifiedName) != keccak256(expectedName)) {
            revert CertifiedNameMismatch();
        }

        if (expectedExtraData.length != 0) {
            if (keccak256(extraData) != keccak256(expectedExtraData)) {
                revert ExtraDataMismatch();
            }
        }

        // Step 4: Extract and return certified public key + signature algorithm
        (certifiedPubkey, certifiedSigAlgo) = extractPubkeyAndSigAlgo(tpmtPublic);
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
        if (certifyInfo.length < 10) revert TpmtPublicTooShort();

        // Validate magic (0xff544347 = "\xffTCG")
        uint32 magic = uint32(bytes4(certifyInfo[0:4]));
        if (magic != TPMConstants.TPM_MAGIC) revert InvalidTpmMagic();

        // Validate type (0x8017 = TPM_ST_ATTEST_CERTIFY)
        uint16 attType = uint16(bytes2(certifyInfo[4:6]));
        if (attType != TPMConstants.TPM_ST_ATTEST_CERTIFY) revert InvalidCertifyAttestType();

        uint256 offset = 6;

        // Skip qualifiedSigner (TPM2B_NAME)
        if (offset + 2 > certifyInfo.length) revert ParseOffsetOutOfBounds();
        uint16 qsLen = uint16(bytes2(certifyInfo[offset:offset + 2]));
        offset += 2 + qsLen;

        // Extract extraData (TPM2B_DATA)
        if (offset + 2 > certifyInfo.length) revert ParseOffsetOutOfBounds();
        uint16 edLen = uint16(bytes2(certifyInfo[offset:offset + 2]));
        offset += 2;
        if (offset + edLen > certifyInfo.length) revert ParseOffsetOutOfBounds();
        extraData = certifyInfo[offset:offset + edLen];
        offset += edLen;

        // Skip clockInfo (17 bytes) + firmwareVersion (8 bytes)
        offset += 25;

        // Extract attested.name (TPM2B_NAME)
        if (offset + 2 > certifyInfo.length) revert ParseOffsetOutOfBounds();
        uint16 nameLen = uint16(bytes2(certifyInfo[offset:offset + 2]));
        offset += 2;
        if (offset + nameLen > certifyInfo.length) revert ParseOffsetOutOfBounds();
        certifiedName = certifyInfo[offset:offset + nameLen];
    }

    /// @notice Computes the TPM KEY_NAME for a TPMT_PUBLIC structure
    /// @dev name = nameAlg || Hash(tpmtPublic)
    ///      For SHA256: name = 0x000b || sha256(tpmtPublic)
    /// @param tpmtPublic The marshalled TPMT_PUBLIC bytes
    /// @return name The computed KEY_NAME (typically 34 bytes: 2-byte alg + 32-byte hash)
    function computeKeyName(bytes calldata tpmtPublic) internal pure returns (bytes memory name) {
        if (tpmtPublic.length < 4) revert TpmtPublicTooShort();

        // Extract nameAlg from bytes [2:4]
        uint16 nameAlg = uint16(bytes2(tpmtPublic[2:4]));

        if (nameAlg == TPMConstants.TPM_ALG_SHA256) {
            bytes32 hash = sha256(tpmtPublic);
            name = abi.encodePacked(nameAlg, hash);
        } else {
            revert UnsupportedNameAlgorithm();
        }
    }

    /// @notice Extracts public key and signature algorithm from TPMT_PUBLIC
    /// @dev Handles both ECC and RSA key types
    /// @param tpmtPublic The marshalled TPMT_PUBLIC bytes
    /// @return pubkey The public key as CertPubkey
    /// @return sigAlgo The signature algorithm (scheme + hashAlg from TPMT_PUBLIC)
    function extractPubkeyAndSigAlgo(bytes calldata tpmtPublic)
        internal
        pure
        returns (CertPubkey memory pubkey, SignatureAlgorithm memory sigAlgo)
    {
        if (tpmtPublic.length < 10) revert TpmtPublicTooShort();

        uint16 keyType = uint16(bytes2(tpmtPublic[0:2]));

        // Skip: type(2) + nameAlg(2) + objectAttributes(4) = 8 bytes
        uint256 offset = 8;

        // Skip authPolicy (TPM2B)
        if (offset + 2 > tpmtPublic.length) revert ParseOffsetOutOfBounds();
        uint16 apLen = uint16(bytes2(tpmtPublic[offset:offset + 2]));
        offset += 2 + apLen;

        if (keyType == TPMConstants.TPM_ALG_ECC) {
            (pubkey, sigAlgo) = _parseEccPublic(tpmtPublic, offset);
        } else if (keyType == TPMConstants.TPM_ALG_RSA) {
            (pubkey, sigAlgo) = _parseRsaPublic(tpmtPublic, offset);
        } else {
            revert InvalidTpmtPublicType();
        }
    }

    /// @dev Parses ECC TPMT_PUBLIC to extract public key and signature algorithm
    /// @param tpmtPublic The full TPMT_PUBLIC bytes
    /// @param offset The offset to start of TPMS_ECC_PARMS
    /// @return pubkey The EC public key in uncompressed format (0x04 || x || y)
    /// @return sigAlgo The signature algorithm from scheme fields
    function _parseEccPublic(bytes calldata tpmtPublic, uint256 offset)
        private
        pure
        returns (CertPubkey memory pubkey, SignatureAlgorithm memory sigAlgo)
    {
        // TPMS_ECC_PARMS: symmetric(2+) + scheme(2+) + curveID(2) + kdf(2+)
        if (offset + 2 > tpmtPublic.length) revert ParseOffsetOutOfBounds();

        // Parse symmetric
        uint16 symmetricAlgo = uint16(bytes2(tpmtPublic[offset:offset + 2]));
        offset += 2;
        if (symmetricAlgo != TPMConstants.TPM_ALG_NULL) {
            // Skip keyBits(2) + mode(2)
            offset += 4;
        }

        // Parse scheme
        if (offset + 2 > tpmtPublic.length) revert ParseOffsetOutOfBounds();
        sigAlgo.scheme = uint16(bytes2(tpmtPublic[offset:offset + 2]));
        offset += 2;

        if (sigAlgo.scheme != TPMConstants.TPM_ALG_NULL) {
            // Extract hashAlg
            if (offset + 2 > tpmtPublic.length) revert ParseOffsetOutOfBounds();
            sigAlgo.hashAlgo = uint16(bytes2(tpmtPublic[offset:offset + 2]));
            offset += 2;
        }

        // Extract curveID
        if (offset + 2 > tpmtPublic.length) revert ParseOffsetOutOfBounds();
        uint16 curveID = uint16(bytes2(tpmtPublic[offset:offset + 2]));
        offset += 2;

        // Skip kdf
        if (offset + 2 > tpmtPublic.length) revert ParseOffsetOutOfBounds();
        uint16 kdfScheme = uint16(bytes2(tpmtPublic[offset:offset + 2]));
        offset += 2;
        if (kdfScheme != TPMConstants.TPM_ALG_NULL) {
            offset += 2; // skip kdf.hashAlg
        }

        // Extract x coordinate (TPM2B)
        if (offset + 2 > tpmtPublic.length) revert ParseOffsetOutOfBounds();
        uint16 xLen = uint16(bytes2(tpmtPublic[offset:offset + 2]));
        offset += 2;
        if (offset + xLen > tpmtPublic.length) revert ParseOffsetOutOfBounds();
        bytes memory xBytes = tpmtPublic[offset:offset + xLen];
        offset += xLen;

        // Extract y coordinate (TPM2B)
        if (offset + 2 > tpmtPublic.length) revert ParseOffsetOutOfBounds();
        uint16 yLen = uint16(bytes2(tpmtPublic[offset:offset + 2]));
        offset += 2;
        if (offset + yLen > tpmtPublic.length) revert ParseOffsetOutOfBounds();
        bytes memory yBytes = tpmtPublic[offset:offset + yLen];

        // Build uncompressed EC point (0x04 || x || y)
        if (xLen != 32 || yLen != 32) revert InvalidTpmtPublicType();
        bytes memory ecPoint = abi.encodePacked(uint8(0x04), xBytes, yBytes);

        pubkey = CertPubkey({algo: TPMConstants.TPM_ALG_ECC, params: curveID, data: ecPoint});
    }

    /// @dev Parses RSA TPMT_PUBLIC to extract public key and signature algorithm
    /// @param tpmtPublic The full TPMT_PUBLIC bytes
    /// @param offset The offset to start of TPMS_RSA_PARMS
    /// @return pubkey The RSA public key as DER-encoded RSAPublicKey
    /// @return sigAlgo The signature algorithm from scheme fields
    function _parseRsaPublic(bytes calldata tpmtPublic, uint256 offset)
        private
        pure
        returns (CertPubkey memory pubkey, SignatureAlgorithm memory sigAlgo)
    {
        // TPMS_RSA_PARMS: symmetric(2+) + scheme(2+) + keyBits(2) + exponent(4)
        if (offset + 2 > tpmtPublic.length) revert ParseOffsetOutOfBounds();

        // Parse symmetric
        uint16 symmetricAlgo = uint16(bytes2(tpmtPublic[offset:offset + 2]));
        offset += 2;
        if (symmetricAlgo != TPMConstants.TPM_ALG_NULL) {
            offset += 4; // skip keyBits + mode
        }

        // Parse scheme
        if (offset + 2 > tpmtPublic.length) revert ParseOffsetOutOfBounds();
        sigAlgo.scheme = uint16(bytes2(tpmtPublic[offset:offset + 2]));
        offset += 2;

        if (sigAlgo.scheme != TPMConstants.TPM_ALG_NULL) {
            // Extract hashAlg
            if (offset + 2 > tpmtPublic.length) revert ParseOffsetOutOfBounds();
            sigAlgo.hashAlgo = uint16(bytes2(tpmtPublic[offset:offset + 2]));
            offset += 2;
        }

        // Skip keyBits (not needed for CertPubkey)
        offset += 2;

        // Parse exponent (uint32, 0 means 65537)
        if (offset + 4 > tpmtPublic.length) revert ParseOffsetOutOfBounds();
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
        if (offset + 2 > tpmtPublic.length) revert ParseOffsetOutOfBounds();
        uint16 nLen = uint16(bytes2(tpmtPublic[offset:offset + 2]));
        offset += 2;
        if (offset + nLen > tpmtPublic.length) revert ParseOffsetOutOfBounds();
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
