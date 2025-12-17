// SPDX-License-Identifier: MIT
// Automata Contracts
pragma solidity ^0.8.15;

import {Asn1Decode, NodePtr} from "./Asn1Decode.sol";
import {LibBytes} from "./LibBytes.sol";
import {DateTimeLib} from "@solady/utils/DateTimeLib.sol";

import {TPMConstants} from "../types/TPMConstants.sol";
import {
    NotEcPublicKey,
    NotRsaPublicKey,
    UnknownSignatureAlgorithm,
    CertificateExpired,
    InvalidCertChainLength,
    UnknownPublicKeyAlgorithm,
    Asn1PointerOutOfBounds,
    UnsupportedECCurve,
    RsaModulusEmpty,
    RsaExponentEmpty,
    InvalidRsaModulusSize,
    InvalidRsaExponentSize,
    RsaModulusNotOdd,
    RsaModulusLengthOverflow,
    InvalidRsaPubkeyFormat,
    InvalidSignatureSize,
    InvalidEcdsaSignatureFormat,
    EcdsaComponentTooLarge,
    InvalidAsn1Tag,
    LeafCertHasPathLen,
    IssuerCertMissingBasicConstraints,
    LeafCertHasKeyCertSign,
    MissingKeyUsageExtension,
    InvalidBooleanLength,
    InvalidBitString,
    CompressedPublicKeyNotSupported,
    LeafCertIsCa,
    CertNotCa,
    PathLenConstraintViolated,
    KeyCertSignNotSet,
    InvalidBasicConstraintsFormat,
    InvalidTimeTag,
    InvalidTimeFormat,
    InvalidSkidFormat,
    InvalidAkidFormat,
    CertChainDNMismatch,
    CertChainAKIDMismatch,
    IssuerCertMissingSKID,
    InvalidSerialNumber,
    DeltaCRLNotSupported,
    PartitionedCRLNotSupported
} from "../types/Errors.sol";

using LibX509 for CertPubkey global;

/// @notice Represents a public key extracted from an X.509 certificate
/// @dev This struct encapsulates the algorithm type, parameters, and raw key data
///      for both RSA and EC public keys used in certificate chain verification.
struct CertPubkey {
    /// @notice Algorithm identifier from TPMConstants (TPM_ALG_RSA or TPM_ALG_ECC)
    uint16 algo;
    /// @notice Algorithm-specific parameters
    /// @dev For RSA (TPM_ALG_RSA): always 0 (parameters are embedded in the key data)
    ///      For EC (TPM_ALG_ECC): curve identifier (e.g., TPM_ECC_NIST_P256)
    uint16 params;
    /// @notice The raw public key data
    /// @dev For RSA: DER-encoded RSAPublicKey SEQUENCE containing modulus n and exponent e
    ///      For EC P-256: 65 bytes in uncompressed format (0x04 || x || y)
    bytes data;
}

/// @notice Signature algorithm parameters extracted from X.509 signatureAlgorithm OID
/// @dev Contains both the signature scheme and the hash algorithm used for signing
struct SignatureAlgorithm {
    /// @notice Signature scheme identifier (e.g., TPM_ALG_RSASSA, TPM_ALG_ECDSA)
    uint16 scheme;
    /// @notice Hash algorithm identifier (e.g., TPM_ALG_SHA256)
    uint16 hashAlgo;
}

/// @notice X.509 Certificate Revocation List (CRL) structure
/// @dev Simplified structure of a DER-decoded X.509 CRL per RFC 5280
struct CRLInfo {
    bytes issuerDN;
    bytes authorityKeyId;
    uint256 thisUpdate;
    uint256 nextUpdate;
    uint256[] revokedSerials;
    bytes signature;
    bytes tbs;
}

/// @title LibX509
/// @notice A library for parsing and validating X.509 certificates
/// @dev This library provides functions for:
///      - Extracting certificate fields (TBS, signature, public key, validity, extensions)
///      - Parsing and validating RSA and EC P-256 public keys
///      - Checking certificate constraints (BasicConstraints, KeyUsage)
///      - Building certificate chain hashes for verification
///
/// @dev Supported algorithms:
///      - Public keys: RSA (2048-4096 bit), EC P-256
///      - Signature algorithms: sha256WithRSAEncryption, ecdsa-with-SHA256
///
/// @custom:security-contact security@ata.network
library LibX509 {
    using Asn1Decode for bytes;
    using NodePtr for uint256;
    using LibBytes for bytes;

    /// @notice Creates a CertPubkey struct from raw RSA modulus and exponent
    /// @dev Constructs a DER-encoded RSAPublicKey SEQUENCE from the provided n and e values.
    ///      Validates RSA parameters according to NIST SP 800-57 recommendations.
    /// @param n The RSA modulus (must be 2048-4096 bits, odd)
    /// @param e The RSA public exponent (must be >= 65537)
    /// @return A CertPubkey struct with TPM_ALG_RSA algorithm and DER-encoded key data
    function newRsaPubkey(bytes memory n, bytes memory e) internal pure returns (CertPubkey memory) {
        // RSAPublicKey ::= SEQ { n, e }
        validateRsa(n, e);

        uint256 nLength = n[0] < 0x80 ? n.length : n.length + 1;
        uint256 eLength = e[0] < 0x80 ? e.length : e.length + 1;
        bytes memory der = abi.encodePacked(uint8(0x30), uint8(0x82), uint16(4 + nLength + 2 + eLength));
        if (n[0] >= 0x80) {
            der = abi.encodePacked(der, uint16(0x0282), uint16(nLength), uint8(0x0), n);
        } else {
            der = abi.encodePacked(der, uint16(0x0282), uint16(nLength), n);
        }
        if (e[0] >= 0x80) {
            der = abi.encodePacked(der, uint8(0x02), uint8(eLength), uint8(0x0), e);
        } else {
            der = abi.encodePacked(der, uint8(0x02), uint8(eLength), e);
        }

        return CertPubkey({algo: TPMConstants.TPM_ALG_RSA, params: 0, data: der});
    }

    /// @notice Checks if a CertPubkey struct is empty (has no key data)
    /// @param pubkey The public key struct to check
    /// @return True if the public key data is empty, false otherwise
    function empty(CertPubkey memory pubkey) internal pure returns (bool) {
        return pubkey.data.length == 0;
    }

    /// @notice Extracts the x and y coordinates from an EC P-256 public key
    /// @dev Validates that the key is EC P-256 and in uncompressed format (0x04 prefix).
    ///      Compressed public keys (0x02/0x03 prefix) are not supported.
    /// @param pubkey The EC P-256 public key struct
    /// @return x The x coordinate of the public key (32 bytes)
    /// @return y The y coordinate of the public key (32 bytes)
    function ecP256(CertPubkey memory pubkey) internal pure returns (bytes32, bytes32) {
        if (pubkey.algo != TPMConstants.TPM_ALG_ECC || pubkey.params != TPMConstants.TPM_ECC_NIST_P256) {
            revert NotEcPublicKey();
        }
        // Check uncompressed format (65 bytes, 0x04 prefix)
        if (pubkey.data.length != 65 || pubkey.data[0] != 0x04) {
            revert CompressedPublicKeyNotSupported();
        }
        bytes memory data = pubkey.data;
        bytes32 x;
        bytes32 y;
        assembly ("memory-safe") {
            x := mload(add(data, 0x21))
            y := mload(add(data, 0x41))
        }
        return (x, y);
    }

    /// @notice Validates RSA public key parameters according to security best practices
    /// @dev Implements the following security checks per NIST SP 800-57:
    ///      - Modulus n must be 2048-4096 bits (256-512 bytes)
    ///      - Modulus n must be odd (as n = p*q where p,q are odd primes)
    ///      - Exponent e must be >= 65537 to prevent small exponent attacks
    ///      - Length constraints for DER encoding compatibility
    /// @param n The RSA modulus bytes
    /// @param e The RSA public exponent bytes
    function validateRsa(bytes memory n, bytes memory e) internal pure {
        // Apply security checks consistent with newRsaPubkey function
        if (n.length == 0) revert RsaModulusEmpty();
        if (e.length == 0) revert RsaExponentEmpty();

        // Validate n is at least 2048 bits (256 bytes minimum)
        // This follows NIST SP 800-57 recommendations for RSA key sizes
        if (n.length < 256 || n.length > 512) revert InvalidRsaModulusSize();

        // Validate n is odd (all valid RSA moduli must be odd, as n = p*q where p,q are odd primes)
        if ((n[n.length - 1] & 0x01) == 0) revert RsaModulusNotOdd();

        // Validate e >= 65537 (NIST recommended minimum to prevent small exponent attacks)
        // Convert e bytes to uint256 for comparison (limit to first 32 bytes to prevent overflow)
        uint256 eValue;
        uint256 maxEBytes = e.length > 32 ? 32 : e.length;
        for (uint256 i; i < maxEBytes; i++) {
            eValue = (eValue << 8) | uint256(uint8(e[i]));
        }
        if (eValue < 65537) revert InvalidRsaExponentSize();

        uint256 nLength = n[0] < 0x80 ? n.length : n.length + 1;
        uint256 eLength = e[0] < 0x80 ? e.length : e.length + 1;

        // Fix the constant 65565 to 65535 (2^16 - 1) and ensure nLength fits in uint16
        // nLength should be at most 65535 to avoid uint16 truncation
        if (nLength > 65535) revert RsaModulusLengthOverflow();
        // Validate that eLength is reasonable (typically 1-3 bytes for common exponents)
        if (eLength >= 0x80) revert InvalidRsaExponentSize();
    }

    /// @notice Extracts the modulus and exponent from an RSA public key
    /// @dev Per RFC 3279 Section 2.3.1, RSA public key is: RSAPublicKey ::= SEQUENCE { modulus n, publicExponent e }
    ///      This function parses the DER-encoded RSA public key and extracts n and e.
    ///      Leading zero bytes in the modulus are trimmed to return the minimal representation.
    /// @param pubkey The RSA public key struct
    /// @return n The RSA modulus (leading zeros trimmed)
    /// @return e The RSA public exponent
    function rsa(CertPubkey memory pubkey) internal pure returns (bytes memory n, bytes memory e) {
        if (pubkey.algo != TPMConstants.TPM_ALG_RSA) {
            revert NotRsaPublicKey();
        }
        if (pubkey.data.length < 10 || pubkey.data[0] != 0x30) revert InvalidRsaPubkeyFormat();

        uint256 root = pubkey.data.root();
        uint256 parentPtr = pubkey.data.firstChildOf(root);
        uint256 next = pubkey.data.nextSiblingOf(parentPtr);
        n = pubkey.data.bytesAt(parentPtr);

        // trim prefix 0
        for (uint256 i; i < n.length; i++) {
            if (n[i] != 0x00) {
                if (i > 0) {
                    n = n.slice(i, n.length - i);
                }
                break;
            }
        }
        e = pubkey.data.bytesAt(next);
        validateRsa(n, e);
    }

    /// @notice Parses X.509 signatureAlgorithm OID to extract signature scheme and hash algorithm
    /// @dev This function determines the cryptographic algorithms used to sign a certificate
    ///      by decoding the signatureAlgorithm OID from the certificate structure.
    ///
    ///      The signatureAlgorithm OID encodes both:
    ///      1. The signature scheme (e.g., RSASSA/PKCS#1 v1.5, ECDSA)
    ///      2. The hash algorithm (e.g., SHA-256)
    ///
    ///      Example OIDs:
    ///      - sha256WithRSAEncryption (1.2.840.113549.1.1.11): RSASSA + SHA256
    ///      - ecdsa-with-SHA256 (1.2.840.10045.4.3.2): ECDSA + SHA256
    ///
    /// @param pubkey The public key from the issuer certificate (used to validate compatibility)
    /// @param sigAlgoOid The signatureAlgorithm OID bytes from the certificate being verified
    /// @return sigAlgo Parsed signature algorithm parameters (scheme and hash algorithm)
    ///
    /// @dev Supported algorithm combinations:
    ///      RSA + SHA-256: OID 1.2.840.113549.1.1.11 (hex: 2a864886f70d01010b)
    ///      EC + SHA-256:  OID 1.2.840.10045.4.3.2 (hex: 2a8648ce3d040302)
    ///
    /// @dev Reverts with UnknownPublicKeyAlgorithm if:
    ///      - The OID is not recognized
    ///      - The signature algorithm is incompatible with the public key type
    function parseSignatureAlgorithm(CertPubkey memory pubkey, bytes memory sigAlgoOid)
        internal
        pure
        returns (SignatureAlgorithm memory)
    {
        if (pubkey.algo == TPMConstants.TPM_ALG_RSA) {
            // RSA signature algorithms
            if (sigAlgoOid.equal(hex"2a864886f70d01010b")) {
                // sha256WithRSAEncryption: 1.2.840.113549.1.1.11
                return SignatureAlgorithm({scheme: TPMConstants.TPM_ALG_RSASSA, hashAlgo: TPMConstants.TPM_ALG_SHA256});
            }
        } else if (pubkey.algo == TPMConstants.TPM_ALG_ECC) {
            // ECDSA signature algorithms
            if (sigAlgoOid.equal(hex"2a8648ce3d040302")) {
                // ecdsa-with-SHA256: 1.2.840.10045.4.3.2
                return SignatureAlgorithm({scheme: TPMConstants.TPM_ALG_ECDSA, hashAlgo: TPMConstants.TPM_ALG_SHA256});
            }
        }

        revert UnknownSignatureAlgorithm(sigAlgoOid);
    }

    /// @notice Extracts the TBSCertificate (To Be Signed) portion from an X.509 certificate
    /// @dev The TBSCertificate is the portion of the certificate that is signed.
    ///      Certificate structure: SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    /// @param der The DER-encoded X.509 certificate bytes
    /// @return The DER-encoded TBSCertificate bytes (including tag and length)
    function getCertTbs(bytes memory der) internal pure returns (bytes memory) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        return der.allBytesAt(tbsParentPtr);
    }

    /// @notice Extracts the signature value from an X.509 certificate
    /// @dev The signature is the third field in the Certificate SEQUENCE, encoded as a BIT STRING.
    ///      This function returns the raw signature bytes (BIT STRING content without padding byte).
    /// @param der The DER-encoded X.509 certificate bytes
    /// @return The signature bytes (64-512 bytes depending on algorithm)
    function getCertSignature(bytes memory der) internal pure returns (bytes memory) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root); // tbs
        uint256 sigPtr = der.nextSiblingOf(tbsParentPtr); // sig algo
        sigPtr = der.nextSiblingOf(sigPtr); // sig
        bytes memory signature = der.bitstringAt(sigPtr);
        if (signature.length < 64 || signature.length > 512) revert InvalidSignatureSize();
        return signature;
    }

    /// @dev Extracts the signature algorithm OID from an X.509 certificate
    /// @notice The signature algorithm is located in the Certificate structure (not TBSCertificate):
    ///         Certificate ::= SEQUENCE {
    ///             tbsCertificate       TBSCertificate,
    ///             signatureAlgorithm   AlgorithmIdentifier,  ← extracted here
    ///             signatureValue       BIT STRING
    ///         }
    /// @param der The DER-encoded X.509 certificate bytes
    /// @return The OID bytes of the signature algorithm
    /// @dev Common signature algorithm OIDs:
    ///      - sha256WithRSAEncryption: 1.2.840.113549.1.1.11 (hex: 2a864886f70d01010b)
    ///      - sha1WithRSAEncryption: 1.2.840.113549.1.1.5 (hex: 2a864886f70d010105)
    ///      - ecdsa-with-SHA256: 1.2.840.10045.4.3.2 (hex: 2a8648ce3d040302)
    function getCertSignatureAlgorithm(bytes memory der) internal pure returns (bytes memory) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root); // tbs
        uint256 sigAlgoPtr = der.nextSiblingOf(tbsParentPtr); // signatureAlgorithm SEQUENCE
        uint256 oidPtr = der.firstChildOf(sigAlgoPtr); // algorithm OID
        return der.bytesAt(oidPtr);
    }

    /// @notice Extracts the serial number from an X.509 certificate
    /// @dev The serial number is an INTEGER in the TBSCertificate, after the optional version field.
    ///      TBSCertificate: [version] -> serialNumber -> ...
    /// @param der The DER-encoded X.509 certificate bytes
    /// @return The serial number bytes (as stored in the INTEGER field)
    function getCertSerialNumberBytes(bytes memory der) internal pure returns (bytes memory) {
        uint256 tbsPtr = _tbsPtr(der);

        // Check if first field is version (tag 0xA0)
        uint256 tag = uint8(der[tbsPtr.ixs()]);
        if (tag == 0xA0) {
            // Version exists, serialNumber is next sibling
            tbsPtr = der.nextSiblingOf(tbsPtr);
        }
        // else: no version field, tbsPtr is already pointing to serialNumber

        // serialNumber should be an INTEGER (tag 0x02)
        if (uint8(der[tbsPtr.ixs()]) != 0x02) revert InvalidAsn1Tag();
        return der.bytesAt(tbsPtr);
    }

    /// @notice Extracts the serial number from an X.509 certificate
    /// @dev The serial number is an INTEGER in the TBSCertificate, after the optional version field.
    ///      TBSCertificate: [version] -> serialNumber -> ...
    /// @param der The DER-encoded X.509 certificate bytes
    /// @return The serial number uint256 (as stored in the INTEGER field)
    function getCertSerialNumber(bytes memory der) internal pure returns (uint256) {
        return _parseSerialNumber(getCertSerialNumberBytes(der));
    }

    /// @dev Parse certificate serial number bytes to uint256 with RFC 5280 validation
    /// @param serialBytes The serial number in bytes format (ASN.1 DER INTEGER content)
    /// @return serial The serial number as uint256
    /// @custom:throws SerialNumberTooLarge if serial number exceeds 20 octets (RFC 5280 Section 4.1.2.2)
    /// @custom:throws SerialNumberNegative if serial number is negative (high bit set without padding)
    /// @dev Per RFC 5280 Section 4.1.2.2:
    ///      - Serial numbers MUST be positive integers
    ///      - Conforming CAs MUST NOT use serial numbers longer than 20 octets
    ///      - In ASN.1 DER, a leading 0x00 byte is added if high bit is set (to indicate positive)
    /// @notice This function allows serial=0 for compatibility with non-conforming CAs
    ///         (e.g., AMD SEV-VCEK certs). Callers should validate serial != 0 if strict compliance is required.
    function _parseSerialNumber(bytes memory serialBytes) internal pure returns (uint256 serial) {
        uint256 len = serialBytes.length;

        // Empty serial number is invalid (not even zero is encoded this way)
        if (len == 0) {
            revert InvalidSerialNumber();
        }

        // Check for negative number: in ASN.1 DER, if high bit is set without leading 0x00, it's negative
        // If first byte has high bit set (>= 0x80), it's negative
        if (uint8(serialBytes[0]) >= 0x80) {
            revert InvalidSerialNumber();
        }

        // Handle leading zero byte (used to indicate positive when high bit would be set)
        uint256 valueLen = len;
        uint256 offset = 0;
        if (len > 1 && serialBytes[0] == 0x00) {
            // Leading 0x00 is only valid if the next byte has high bit set (>= 0x80)
            // Otherwise, the leading zero is unnecessary and the DER is malformed
            if (uint8(serialBytes[1]) < 0x80) {
                revert InvalidSerialNumber();
            }
            offset = 1;
            valueLen = len - 1;
        }

        // Per RFC 5280 Section 4.1.2.2: serial number MUST NOT exceed 20 octets
        if (valueLen > 20) {
            revert InvalidSerialNumber();
        }

        // Parse to uint256 (valueLen <= 20 <= 32, so this is safe)
        // Skip leading zero padding and parse big-endian bytes
        // Note: This function allows serial=0 for compatibility with non-conforming CAs
        // (e.g., AMD SEV-VCEK certs use serial=0). Callers should validate if needed.
        for (uint256 i = offset; i < len; i++) {
            serial = (serial << 8) | uint8(serialBytes[i]);
        }
    }

    /// @notice Extracts the issuer Distinguished Name (DN) from an X.509 certificate
    /// @dev The issuer is a Name (SEQUENCE of RDNs) in the TBSCertificate.
    ///      TBSCertificate: [version] -> serialNumber -> signature -> issuer -> ...
    /// @param der The DER-encoded X.509 certificate bytes
    /// @return The DER-encoded issuer DN (entire SEQUENCE including tag and length)
    function getCertIssuerDN(bytes memory der) internal pure returns (bytes memory) {
        uint256 tbsPtr = _tbsPtr(der);

        // Navigate to issuer field
        // TBSCertificate: [version] -> serialNumber -> signature -> issuer
        // Skip version if exists
        uint256 tag = uint8(der[tbsPtr.ixs()]);
        if (tag == 0xA0) {
            tbsPtr = der.nextSiblingOf(tbsPtr); // skip version
        }
        tbsPtr = der.nextSiblingOf(tbsPtr); // skip serialNumber
        tbsPtr = der.nextSiblingOf(tbsPtr); // skip signature, now at issuer

        // issuer should be a SEQUENCE (tag 0x30)
        if (uint8(der[tbsPtr.ixs()]) != 0x30) revert InvalidAsn1Tag();
        return der.allBytesAt(tbsPtr);
    }

    /// @notice Extracts the Subject Distinguished Name (DN) from an X.509 certificate
    /// @dev Per RFC 5280 Section 4.1.2.6, the subject field identifies the entity
    ///      associated with the public key stored in the subject public key field.
    ///      TBSCertificate structure:
    ///      [version] -> serialNumber -> signature -> issuer -> validity -> subject
    /// @param der The DER-encoded X.509 certificate bytes
    /// @return The DER-encoded Subject DN (including the SEQUENCE tag and length)
    function getCertSubjectDN(bytes memory der) internal pure returns (bytes memory) {
        uint256 tbsPtr = _tbsPtr(der);

        // Navigate to subject field
        // TBSCertificate: [version] -> serialNumber -> signature -> issuer -> validity -> subject
        // Skip version if exists
        uint256 tag = uint8(der[tbsPtr.ixs()]);
        if (tag == 0xA0) {
            tbsPtr = der.nextSiblingOf(tbsPtr); // skip version
        }
        tbsPtr = der.nextSiblingOf(tbsPtr); // skip serialNumber
        tbsPtr = der.nextSiblingOf(tbsPtr); // skip signature
        tbsPtr = der.nextSiblingOf(tbsPtr); // skip issuer
        tbsPtr = der.nextSiblingOf(tbsPtr); // skip validity, now at subject

        // subject should be a SEQUENCE (tag 0x30)
        if (uint8(der[tbsPtr.ixs()]) != 0x30) revert InvalidAsn1Tag();
        return der.allBytesAt(tbsPtr);
    }

    /// @dev Extracts Subject Key Identifier extension from an X.509 certificate
    /// @notice SKID is encoded as OCTET STRING containing the key identifier
    /// @notice Per RFC 5280 Section 4.2.1.2: SubjectKeyIdentifier ::= KeyIdentifier
    ///         where KeyIdentifier ::= OCTET STRING
    /// @param der The DER-encoded certificate bytes
    /// @return exists Whether the SKID extension exists
    /// @return skid The subject key identifier bytes
    function getSubjectKeyIdentifier(bytes memory der) internal pure returns (bool exists, bytes memory skid) {
        // OID for SubjectKeyIdentifier: 2.5.29.14
        (bool found, bytes memory skidValue) = _getExtension(der, hex"551D0E");
        if (!found) {
            return (false, "");
        }

        exists = true;

        // SKID is encoded as OCTET STRING within an OCTET STRING
        // skidValue should contain: [OCTET STRING tag][length][key identifier bytes]
        if (skidValue.length < 2 || skidValue[0] != 0x04) {
            revert InvalidSkidFormat();
        }

        uint8 length = uint8(skidValue[1]);
        // Handle multi-byte length encoding
        if (length > 0x80) {
            revert InvalidSkidFormat();
        }

        if (skidValue.length < 2 + length) {
            revert InvalidSkidFormat();
        }

        // Extract the key identifier bytes (skip tag and length)
        skid = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            skid[i] = skidValue[2 + i];
        }

        return (exists, skid);
    }

    /// @dev Extracts Authority Key Identifier extension from an X.509 certificate
    /// @notice AKID can contain: keyIdentifier, authorityCertIssuer, authorityCertSerialNumber
    ///         This implementation only extracts the keyIdentifier field
    /// @notice Per RFC 5280 Section 4.2.1.1:
    ///         AuthorityKeyIdentifier ::= SEQUENCE {
    ///             keyIdentifier             [0] IMPLICIT OCTET STRING OPTIONAL,
    ///             authorityCertIssuer       [1] IMPLICIT GeneralNames OPTIONAL,
    ///             authorityCertSerialNumber [2] IMPLICIT INTEGER OPTIONAL
    ///         }
    /// @param der The DER-encoded certificate bytes
    /// @return exists Whether the AKID extension exists
    /// @return akid The authority key identifier bytes (only keyIdentifier field)
    function getAuthorityKeyIdentifier(bytes memory der) internal pure returns (bool exists, bytes memory akid) {
        // OID for AuthorityKeyIdentifier: 2.5.29.35
        (bool found, bytes memory akidValue) = _getExtension(der, hex"551D23");
        if (!found) {
            return (false, "");
        }

        exists = true;

        // AKID is encoded as SEQUENCE within an OCTET STRING
        if (akidValue.length < 2 || akidValue[0] != 0x30) {
            revert InvalidAkidFormat();
        }

        uint256 seqPtr = akidValue.root();
        uint256 firstChild = akidValue.firstChildOf(seqPtr);
        if (firstChild == 0) {
            return (exists, "");
        }

        // keyIdentifier has context-specific tag [0] (0x80)
        uint256 tag = uint8(akidValue[firstChild.ixs()]);
        if (tag == 0x80) {
            // This is the keyIdentifier field
            akid = akidValue.bytesAt(firstChild);
            return (exists, akid);
        }

        // keyIdentifier not present (only authorityCertIssuer/authorityCertSerialNumber)
        return (exists, "");
    }

    /// @notice Verifies DN (Distinguished Name) chain linkage per RFC 5280 Section 6.1.4(a)
    /// @dev Each certificate's issuer DN must match its signing certificate's subject DN
    /// @param certs Array of certificates in the chain (leaf to root order)
    /// @custom:throws CertChainDNMismatch if any issuer DN doesn't match the expected subject DN
    function verifyDNChainLinkage(bytes[] memory certs) internal pure {
        for (uint256 i = 0; i < certs.length - 1; i++) {
            bytes memory issuerDN = getCertIssuerDN(certs[i]);
            bytes memory subjectDN = getCertSubjectDN(certs[i + 1]);

            if (keccak256(issuerDN) != keccak256(subjectDN)) {
                revert CertChainDNMismatch(i, issuerDN, subjectDN);
            }
        }
    }

    /// @notice Verifies AKID/SKID chain linkage per RFC 5280 Section 6.1.4(d)
    /// @dev RFC 5280 Section 4.2.1.2: SKID MUST appear in all conforming CA certificates
    ///      RFC 5280 Section 4.2.1.1:
    ///      - For CA certificates: AKID MUST be included when issuer has SKID
    ///      - For end entity (leaf) certificates: AKID SHOULD be included
    ///      RFC 5280 Section 6.1.4(d): If issuer has SKID, verify AKID matches
    /// @param certs Array of certificates in the chain (leaf to root order)
    /// @custom:throws IssuerCertMissingSKID if CA cert lacks required SKID extension
    /// @custom:throws CertChainAKIDMismatch if CA cert lacks AKID when issuer has SKID, or if AKID/SKID mismatch
    function verifyAKIDSKIDChainLinkage(bytes[] memory certs) internal pure {
        for (uint256 i = 0; i < certs.length - 1; i++) {
            // Per RFC 5280 Section 4.2.1.2: SKID MUST appear in all conforming CA certificates
            // certs[i+1] is the issuer (a CA certificate) for certs[i]
            (bool skidExists, bytes memory skid) = getSubjectKeyIdentifier(certs[i + 1]);
            if (!skidExists || skid.length == 0) {
                // Issuer CA cert is missing required SKID extension
                revert IssuerCertMissingSKID();
            }

            (bool akidExists, bytes memory akid) = getAuthorityKeyIdentifier(certs[i]);
            if (!akidExists || akid.length == 0) {
                // Issuer has SKID but current cert lacks AKID
                if (i > 0) {
                    // For CA/Intermediate certs: AKID is required
                    revert CertChainAKIDMismatch(i, akid, skid);
                } else {
                    // For leaf cert: AKID is optional (SHOULD, not MUST per RFC 5280)
                    continue;
                }
            }

            if (keccak256(akid) != keccak256(skid)) {
                revert CertChainAKIDMismatch(i, akid, skid);
            }
        }
    }

    /// @notice Checks if a certificate is currently valid based on its validity period
    /// @dev Compares the certificate's notBefore and notAfter times against the current block timestamp.
    ///      Reverts if the certificate has expired or is not yet valid.
    /// @param ca The DER-encoded X.509 certificate bytes
    function checkCertValidity(bytes memory ca) internal view {
        (uint256 validityNotBefore, uint256 validityNotAfter) = getCertValidity(ca);
        if (validityNotBefore > block.timestamp || block.timestamp > validityNotAfter) {
            revert CertificateExpired();
        }
    }

    /// @notice Extracts the validity period (notBefore and notAfter) from an X.509 certificate
    /// @dev The validity field is in the TBSCertificate: [version] -> serialNumber -> signature -> issuer -> validity
    ///      Times are converted from ASN.1 UTCTime or GeneralizedTime to Unix timestamps.
    /// @param der The DER-encoded X.509 certificate bytes
    /// @return validityNotBefore Unix timestamp when the certificate becomes valid
    /// @return validityNotAfter Unix timestamp when the certificate expires
    function getCertValidity(bytes memory der)
        internal
        pure
        returns (uint256 validityNotBefore, uint256 validityNotAfter)
    {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        uint256 tbsPtr = der.firstChildOf(tbsParentPtr);

        // Check for optional version field
        uint256 tag = uint8(der[tbsPtr.ixs()]);
        if (tag == 0xA0) {
            tbsPtr = der.nextSiblingOf(tbsPtr); // skip version
        }
        // Now tbsPtr points to serialNumber regardless of whether version existed

        tbsPtr = der.nextSiblingOf(tbsPtr); // signature
        tbsPtr = der.nextSiblingOf(tbsPtr); // issuer
        tbsPtr = der.nextSiblingOf(tbsPtr); // validity
        (validityNotBefore, validityNotAfter) = _getValidity(der, tbsPtr);
    }

    /// @dev Extracts the subject's public key from an X.509 certificate
    /// @notice This function navigates through the TBSCertificate structure to locate the subjectPublicKeyInfo field.
    ///         The navigation path skips: version (if present), serialNumber, signature, issuer, validity, and subject
    ///         to reach the subjectPublicKeyInfo field at position 7 in the TBSCertificate sequence.
    /// @notice TBSCertificate structure (RFC 5280):
    ///         1. version [0] EXPLICIT (optional)
    ///         2. serialNumber
    ///         3. signature (algorithm)
    ///         4. issuer
    ///         5. validity
    ///         6. subject
    ///         7. subjectPublicKeyInfo ← this function extracts the public key from here
    /// @param der The DER-encoded X.509 certificate bytes
    /// @return CertPubkey The subject's public key, including algorithm type (RSA/EC) and key data
    function getPubkey(bytes calldata der) internal pure returns (CertPubkey memory) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        uint256 tbsPtr = der.firstChildOf(tbsParentPtr);

        // Check for optional version field
        uint256 tag = uint8(der[tbsPtr.ixs()]);
        if (tag == 0xA0) {
            tbsPtr = der.nextSiblingOf(tbsPtr); // skip version
        }
        // Now tbsPtr points to serialNumber regardless of whether version existed

        tbsPtr = der.nextSiblingOf(tbsPtr); // signature
        tbsPtr = der.nextSiblingOf(tbsPtr); // issuer
        tbsPtr = der.nextSiblingOf(tbsPtr); // validity
        tbsPtr = der.nextSiblingOf(tbsPtr); // subject
        tbsPtr = der.nextSiblingOf(tbsPtr); // subjectPublicKeyInfo
        CertPubkey memory subjectPublicKey = _getSubjectPublicKey(der, tbsPtr);
        return subjectPublicKey;
    }

    /// @dev Encodes r and s components into a DER-encoded ECDSA signature
    /// @notice Produces a DER-encoded signature in the format:
    ///         ECDSA-Sig-Value ::= SEQUENCE {
    ///             r INTEGER,
    ///             s INTEGER
    ///         }
    ///         This function properly handles DER INTEGER encoding rules:
    ///         - Removes leading zero bytes (except when needed for sign bit)
    ///         - Adds 0x00 prefix byte if the high bit is set (to indicate positive number)
    /// @param r The r component of the signature (32 bytes for P-256)
    /// @param s The s component of the signature (32 bytes for P-256)
    /// @return der The DER-encoded ECDSA signature bytes
    function encodeEcdsaSignature(bytes32 r, bytes32 s) internal pure returns (bytes memory der) {
        // Process r
        uint256 rLen = 32;
        while (rLen > 1 && r[32 - rLen] == 0) {
            rLen--;
        }
        // If high bit is set, need to add 0x00 prefix for DER encoding
        bool rNeedsPrefix = uint8(r[32 - rLen]) >= 0x80;
        uint256 rTotalLen = rLen + (rNeedsPrefix ? 1 : 0);
        bytes memory rBytes = new bytes(rTotalLen);
        assembly ("memory-safe") {
            let ptr := add(rBytes, 0x20)

            if rNeedsPrefix {
                mstore8(ptr, 0x00)
                ptr := add(ptr, 1)
            }

            let shift := mul(sub(32, rLen), 8)
            mstore(ptr, shl(shift, r))
        }

        // Process s
        uint256 sLen = 32;
        while (sLen > 1 && s[32 - sLen] == 0) {
            sLen--;
        }
        // If high bit is set, need to add 0x00 prefix for DER encoding
        bool sNeedsPrefix = uint8(s[32 - sLen]) >= 0x80;
        uint256 sTotalLen = sLen + (sNeedsPrefix ? 1 : 0);

        bytes memory sBytes = new bytes(sTotalLen);
        assembly ("memory-safe") {
            let ptr := add(sBytes, 0x20)

            if sNeedsPrefix {
                mstore8(ptr, 0x00)
                ptr := add(ptr, 1)
            }

            let shift := mul(sub(32, sLen), 8)
            mstore(ptr, shl(shift, s))
        }

        // Build DER SEQUENCE
        // SEQUENCE = 0x30 [length] [INTEGER r] [INTEGER s]
        // INTEGER = 0x02 [length] [data]
        uint256 sequenceContentLen = 2 + rTotalLen + 2 + sTotalLen; // (tag+len+data) for r and s
        der = abi.encodePacked(
            uint8(0x30), // SEQUENCE tag
            uint8(sequenceContentLen), // SEQUENCE length
            uint8(0x02), // INTEGER tag for r
            uint8(rTotalLen), // r length
            rBytes, // r data
            uint8(0x02), // INTEGER tag for s
            uint8(sTotalLen), // s length
            sBytes // s data
        );
    }

    /// @dev Decodes a DER-encoded ECDSA signature into r and s components
    /// @notice ECDSA signatures in X.509 certificates are DER-encoded as:
    ///         ECDSA-Sig-Value ::= SEQUENCE {
    ///             r INTEGER,
    ///             s INTEGER
    ///         }
    ///         This function extracts r and s, removing any leading zero padding bytes
    ///         that may be present in the DER INTEGER encoding.
    /// @param der The DER-encoded ECDSA signature bytes
    /// @return r The r component of the signature (32 bytes for P-256)
    /// @return s The s component of the signature (32 bytes for P-256)
    /// @dev Reverts if the signature is not a valid DER SEQUENCE or if r/s are not INTEGERs
    function decodeEcdsaSignature(bytes memory der) internal pure returns (bytes32 r, bytes32 s) {
        // The signature should be a SEQUENCE
        if (der.length == 0 || der[0] != 0x30) revert InvalidEcdsaSignatureFormat();

        uint256 root = der.root();
        uint256 rPtr = der.firstChildOf(root);
        uint256 sPtr = der.nextSiblingOf(rPtr);

        if (rPtr == 0 || sPtr == 0) revert InvalidEcdsaSignatureFormat();

        // Extract r and s as bytes
        bytes memory rBytes = der.bytesAt(rPtr);
        bytes memory sBytes = der.bytesAt(sPtr);

        // Remove leading zero bytes if present (DER encoding adds 0x00 prefix for positive integers with high bit set)
        uint256 rStart;
        while (rStart < rBytes.length && rBytes[rStart] == 0x00) {
            rStart++;
        }

        uint256 sStart;
        while (sStart < sBytes.length && sBytes[sStart] == 0x00) {
            sStart++;
        }

        // For P-256, r and s should be at most 32 bytes after removing leading zeros
        uint256 rLen = rBytes.length - rStart;
        uint256 sLen = sBytes.length - sStart;
        if (rLen > 32 || sLen > 32) revert EcdsaComponentTooLarge();

        // Convert to bytes32, padding on the left if necessary
        assembly ("memory-safe") {
            // Load r into bytes32
            let rDataPtr := add(add(rBytes, 0x20), rStart)
            r := mload(rDataPtr)
            // If rLen < 32, we need to right-shift to align the data
            if lt(rLen, 32) { r := shr(mul(sub(32, rLen), 8), r) }

            // Load s into bytes32
            let sDataPtr := add(add(sBytes, 0x20), sStart)
            s := mload(sDataPtr)
            // If sLen < 32, we need to right-shift to align the data
            if lt(sLen, 32) { s := shr(mul(sub(32, sLen), 8), s) }
        }
    }

    /// @dev Validates CA certificate constraints during chain verification
    /// @notice This function checks BasicConstraints (CA flag, pathLen) and KeyUsage (keyCertSign) for CA certificates
    /// @param der The DER-encoded certificate bytes
    /// @param remainingCAs The number of CA certificates that appear AFTER this certificate in the chain
    ///                     (excluding leaf certificates). For example:
    ///                     - Root CA → Intermediate CA → Leaf: when checking Root, remainingCAs = 1
    ///                     - Root CA → Leaf: when checking Root, remainingCAs = 0
    ///                     - Intermediate CA → Leaf: when checking Intermediate, remainingCAs = 0
    /// @dev Per RFC 5280 Section 4.2.1.9: "pathLenConstraint gives the maximum number of non-self-issued
    ///      intermediate CA certificates that may follow this certificate in a valid certification path."
    /// @dev Per RFC 5280 Section 4.2.1.3: KeyUsage extension with keyCertSign bit must be set for CA certificates
    function checkCAConstraints(bytes memory der, uint256 remainingCAs, bool isLeaf) internal pure {
        // Check BasicConstraints
        (bool bcExists, bool isCA, bool hasPathLen, uint256 pathLen) = getBasicConstraints(der);
        if (isLeaf) {
            if (isCA) revert LeafCertIsCa();
            if (hasPathLen) revert LeafCertHasPathLen();
        } else {
            if (!bcExists) revert IssuerCertMissingBasicConstraints();
            if (!isCA) revert CertNotCa();

            if (hasPathLen) {
                if (remainingCAs > pathLen) revert PathLenConstraintViolated();
            }
        }

        // Check KeyUsage - keyCertSign bit (0x0400) must be set if extension exists
        (bool kuExists, uint16 keyUsage) = getKeyUsage(der);
        if (isLeaf) {
            // Leaf certificates can have KeyUsage (for digitalSignature, keyEncipherment, etc.)
            // but must not have keyCertSign bit
            if (kuExists) {
                uint16 KEY_USAGE_KEY_CERT_SIGN = 0x0400;
                if ((keyUsage & KEY_USAGE_KEY_CERT_SIGN) != 0) revert LeafCertHasKeyCertSign();
            }
        } else {
            // Per RFC 5280 Section 4.2.1.3, KeyUsage extension MUST be present in CA certificates
            // that are used to validate digital signatures on other public keys or on CRLs
            if (!kuExists) revert MissingKeyUsageExtension();

            uint16 KEY_USAGE_KEY_CERT_SIGN = 0x0400;
            if ((keyUsage & KEY_USAGE_KEY_CERT_SIGN) == 0) revert KeyCertSignNotSet();
        }
    }

    /// @dev Extracts BasicConstraints extension from an X.509 certificate
    /// @notice BasicConstraints ::= SEQUENCE {
    ///     cA BOOLEAN DEFAULT FALSE,
    ///     pathLenConstraint INTEGER (0..MAX) OPTIONAL
    /// }
    /// Per RFC 5280 Section 4.2.1.9: "The pathLenConstraint field is meaningful only if the cA boolean is asserted"
    /// Therefore, hasPathLen and pathLen will only have meaningful values when isCA is TRUE.
    /// @notice Empty sequence (0x3000) is treated as not exists
    /// @param der The DER-encoded certificate bytes
    /// @return exists Whether the BasicConstraints extension exists
    /// @return isCA Whether this certificate is a CA certificate
    /// @return hasPathLen Whether pathLenConstraint is present (only meaningful when isCA is TRUE)
    /// @return pathLen The maximum number of CA certificates in the chain (only valid when isCA is TRUE and hasPathLen
    /// is true)
    function getBasicConstraints(bytes memory der)
        internal
        pure
        returns (bool exists, bool isCA, bool hasPathLen, uint256 pathLen)
    {
        // OID for BasicConstraints: 2.5.29.19
        (bool found, bytes memory bcValue) = _getExtension(der, hex"551D13");
        if (!found) {
            return (false, false, false, 0);
        }

        // BasicConstraints is encoded as a SEQUENCE within an OCTET STRING
        // bcValue should contain: [SEQUENCE tag][length][content...]
        // Validate SEQUENCE structure: minimum length is 2 bytes (tag + length)
        if (bcValue.length < 2 || bcValue[0] != 0x30) {
            revert InvalidBasicConstraintsFormat();
        }

        // Check for empty SEQUENCE (0x3000)
        if (bcValue.length == 2 && bcValue[1] == 0x00) {
            return (false, false, false, 0);
        }

        exists = true;
        uint256 seqPtr = bcValue.root();
        uint256 firstChild = bcValue.firstChildOf(seqPtr);
        if (firstChild == 0) {
            return (exists, false, false, 0);
        }
        uint256 tag = uint8(bcValue[firstChild.ixs()]);

        // First element is BOOLEAN (tag 0x01) - this is the cA field
        if (tag == 0x01) {
            uint256 len = firstChild.ixl() + 1 - firstChild.ixf();
            if (len != 1) revert InvalidBooleanLength();
            isCA = bcValue[firstChild.ixf()] != 0x00;

            // If cA is FALSE, we're done (pathLen is only meaningful when cA is TRUE)
            // This also ensures forward compatibility: we ignore any additional fields
            if (!isCA) {
                return (exists, false, false, 0);
            }

            // cA is TRUE: check for optional pathLenConstraint (INTEGER tag 0x02)
            uint256 nextNodeStart = firstChild.ixl() + 1 + len;
            if (nextNodeStart + 1 < bcValue.length) {
                uint256 nextSibling = bcValue.nextSiblingOf(firstChild);
                if (nextSibling != 0) {
                    uint256 nextTag = uint8(bcValue[nextSibling.ixs()]);
                    // Only read if it's an INTEGER (pathLenConstraint)
                    // Ignore other tags for forward compatibility with future extensions
                    if (nextTag == 0x02) {
                        hasPathLen = true;
                        pathLen = bcValue.uintAt(nextSibling);
                    }
                }
            }
        } else {
            // First element is not BOOLEAN, treat as: cA defaults to FALSE, no pathLen
            return (exists, false, false, 0);
        }

        return (exists, isCA, hasPathLen, pathLen);
    }

    /// @dev Extracts KeyUsage extension from an X.509 certificate
    /// @notice KeyUsage ::= BIT STRING {
    ///     digitalSignature        (0),
    ///     nonRepudiation          (1),
    ///     keyEncipherment         (2),
    ///     dataEncipherment        (3),
    ///     keyAgreement            (4),
    ///     keyCertSign             (5),
    ///     cRLSign                 (6),
    ///     encipherOnly            (7),
    ///     decipherOnly            (8)
    /// }
    /// Per RFC 5280 Section 4.2.1.3: Conforming CAs MUST include this extension in certificates that
    /// contain public keys that are used to validate digital signatures on other public key certificates or CRLs.
    /// @param der The DER-encoded certificate bytes
    /// @return exists Whether the KeyUsage extension exists
    /// @return keyUsage A 16-bit bitmap of key usage flags (bit 0 is MSB, following RFC 5280 bit ordering)
    function getKeyUsage(bytes memory der) internal pure returns (bool, uint16) {
        // OID for KeyUsage: 2.5.29.15
        bytes memory kuOid = hex"551D0F";
        (bool found, bytes memory kuValue) = _getExtension(der, kuOid);
        if (!found) {
            return (false, 0);
        }

        // KeyUsage is encoded as a BIT STRING within an OCTET STRING
        // kuValue should contain: [BIT STRING tag][length][unused bits][data bytes]
        if (kuValue.length < 3 || kuValue[0] != 0x03) {
            revert InvalidBitString();
        }

        uint8 length = uint8(kuValue[1]);
        uint8 unusedBits = uint8(kuValue[2]);
        if (unusedBits >= 8 || kuValue.length < 2 + length) revert InvalidBitString();
        uint256 dataLength = length - 1;
        uint16 keyUsage = 0;
        if (dataLength >= 1) {
            // First byte contains bits 0-7 (MSB ordering)
            keyUsage = uint16(uint8(kuValue[3])) << 8;
            if (dataLength >= 2) {
                // Second byte contains bits 8+ (e.g., decipherOnly at bit 8)
                keyUsage |= uint16(uint8(kuValue[4]));
            }
        }

        return (true, keyUsage);
    }

    /// @notice Computes a cumulative hash chain for certificate verification
    /// @dev This function creates a chain of hashes where each certificate's hash is combined
    ///      with all subsequent certificates' hashes, enabling efficient proof of the entire chain.
    ///
    /// @dev Algorithm:
    ///      Given certificates [cert0, cert1, cert2] (leaf to root order):
    ///      - certHashes[2] = hash(cert2)                                    // root certificate hash
    ///      - certHashes[1] = hash(hash(cert1) || certHashes[2])            // intermediate + root
    ///      - certHashes[0] = hash(hash(cert0) || certHashes[1])            // leaf + (intermediate + root)
    ///
    ///      This creates a Merkle-like structure where certHashes[0] represents the hash of the entire chain.
    ///
    /// @dev Security properties:
    ///      - Any modification to any certificate in the chain will change certHashes[0]
    ///      - The hash chain is built from root to leaf, ensuring dependency order
    ///      - Each hash commits to all certificates from that position to the root
    ///
    /// @param certs Array of DER-encoded certificates ordered from leaf (index 0) to root (last index)
    /// @return certHashes Array of cumulative hashes, same length as input:
    ///                    - certHashes[i] = hash of certificate i combined with all certificates after it
    ///                    - certHashes[0] represents the hash commitment of the entire certificate chain
    ///
    /// @dev Reverts with InvalidCertChainLength if the input array is empty
    function getCertChainHashes(bytes[] memory certs) internal pure returns (bytes32[] memory certHashes) {
        uint256 certLen = certs.length;
        if (certLen == 0) {
            revert InvalidCertChainLength();
        }

        certHashes = new bytes32[](certLen);

        // Build hash chain from root to leaf (backwards iteration)
        // Start with the root certificate (last element) and work towards the leaf (first element)
        for (uint256 i = certLen; i > 0;) {
            unchecked {
                --i; // Decrement first to avoid underflow issues
            }

            // Hash the current certificate
            certHashes[i] = keccak256(certs[i]);

            // If not the root certificate, combine with the next certificate's hash
            // This creates a cumulative hash: hash(current_cert) || hash(next_cert + ... + root)
            if (i < certLen - 1) {
                certHashes[i] = keccak256(abi.encodePacked(certHashes[i], certHashes[i + 1]));
            }
        }
    }

    /// @notice Converts ASN.1 UTCTime or GeneralizedTime to Unix timestamp
    /// @dev Handles both UTCTime (YYMMDDHHMMSSZ, 13 chars) and GeneralizedTime (YYYYMMDDHHMMSSZ, 15 chars).
    ///      For UTCTime, years 00-49 are interpreted as 2000-2049, and 50-99 as 1950-1999 (RFC 5280).
    /// @param x509Time The ASN.1 time string bytes
    /// @return Unix timestamp (seconds since 1970-01-01 00:00:00 UTC)
    function fromDERToTimestamp(bytes memory x509Time) internal pure returns (uint256) {
        uint16 yrs;
        uint8 mnths;
        uint8 dys;
        uint8 hrs;
        uint8 mins;
        uint8 secs;
        uint8 offset;

        if (x509Time.length == 13) {
            if (uint8(x509Time[0]) - 48 < 5) yrs += 2000;
            else yrs += 1900;
        } else {
            yrs += (uint8(x509Time[0]) - 48) * 1000 + (uint8(x509Time[1]) - 48) * 100;
            offset = 2;
        }
        yrs += (uint8(x509Time[offset + 0]) - 48) * 10 + uint8(x509Time[offset + 1]) - 48;
        mnths = (uint8(x509Time[offset + 2]) - 48) * 10 + uint8(x509Time[offset + 3]) - 48;
        dys += (uint8(x509Time[offset + 4]) - 48) * 10 + uint8(x509Time[offset + 5]) - 48;
        hrs += (uint8(x509Time[offset + 6]) - 48) * 10 + uint8(x509Time[offset + 7]) - 48;
        mins += (uint8(x509Time[offset + 8]) - 48) * 10 + uint8(x509Time[offset + 9]) - 48;
        secs += (uint8(x509Time[offset + 10]) - 48) * 10 + uint8(x509Time[offset + 11]) - 48;

        return DateTimeLib.dateTimeToTimestamp(yrs, mnths, dys, hrs, mins, secs);
    }

    /// @notice Extracts and validates the SubjectPublicKeyInfo structure from an X.509 certificate
    ///
    /// @notice SCOPE AND LIMITATIONS:
    ///         This function performs format validation and algorithm type identification.
    ///         Only RSA and EC P-256 public keys are supported. Unsupported algorithm types will revert.
    /// @notice SubjectPublicKeyInfo structure (RFC 5280):
    ///         SubjectPublicKeyInfo ::= SEQUENCE {
    ///             algorithm         AlgorithmIdentifier,
    ///             subjectPublicKey  BIT STRING
    ///         }
    ///         AlgorithmIdentifier ::= SEQUENCE {
    ///             algorithm   OBJECT IDENTIFIER,
    ///             parameters  ANY DEFINED BY algorithm OPTIONAL
    ///         }
    ///
    /// @param der The DER-encoded certificate bytes
    /// @param subjectPublicKeyInfoPtr Pointer to the SubjectPublicKeyInfo SEQUENCE node in the DER structure
    /// @return pubkey The extracted public key with algorithm type (TPM_ALG_RSA or TPM_ALG_ECC),
    ///                curve information (for EC), and raw key data
    ///
    /// @dev Supported algorithm OIDs:
    ///      - RSA: 1.2.840.113549.1.1.1 (rsaEncryption, hex: 2a864886f70d010101)
    ///            Parameters: NULL or omitted
    ///      - EC:  1.2.840.10045.2.1 (ecPublicKey, hex: 2a8648ce3d0201)
    ///            Parameters: namedCurve OID = 1.2.840.10045.3.1.7 (P-256, hex: 2a8648ce3d030107)
    ///
    /// @dev Reverts with:
    ///      - UnknownPublicKeyAlgorithm: Algorithm OID is not RSA or EC
    ///      - "Unsupported EC curve (only P-256 supported)": EC curve is not P-256
    ///      - "EC parameters out of bounds": Malformed AlgorithmIdentifier.parameters field
    ///      - Various errors from extractRsaPubKeyData:
    ///        * "RSA modulus too small (min 2048 bits)"
    ///        * "RSA modulus too large (max 4096 bits)"
    ///        * "RSA modulus n must be odd"
    ///        * "RSA exponent e too small (min 65537)"
    ///        * "RSA pubkey not a SEQUENCE"
    ///        * "RSA modulus n cannot be empty"
    ///        * "RSA exponent e cannot be empty"
    function _getSubjectPublicKey(bytes memory der, uint256 subjectPublicKeyInfoPtr)
        private
        pure
        returns (CertPubkey memory pubkey)
    {
        uint256 algoPtr = der.firstChildOf(subjectPublicKeyInfoPtr);
        uint256 subjectPublicKeyPtr = der.nextSiblingOf(algoPtr);

        uint256 algorithmOidPtr = der.firstChildOf(algoPtr);
        bytes memory oid = der.bytesAt(algorithmOidPtr);

        pubkey.data = der.bitstringAt(subjectPublicKeyPtr);
        if (oid.equal(hex"2a864886f70d010101")) {
            // RSA OID: 1.2.840.113549.1.1.1
            pubkey.algo = TPMConstants.TPM_ALG_RSA;
        } else if (oid.equal(hex"2a8648ce3d0201")) {
            // EC OID: 1.2.840.10045.2.1
            pubkey.algo = TPMConstants.TPM_ALG_ECC;
        } else {
            revert UnknownPublicKeyAlgorithm(oid);
        }

        if (pubkey.algo == TPMConstants.TPM_ALG_ECC) {
            // Validate EC curve parameters
            // Per RFC 3279 Section 2.3.5, ECParameters can be a namedCurve OID
            // Get the parameters field from AlgorithmIdentifier SEQUENCE
            // AlgorithmIdentifier for EC contains: algorithm OID + parameters (namedCurve OID)
            uint256 paramsPtr = der.nextSiblingOf(algorithmOidPtr);
            if (paramsPtr.ixs() > algoPtr.ixl()) {
                revert Asn1PointerOutOfBounds();
            }
            bytes memory curveOid = der.bytesAt(paramsPtr);

            // P-256 OID: 1.2.840.10045.3.1.7 (hex: 2a8648ce3d030107)
            if (curveOid.equal(hex"2a8648ce3d030107")) {
                pubkey.params = TPMConstants.TPM_ECC_NIST_P256;
            } else {
                revert UnsupportedECCurve(curveOid);
            }
        }
    }

    /// @notice Parses the Validity SEQUENCE to extract notBefore and notAfter timestamps
    /// @dev Validity ::= SEQUENCE { notBefore Time, notAfter Time }
    ///      Time is either UTCTime or GeneralizedTime.
    /// @param der The DER-encoded certificate bytes
    /// @param validityPtr Node pointer to the Validity SEQUENCE
    /// @return notBefore Unix timestamp when the certificate becomes valid
    /// @return notAfter Unix timestamp when the certificate expires
    function _getValidity(bytes memory der, uint256 validityPtr)
        internal
        pure
        returns (uint256 notBefore, uint256 notAfter)
    {
        uint256 notBeforePtr = der.firstChildOf(validityPtr);
        uint256 notAfterPtr = der.nextSiblingOf(notBeforePtr);

        // Verify ASN.1 tags per RFC 5280 Section 4.1.2.5:
        // - 0x17 = UTCTime (format: YYMMDDhhmmssZ, 13 bytes)
        // - 0x18 = GeneralizedTime (format: YYYYMMDDhhmmssZ, 15 bytes)
        uint8 notBeforeTag = uint8(der[notBeforePtr.ixs()]);
        uint8 notAfterTag = uint8(der[notAfterPtr.ixs()]);

        if (notBeforeTag != 0x17 && notBeforeTag != 0x18) {
            revert InvalidTimeTag(notBeforeTag);
        }
        if (notAfterTag != 0x17 && notAfterTag != 0x18) {
            revert InvalidTimeTag(notAfterTag);
        }

        notBefore = _parseTimestamp(der.bytesAt(notBeforePtr), notBeforeTag);
        notAfter = _parseTimestamp(der.bytesAt(notAfterPtr), notAfterTag);
    }

    /// @dev Parses X.509 time bytes with strict RFC 5280 validation
    /// @notice Per RFC 5280 Section 4.1.2.5:
    ///         - UTCTime (0x17): YYMMDDhhmmssZ (13 bytes), where YY < 50 means 20YY, YY >= 50 means 19YY
    ///         - GeneralizedTime (0x18): YYYYMMDDhhmmssZ (15 bytes)
    ///         Both formats MUST end with 'Z' (UTC) and timezone offsets are not permitted.
    /// @param x509Time The time value bytes (content only, no tag/length)
    /// @param tag The ASN.1 tag (0x17 for UTCTime, 0x18 for GeneralizedTime)
    /// @return timestamp Unix timestamp
    function _parseTimestamp(bytes memory x509Time, uint8 tag) private pure returns (uint256) {
        // Validate length: UTCTime = 13 bytes, GeneralizedTime = 15 bytes
        if (x509Time.length != ((tag == 0x17) ? 13 : 15)) {
            revert InvalidTimeFormat();
        }

        // Validate trailing 'Z' (0x5A) - RFC 5280 requires UTC representation
        if (x509Time[x509Time.length - 1] != 0x5A) {
            revert InvalidTimeFormat();
        }

        // Validate all characters before 'Z' are ASCII digits (0x30-0x39)
        for (uint256 i = 0; i < x509Time.length - 1; i++) {
            uint8 c = uint8(x509Time[i]);
            if (c < 0x30 || c > 0x39) {
                revert InvalidTimeFormat();
            }
        }

        // Parse and validate time components using helper function
        return _parseTimeComponents(x509Time, tag);
    }

    /// @dev Helper function to parse time components (separated to avoid stack too deep)
    function _parseTimeComponents(bytes memory x509Time, uint8 tag) private pure returns (uint256) {
        uint16 yrs;
        uint8 offset;

        if (tag == 0x17) {
            // UTCTime: YY represents 1950-2049
            // Per RFC 5280: YY < 50 means 20YY, YY >= 50 means 19YY
            uint8 yy = (uint8(x509Time[0]) - 48) * 10 + uint8(x509Time[1]) - 48;
            yrs = (yy < 50) ? (2000 + yy) : (1900 + yy);
            offset = 2;
        } else {
            // GeneralizedTime: YYYY
            yrs = (uint8(x509Time[0]) - 48) * 1000 + (uint8(x509Time[1]) - 48) * 100 + (uint8(x509Time[2]) - 48) * 10
                + uint8(x509Time[3]) - 48;
            offset = 4;
        }

        uint8 mnths = (uint8(x509Time[offset]) - 48) * 10 + uint8(x509Time[offset + 1]) - 48;
        uint8 dys = (uint8(x509Time[offset + 2]) - 48) * 10 + uint8(x509Time[offset + 3]) - 48;
        uint8 hrs = (uint8(x509Time[offset + 4]) - 48) * 10 + uint8(x509Time[offset + 5]) - 48;
        uint8 mins = (uint8(x509Time[offset + 6]) - 48) * 10 + uint8(x509Time[offset + 7]) - 48;
        uint8 secs = (uint8(x509Time[offset + 8]) - 48) * 10 + uint8(x509Time[offset + 9]) - 48;

        // Validate component ranges per RFC 5280
        // Month: 01-12, Day: 01-31, Hour: 00-23, Minute: 00-59, Second: 00-59
        if (mnths == 0 || mnths > 12 || dys == 0 || dys > 31 || hrs > 23 || mins > 59 || secs > 59) {
            revert InvalidTimeFormat();
        }

        return DateTimeLib.dateTimeToTimestamp(yrs, mnths, dys, hrs, mins, secs);
    }

    /// @notice Gets a pointer to the first field inside TBSCertificate
    /// @dev Navigates to TBSCertificate and returns a pointer to its first child.
    ///      The first child is either the version field (tag 0xA0) or serialNumber (tag 0x02).
    /// @param der The DER-encoded certificate bytes
    /// @return Node pointer to the first field in TBSCertificate
    function _tbsPtr(bytes memory der) internal pure returns (uint256) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        uint256 tbsPtr = der.firstChildOf(tbsParentPtr);
        return tbsPtr;
    }

    /// @dev Extracts a specific extension from an X.509 certificate by OID
    /// @param der The DER-encoded certificate bytes
    /// @param targetOid The OID of the extension to search for
    /// @return found Whether the extension was found
    /// @return value The extension value (OCTET STRING contents, already decoded)
    function _getExtension(bytes memory der, bytes memory targetOid) private pure returns (bool, bytes memory) {
        uint256 tbsPtr = _tbsPtr(der);
        uint256 versionTag = uint8(der[tbsPtr.ixs()]);
        if (versionTag == 0xA0) {
            tbsPtr = der.nextSiblingOf(tbsPtr);
        }
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        uint256 nextPtr = der.nextSiblingOf(tbsPtr);
        if (nextPtr == 0) {
            return (false, "");
        }
        if (uint8(der[nextPtr.ixs()]) != 0xA3) {
            return (false, "");
        }
        // Navigate into extensions sequence
        // [3] EXPLICIT SEQUENCE OF Extension
        uint256 extensionsSeqPtr = der.firstChildOf(nextPtr);
        // Save the parent SEQUENCE pointer to check boundaries
        uint256 parentSeqPtr = extensionsSeqPtr;
        extensionsSeqPtr = der.firstChildOf(extensionsSeqPtr);
        // Get the end position of the parent SEQUENCE (SEQUENCE OF Extension)
        // All child Extension nodes must be within [parentSeqPtr.ixf(), parentSeqPtr.ixl()]
        uint256 parentEndPos = parentSeqPtr.ixl();

        // Iterate through all extensions to find the target OID
        // Extension ::= SEQUENCE { extnID, [critical BOOLEAN], extnValue OCTET STRING }
        while (extensionsSeqPtr != 0) {
            // Check if current extension is within parent SEQUENCE bounds
            // extensionsSeqPtr must start within the parent's content range
            if (extensionsSeqPtr.ixs() > parentEndPos) {
                // We've gone past the extensions list - nextSiblingOf went out of bounds
                break;
            }
            uint256 extOidPtr = der.firstChildOf(extensionsSeqPtr);
            bytes memory extOid = der.bytesAt(extOidPtr);
            if (extOid.equal(targetOid)) {
                uint256 extValuePtr = der.nextSiblingOf(extOidPtr);

                // Skip optional critical BOOLEAN if present (tag 0x01)
                // critical BOOLEAN DEFAULT FALSE
                if (uint8(der[extValuePtr.ixs()]) == 0x01) {
                    extValuePtr = der.nextSiblingOf(extValuePtr);
                }

                // Return the OCTET STRING containing the extension value
                bytes memory octetString = der.bytesAt(extValuePtr);
                return (true, octetString);
            }
            extensionsSeqPtr = der.nextSiblingOf(extensionsSeqPtr);
        }
        return (false, "");
    }

    /// ============ CRL (Certificate Revocation List) Functions ============

    // 2.5.29.35 - Authority Key Identifier OID (for CRL)
    bytes constant CRL_AUTHORITY_KEY_IDENTIFIER_OID = hex"551D23";
    // 2.5.29.27 - Delta CRL Indicator OID (RFC 5280 Section 5.2.4)
    bytes constant DELTA_CRL_INDICATOR_OID = hex"551D1B";
    // 2.5.29.28 - Issuing Distribution Point OID (RFC 5280 Section 5.2.5)
    bytes constant ISSUING_DISTRIBUTION_POINT_OID = hex"551D1C";

    /// @notice Parse a DER-encoded X.509 CRL
    /// @param der The DER-encoded CRL bytes
    /// @return crl The parsed CRL information
    /// @dev TBSCertList structure per RFC 5280:
    ///      TBSCertList ::= SEQUENCE {
    ///          version              Version OPTIONAL,  -- INTEGER, v2(1) if present
    ///          signature            AlgorithmIdentifier,
    ///          issuer               Name,
    ///          thisUpdate           Time,
    ///          nextUpdate           Time OPTIONAL,
    ///          revokedCertificates  SEQUENCE OF SEQUENCE {...} OPTIONAL,
    ///          crlExtensions        [0] EXPLICIT Extensions OPTIONAL
    ///      }
    function parseCRL(bytes calldata der) internal pure returns (CRLInfo memory crl) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);

        // Extract TBS (To-Be-Signed) portion
        crl.tbs = der.allBytesAt(tbsParentPtr);

        uint256 tbsPtr = der.firstChildOf(tbsParentPtr);

        uint256 tag = uint8(der[tbsPtr.ixs()]);
        if (tag == 0x02) {
            tbsPtr = der.nextSiblingOf(tbsPtr);
        }

        // Skip signature algorithm
        tbsPtr = der.nextSiblingOf(tbsPtr);

        // Extract issuer DN
        crl.issuerDN = der.allBytesAt(tbsPtr);

        // Extract thisUpdate and nextUpdate
        tbsPtr = der.nextSiblingOf(tbsPtr);
        (crl.thisUpdate, crl.nextUpdate) = _getCRLValidity(der, tbsPtr);

        // Move to next field (either revoked certs or extensions)
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);

        // Check if revoked certificates list exists (tag 0x30 = SEQUENCE)
        if (tbsPtr != 0 && bytes1(der[tbsPtr.ixs()]) == 0x30) {
            crl.revokedSerials = _getCRLRevokedSerials(der, tbsPtr);
            tbsPtr = der.nextSiblingOf(tbsPtr);
        }

        // Extract extensions (tag 0xA0 = context-specific)
        if (tbsPtr != 0 && bytes1(der[tbsPtr.ixs()]) == 0xA0) {
            // Check for Delta CRL Indicator - reject if present
            // Delta CRLs only contain changes since a base CRL, which could miss revoked certificates
            uint256 deltaCrlPtr = _findCRLExtensionValue(der, tbsPtr, DELTA_CRL_INDICATOR_OID);
            if (deltaCrlPtr != 0) {
                revert DeltaCRLNotSupported();
            }

            // Check for Issuing Distribution Point - reject if present
            // Partitioned CRLs only cover specific certificate types, which could miss revocations
            uint256 idpPtr = _findCRLExtensionValue(der, tbsPtr, ISSUING_DISTRIBUTION_POINT_OID);
            if (idpPtr != 0) {
                revert PartitionedCRLNotSupported();
            }

            uint256 akidPtr = _findCRLExtensionValue(der, tbsPtr, CRL_AUTHORITY_KEY_IDENTIFIER_OID);
            if (akidPtr != 0) {
                crl.authorityKeyId = _extractAKIDFromExtension(der, akidPtr);
            }
        }

        // Extract signature
        uint256 sigPtr = der.nextSiblingOf(tbsParentPtr);
        sigPtr = der.nextSiblingOf(sigPtr); // Skip signature algorithm
        crl.signature = _getCRLSignature(der, sigPtr);
    }

    /// @notice Get the signature algorithm OID from a CRL
    /// @param der The DER-encoded CRL bytes
    /// @return The signature algorithm OID bytes
    function getCRLSignatureAlgorithm(bytes calldata der) internal pure returns (bytes memory) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        uint256 sigAlgoPtr = der.nextSiblingOf(tbsParentPtr);
        uint256 oidPtr = der.firstChildOf(sigAlgoPtr);
        return der.bytesAt(oidPtr);
    }

    /// @notice Check if a serial number is revoked in a CRL
    /// @param serialNumber The certificate serial number to check
    /// @param der The DER-encoded CRL bytes
    /// @return revoked True if the serial number is in the revoked list
    function isSerialRevokedInCRL(uint256 serialNumber, bytes memory der) internal pure returns (bool revoked) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        uint256 tbsPtr = der.firstChildOf(tbsParentPtr);

        uint256 tag = uint8(der[tbsPtr.ixs()]);
        if (tag == 0x02) {
            tbsPtr = der.nextSiblingOf(tbsPtr);
        }

        tbsPtr = der.nextSiblingOf(tbsPtr); // skip sigAlg
        tbsPtr = der.nextSiblingOf(tbsPtr); // skip issuer
        tbsPtr = der.nextSiblingOf(tbsPtr); // skip thisUpdate
        tbsPtr = der.nextSiblingOf(tbsPtr); // skip nextUpdate

        if (tbsPtr != 0 && bytes1(der[tbsPtr.ixs()]) == 0x30) {
            return _isSerialInRevokedList(der, tbsPtr, serialNumber);
        }
        return false;
    }

    /// @notice Get CRL validity period (thisUpdate and nextUpdate)
    function _getCRLValidity(bytes calldata der, uint256 validityPtr)
        private
        pure
        returns (uint256 thisUpdate, uint256 nextUpdate)
    {
        uint256 thisUpdatePtr = validityPtr;
        uint256 nextUpdatePtr = der.nextSiblingOf(thisUpdatePtr);
        thisUpdate = fromDERToTimestamp(der.bytesAt(thisUpdatePtr));
        nextUpdate = fromDERToTimestamp(der.bytesAt(nextUpdatePtr));
    }

    /// @notice Extract all revoked serial numbers from CRL
    function _getCRLRevokedSerials(bytes calldata der, uint256 revokedParentPtr)
        private
        pure
        returns (uint256[] memory serialNumbers)
    {
        uint256 revokedPtr = der.firstChildOf(revokedParentPtr);
        uint256 count = 0;

        // First pass: count the number of revoked certs
        uint256 tempPtr = revokedPtr;
        while (tempPtr != 0 && tempPtr.ixl() <= revokedParentPtr.ixl()) {
            count++;
            tempPtr = der.nextSiblingOf(tempPtr);
        }

        // Second pass: extract serial numbers
        serialNumbers = new uint256[](count);
        uint256 index = 0;
        while (revokedPtr != 0 && revokedPtr.ixl() <= revokedParentPtr.ixl()) {
            uint256 serialPtr = der.firstChildOf(revokedPtr);
            bytes memory serialBytes = der.bytesAt(serialPtr);
            serialNumbers[index] = _parseSerialNumber(serialBytes);
            index++;
            revokedPtr = der.nextSiblingOf(revokedPtr);
        }
    }

    /// @notice Check if a serial number exists in the revoked list
    function _isSerialInRevokedList(bytes memory der, uint256 revokedParentPtr, uint256 targetSerial)
        private
        pure
        returns (bool)
    {
        uint256 revokedPtr = der.firstChildOf(revokedParentPtr);
        while (revokedPtr != 0 && revokedPtr.ixl() <= revokedParentPtr.ixl()) {
            uint256 serialPtr = der.firstChildOf(revokedPtr);
            bytes memory serialBytes = der.bytesAt(serialPtr);
            uint256 serial = _parseSerialNumber(serialBytes);
            if (serial == targetSerial) {
                return true;
            }
            revokedPtr = der.nextSiblingOf(revokedPtr);
        }
        return false;
    }

    /// @notice Extract signature from CRL
    function _getCRLSignature(bytes calldata der, uint256 sigPtr) private pure returns (bytes memory sig) {
        // Extract the BIT STRING content (skips the unused bits byte)
        // The content is a DER-encoded ECDSA signature (SEQUENCE of two INTEGERs)
        // Return it as-is, just like getCertSignature does
        sig = der.bitstringAt(sigPtr);
        if (sig.length < 64 || sig.length > 512) revert InvalidSignatureSize();
    }

    /// @notice Find extension value in CRL extensions
    function _findCRLExtensionValue(bytes calldata der, uint256 extensionPtr, bytes memory oid)
        private
        pure
        returns (uint256)
    {
        uint256 parentPtr = der.firstChildOf(extensionPtr);
        uint256 ptr = der.firstChildOf(parentPtr);

        while (ptr != 0 && ptr.ixl() <= parentPtr.ixl()) {
            uint256 oidPtr = der.firstChildOf(ptr);
            if (keccak256(der.bytesAt(oidPtr)) == keccak256(oid)) {
                return der.nextSiblingOf(oidPtr);
            }
            ptr = der.nextSiblingOf(ptr);
        }
        return 0;
    }

    /// @notice Extract AKID from extension value
    function _extractAKIDFromExtension(bytes calldata der, uint256 extnValuePtr)
        private
        pure
        returns (bytes memory akid)
    {
        bytes memory extValue = der.bytesAt(extnValuePtr);
        uint256 parentPtr = extValue.root();
        uint256 ptr = extValue.firstChildOf(parentPtr);

        // Look for context tag [0] which contains the keyIdentifier
        bytes1 contextTag = 0x80;
        while (ptr != 0 && ptr.ixl() <= parentPtr.ixl()) {
            bytes1 tag = bytes1(extValue[ptr.ixs()]);
            if (tag == contextTag) {
                akid = extValue.bytesAt(ptr);
                break;
            }
            ptr = extValue.nextSiblingOf(ptr);
        }
    }
}
