// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

// --- Generic Errors ---
error InvalidLength(uint256 actual, uint256 expected);
error InvalidArgument();
error ZeroAddress(string paramName);

// --- TPM Attestation Errors ---
error InvalidTpmQuote();
error TpmQuoteTooShort();
error InvalidTpmAttType();
error InvalidTpmsPcrCount();
error PcrDigestMismatch();
error PcrSelectionMismatch();
error TpmSignatureVerificationFailed();
error UnsupportedHashAlgorithm();
error InvalidPcrDigestSize();
error InvalidEcdsaSignature();
error InvalidPcrEvents();
error InvalidPcrEventIndex();
error TpmSignatureTooShort();
error InvalidRsaSignatureSize();
error PcrIndexOutOfRange();
error RootCaNotAtEndOfChain();

// --- Certificate & Crypto Errors ---
error CertChainVerificationFailed(string reason);
error CertificateExpired();
error CertificateNotYetValid();
error InvalidCertificateChain();
error InvalidSignature();
error UnknownPublicKeyAlgorithm(bytes oid);
error UnknownSignatureAlgorithm(bytes oid);
error CompressedPublicKeyNotSupported();
error InvalidP256PublicKeyLength();
error NotAP256ECPublicKey();
error RsaKeyModulusTooSmall();
error RsaKeyModulusTooLarge();
error RsaSignatureSizeMismatchModulusSize();
error InvalidCertChainLength();
error RootCaNotVerified();
error CertNotCa();
error LeafCertIsCa();
error KeyCertSignNotSet();
error PathLenConstraintViolated();
error NotEcPublicKey();
error NotRsaPublicKey();
error Asn1PointerOutOfBounds();
error UnsupportedECCurve(bytes oid);
error UnsupportedSignatureScheme(uint16 scheme, uint16 keyAlgo);
error InvalidBasicConstraintsFormat();
error CertChainDNMismatch(uint256 certIndex, bytes issuerDN, bytes expectedSubjectDN);
error InvalidSkidFormat();
error InvalidAkidFormat();
error CertChainAKIDMismatch(uint256 certIndex, bytes akid, bytes expectedSkid);

// --- RSA Validation Errors ---
error RsaModulusEmpty();
error RsaExponentEmpty();
error InvalidRsaModulusSize();
error InvalidRsaExponentSize();
error RsaModulusNotOdd();
error RsaModulusLengthOverflow();
error InvalidRsaPubkeyFormat();

// --- Signature Validation Errors ---
error InvalidSignatureSize();

// --- ECDSA Signature Errors ---
error InvalidEcdsaSignatureFormat();
error EcdsaComponentTooLarge();

// --- Certificate Format Errors ---
error InvalidAsn1Tag();

// --- CA Constraints Errors ---
error LeafCertHasPathLen();
error IssuerCertMissingBasicConstraints();
error LeafCertHasKeyCertSign();
error MissingKeyUsageExtension();

// --- ASN.1/DER Parsing Errors ---
error InvalidBooleanLength();
error InvalidBitString();
error Asn1NotBitString();
error Asn1NotOctetString();
error Asn1NotConstructedType();
error Asn1NotInteger();
error Asn1NotPositiveInteger();
error Asn1BitStringNotZeroPadded();
error Asn1IndexOutOfBounds();
error Asn1LengthCannotBeZero();
error Asn1InvalidLengthBytes();
error Asn1ContentLengthOutOfBounds();

// --- BytesUtils Errors ---
error BytesOffsetOutOfBounds();
error BytesInsufficientLength();
error BytesLengthExceeds32();
error BytesLengthExceeds52();
error BytesInvalidBase32Char();
error BytesInvalidBase32DecodedValue();
error BytesInvalidBase32Length();

// --- CRL Errors ---
error CRLExpired();
error CRLNotYetValid();
error CRLSignatureVerificationFailed();
error CRLIssuerMismatch();
error CRLRollbackAttempt();
error InvalidCRLFormat();
error CRLRequiredInStrictMode();
error CRLExpiredInStrictMode();
/// @dev Per RFC 5280 Section 5.2.1, conforming CRL issuers MUST include AKID extension
error CRLMissingAKID();
/// @dev Per RFC 5280 Section 4.2.1.2, conforming CA certificates MUST include SKID extension
error IssuerCertMissingSKID();
/// @dev Delta CRLs (RFC 5280 Section 5.2.4) are not supported - only full CRLs are accepted
error DeltaCRLNotSupported();
/// @dev Partitioned CRLs with Issuing Distribution Point (RFC 5280 Section 5.2.5) are not supported
/// Only complete CRLs covering all certificate types are accepted
error PartitionedCRLNotSupported();

// --- Serial Number Validation Errors ---
/// @dev Per RFC 5280 Section 4.1.2.2:
/// - Serial numbers MUST be positive integers (non-zero)
/// - Conforming CAs MUST NOT use serial numbers longer than 20 octets
error InvalidSerialNumber();

// --- Certificate Revocation Errors ---
error CertificateAlreadyRevoked();

// --- Certificate Chain Linkage Errors ---
error IssuerSubjectDNMismatch();

// --- X.509 Time Parsing Errors ---
error InvalidTimeTag(uint8 tag);
error InvalidTimeFormat();
