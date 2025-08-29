// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

// --- Generic Errors ---
error InvalidLength(uint256 actual, uint256 expected);
error InvalidArgument();

// --- TPM Attestation Errors ---
error InvalidTpmQuote(string reason);
error PcrDigestMismatch();
error PcrSelectionMismatch();
error TpmSignatureVerificationFailed();
error UnsupportedHashAlgorithm();
error InvalidPcrDigestSize();
error InvalidEcdsaSignature();

// --- Certificate & Crypto Errors ---
error CertChainVerificationFailed(string reason);
error CertificateExpired();
error CertificateNotYetValid();
error InvalidCertificateChain();
error InvalidSignature();
error UnknownPublicKeyAlgorithm();
error CompressedPublicKeyNotSupported();
error InvalidP256PublicKeyLength();
error NotAP256ECPublicKey();
error RsaKeyModulusTooSmall();
error InvalidCertChainLength();
error RootCaNotVerified();
error CertNotCa();
error LeafCertIsCa();
error KeyCertSignNotSet();
error PathLenConstraintViolated();
