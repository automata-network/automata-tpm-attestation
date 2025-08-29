# Automata TPM Attestation Protocol Specification

## 1. Overview

This document specifies the protocol for on-chain verification of TPM (Trusted Platform Module) quotes as implemented in the Automata TPM Attestation contracts. The system allows smart contracts to verify the integrity and identity of a TPM-equipped machine by validating its signed attestations (quotes).

## 2. TPM Quote Verification

The primary function is `verifyTpmQuote`, which is exposed in two ways:
1.  `verifyTpmQuote(bytes tpmQuote, bytes tpmSignature, bytes[] akCertchain)`: Verifies a quote using a full X.509 certificate chain for the Attestation Key (AK).
2.  `verifyTpmQuote(bytes tpmQuote, bytes tpmSignature, Pubkey akPub)`: Verifies a quote using a pre-trusted public key, bypassing the chain validation for gas savings.

### 2.1. Quote Format

The `tpmQuote` is expected to follow the TPM 2.0 `TPMS_ATTEST` structure, specifically for `TPM_ST_ATTEST_QUOTE` (0x8018). The contract parses this structure to extract key information, including:
-   **Magic Number**: Must be `0xff544347` ('TCG').
-   **Attestation Type**: Must be `TPM_ST_ATTEST_QUOTE` (0x8018).
-   **Extra Data**: A caller-supplied nonce or other data to ensure freshness and prevent replay attacks. The contract's `extractExtraData` function can be used to retrieve this.
-   **PCR Selection & Digest**: The selection of Platform Configuration Registers (PCRs) and their combined digest.

### 2.2. Signature Format

The `tpmSignature` is a packed structure containing:
-   **Signature Algorithm**: `TPM_ALG_ID` (e.g., `TPM_ALG_RSASSA`, `TPM_ALG_ECDSA`).
-   **Hash Algorithm**: `TPM_ALG_ID` (currently only `TPM_ALG_SHA256` is supported).
-   **Signature**: The raw signature data. For ECDSA, this is the concatenated `r` and `s` values.

## 3. Certificate Chain Validation

The `verifyCertChain` function validates an X.509 certificate chain.

### 3.1. Trust Model

-   **Root of Trust**: The system relies on a set of trusted root Certificate Authorities (CAs) registered on-chain by the contract owner.
-   **Chain Validation**: A certificate chain is considered valid if it meets all of the following criteria:
    1.  The chain starts with a leaf certificate, followed by one or more intermediates, and ends with a registered root CA.
    2.  The chain length is between 1 and 4 certificates (inclusive).
    3.  Each certificate's signature is valid and signed by the public key of the next certificate in the chain.
    4.  Each certificate is within its validity period (`notBefore` and `notAfter`).
-   **Revocation**: Certificate revocation (via CRL or OCSP) is **not** currently implemented on-chain due to gas and complexity constraints. Revocation must be handled off-chain or by administrative removal of root CAs.

### 3.2. Caching

To optimize gas usage, the system implements two levels of caching:
1.  **Verified CA Issuers**: The hashes of registered CAs are stored.
2.  **Verified Leaf Keys**: The public keys of successfully verified leaf certificates are cached. Subsequent verifications using the same leaf certificate will use the cached key, skipping the expensive chain validation.

## 4. PCR Measurement Verification

The `checkPcrMeasurements` function verifies that the PCR digest in the TPM quote matches a set of expected measurements.

### 4.1. Measurement Semantics

-   A `MeasureablePcr` struct can define an expected PCR state in two ways:
    1.  By providing the final `pcr` digest directly.
    2.  By providing a list of `allEvents`, from which the final PCR digest is calculated (`pcr = sha256(sha256(0 || event1) || event2)...`).
-   If `pcr` is `bytes32(0)`, it **must** be accompanied by a non-empty `allEvents` list.
-   If both `pcr` and `allEvents` are provided, the contract verifies that the provided `pcr` matches the calculated digest from the events.

## 5. Supported Algorithms

-   **Signature Schemes**: RSASSA-PKCS1-v1_5, ECDSA over NIST P-256.
-   **Hash Algorithm**: SHA-256.
-   **RSA Key Size**: Minimum 2048-bit modulus.
-   **Elliptic Curve**: NIST P-256 (secp256r1). Compressed public keys are not supported.

## 6. Security Considerations

-   **Replay Attacks**: The `extraData` field in the TPM quote should be used for a unique, caller-supplied nonce to prevent replay attacks. The contract itself does not enforce nonce uniqueness; this is the responsibility of the calling application.
-   **Owner Centralization**: The contract owner has the sole authority to add and remove trusted CAs. A compromised owner key could compromise the entire trust model. Consider using a multi-sig or timelock for owner actions.
