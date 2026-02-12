# User Guide

This guide covers installation, configuration, API reference, integration, and development for Automata TPM Attestation.

## Table of Contents

- [Installation \& Setup](#installation--setup)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Integration Guide](#integration-guide)
- [Development \& Testing](#development--testing)

## Installation & Setup

### 1. Install via Foundry

```bash
forge install automata-network/automata-tpm-attestation
```

### 2. Configure Remappings

Add to your `foundry.toml`:

```toml
remappings = [
    "@automata-network/automata-tpm-attestation/=lib/automata-tpm-attestation/src/",
    "@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/",
    "@solady/=lib/solady/src/"
]
```

### 3. P256 Configuration

The contract requires P256 elliptic curve support for ECDSA verification:

#### Option A: RIP-7212 Native Support (Recommended)
If your target chain implements [RIP-7212](https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7212.md):

```solidity
// Use the precompile address
address p256Precompile = 0x0000000000000000000000000000000000000100;
TpmAttestation tpmAttestation = new TpmAttestation(owner, p256Precompile);
```

#### Option B: daimo-eth P256 Verifier
For chains without RIP-7212 support, deploy the [daimo-eth P256 verifier](https://github.com/daimo-eth/p256-verifier):

```solidity
// Deploy P256 verifier
address p256Verifier = 0xc2b78104907F722DABAc4C69f826a522B2754De4;
TpmAttestation tpmAttestation = new TpmAttestation(owner, p256Verifier);
```

## Configuration

### 1. Deploy Contract

```solidity
import {TpmAttestation} from "@automata-network/automata-tpm-attestation/TpmAttestation.sol";

// Deploy with owner and P256 implementation
TpmAttestation tpmAttestation = new TpmAttestation(
    owner,        // Contract owner address
    p256Address   // P256 verifier address
);
```

### 2. Configure Trusted Certificate Authorities

Only the contract owner can manage trusted CAs:

```solidity
// Add a trusted CA that issues TPM Attestation Key certificates
bytes memory caCert = /* DER-encoded CA certificate */;
tpmAttestation.addCA(caCert);

// Remove a CA if needed
tpmAttestation.removeCA(caCert);
```

## API Reference

### TPM Quote Verification

#### `verifyTpmQuote(bytes tpmQuote, bytes tpmSignature, bytes[] akCertchain)`

Verifies a TPM quote with full certificate chain validation. Upon successful verification, returns the ABI-encoded TPM Attestation Key public key and the extraData field from the quote.

```solidity
function verifyTpmQuote(
    bytes calldata tpmQuote,      // TPM quote data
    bytes calldata tpmSignature,  // TPM signature
    bytes[] calldata akCertchain  // AK certificate chain [leaf, intermediate, root]
) external returns (bool success, bytes memory akPubkey, bytes memory extraData);
```

**Example:**

```solidity
import {CertPubkey} from "@automata-network/automata-tpm-attestation/lib/LibX509.sol";

bytes[] memory certChain = new bytes[](3);
certChain[0] = akLeafCert;
certChain[1] = intermediateCert;
certChain[2] = rootCaCert;

(bool success, bytes memory akPubkey, bytes memory extraData) = tpmAttestation.verifyTpmQuote(
    tpmQuote,
    tpmSignature,
    certChain
);

require(success, "Failed to verify TPM Quote");

// Decode the Attestation Key
CertPubkey memory ak = abi.decode(akPubkey, (CertPubkey));

// extraData can be used for replay protection (e.g., compare against a nonce you provided)
```

#### `verifyTpmQuoteWithTrustedAkPub(bytes tpmQuote, bytes tpmSignature, CertPubkey akPub)`

Verifies a TPM quote using a pre-verified Attestation Key (saves gas by skipping certificate chain verification). The caller is responsible for ensuring the provided `akPub` is trusted.

```solidity
function verifyTpmQuoteWithTrustedAkPub(
    bytes calldata tpmQuote,
    bytes calldata tpmSignature,
    CertPubkey calldata akPub    // Pre-verified AK public key
) external returns (bool success, bytes memory extraData);
```

### Data Extraction & Validation

#### `checkPcrMeasurements(bytes tpmQuote, PcrValue[] tpmPcrs)`

Validates PCR measurements against the TPM quote. Parses the quote's PCR selection bitmap and digest, then verifies that the provided PCR values produce the same digest.

> [!NOTE]
> PCR Digest currently only supports SHA256 hash (`TPM_ALG_SHA256 = 0x000B`).

> [!IMPORTANT]
> The `tpmPcrs` array **must be sorted in ascending order by `pcrIndex`**. The contract will revert with `PcrNotSorted()` if this constraint is violated.

```solidity
struct PcrValue {
    uint8 pcrIndex;            // PCR index (0-23)
    bytes32 value;             // Final PCR value (cumulative hash)
    bytes32[] eventLogHashes;  // Event hashes extended into this PCR (optional)
}

function checkPcrMeasurements(
    bytes calldata tpmQuote,
    PcrValue[] calldata tpmPcrs
) external returns (bool success, bytes memory extraData);
```

If `eventLogHashes` is provided for a PCR, the contract reconstructs the PCR value by iteratively extending each event hash (starting from zero) using SHA-256:

```
pcr = sha256(pcr || event[0])
pcr = sha256(pcr || event[1])
...
```

If `value` is `bytes32(0)` and events are provided, the computed value is used directly. If `value` is non-zero and events are provided, the computed value must match `value` or the call reverts with `InvalidPcrEvents()`.

**Example:**
```solidity
import {PcrValue} from "@automata-network/automata-tpm-attestation/types/Types.sol";

// Provide known PCR values (sorted by pcrIndex)
PcrValue[] memory expectedPcrs = new PcrValue[](2);
expectedPcrs[0] = PcrValue({
    pcrIndex: 0,
    value: expectedPcr0Value,
    eventLogHashes: new bytes32[](0)  // No event log verification
});
expectedPcrs[1] = PcrValue({
    pcrIndex: 4,
    value: bytes32(0),                // Will be computed from events
    eventLogHashes: pcr4Events        // Reconstruct PCR from event log
});

(bool success, bytes memory extraData) = tpmAttestation.checkPcrMeasurements(
    tpmQuote,
    expectedPcrs
);

require(success, "PCR validation failed");

// extraData contains the data embedded in the TPM quote (e.g., a nonce for replay protection)
```

#### `extractExtraData(bytes tpmQuote)`

Extracts the extraData field from a TPM quote without performing any signature or PCR verification. Useful for reading the embedded nonce or user data before deciding whether to perform full verification.

```solidity
function extractExtraData(
    bytes calldata tpmQuote
) external pure returns (bool success, bytes memory extraData);
```

### TPM Key Certification

#### `verifyTpmKeyCertification(bytes certifyInfo, bytes akSignature, bytes tpmtPublic, CertPubkey akPub, uint32 tpmaObjectBitMask)`

Verifies a TPM2_Certify attestation proving a key is bound to the same TPM as the Attestation Key. Returns the certified public key and the extraData field for the caller's own replay protection logic.

The function performs the following steps:
1. Verifies the AK signature over `certifyInfo`
2. Parses `certifyInfo` to extract the certified key name and extraData
3. Computes the expected key name from `tpmtPublic` and verifies it matches
4. Optionally validates TPMA_OBJECT attribute bits if `tpmaObjectBitMask` is non-zero
5. Extracts and returns the certified public key from `tpmtPublic`

```solidity
function verifyTpmKeyCertification(
    bytes calldata certifyInfo,     // Raw TPMS_ATTEST bytes from TPM2_Certify
    bytes calldata akSignature,     // TPMT_SIGNATURE bytes from TPM2_Certify
    bytes calldata tpmtPublic,      // Marshalled TPMT_PUBLIC of the certified key
    CertPubkey calldata akPub,      // The trusted Attestation Key public key
    uint32 tpmaObjectBitMask        // Required attribute bits (pass 0 to skip validation)
) external view returns (CertPubkey memory certifiedPubkey, bytes memory extraData);
```

**TPMA_OBJECT Bit Reference** (TPM 2.0 Part 2, Table 31):

| Bit | Name | Value | Description |
|-----|------|-------|-------------|
| 1 | fixedTPM | `0x00002` | Key cannot be duplicated outside the TPM |
| 2 | stClear | `0x00004` | Cleared on TPM2_Startup(CLEAR) |
| 4 | fixedParent | `0x00010` | Key cannot be moved to a different parent |
| 5 | sensitiveDataOrigin | `0x00020` | TPM generated all sensitive data |
| 6 | userWithAuth | `0x00040` | User role auth via HMAC/password |
| 7 | adminWithPolicy | `0x00080` | Admin role requires policy session |
| 10 | noDA | `0x00400` | Not subject to dictionary attack lockout |
| 11 | encryptedDuplication | `0x00800` | May be duplicated with symmetric encryption |
| 16 | restricted | `0x10000` | Usage restricted to known-format structures |
| 17 | decrypt | `0x20000` | Private portion may decrypt |
| 18 | sign/encrypt | `0x40000` | Private portion may sign / encrypt |

Combine bit values with OR to require multiple attributes. For example, requiring `fixedTPM | fixedParent | sensitiveDataOrigin | sign/encrypt` → `0x40032`.

**Example:**
```solidity
// Require that the certified key is TPM-bound and can sign
uint32 requiredAttributes = 0x40032; // fixedTPM | fixedParent | sensitiveDataOrigin | sign

(CertPubkey memory certifiedKey, bytes memory extraData) = tpmAttestation.verifyTpmKeyCertification(
    certifyInfo,
    akSignature,
    tpmtPublic,
    trustedAkPub,
    requiredAttributes  // Pass 0 to skip attribute validation
);

// The caller is responsible for checking extraData for replay protection
// e.g., compare against a nonce you provided to TPM2_Certify
require(keccak256(extraData) == keccak256(expectedNonce), "Replay detected");
```

### Certificate Management (Inherited from CertChainRegistry)

#### `addCA(bytes ca)` / `removeCA(bytes ca)`

Manage trusted Certificate Authorities (owner only).

#### `verifyCertChain(bytes[] certs)`

Verify a certificate chain against trusted CAs.

#### `verifyCertSignature(bytes cert, CertPubkey issuer)`

Verify a certificate's signature using the issuer's public key (supports RSA and ECDSA).

### CRL (Certificate Revocation List) Management

#### `updateCRL(bytes crl, bytes issuerCert)`

Update the Certificate Revocation List for a specific issuer. This function:
- Verifies CRL validity period
- Verifies CRL signature against issuer's public key
- Validates issuer DN and AKID match
- Performs anti-rollback checks
- Syncs revoked certificates to the blacklist

```solidity
function updateCRL(bytes calldata crl, bytes calldata issuerCert) external;
```

#### `isCertificateRevoked(bytes cert)`

Check if a certificate has been revoked.

```solidity
function isCertificateRevoked(bytes calldata cert) external view returns (bool);
```

#### `setStrictCRLMode(bool enabled)`

Enable or disable strict CRL mode (owner only). When enabled, `verifyCertChain` requires a valid CRL for each issuer in the chain.

```solidity
function setStrictCRLMode(bool enabled) external;
```

#### `removeIntermediateCerts(bytes32[] certHashes)`

Remove cached intermediate certificates from the registry (owner only). Used for cache invalidation when intermediate CAs are compromised or retired.

```solidity
function removeIntermediateCerts(bytes32[] calldata certHashes) external;
```

## Integration Guide

### Basic Integration Example

```solidity
pragma solidity ^0.8.27;

import {PcrValue} from "@automata-network/automata-tpm-attestation/types/Types.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";

contract MyApplication {
    ITpmAttestation public immutable tpmAttestation;

    constructor(address _tpmAttestation) {
        tpmAttestation = ITpmAttestation(_tpmAttestation);
    }

    function verifyAndExecute(
        bytes calldata tpmQuote,
        bytes calldata tpmSignature,
        bytes[] calldata akCertchain,
        PcrValue[] calldata expectedPcrs
    ) external {
        // 1. Verify TPM quote and certificate chain
        (bool quoteValid, bytes memory akPubkey, bytes memory extraData) = tpmAttestation.verifyTpmQuote(
            tpmQuote,
            tpmSignature,
            akCertchain
        );
        require(quoteValid, "Invalid TPM Quote");

        // 2. Validate PCR measurements (tpmPcrs must be sorted by pcrIndex)
        (bool pcrValid,) = tpmAttestation.checkPcrMeasurements(
            tpmQuote,
            expectedPcrs
        );
        require(pcrValid, "Invalid PCR measurements");

        // 3. Process the extraData from the quote (e.g., verify nonce for replay protection)
        _processExtraData(extraData);
    }

    function _processExtraData(bytes memory extraData) internal {
        // Implement your application logic here
        // extraData contains the data embedded in the TPM quote (e.g., a nonce)
    }
}
```

### Advanced Usage: Pre-verified AK

For gas optimization, you can pre-verify and cache Attestation Keys:

```solidity
import {CertPubkey} from "@automata-network/automata-tpm-attestation/lib/LibX509.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";

contract OptimizedTpmVerifier {
    ITpmAttestation public immutable tpmAttestation;
    mapping(bytes32 => CertPubkey) public trustedAKs;

    constructor(address _tpmAttestation) {
        tpmAttestation = ITpmAttestation(_tpmAttestation);
    }

    function addTrustedAK(
        bytes[] calldata akCertchain,
        bytes32 akHash
    ) external onlyOwner {
        CertPubkey memory akPub = tpmAttestation.verifyCertChain(akCertchain);
        trustedAKs[akHash] = akPub;
    }

    function fastVerify(
        bytes calldata tpmQuote,
        bytes calldata tpmSignature,
        bytes32 akHash
    ) external returns (bool) {
        CertPubkey memory akPub = trustedAKs[akHash];
        require(akPub.data.length > 0, "AK not trusted");

        (bool success,) = tpmAttestation.verifyTpmQuoteWithTrustedAkPub(
            tpmQuote,
            tpmSignature,
            akPub
        );
        return success;
    }
}
```

### Key Certification Integration

Use `verifyTpmKeyCertification` to prove a key was generated on the same TPM as a trusted Attestation Key:

```solidity
import {CertPubkey} from "@automata-network/automata-tpm-attestation/lib/LibX509.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";

contract KeyCertificationVerifier {
    ITpmAttestation public immutable tpmAttestation;

    constructor(address _tpmAttestation) {
        tpmAttestation = ITpmAttestation(_tpmAttestation);
    }

    function verifyCertifiedKey(
        bytes calldata certifyInfo,
        bytes calldata akSignature,
        bytes calldata tpmtPublic,
        CertPubkey calldata trustedAkPub,
        bytes32 expectedNonce
    ) external view returns (CertPubkey memory) {
        // Require fixedTPM + fixedParent + sensitiveDataOrigin + sign
        uint32 requiredAttrs = 0x40032;

        (CertPubkey memory certifiedKey, bytes memory extraData) =
            tpmAttestation.verifyTpmKeyCertification(
                certifyInfo,
                akSignature,
                tpmtPublic,
                trustedAkPub,
                requiredAttrs
            );

        // Verify nonce for replay protection
        require(keccak256(extraData) == keccak256(abi.encodePacked(expectedNonce)), "Stale attestation");

        return certifiedKey;
    }
}
```

### Replay Protection

> [!IMPORTANT]
> The `TpmAttestation` contract does **not** include built-in replay protection. All verification functions return `extraData` — the caller is responsible for implementing freshness checks.

A common pattern is to provide a nonce as the `qualifyingData` parameter when generating the TPM quote or TPM2_Certify command. The TPM embeds this nonce in the attestation structure as `extraData`. On-chain, compare the returned `extraData` against the expected nonce to ensure the attestation is fresh:

```solidity
// Generate a nonce off-chain, pass it to TPM as qualifyingData
// Then on-chain:
(bool success, bytes memory akPubkey, bytes memory extraData) = tpmAttestation.verifyTpmQuote(
    tpmQuote, tpmSignature, akCertchain
);
require(success);
require(keccak256(extraData) == keccak256(abi.encodePacked(expectedNonce)), "Replay detected");
```

## Development & Testing

### Running Tests

```bash
forge test
```

### Development Setup

```bash
git clone https://github.com/automata-network/automata-tpm-attestation.git
cd automata-tpm-attestation
forge install
forge build
forge test
```
