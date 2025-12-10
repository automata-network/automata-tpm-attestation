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
import {TpmAttestation} from "@automata-tpm-attestation/TpmAttestation.sol";

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

Verifies a TPM quote with full certificate chain validation. Upon successful verification, this method returns the ABI encoded TPM Attestation Key.

```solidity
function verifyTpmQuote(
    bytes calldata tpmQuote,      // TPM quote data
    bytes calldata tpmSignature,  // TPM signature
    bytes[] calldata akCertchain  // AK certificate chain [leaf, intermediate, root]
) external returns (bool success, bytes memory encodedAkPub);
```

**Example:**

```solidity
import {Pubkey} from "@automata-network/automata-tpm-attestation/types/Crypto.sol";

bytes[] memory certChain = new bytes[](3);
certChain[0] = akLeafCert;
certChain[1] = intermediateCert;
certChain[2] = rootCaCert;

(bool success, bytes memory encodedAkPub) = tpmAttestation.verifyTpmQuote(
    tpmQuote,
    tpmSignature,
    certChain
);

require(success, "Failed to verify TPM Quote");

// Decode the key
Pubkey memory ak = abi.decode(encodedAkPub, (Pubkey));
```

#### `verifyTpmQuote(bytes tpmQuote, bytes tpmSignature, CertPubkey akPub)`

Verifies a TPM quote using a pre-verified Attestation Key (saves gas).

```solidity
function verifyTpmQuote(
    bytes calldata tpmQuote,
    bytes calldata tpmSignature,
    CertPubkey calldata akPub    // Pre-verified AK public key
) external view returns (bool success, string memory errorMessage);
```

### Data Extraction & Validation

#### `extractExtraData(bytes tpmQuote)`

Extracts user data embedded in the TPM quote.

> [!NOTE]
> You may also call the `checkPcrMeasurements()` method directly to get the extra data as a return value upon successful PCR check.

```solidity
function extractExtraData(bytes calldata tpmQuote)
    external pure returns (bool success, bytes memory extraData);
```

**Example:**
```solidity
(bool success, bytes memory userData) = tpmAttestation.extractExtraData(tpmQuote);
if (success) {
    // Process extracted user data
    address userAddress = abi.decode(userData, (address));
}
```

#### `checkPcrMeasurements(bytes tpmQuote, MeasureablePcr[] tpmPcrs)`

Validates PCR measurements against the TPM quote.

> [!NOTE]
> PCR Digest currently only supports SHA256 hash (`TPM_ALG_SHA256 = 0x000B`).

```solidity
function checkPcrMeasurements(
    bytes calldata tpmQuote,
    MeasureablePcr[] calldata tpmPcrs
) external pure returns (bool success, bytes memory returnData);
```

**Example:**
```solidity
MeasureablePcr[] memory expectedPcrs = new MeasureablePcr[](1);
expectedPcrs[0] = MeasureablePcr({
    index: 0,
    pcr: expectedPcrValue,
    allEvents: eventHistory,
    measureEventsIdx: relevantEventIndices,
    measurePcr: true
});

(bool success, bytes memory userData) = tpmAttestation.checkPcrMeasurements(
    tpmQuote,
    expectedPcrs
);

require(success, "PCR validation failed");

// At this point, you might want to check whether the extracted userData matches with the intended value.
```

#### `toFinalMeasurement(MeasureablePcr[] tpmPcrs)`

Converts PCR measurements to final measurement format.

```solidity
function toFinalMeasurement(MeasureablePcr[] calldata tpmPcrs)
    external pure returns (Pcr[] memory);
```
> [!NOTE]
> The final measurement format of the PCR object can be used for reference as a **Golden Measurement** for CVM Workloads that are built specifically for the intended application.

### Certificate Management (Inherited from CertChainRegistry)

#### `addCA(bytes ca)` / `removeCA(bytes ca)`

Manage trusted Certificate Authorities (owner only).

#### `verifyCertChain(bytes[] certs)`

Verify a certificate chain against trusted CAs.

#### `verifySignature(bytes32 digest, bytes sig, CertPubkey pubkey)`

Verify digital signatures (supports RSA and ECDSA).

## Integration Guide

### Basic Integration Example

```solidity
pragma solidity ^0.8.20;

import {MeasureablePcr, ITpmAttestation} from "@automata-tpm-attestation/interfaces/ITpmAttestation.sol";

contract MyApplication {
    ITpmAttestation public immutable tpmAttestation;

    constructor(address _tpmAttestation) {
        tpmAttestation = ITpmAttestation(_tpmAttestation);
    }

    function verifyAndExecute(
        bytes calldata tpmQuote,
        bytes calldata tpmSignature,
        bytes[] calldata akCertchain,
        MeasureablePcr[] calldata expectedPcrs
    ) external {
        // 1. Verify TPM quote and certificate chain
        (bool quoteValid, bytes memory encodedAkPub) = tpmAttestation.verifyTpmQuote(
            tpmQuote,
            tpmSignature,
            akCertchain
        );
        require(quoteValid, "Invalid TPM Quote");

        // 2. Validate PCR measurements
        (bool pcrValid, bytes memory userData) = tpmAttestation.checkPcrMeasurements(
            tpmQuote,
            expectedPcrs
        );
        require(pcrValid, "Invalid PCR measurements");

        // 3. Process extracted user data
        _processUserData(userData);
    }

    function _processUserData(bytes memory userData) internal {
        // Implement your application logic here
        // userData contains the information embedded in the TPM quote
    }
}
```

### Advanced Usage: Pre-verified AK

For gas optimization, you can pre-verify and cache Attestation Keys:

```solidity
contract OptimizedTpmVerifier {
    mapping(bytes32 => CertPubkey) public trustedAKs;

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
    ) external view returns (bool) {
        CertPubkey memory akPub = trustedAKs[akHash];
        require(akPub.data.length > 0, "AK not trusted");

        (bool success,) = tpmAttestation.verifyTpmQuote(
            tpmQuote,
            tpmSignature,
            akPub
        );
        return success;
    }
}
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
