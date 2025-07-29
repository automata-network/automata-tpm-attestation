# Automata TPM Attestation

A Solidity library for on-chain verification of Trusted Platform Module (TPM) attestations, enabling secure validation of hardware-backed cryptographic proofs in smart contracts.

## Overview

TPM attestation provides a mechanism to cryptographically prove the integrity and authenticity of software and hardware configurations. This library enables Ethereum smart contracts to verify TPM quotes, validate Platform Configuration Register (PCR) measurements, and extract user data from TPM attestations.

The `TpmAttestation` contract extends `CertChainRegistry` to provide a complete solution for managing trusted Certificate Authorities (CAs) that issue TPM Attestation Keys and verifying the entire attestation chain.

## TPM Attestation Workflow

```
1. Hardware Setup
   ├── TPM generates Attestation Key (AK)
   ├── CA issues certificate for AK
   └── CA is registered as trusted in contract

2. Quote Generation
   ├── Application measures software/data into PCRs
   ├── TPM generates quote containing PCR digest
   ├── TPM signs quote with AK
   └── User data embedded in quote

3. On-Chain Verification
   ├── Verify AK certificate chain against trusted CAs
   ├── Verify TPM quote signature using AK
   ├── Validate PCR measurements against expected values
   └── Extract and use embedded user data
```

## Architecture

### Core Components

- **`TpmAttestation`**: Main contract extending `CertChainRegistry`
- **`CertChainRegistry`**: Base contract for managing trusted CAs and certificate verification
- **`ITpmAttestation`**: Interface defining TPM-specific verification methods
- **`ICertChainRegistry`**: Interface for certificate chain management

### Key Data Structures

```solidity
// Input PCR measurements with event history
struct MeasureablePcr {
    uint256 index;           // PCR index
    bytes32 pcr;            // Current PCR value
    bytes32[] allEvents;    // Complete event history
    uint256[] measureEventsIdx; // Indices of events to measure
    bool measurePcr;        // Whether to include PCR value
}

// Golden measurement format for validation
struct Pcr {
    uint256 index;          // PCR index
    bytes32 pcr;           // Expected PCR value (0 if not measured)
    bytes32[] measureEvents; // Expected events subset
    uint256[] measureEventsIdx; // Event indices
}

// Public key representation
struct CertPubkey {
    uint256 algo;          // Algorithm identifier
    bytes data;           // Key data
}
```

## Installation & Setup

### 1. Install via Foundry

```bash
forge install automata-network/automata-tpm-attestation
```

### 2. Configure Remappings

Add to your `foundry.toml`:

```toml
remappings = [
    "@automata-tpm-attestation/=lib/automata-tpm-attestation/src/",
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

Verifies a TPM quote with full certificate chain validation.

```solidity
function verifyTpmQuote(
    bytes calldata tpmQuote,      // TPM quote data
    bytes calldata tpmSignature,  // TPM signature
    bytes[] calldata akCertchain  // AK certificate chain [leaf, intermediate, root]
) external returns (bool success, string memory errorMessage);
```

**Example:**
```solidity
bytes[] memory certChain = new bytes[](3);
certChain[0] = akLeafCert;
certChain[1] = intermediateCert;
certChain[2] = rootCaCert;

(bool success, string memory error) = tpmAttestation.verifyTpmQuote(
    tpmQuote,
    tpmSignature,
    certChain
);

require(success, error);
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
> PCR Digest currently only supports SHA256 hash (`HASH_SHA256 = 0x000B`).

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
```

#### `toGoldenMeasurement(MeasureablePcr[] tpmPcrs)`

Converts PCR measurements to golden measurement format.

```solidity
function toGoldenMeasurement(MeasureablePcr[] calldata tpmPcrs) 
    external pure returns (Pcr[] memory);
```

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
        (bool quoteValid, string memory quoteError) = tpmAttestation.verifyTpmQuote(
            tpmQuote,
            tpmSignature,
            akCertchain
        );
        require(quoteValid, quoteError);
        
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

## Contributing

Contributions are welcome! Please ensure all tests pass and follow the existing code style.

## Support

For questions and support, please open an issue.
