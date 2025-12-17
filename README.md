<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_Black%20Text%20with%20Color%20Logo.png">
    <img src="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png" width="50%">
  </picture>
</div>


# Automata TPM Attestation
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Automata TPM Attestation](https://img.shields.io/badge/Power%20By-Automata-orange.svg)](https://github.com/automata-network)

A Solidity library for on-chain verification of Trusted Platform Module (TPM) attestations, enabling secure validation of hardware-backed cryptographic proofs in smart contracts.


## 📑 Table of Contents <!-- omit in toc -->
- [Overview](#overview)
- [Deployment Info](#deployment-info)
- [TPM Attestation Workflow](#tpm-attestation-workflow)
- [Architecture](#architecture)
- [User Guide](#user-guide)
- [Related Projects](#related-projects)
- [Contributing](#contributing)
- [Support](#support)


## Overview

TPM attestation provides a mechanism to cryptographically prove the integrity and authenticity of software and hardware configurations. This library enables Ethereum smart contracts to verify TPM quotes, validate Platform Configuration Register (PCR) measurements, and extract user data from TPM attestations.

The `TpmAttestation` contract extends `CertChainRegistry` to provide a complete solution for managing trusted Certificate Authorities (CAs) that issue TPM Attestation Keys and verifying the entire attestation chain.

## Deployment Info

| Network | Contract Address |
| --- | --- |
| Automata Testnet | [0xd8f86325Ea717F167cabc5BF0c5f06Df2E546368](https://explorer-testnet.ata.network/address/0xd8f86325Ea717F167cabc5BF0c5f06Df2E546368) |
| Sepolia Testnet | [0xd8f86325Ea717F167cabc5BF0c5f06Df2E546368](https://sepolia.etherscan.io/address/0xd8f86325Ea717F167cabc5BF0c5f06Df2E546368) |

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

// Final measurement format for validation
struct Pcr {
    uint256 index;          // PCR index
    bytes32 pcr;           // Expected PCR value (0 if not measured)
    bytes32[] measureEvents; // Expected events subset
    uint256[] measureEventsIdx; // Event indices
}

// Public key representation
struct CertPubkey {
    uint16 algo;           // Algorithm identifier (TPM_ALG_RSA or TPM_ALG_ECC)
    uint16 params;         // Algorithm-specific parameters (curve ID for EC, 0 for RSA)
    bytes data;            // Key data
}
```

## User Guide

For detailed documentation on installation, configuration, API reference, integration examples, and development setup, see the **[User Guide](docs/User-Guide.md)**.

## Related Projects

- [DCAP Attestation](https://github.com/automata-network/automata-dcap-attestation) - On-chain verification of Intel SGX/TDX DCAP attestations
- [TDX Attestation SDK](https://github.com/automata-network/tdx-attestation-sdk) - TDX Development SDK to generate Intel TDX quotes from cloud providers.
- [AMD SEV-SNP Attestation SDK](https://github.com/automata-network/amd-sev-snp-attestation-sdk) - On-chain verification of AMD SEV-SNP attestations
- [AWS Nitro Enclave Attestation](https://github.com/automata-network/aws-nitro-enclave-attestation) - On-chain verification of AWS Nitro Enclave attestations
- [TEE Workload Measurement](https://github.com/automata-network/tee-workload-measurement) - On-chain verification of CVM workload integrity and CVM identity management
- [CVM Base Image](https://github.com/automata-network/cvm-base-image) - Tools for deploying Confidential VMs with workloads on GCP, AWS, and Azure

## Contributing

Contributions are welcome! Please ensure all tests pass and follow the existing code style.

## Support

For questions and support, please open an issue.
