// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.0;

import {CertPubkey} from "../lib/LibX509.sol";

/// @notice CRL cache data structure
/// @dev Stores Certificate Revocation List information for a specific issuer
struct CRLData {
    bytes32 crlHash; // Hash of current CRL (for external reference/indexing)
    uint256 thisUpdate; // Timestamp when CRL was issued
    uint256 nextUpdate; // Timestamp when next CRL should be issued
}

/// @title Certificate Chain Registry Interface
/// @notice This is a simple interface for managing certificate authorities (CAs) and verifying certificate chains.
/// @custom:security-contact security@ata.network
interface ICertChainRegistry {
    event AddCA(bytes ca);
    event RemoveCA(bytes ca);
    event IntermediateCertRemoved(bytes32 indexed certHash);
    event CertificateRevoked(
        bytes32 indexed issuerHash, bytes issuerDN, bytes akid, uint256 serialNumber, string reason
    );
    event CRLUpdated(
        bytes32 indexed issuerHash, bytes issuerDN, bytes akid, bytes32 crlHash, uint256 thisUpdate, uint256 nextUpdate
    );
    event StrictCRLModeChanged(bool enabled);

    /// @notice Returns the address of the P256 Verifier that the contract uses
    function p256() external view returns (address);

    /// @notice Adds a Certificate Authority (CA) to the registry.
    /// @param ca - The X509 Certificate Authority (CA) in DER format.
    /// @dev should implement access-control
    function addCA(bytes calldata ca) external;

    /// @notice Removes a Certificate Authority (CA) from the registry.
    /// @param ca - The X509 Certificate Authority (CA) in DER format.
    /// @dev should implement access-control
    function removeCA(bytes calldata ca) external;

    /// @notice Check if a certificate is revoked
    /// @param cert The DER-encoded certificate to check
    /// @return True if the certificate is revoked
    function isCertificateRevoked(bytes calldata cert) external view returns (bool);

    function removeIntermediateCerts(bytes32[] calldata certHashes) external;

    /// @notice Update CRL for a specific issuer
    /// @param crl The DER-encoded CRL
    /// @param issuerCert The issuer's certificate for signature verification
    function updateCRL(bytes calldata crl, bytes calldata issuerCert) external;

    function verifyCertSignature(bytes calldata cert, CertPubkey memory issuer) external view returns (bool);

    /// @notice Verifies a certificate chain
    /// @param certs - An array of X509 certificates in DER format.
    /// @return the public key of the leaf certificate
    function verifyCertChain(bytes[] calldata certs) external returns (CertPubkey memory);

    // Root CAs: cert hash => true
    function verifiedCA(bytes32 _certHash) external view returns (bool);
}
