// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.0;

import {CertPubkey} from "../lib/LibX509.sol";

/// @notice CRL cache data structure
/// @dev Stores Certificate Revocation List information for an authenticated issuer identity
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
        bytes32 indexed revocationScope, bytes issuerDN, bytes akid, uint256 serialNumber, string reason
    );
    event CRLUpdated(
        bytes32 indexed revocationScope,
        bytes issuerDN,
        bytes akid,
        bytes32 crlHash,
        uint256 thisUpdate,
        uint256 nextUpdate
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

    /// @notice Check whether the target certificate is revoked in an authenticated chain
    /// @param certChain Certificates ordered as [target, issuer, ..., trusted root]
    /// @return True if the target certificate is revoked by its authenticated issuer
    function isCertificateRevokedInChain(bytes[] calldata certChain) external view returns (bool);

    /// @notice Compute the revocation namespace for an issuer certificate identity
    /// @param rootCertHash Compatibility parameter; authenticated path validation still
    ///        uses the root, but the issuer's revocation namespace does not
    /// @param issuerCert DER-encoded issuer certificate
    function computeRevocationScope(bytes32 rootCertHash, bytes calldata issuerCert) external pure returns (bytes32);

    function removeIntermediateCerts(bytes32[] calldata certHashes) external;

    /// @notice Update the CRL for a specific issuer
    /// @param crl The DER-encoded CRL
    /// @param signerChain The complete certificate path ordered as
    ///        [CRL signer, parent, ..., trusted root]
    /// @dev Any caller may relay a CRL. The CRL signer must have cRLSign key usage; every
    ///      non-root certificate signature and every certificate's validity and CA constraints
    ///      are checked. The final root must be registered in verifiedCA. A trusted root signer
    ///      uses a one-element path; an intermediate signer must include its complete path.
    ///      CRLNumber is required and must strictly increase for the authenticated issuer scope.
    ///      In strict CRL mode, current CRLs must already exist for the signer's issuing CAs.
    function updateCRL(bytes calldata crl, bytes[] calldata signerChain) external;

    /// @notice Latest accepted CRLNumber for an authenticated issuer identity
    function latestCRLNumber(bytes32 revocationScope) external view returns (uint256);

    function verifyCertSignature(bytes calldata cert, CertPubkey memory issuer) external view returns (bool);

    /// @notice Verifies a certificate chain
    /// @param certs - An array of X509 certificates in DER format.
    /// @return the public key of the leaf certificate
    function verifyCertChain(bytes[] calldata certs) external returns (CertPubkey memory);

    // Root CAs: cert hash => true
    function verifiedCA(bytes32 _certHash) external view returns (bool);
}
