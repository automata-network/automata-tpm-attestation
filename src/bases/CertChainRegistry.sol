// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.27;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

import { ICertChainRegistry, CRLData } from "../interfaces/ICertChainRegistry.sol";
import { CertPubkey, LibX509, SignatureAlgorithm, CRLInfo } from "../lib/LibX509.sol";
import { LibX509Verify } from "../lib/LibX509Verify.sol";
import {
    InvalidCertChainLength,
    InvalidSignature,
    CertNotCa,
    CertificateAlreadyRevoked,
    CRLExpired,
    CRLNotYetValid,
    CRLSignatureVerificationFailed,
    CRLIssuerMismatch,
    CRLRollbackAttempt,
    InvalidCRLFormat,
    CRLRequiredInStrictMode,
    CRLExpiredInStrictMode,
    CRLMissingAKID,
    IssuerCertMissingSKID,
    IssuerSubjectDNMismatch,
    RootCaNotAtEndOfChain,
    ZeroAddress
} from "../types/Errors.sol";

/// @title CertChainRegistry
/// @notice Registry for managing and verifying X.509 certificate chains used in TEE attestation
/// @dev This abstract contract provides X.509 certificate chain verification for TPM attestation keys (AK).
///      It implements a trust hierarchy with root CAs and supports intermediate certificate caching
///      for gas optimization.
///      Certificate chain order: [leaf, intermediate(s)..., root]
///      Maximum chain length: 4 certificates
/// @custom:security-contact security@ata.network
abstract contract CertChainRegistry is ICertChainRegistry, Ownable {
    using LibX509 for bytes;
    using LibX509Verify for CertPubkey;

    /// @notice Address of the P-256 (secp256r1) signature verifier for ECDSA certificate verification
    /// @dev If the chain supports the RIP-7212 secp256r1 precompile (address 0x100), this can be set
    ///      to the precompile address for gas-efficient native verification. Otherwise, a contract
    ///      implementing the P256 verification interface (e.g., Daimo's P256Verifier) should be deployed
    ///      and its address provided here.
    address public immutable override p256;

    /// @notice Mapping of trusted root CA certificate hashes
    /// @dev keccak256(DER-encoded certificate) => true if trusted
    mapping(bytes32 certHash => bool isVerified) public verifiedCA;

    /// @notice Cache of verified intermediate certificates with chain binding
    /// @dev Maps bindingHash => rootCAHash, where:
    ///      bindingHash = keccak256(abi.encode(parentBindingHash, keccak256(cert)))
    ///      This ensures an intermediate can only be reused within the SAME chain context,
    ///      preventing certificate substitution attacks across different CA hierarchies.
    mapping(bytes32 bindingHash => bytes32 rootCAHash) public cachedIntermediates;

    /// @notice Revocation blacklist indexed by issuer DN hash and serial number
    /// @dev Maps keccak256(issuerDN) => serialNumber => isRevoked
    ///      Revoked certificates fail verification even if otherwise valid
    mapping(bytes32 issuerHash => mapping(uint256 serialNumber => bool isRevoked)) public revokedCertificates;

    // CRL cache: issuerHash => CRLData
    // issuerHash = keccak256(abi.encode(issuerDN, akid))
    mapping(bytes32 issuerHash => CRLData crlData) public crlCache;

    // Strict mode: requires valid CRL for certificate chain verification
    bool public strictCRLMode;

    constructor(address _intialOwner, address _p256) Ownable(_intialOwner) {
        if (_p256 == address(0)) revert ZeroAddress("p256");
        p256 = _p256;
        strictCRLMode = false; // Default: disabled for backward compatibility
    }

    /// @notice Adds a trusted root Certificate Authority to the registry
    /// @dev Performs the following validations before adding:
    ///      1. Verifies certificate constraints (CA flag, key usage)
    ///      2. Verifies the certificate is self-signed (root CA)
    /// @param ca The DER-encoded X.509 root CA certificate
    function addCA(bytes calldata ca) public override onlyOwner {
        bytes32 key = keccak256(ca);
        _verifyCertificateConstraints(ca, false, 0);

        CertPubkey memory issuer = LibX509.getPubkey(ca);
        bool result = verifyCertSignature(ca, issuer);
        require(result, InvalidSignature());
        verifiedCA[key] = true;
        emit AddCA(ca);
    }

    /// @notice Removes a Certificate Authority (CA) from the registry.
    /// @param ca - The X509 Certificate Authority (CA) in DER format.
    /// @dev should implement access-control
    function removeCA(bytes calldata ca) public onlyOwner {
        bytes32 key = keccak256(ca);
        require(verifiedCA[key], CertNotCa());
        delete verifiedCA[key];
        emit RemoveCA(ca);
    }

    /// @notice Enable or disable strict CRL mode
    /// @param enabled True to enable strict mode, false to disable
    /// @dev In strict mode, verifyCertChain requires valid CRL for each issuer
    function setStrictCRLMode(bool enabled) public onlyOwner {
        strictCRLMode = enabled;
        emit StrictCRLModeChanged(enabled);
    }

    /// @notice Check if a certificate is revoked
    /// @param cert The DER-encoded certificate to check
    /// @return True if the certificate is revoked
    function isCertificateRevoked(bytes calldata cert) public view returns (bool) {
        bytes memory issuerDN = LibX509.getCertIssuerDN(cert);
        uint256 serialNumber = LibX509.getCertSerialNumber(cert);

        (, bytes memory akid) = LibX509.getAuthorityKeyIdentifier(cert);
        bytes32 issuerHash = _computeRevocationKey(issuerDN, akid);

        return revokedCertificates[issuerHash][serialNumber];
    }

    /// @notice Removes cached intermediate certificates from the registry
    /// @dev Used for cache invalidation when intermediate CAs are compromised or retired.
    ///      Does not affect root CA trust - only clears the verification cache.
    /// @param certHashes Array of binding hashes to remove from cache
    function removeIntermediateCerts(bytes32[] calldata certHashes) public onlyOwner {
        for (uint256 i = 0; i < certHashes.length; i++) {
            bytes32 certHash = certHashes[i];
            if (cachedIntermediates[certHash] != bytes32(0)) {
                delete cachedIntermediates[certHash];
                emit IntermediateCertRemoved(certHash);
            }
        }
    }

    /// @notice Update CRL for a specific issuer
    /// @param crl The DER-encoded CRL
    /// @param issuerCert The issuer's certificate for signature verification
    /// @dev The function verifies:
    /// @dev 1. CRL validity period (thisUpdate <= now < nextUpdate)
    /// @dev 2. CRL signature against issuer's public key
    /// @dev 3. Issuer DN and AKID match
    /// @dev 4. Anti-rollback: new CRL's thisUpdate must be >= cached CRL's thisUpdate
    function updateCRL(bytes calldata crl, bytes calldata issuerCert) public {
        // Parse CRL
        CRLInfo memory crlInfo = LibX509.parseCRL(crl);

        // Verify CRL validity period
        if (block.timestamp < crlInfo.thisUpdate) {
            revert CRLNotYetValid();
        }
        if (block.timestamp >= crlInfo.nextUpdate) {
            revert CRLExpired();
        }

        bytes32 issuerHash;
        bytes memory akidForHash;
        {
            // Extract issuer cert information
            bytes memory issuerCertDN = LibX509.getCertSubjectDN(issuerCert);
            (bool skidExists, bytes memory issuerCertSkid) = LibX509.getSubjectKeyIdentifier(issuerCert);

            // Verify issuer DN matches
            if (keccak256(crlInfo.issuerDN) != keccak256(issuerCertDN)) {
                revert CRLIssuerMismatch();
            }

            // Per RFC 5280 Section 5.2.1: Conforming CRL issuers MUST include AKID extension
            if (crlInfo.authorityKeyId.length == 0) {
                revert CRLMissingAKID();
            }

            // Per RFC 5280 Section 4.2.1.2: Conforming CA certificates MUST include SKID extension
            if (!skidExists || issuerCertSkid.length == 0) {
                revert IssuerCertMissingSKID();
            }

            // Verify CRL's AKID matches issuer cert's SKID
            if (keccak256(crlInfo.authorityKeyId) != keccak256(issuerCertSkid)) {
                revert CRLIssuerMismatch();
            }

            // Use AKID for issuer hash (now guaranteed to be present)
            akidForHash = crlInfo.authorityKeyId;
            issuerHash = _computeRevocationKey(crlInfo.issuerDN, akidForHash);
        }

        {
            // Verify CRL signature
            CertPubkey memory issuerPubkey = LibX509.getPubkey(issuerCert);
            bytes memory sigAlgoOid = LibX509.getCRLSignatureAlgorithm(crl);
            SignatureAlgorithm memory sigAlgo = issuerPubkey.parseSignatureAlgorithm(sigAlgoOid);
            bool sigValid = issuerPubkey.verifySignature(sigAlgo, crlInfo.tbs, crlInfo.signature, p256);
            if (!sigValid) {
                revert CRLSignatureVerificationFailed();
            }
        }

        // Anti-rollback check
        CRLData storage cached = crlCache[issuerHash];
        if (cached.thisUpdate > 0 && crlInfo.thisUpdate < cached.thisUpdate) {
            revert CRLRollbackAttempt();
        }

        // Sync revoked certificates to blacklist
        for (uint256 i = 0; i < crlInfo.revokedSerials.length; i++) {
            uint256 serialNumber = crlInfo.revokedSerials[i];
            if (!revokedCertificates[issuerHash][serialNumber]) {
                revokedCertificates[issuerHash][serialNumber] = true;
                emit CertificateRevoked(issuerHash, crlInfo.issuerDN, akidForHash, serialNumber, "Synced from CRL");
            }
        }

        // Update cache
        bytes32 crlHash = keccak256(crl);
        cached.crlHash = crlHash;
        cached.thisUpdate = crlInfo.thisUpdate;
        cached.nextUpdate = crlInfo.nextUpdate;

        emit CRLUpdated(
            issuerHash, crlInfo.issuerDN, crlInfo.authorityKeyId, crlHash, crlInfo.thisUpdate, crlInfo.nextUpdate
        );
    }

    /// @notice Verifies a certificate's signature using the issuer's public key
    /// @dev Extracts the TBS (To Be Signed) data, signature, and algorithm from the certificate,
    ///      then verifies using the appropriate algorithm (RSA or ECDSA).
    /// @param cert The DER-encoded certificate to verify
    /// @param issuer The public key of the issuing CA
    /// @return True if the signature is valid, false otherwise
    function verifyCertSignature(bytes calldata cert, CertPubkey memory issuer) public view returns (bool) {
        bytes memory tbs = LibX509.getCertTbs(cert);
        bytes memory signature = LibX509.getCertSignature(cert);
        bytes memory sigAlgoOid = LibX509.getCertSignatureAlgorithm(cert);
        SignatureAlgorithm memory sigAlgo = issuer.parseSignatureAlgorithm(sigAlgoOid);
        return issuer.verifySignature(sigAlgo, tbs, signature, p256);
    }

    /// @notice Verifies an X.509 certificate chain up to a trusted root CA
    /// @dev Performs comprehensive chain verification:
    ///      1. Validates chain length (1-4 certificates)
    ///      2. Verifies root CA is in the trusted set
    ///      3. Checks for cached intermediates to skip re-verification
    ///      4. Validates each certificate (validity, CA constraints, revocation)
    ///      5. Verifies signatures from leaf to cached/root
    ///      6. Caches newly verified intermediates for future use
    ///
    ///      Chain order: [leaf, intermediate(s)..., root]
    ///
    /// @param certs Array of DER-encoded certificates ordered from leaf to root
    /// @return The public key extracted from the leaf certificate
    /// @custom:security Revocation is checked for all certificates in the chain
    function verifyCertChain(bytes[] calldata certs) public returns (CertPubkey memory) {
        uint256 certLen = certs.length;
        require(certLen > 0 && certLen < 5, InvalidCertChainLength());

        bytes32[] memory bindingHashes = LibX509.getCertChainHashes(certs);
        if (!verifiedCA[bindingHashes[bindingHashes.length - 1]]) {
            revert RootCaNotAtEndOfChain();
        }

        // Strict CRL mode: verify that valid CRL exists for all issuers in the chain
        if (strictCRLMode) {
            _checkCRLValidityForChain(certs);
        }

        uint256 verifiedFrom = _findCachedIntermediate(bindingHashes);

        // Step 4: Perform verification
        CertPubkey[] memory issuers = _verifyChain(certs, verifiedFrom);

        // Step 5: Cache newly verified intermediates
        _cacheIntermediates(bindingHashes);

        // Return leaf certificate's issuer (the public key)
        return issuers[0];
    }

    /// @dev Find the earliest cached intermediate certificate
    function _findCachedIntermediate(bytes32[] memory bindingHashes) internal view returns (uint256) {
        uint256 verifiedFrom = bindingHashes.length - 1;

        // Need at least 2 elements (root CA + intermediate) to have cached intermediates
        if (bindingHashes.length < 2) {
            return verifiedFrom;
        }

        bytes32 rootCA = bindingHashes[bindingHashes.length - 1];

        // Start from second-to-last element (skip root CA)
        for (uint256 i = bindingHashes.length - 2; i > 0; i--) {
            bytes32 cachedRootCA = cachedIntermediates[bindingHashes[i]];
            if (cachedRootCA != rootCA) {
                break;
            }
            verifiedFrom = i;
        }
        return verifiedFrom;
    }

    /// @dev Verify the certificate chain
    /// @notice Per RFC 5280 Section 6.1.3, this function validates:
    ///         1. Certificate constraints (validity, CA, revocation)
    ///         2. Issuer-Subject DN linkage: Issuer DN of certs[i] must match Subject DN of certs[i+1]
    ///         3. Cryptographic signatures
    function _verifyChain(bytes[] calldata certs, uint256 verifiedFrom) internal view returns (CertPubkey[] memory) {
        CertPubkey[] memory issuers = new CertPubkey[](certs.length);

        // Get all issuers
        for (uint256 i = 0; i < certs.length; i++) {
            issuers[i] = LibX509.getPubkey(certs[i]);
        }

        // Verify all certificates (validity, CA constraints, revocation)
        for (uint256 i = 0; i < certs.length; i++) {
            uint256 pathLen = 0;
            if (i >= 1) {
                pathLen = i - 1;
            }
            _verifyCertificateConstraints(certs[i], i == 0, pathLen);
        }

        // Verify Issuer-Subject DN linkage per RFC 5280 Section 6.1.3
        // The Issuer DN of certs[i] must match the Subject DN of certs[i+1]
        for (uint256 i = 0; i < certs.length - 1; i++) {
            bytes memory issuerDN = LibX509.getCertIssuerDN(certs[i]);
            bytes memory subjectDN = LibX509.getCertSubjectDN(certs[i + 1]);
            if (keccak256(issuerDN) != keccak256(subjectDN)) {
                revert IssuerSubjectDNMismatch();
            }
        }

        // Verify DN and AKID/SKID chain linkage per RFC 5280
        LibX509.verifyDNChainLinkage(certs);
        LibX509.verifyAKIDSKIDChainLinkage(certs);

        // Verify signatures from leaf to verifiedFrom
        for (uint256 i = 0; i < verifiedFrom; i++) {
            bool result = verifyCertSignature(certs[i], issuers[i + 1]);
            require(result, InvalidSignature());
        }

        return issuers;
    }

    /// @dev Compute revocation key from issuer DN and optional AKID
    /// @param issuerDN The DER-encoded issuer Distinguished Name
    /// @param akid The Authority Key Identifier (empty if not present)
    /// @return The computed revocation key
    function _computeRevocationKey(bytes memory issuerDN, bytes memory akid) internal pure returns (bytes32) {
        // If AKID is present, use DN + AKID for unique identification
        // This prevents cross-CA conflicts when different CAs share the same DN
        if (akid.length > 0) {
            return keccak256(abi.encode(issuerDN, akid));
        }
        // Fallback to DN-only for backward compatibility with old certificates
        return keccak256(issuerDN);
    }

    /// @dev Verify individual certificate (validity, constraints, revocation)
    function _verifyCertificateConstraints(bytes calldata cert, bool isLeaf, uint256 pathLen) internal view {
        LibX509.checkCertValidity(cert);
        LibX509.checkCAConstraints(cert, pathLen, isLeaf);

        bytes memory issuerDN = LibX509.getCertIssuerDN(cert);
        uint256 serialNumber = LibX509.getCertSerialNumber(cert);

        // Extract AKID to uniquely identify issuer
        (, bytes memory akid) = LibX509.getAuthorityKeyIdentifier(cert);
        bytes32 issuerHash = _computeRevocationKey(issuerDN, akid);

        require(!revokedCertificates[issuerHash][serialNumber], CertificateAlreadyRevoked());
    }

    /// @dev Cache newly verified intermediate certificates
    function _cacheIntermediates(bytes32[] memory bindingHashes) internal {
        bytes32 rootBinding = bindingHashes[bindingHashes.length - 1];

        // Cache all intermediates (skip leaf at index 0)
        for (uint256 i = 1; i < bindingHashes.length - 1; i++) {
            // Only cache if not already cached
            if (cachedIntermediates[bindingHashes[i]] == bytes32(0)) {
                cachedIntermediates[bindingHashes[i]] = rootBinding;
            }
        }
    }

    /// @dev Check that valid CRL exists for all issuers in the certificate chain
    /// @notice This is only called when strictCRLMode is enabled
    /// @param certs Array of certificates in the chain (leaf to root)
    function _checkCRLValidityForChain(bytes[] calldata certs) internal view {
        // For each certificate (except the leaf), check its issuer has a valid CRL
        // We check certs[1..n] as issuers (root CA and intermediates)
        for (uint256 i = 1; i < certs.length; i++) {
            bytes memory subjectDN = LibX509.getCertSubjectDN(certs[i]);
            (, bytes memory skid) = LibX509.getSubjectKeyIdentifier(certs[i]);

            // Compute issuer hash (this cert is the issuer of certs[i-1])
            bytes32 issuerHash = _computeRevocationKey(subjectDN, skid);

            CRLData storage cached = crlCache[issuerHash];

            // Check if CRL exists
            if (cached.thisUpdate == 0) {
                revert CRLRequiredInStrictMode();
            }

            // Check if CRL is still valid (not expired)
            if (block.timestamp >= cached.nextUpdate) {
                revert CRLExpiredInStrictMode();
            }
        }
    }
}
