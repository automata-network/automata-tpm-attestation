// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.27;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {ICertChainRegistry, CRLData} from "../interfaces/ICertChainRegistry.sol";
import {CertPubkey, LibX509, SignatureAlgorithm, CRLInfo} from "../lib/LibX509.sol";
import {LibX509Verify} from "../lib/LibX509Verify.sol";
import {
    InvalidCertChainLength,
    InvalidCertificateChain,
    InvalidSignature,
    CertNotCa,
    CertificateAlreadyRevoked,
    CRLExpired,
    CRLNotYetValid,
    CRLSignatureVerificationFailed,
    CRLIssuerMismatch,
    CRLRollbackAttempt,
    InvalidCRLFormat,
    CRLSignerNotTrusted,
    CRLSignNotSet,
    CRLRequiredInStrictMode,
    CRLExpiredInStrictMode,
    CRLMissingAKID,
    IssuerCertMissingSKID,
    CertChainAKIDMismatch,
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

    bytes32 private constant ISSUER_IDENTITY_V1 = keccak256("AUTOMATA_ISSUER_IDENTITY_V1");
    bytes32 private constant REVOCATION_SCOPE_V2 = keccak256("AUTOMATA_REVOCATION_SCOPE_V2");
    bytes32 internal constant REVOKED_SET_DOMAIN = keccak256("AUTOMATA_CRL_REVOKED_SET_V1");

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

    mapping(bytes32 revocationScope => bytes32 setHash) public activeRevokedSetHash;
    mapping(bytes32 setHash => bool isIndexed) internal _indexedRevokedSets;
    mapping(bytes32 setHash => mapping(uint256 serialNumber => bool isMember)) internal _revokedSerials;

    // CRL cache: authenticated revocation scope => CRLData
    mapping(bytes32 revocationScope => CRLData crlData) public crlCache;

    // Strict mode: requires valid CRL for certificate chain verification
    bool public strictCRLMode;

    // Latest accepted CRLNumber for each authenticated issuer identity
    mapping(bytes32 revocationScope => uint256 crlNumber) public latestCRLNumber;

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
        _requireCertificateNotRevoked(ca, _computeRevocationScope(ca));

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

    function revokedCertificates(bytes32 revocationScope, uint256 serialNumber) public view returns (bool) {
        bytes32 setHash = activeRevokedSetHash[revocationScope];
        return setHash != bytes32(0) && _revokedSerials[setHash][serialNumber];
    }

    /// @notice Check whether a target certificate is revoked in an authenticated chain
    /// @param certChain Certificates ordered as [target, issuer, ..., trusted root]
    /// @return True if the target is revoked by its authenticated issuer
    function isCertificateRevokedInChain(bytes[] calldata certChain) public view returns (bool) {
        uint256 certLen = certChain.length;
        if (certLen == 0 || certLen > 4) {
            revert InvalidCertChainLength();
        }

        bytes32 rootCertHash = keccak256(certChain[certLen - 1]);
        if (!verifiedCA[rootCertHash]) {
            revert RootCaNotAtEndOfChain();
        }

        if (strictCRLMode) {
            _checkCRLValidityForChain(certChain);
        }

        // Authenticate the supplied path while allowing the target's revocation
        // status to be returned instead of reverting during path validation.
        (, bool targetIsCA,,) = LibX509.getBasicConstraints(certChain[0]);
        _verifyChain(certChain, certLen - 1, !targetIsCA, true);

        uint256 issuerIndex = certLen > 1 ? 1 : 0;
        bytes32 revocationScope = _computeRevocationScope(certChain[issuerIndex]);
        uint256 serialNumber = LibX509.getCertSerialNumber(certChain[0]);
        return revokedCertificates(revocationScope, serialNumber);
    }

    /// @notice Compute the authenticated revocation namespace for an issuer
    /// @dev The identity is stable across cross-certification and certificate renewals
    ///      that retain the same subject DN and public key.
    function computeRevocationScope(bytes32 rootCertHash, bytes calldata issuerCert) public pure returns (bytes32) {
        rootCertHash; // Retained for ABI compatibility; issuer identity is root-independent.
        return _computeRevocationScope(issuerCert);
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
    /// @param signerChain The CRL signer chain ordered as [signer, parent(s), trusted root]
    /// @dev The function verifies:
    /// @dev 1. CRL validity period (thisUpdate <= now < nextUpdate)
    /// @dev 2. CRL signer chain terminates at a root in verifiedCA
    /// @dev 3. Every certificate is valid/authorized as a CA, and every non-root is signed by its parent
    /// @dev 4. The direct signer has the cRLSign key usage
    /// @dev 5. CRL signature, issuer DN, and AKID match the direct signer
    /// @dev 6. Anti-rollback: CRLNumber must strictly increase and thisUpdate must not decrease
    /// @dev In strict CRL mode, the signer path must also have current issuer CRLs.
    function updateCRL(bytes calldata crl, bytes[] calldata signerChain) public {
        uint256 signerChainLength = signerChain.length;
        if (signerChainLength == 0 || signerChainLength > 4) {
            revert InvalidCertChainLength();
        }

        // Parse CRL
        CRLInfo memory crlInfo = LibX509.parseCRL(crl);

        // Verify CRL validity period
        if (block.timestamp < crlInfo.thisUpdate) {
            revert CRLNotYetValid();
        }
        if (block.timestamp >= crlInfo.nextUpdate) {
            revert CRLExpired();
        }

        // Authenticate the exact CRL signer back to a currently trusted root.
        _verifyCRLSignerChain(signerChain);
        bytes calldata issuerCert = signerChain[0];

        bytes32 revocationScope;
        bytes memory authorityKeyId;
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

            authorityKeyId = crlInfo.authorityKeyId;
            revocationScope = _computeRevocationScope(issuerCert);
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
        CRLData storage cached = crlCache[revocationScope];
        if (cached.crlHash != bytes32(0)) {
            if (crlInfo.crlNumber <= latestCRLNumber[revocationScope] || crlInfo.thisUpdate < cached.thisUpdate) {
                revert CRLRollbackAttempt();
            }
        }

        bytes32 revokedSetHash = _computeRevokedSetHash(revocationScope, crlInfo.revokedSerials);
        bool reused = _indexedRevokedSets[revokedSetHash];

        if (!reused) {
            for (uint256 i = 0; i < crlInfo.revokedSerials.length; i++) {
                uint256 serialNumber = crlInfo.revokedSerials[i];
                _revokedSerials[revokedSetHash][serialNumber] = true;
                emit CertificateRevoked(
                    revocationScope, crlInfo.issuerDN, authorityKeyId, serialNumber, "Indexed from complete CRL"
                );
            }
            _indexedRevokedSets[revokedSetHash] = true;
        }

        activeRevokedSetHash[revocationScope] = revokedSetHash;

        bytes32 crlHash = keccak256(crl);
        cached.crlHash = crlHash;
        cached.thisUpdate = crlInfo.thisUpdate;
        cached.nextUpdate = crlInfo.nextUpdate;
        latestCRLNumber[revocationScope] = crlInfo.crlNumber;

        emit CRLRevokedSetActivated(revocationScope, revokedSetHash, crlInfo.revokedSerials.length, reused);
        emit CRLUpdated(
            revocationScope, crlInfo.issuerDN, crlInfo.authorityKeyId, crlHash, crlInfo.thisUpdate, crlInfo.nextUpdate
        );
    }

    /// @dev Validate a direct CRL signer certificate path to a trusted root.
    ///      This contract intentionally supports complete, direct CRLs only: the first
    ///      certificate must be a CA authorized for both certificate and CRL signing.
    /// @param signerChain Certificates ordered as [CRL signer, parent(s), trusted root]
    function _verifyCRLSignerChain(bytes[] calldata signerChain) internal view {
        uint256 signerChainLength = signerChain.length;
        if (signerChainLength == 0 || signerChainLength > 4) {
            revert InvalidCertChainLength();
        }

        bytes32 rootCertHash = keccak256(signerChain[signerChainLength - 1]);
        if (!verifiedCA[rootCertHash]) {
            revert CRLSignerNotTrusted();
        }

        // A root CRL can always refresh itself. For subordinate signers in strict
        // mode, each issuing CA above the signer must already have a current CRL.
        if (strictCRLMode) {
            _checkCRLValidityForChain(signerChain);
        }

        // A direct CRL signer must explicitly be authorized to sign CRLs.
        (bool keyUsageExists, uint16 keyUsage) = LibX509.getKeyUsage(signerChain[0]);
        uint16 keyUsageCRLSign = 0x0200;
        if (!keyUsageExists || (keyUsage & keyUsageCRLSign) == 0) {
            revert CRLSignNotSet();
        }

        for (uint256 i = 0; i < signerChainLength; i++) {
            bytes32 certHash = keccak256(signerChain[i]);
            for (uint256 j = 0; j < i; j++) {
                if (certHash == keccak256(signerChain[j])) {
                    revert InvalidCertificateChain();
                }
            }

            // The CRL signer is the certification-path target and is not counted
            // as an intermediate CA for pathLenConstraint purposes.
            uint256 intermediateCACount = i == 0 ? 0 : i - 1;
            _verifyCertificateConstraints(signerChain[i], false, intermediateCACount);

            uint256 issuerIndex = i + 1 < signerChainLength ? i + 1 : i;
            bytes32 revocationScope = _computeRevocationScope(signerChain[issuerIndex]);
            _requireCertificateNotRevoked(signerChain[i], revocationScope);
        }

        for (uint256 i = 0; i + 1 < signerChainLength; i++) {
            bytes memory issuerDN = LibX509.getCertIssuerDN(signerChain[i]);
            bytes memory parentSubjectDN = LibX509.getCertSubjectDN(signerChain[i + 1]);
            if (keccak256(issuerDN) != keccak256(parentSubjectDN)) {
                revert IssuerSubjectDNMismatch();
            }

            (bool akidExists, bytes memory akid) = LibX509.getAuthorityKeyIdentifier(signerChain[i]);
            (bool skidExists, bytes memory skid) = LibX509.getSubjectKeyIdentifier(signerChain[i + 1]);
            if (!skidExists || skid.length == 0) {
                revert IssuerCertMissingSKID();
            }
            if (!akidExists || akid.length == 0 || keccak256(akid) != keccak256(skid)) {
                revert CertChainAKIDMismatch(i, akid, skid);
            }

            CertPubkey memory parentPubkey = LibX509.getPubkey(signerChain[i + 1]);
            if (!verifyCertSignature(signerChain[i], parentPubkey)) {
                revert InvalidSignature();
            }
        }
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
        CertPubkey[] memory issuers = _verifyChain(certs, verifiedFrom, true, false);

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
    function _verifyChain(bytes[] calldata certs, uint256 verifiedFrom, bool targetIsLeaf, bool skipTargetRevocation)
        internal
        view
        returns (CertPubkey[] memory)
    {
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
            _verifyCertificateConstraints(certs[i], i == 0 && targetIsLeaf, pathLen);

            if (!(skipTargetRevocation && i == 0)) {
                uint256 issuerIndex = i + 1 < certs.length ? i + 1 : i;
                bytes32 revocationScope = _computeRevocationScope(certs[issuerIndex]);
                _requireCertificateNotRevoked(certs[i], revocationScope);
            }
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

        // The shared helper permits a missing AKID only for an end-entity target.
        // A CA used as the path target remains subject to the CA AKID requirement.
        if (!targetIsLeaf && certs.length > 1) {
            (bool akidExists, bytes memory akid) = LibX509.getAuthorityKeyIdentifier(certs[0]);
            (bool skidExists, bytes memory skid) = LibX509.getSubjectKeyIdentifier(certs[1]);
            if (!skidExists || skid.length == 0) {
                revert IssuerCertMissingSKID();
            }
            if (!akidExists || akid.length == 0 || keccak256(akid) != keccak256(skid)) {
                revert CertChainAKIDMismatch(0, akid, skid);
            }
        }

        // Verify signatures from leaf to verifiedFrom
        for (uint256 i = 0; i < verifiedFrom; i++) {
            bool result = verifyCertSignature(certs[i], issuers[i + 1]);
            require(result, InvalidSignature());
        }

        return issuers;
    }

    /// @dev Derive a stable CA identity from its exact subject DN and actual public key.
    ///      SKID is intentionally excluded because it can be reassigned across certificate
    ///      renewals and is not itself cryptographically bound to the public key.
    function _computeIssuerIdentity(bytes calldata issuerCert) internal pure returns (bytes32) {
        bytes memory subjectDN = LibX509.getCertSubjectDN(issuerCert);
        CertPubkey memory pubkey = LibX509.getPubkey(issuerCert);
        bytes32 pubkeyHash = LibX509.canonicalPubkeyHash(pubkey);
        return keccak256(abi.encode(ISSUER_IDENTITY_V1, keccak256(subjectDN), pubkey.algo, pubkey.params, pubkeyHash));
    }

    /// @dev Derive one revocation namespace for a CA identity across every authenticated path.
    function _computeRevocationScope(bytes calldata issuerCert) internal pure returns (bytes32) {
        return keccak256(abi.encode(REVOCATION_SCOPE_V2, _computeIssuerIdentity(issuerCert)));
    }

    function _computeRevokedSetHash(bytes32 revocationScope, uint256[] memory serials) internal pure returns (bytes32) {
        return keccak256(abi.encode(REVOKED_SET_DOMAIN, revocationScope, serials));
    }

    /// @dev Verify individual certificate validity and CA/leaf constraints.
    function _verifyCertificateConstraints(bytes calldata cert, bool isLeaf, uint256 pathLen) internal view {
        LibX509.validateCertificateExtensions(cert);
        LibX509.checkCertValidity(cert);
        LibX509.checkCAConstraints(cert, pathLen, isLeaf);
    }

    /// @dev Reject a certificate serial revoked by its authenticated issuer scope.
    function _requireCertificateNotRevoked(bytes calldata cert, bytes32 revocationScope) internal view {
        uint256 serialNumber = LibX509.getCertSerialNumber(cert);
        require(!revokedCertificates(revocationScope, serialNumber), CertificateAlreadyRevoked());
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
            bytes32 revocationScope = _computeRevocationScope(certs[i]);
            CRLData storage cached = crlCache[revocationScope];

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
