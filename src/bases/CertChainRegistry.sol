// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.27;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {ICertChainRegistry, CRLData} from "../interfaces/ICertChainRegistry.sol";
import {CertPubkey, LibX509, SignatureAlgorithm, CRLInfo} from "../lib/LibX509.sol";
import {LibX509Verify} from "../lib/LibX509Verify.sol";
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
///      Certificate chain order: [target (CA or end entity), intermediate(s)..., root]
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

    /// @notice Revocation blacklist indexed by authenticated issuer identity and serial number
    /// @dev The issuer identity binds its subject name, public-key algorithm, and public key.
    ///      Revoked certificates fail verification even if otherwise valid
    mapping(bytes32 issuerHash => mapping(uint256 serialNumber => bool isRevoked)) public revokedCertificates;

    // CRL cache: issuerHash => CRLData
    // issuerHash binds the authenticated issuer name and public key, not its copyable SKID.
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
    function addCA(bytes calldata ca) external override onlyOwner {
        bytes32 key = keccak256(ca);
        _verifyCertificateConstraints(ca, false, 0);

        CertPubkey memory issuer = LibX509.getPubkey(ca);
        require(!_isRevoked(ca, ca, issuer), CertificateAlreadyRevoked());
        bool result = verifyCertSignature(ca, issuer);
        require(result, InvalidSignature());
        verifiedCA[key] = true;
        emit AddCA(ca);
    }

    /// @notice Removes a Certificate Authority (CA) from the registry.
    /// @param ca - The X509 Certificate Authority (CA) in DER format.
    /// @dev should implement access-control
    function removeCA(bytes calldata ca) external onlyOwner {
        bytes32 key = keccak256(ca);
        require(verifiedCA[key], CertNotCa());
        delete verifiedCA[key];
        emit RemoveCA(ca);
    }

    /// @notice Enable or disable strict CRL mode
    /// @param enabled True to enable strict mode, false to disable
    /// @dev In strict mode, verifyCertChain requires valid CRL for each issuer
    function setStrictCRLMode(bool enabled) external onlyOwner {
        strictCRLMode = enabled;
        emit StrictCRLModeChanged(enabled);
    }

    /// @notice Return the first certificate's revocation status after authenticating its chain.
    /// @dev Applies normal validity, issuer, ancestor-revocation, and strict-CRL checks.
    ///      Only the target's revocation rejection is suppressed so this query can return true.
    function isCertificateRevoked(bytes[] calldata certs) external view returns (bool) {
        (CertPubkey[] memory keys,) = _verifyCertChain(certs);
        _checkChainRevocations(certs, keys, 1);
        uint256 issuerIndex = certs.length == 1 ? 0 : 1;
        return _isRevoked(certs[0], certs[issuerIndex], keys[issuerIndex]);
    }

    /// @notice Removes cached intermediate certificates from the registry
    /// @dev Used for cache invalidation when intermediate CAs are compromised or retired.
    ///      Does not affect root CA trust - only clears the verification cache.
    /// @param certHashes Array of binding hashes to remove from cache
    function removeIntermediateCerts(bytes32[] calldata certHashes) external onlyOwner {
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
    /// @param issuerChain Certificates ordered [CRL signer, intermediate(s), trusted root]
    /// @dev The function verifies:
    /// @dev 1. CRL validity period (thisUpdate <= now < nextUpdate)
    /// @dev 2. Trusted signer chain, CA/cRLSign permission, and CRL signature
    /// @dev 3. Issuer DN and AKID match
    /// @dev 4. Anti-rollback: new CRL's thisUpdate must be >= cached CRL's thisUpdate
    function updateCRL(bytes calldata crl, bytes[] calldata issuerChain) external {
        // Authenticate the signer before using its name, key identifier, or public key.
        // The chain checks ancestor CRLs, not the CRL this signer is submitting.
        CertPubkey memory issuerPubkey = verifyCertChain(issuerChain);
        bytes calldata issuerCert = issuerChain[0];
        LibX509.checkCAConstraints(issuerCert, 0, false);
        LibX509.checkCRLSign(issuerCert);

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

            // AKID is checked for linkage; authority is bound to the authenticated key.
            akidForHash = crlInfo.authorityKeyId;
            issuerHash = _computeRevocationKey(issuerCert, issuerPubkey);
        }

        {
            // Verify CRL signature
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
    ///      Chain order: [target (CA or end entity), intermediate(s)..., root]
    ///
    /// @param certs Array of DER-encoded certificates ordered from target to root
    /// @return The public key extracted from the first certificate (CA or end entity)
    /// @custom:security Revocation is checked for all certificates in the chain
    function verifyCertChain(bytes[] calldata certs) public returns (CertPubkey memory) {
        (CertPubkey[] memory keys, bytes32[] memory bindingHashes) = _verifyCertChain(certs);
        _checkChainRevocations(certs, keys, 0);
        _cacheIntermediates(bindingHashes);
        return keys[0];
    }

    function _verifyCertChain(bytes[] calldata certs)
        internal
        view
        returns (CertPubkey[] memory keys, bytes32[] memory bindingHashes)
    {
        uint256 certLen = certs.length;
        require(certLen > 0 && certLen < 5, InvalidCertChainLength());

        bindingHashes = LibX509.getCertChainHashes(certs);
        if (!verifiedCA[bindingHashes[bindingHashes.length - 1]]) {
            revert RootCaNotAtEndOfChain();
        }

        // Strict CRL mode: verify that valid CRL exists for all issuers in the chain
        if (strictCRLMode) {
            _checkCRLValidityForChain(certs);
        }

        uint256 verifiedFrom = _findCachedIntermediate(bindingHashes);

        keys = _verifyChain(certs, verifiedFrom);
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

        // The target can be a CA. Every subsequent certificate is an issuer CA.
        (, bool targetIsCA,,) = LibX509.getBasicConstraints(certs[0]);
        uint256 remainingCAs;
        for (uint256 i = 0; i < certs.length; i++) {
            _verifyCertificateConstraints(certs[i], i == 0 && !targetIsCA, remainingCAs);
            // RFC 5280 counts non-self-issued intermediate CAs, excluding the target.
            if (i > 0 && keccak256(LibX509.getCertIssuerDN(certs[i])) != keccak256(LibX509.getCertSubjectDN(certs[i])))
            {
                remainingCAs++;
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

        // Verify signatures from leaf to verifiedFrom
        for (uint256 i = 0; i < verifiedFrom; i++) {
            bool result = verifyCertSignature(certs[i], issuers[i + 1]);
            require(result, InvalidSignature());
        }

        return issuers;
    }

    /// @dev The status query checks ancestors here and returns the target's status separately.
    function _checkChainRevocations(bytes[] calldata certs, CertPubkey[] memory keys, uint256 start) internal view {
        for (uint256 i = start; i < certs.length; i++) {
            uint256 issuerIndex = i + 1 < certs.length ? i + 1 : i;
            require(!_isRevoked(certs[i], certs[issuerIndex], keys[issuerIndex]), CertificateAlreadyRevoked());
        }
    }

    /// @dev Bind CRLs to the actual issuer key, independent of certificate serial, SKID, or validity dates.
    function _computeRevocationKey(bytes calldata issuerCert, CertPubkey memory issuer)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                "automata.tpm.crl.issuer.v1",
                LibX509.getCertSubjectDN(issuerCert),
                issuer.algo,
                issuer.params,
                issuer.data
            )
        );
    }

    function _isRevoked(bytes calldata cert, bytes calldata issuerCert, CertPubkey memory issuer)
        internal
        view
        returns (bool)
    {
        return revokedCertificates[_computeRevocationKey(issuerCert, issuer)][LibX509.getCertSerialNumber(cert)];
    }

    /// @dev Validate a certificate's validity period and CA or end-entity constraints.
    function _verifyCertificateConstraints(bytes calldata cert, bool isLeaf, uint256 pathLen) internal view {
        LibX509.checkCertValidity(cert);
        LibX509.checkCAConstraints(cert, pathLen, isLeaf);
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
            bytes32 issuerHash = _computeRevocationKey(certs[i], LibX509.getPubkey(certs[i]));

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
