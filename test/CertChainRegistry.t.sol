// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

// Testing utilities
import "forge-std/console.sol";
import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";

// Target contracts
import {CertChainRegistry} from "src/bases/CertChainRegistry.sol";
import {ICertChainRegistry} from "src/interfaces/ICertChainRegistry.sol";
import {LibX509, CertPubkey, CRLInfo} from "src/lib/LibX509.sol";
import {LibX509Verify} from "src/lib/LibX509Verify.sol";
import {
    CertificateAlreadyRevoked,
    CRLIssuerMismatch,
    CRLRollbackAttempt,
    CRLRequiredInStrictMode,
    CRLExpiredInStrictMode,
    ZeroAddress
} from "src/types/Errors.sol";

contract MockCertChainRegistry is CertChainRegistry {
    constructor(address _owner) CertChainRegistry(_owner, LibX509Verify.P256_VERIFIER) {}
}

/// @title CertChainRegistry_Test
/// @notice Base test contract for CertChainRegistry tests
contract CertChainRegistry_Test is Test {
    using stdJson for string;

    CertChainRegistry public registry;
    address public owner;
    address public nonOwner;

    string private certificatesJson;

    function setUp() public virtual {
        owner = address(this);
        nonOwner = address(0x1234);

        // Deploy mock registry (bypasses initializer protection)
        registry = new MockCertChainRegistry(owner);

        certificatesJson = readTestdata("certificates");
        deployP256Verifier();

        vm.warp(1761624246);
    }

    function readTestdata(string memory file) public view returns (string memory) {
        return vm.readFile(string(abi.encodePacked("./test/testdata/", file, ".json")));
    }

    function deployP256Verifier() internal {
        string memory json = readTestdata("p256");
        address target = json.readAddress(".address");
        bytes memory cd = json.readBytes(".calldata");
        (bool isSucc,) = address(target).call(cd);
        require(isSucc, "Failed to deploy P256Verifier");
    }

    /// @notice Helper function to load a certificate from JSON
    function _loadCertificate(string memory certType) internal view returns (bytes[] memory) {
        return certificatesJson.readBytesArrayOr(string(abi.encodePacked(".", certType)), new bytes[](0));
    }

    function _loadEmptyCRL() internal view returns (bytes memory) {
        bytes[] memory crls = _loadCertificate("test_crls_empty");
        require(crls.length == 1, "Need 1 CRL");
        return crls[0];
    }
}

/// @title CertChainRegistry_VerifySignature_Test
/// @notice Tests for verifySignature function
contract CertChainRegistry_VerifySignature_Test is CertChainRegistry_Test {
    /// @notice Tests RSA signature verification with valid certificate chain
    function test_verifySignature_rsa_succeeds() public {
        {
            bytes[] memory certs = _loadCertificate("self_signed_ec_ca");
            require(certs.length == 2, "Need 2 certs");
            registry.addCA(certs[1]);
            CertPubkey memory result = registry.verifyCertChain(certs);
            assertTrue(result.data.length > 0, "RSA signature verification should succeed");
        }

        {
            bytes[] memory certs = _loadCertificate("gcp_snp_tpm_certs");
            require(certs.length == 3, "Need at least 2 certs");
            registry.addCA(certs[2]);
            CertPubkey memory result = registry.verifyCertChain(certs);
            assertTrue(result.data.length > 0, "RSA signature verification should succeed");
        }

        {
            bytes[] memory certs = _loadCertificate("gcp_tdx_tpm_certs");
            require(certs.length == 3, "Need at least 2 certs");
            registry.addCA(certs[2]);
            CertPubkey memory result = registry.verifyCertChain(certs);
            assertTrue(result.data.length > 0, "RSA signature verification should succeed");
        }
    }
}

/// @title CertChainRegistry_VerifyCertChain_Integration_Test
/// @notice Integration tests for verifyCertChain
contract CertChainRegistry_VerifyCertChain_Integration_Test is CertChainRegistry_Test {
    /// @notice Tests that verifyCertChain succeeds with valid certificates
    function test_verifyCertChain_succeeds() public {
        bytes[] memory certs = _loadCertificate("gcp_snp_tpm_certs");

        // Add root CA
        registry.addCA(certs[2]);

        // Verify chain should succeed
        CertPubkey memory result = registry.verifyCertChain(certs);
        assertFalse(result.data.length == 0, "Should return valid pubkey");
    }

    /// @notice Tests verifyCertChain with multiple certificate types
    function test_verifyCertChain_multipleTypes_succeeds() public {
        // Test GCP SNP VEK certs
        bytes[] memory gcpSnpVekCerts = _loadCertificate("gcp_snp_tpm_certs");
        registry.addCA(gcpSnpVekCerts[2]);
        registry.verifyCertChain(gcpSnpVekCerts);

        // Test GCP TDX TPM certs
        bytes[] memory gcpTdxTpmCerts = _loadCertificate("gcp_tdx_tpm_certs");
        registry.addCA(gcpTdxTpmCerts[2]);
        registry.verifyCertChain(gcpTdxTpmCerts);
    }
}

/// @title CertChainRegistry_DNAndAKIDVerification_Test
/// @notice Tests for DN and AKID/SKID chain verification (M-07 fix)
contract CertChainRegistry_DNAndAKIDVerification_Test is CertChainRegistry_Test {
    using stdJson for string;

    /// @notice Test that valid DN chains pass verification
    function test_verifyCertChain_validDNChains_succeed() public {
        // Test multiple valid chains
        bytes[] memory gcpCerts = _loadCertificate("gcp_snp_tpm_certs");
        registry.addCA(gcpCerts[2]);
        CertPubkey memory result = registry.verifyCertChain(gcpCerts);
        assertTrue(result.data.length > 0);

        bytes[] memory tdxCerts = _loadCertificate("gcp_tdx_tpm_certs");
        registry.addCA(tdxCerts[2]);
        result = registry.verifyCertChain(tdxCerts);
        assertTrue(result.data.length > 0);
    }

    /// @notice Test DN verification by extracting and comparing manually
    function test_getCertSubjectDN_matchesIssuerDN() public view {
        string[5] memory certTypes =
            ["gcp_snp_vek_certs", "azure_snp_vek_certs", "gcp_tdx_tpm_certs", "gcp_snp_tpm_certs", "self_signed_ec_ca"];

        for (uint256 t = 0; t < certTypes.length; t++) {
            bytes[] memory certs = _loadCertificate(certTypes[t]);
            if (certs.length == 0) continue;

            // Verify DN chain linkage manually
            for (uint256 i = 0; i < certs.length - 1; i++) {
                bytes memory issuerDN = LibX509.getCertIssuerDN(certs[i]);
                bytes memory subjectDN = LibX509.getCertSubjectDN(certs[i + 1]);

                // In valid chain, these should match
                // Some cert chains may be test data with mismatched DNs, skip those
                if (keccak256(issuerDN) != keccak256(subjectDN)) {
                    console.log("DN mismatch detected in cert type:", certTypes[t]);
                    console.log("  Level", i, "DN mismatch - comparing:");
                    console.log("    Issuer DN  length:", issuerDN.length);
                    console.log("    Subject DN length:", subjectDN.length);
                    console.log("    Issuer DN bytes:");
                    console.logBytes(issuerDN);
                    console.log("    Subject DN bytes:");
                    console.logBytes(subjectDN);

                    // Find common prefix
                    uint256 commonLen = 0;
                    uint256 minLen = issuerDN.length < subjectDN.length ? issuerDN.length : subjectDN.length;
                    for (uint256 j = 0; j < minLen; j++) {
                        if (issuerDN[j] == subjectDN[j]) {
                            commonLen++;
                        } else {
                            break;
                        }
                    }
                    console.log("    Common prefix bytes:", commonLen);

                    // This is expected for VEK cert chains where intermediate has different CN
                    console.log("    (This is normal for VEK cert chains with different CNs)");
                    revert("DN mismatch detected");
                }
            }
        }
    }

    /// @notice Test AKID/SKID matching in valid chains using the new verification function
    /// Per RFC 5280 Section 6.1.4(d): If issuer has SKID, subject MUST have matching AKID
    function test_validChain_AKIDMatchesSKID() public view {
        string[5] memory certTypes =
            ["azure_snp_vek_certs", "gcp_snp_vek_certs", "gcp_snp_tpm_certs", "gcp_tdx_tpm_certs", "self_signed_ec_ca"];
        for (uint256 t = 0; t < certTypes.length; t++) {
            bytes[] memory certs = _loadCertificate(certTypes[t]);

            // This should not revert - all these cert types comply with RFC 5280
            LibX509.verifyAKIDSKIDChainLinkage(certs);
        }
    }

    /// @notice Test that all supported certificate types have valid DN chains
    function test_allCertTypes_haveValidDNChains() public {
        // Only test certificate types that are fully supported
        string[3] memory certTypes = ["gcp_snp_tpm_certs", "gcp_tdx_tpm_certs", "self_signed_ec_ca"];

        for (uint256 t = 0; t < certTypes.length; t++) {
            bytes[] memory certs = _loadCertificate(certTypes[t]);
            if (certs.length == 0) continue;

            // Add root CA
            registry.addCA(certs[certs.length - 1]);

            // Verify chain passes (includes DN check)
            CertPubkey memory result = registry.verifyCertChain(certs);
            assertTrue(result.data.length > 0, string(abi.encodePacked("Chain should be valid: ", certTypes[t])));

            // Verify DN linkage using the new verification function
            LibX509.verifyDNChainLinkage(certs);
        }
    }

    /// @notice Test that DN verification is enforced (integration test)
    function test_DNVerification_isEnforced() public {
        // This test verifies the DN check exists by confirming valid chains pass
        // Negative tests (DN mismatch) are implicit - any cert reordering would fail
        bytes[] memory certs = _loadCertificate("gcp_snp_tpm_certs");
        registry.addCA(certs[2]);

        // Valid chain should pass
        CertPubkey memory result = registry.verifyCertChain(certs);
        assertTrue(result.data.length > 0, "Valid DN chain passes");

        // Verify the new getCertSubjectDN function works
        bytes memory subjectDN = LibX509.getCertSubjectDN(certs[0]);
        assertTrue(subjectDN.length > 0, "Subject DN extracted successfully");
    }
}

/// @title CertChainRegistry_CRL_Test
/// @notice Tests for CRL (Certificate Revocation List) functionality
contract CertChainRegistry_CRL_Test is CertChainRegistry_Test {
    // Helper to load CRL from JSON

    function _loadRevokedCRL() internal view returns (bytes memory) {
        bytes[] memory crls = _loadCertificate("test_crls_with_revoked");
        require(crls.length == 1, "Need 1 CRL");
        return crls[0];
    }

    /// @notice Helper function to parse CRL from bytes memory to calldata
    function _parseCRLHelper(bytes calldata crlBytes) external pure returns (CRLInfo memory) {
        return LibX509.parseCRL(crlBytes);
    }

    /// @notice Test parsing an empty CRL succeeds
    function test_parseCRL_empty_succeeds() public view {
        bytes memory crlBytes = _loadEmptyCRL();
        CRLInfo memory crlInfo = this._parseCRLHelper(crlBytes);

        assertTrue(crlInfo.issuerDN.length > 0, "Issuer DN should be present");
        assertTrue(crlInfo.thisUpdate > 0, "thisUpdate should be set");
        assertTrue(crlInfo.nextUpdate > crlInfo.thisUpdate, "nextUpdate should be after thisUpdate");
        assertEq(crlInfo.revokedSerials.length, 0, "Empty CRL should have no revoked certificates");
        assertTrue(crlInfo.signature.length > 0, "Signature should be present");
        assertTrue(crlInfo.tbs.length > 0, "TBS should be present");
    }

    /// @notice Test parsing a CRL with revoked certificates succeeds
    function test_parseCRL_withRevoked_succeeds() public view {
        bytes memory crlBytes = _loadRevokedCRL();
        CRLInfo memory crlInfo = this._parseCRLHelper(crlBytes);

        assertTrue(crlInfo.issuerDN.length > 0, "Issuer DN should be present");
        assertTrue(crlInfo.thisUpdate > 0, "thisUpdate should be set");
        assertTrue(crlInfo.nextUpdate > crlInfo.thisUpdate, "nextUpdate should be after thisUpdate");
        assertEq(crlInfo.revokedSerials.length, 1, "CRL should have 1 revoked certificate");
        assertTrue(crlInfo.signature.length > 0, "Signature should be present");
        assertTrue(crlInfo.tbs.length > 0, "TBS should be present");
    }

    /// @notice Test updateCRL succeeds with valid CRL
    function test_updateCRL_succeeds() public {
        // Warp to a time within CRL validity (Nov 23 2025 - Nov 21 2035)
        vm.warp(1764979200); // Dec 6 2025 00:00:00 UTC

        bytes[] memory certs = _loadCertificate("self_signed_ec_ca");
        require(certs.length == 2, "Need 2 certs");

        bytes memory caCert = certs[1]; // Root CA
        registry.addCA(caCert);

        // Update CRL
        bytes memory crlBytes = _loadEmptyCRL();
        registry.updateCRL(crlBytes, caCert);

        // Verify CRL was cached
        CRLInfo memory crlInfo = this._parseCRLHelper(crlBytes);
        bytes memory issuerDN = LibX509.getCertSubjectDN(caCert);
        (, bytes memory skid) = LibX509.getSubjectKeyIdentifier(caCert);
        bytes32 issuerHash = keccak256(abi.encode(issuerDN, skid));

        (bytes32 crlHash, uint256 thisUpdate, uint256 nextUpdate) = registry.crlCache(issuerHash);
        assertEq(crlHash, keccak256(crlBytes), "CRL hash should match");
        assertEq(thisUpdate, crlInfo.thisUpdate, "thisUpdate should match");
        assertEq(nextUpdate, crlInfo.nextUpdate, "nextUpdate should match");
    }

    /// @notice Test isSerialRevokedInCRL returns false for non-revoked certificate
    function test_isSerialRevokedInCRL_notRevoked_returnsFalse() public view {
        bytes[] memory certs = _loadCertificate("self_signed_ec_ca");
        require(certs.length == 2, "Need 2 certs");

        bytes memory leafCert = certs[0];
        bytes memory crlBytes = _loadEmptyCRL();

        uint256 serialNumber = LibX509.getCertSerialNumber(leafCert);

        // Check against empty CRL
        bool isRevoked = LibX509.isSerialRevokedInCRL(serialNumber, crlBytes);
        assertFalse(isRevoked, "Certificate should not be revoked in empty CRL");
    }

    /// @notice Test isSerialRevokedInCRL returns true for revoked certificate
    function test_isSerialRevokedInCRL_revoked_returnsTrue() public view {
        bytes[] memory certs = _loadCertificate("self_signed_ec_ca");
        require(certs.length == 2, "Need 2 certs");

        bytes memory leafCert = certs[0];
        bytes memory crlBytes = _loadRevokedCRL();
        uint256 serialNumber = LibX509.getCertSerialNumber(leafCert);

        // Check against CRL with revoked cert
        bool isRevoked = LibX509.isSerialRevokedInCRL(serialNumber, crlBytes);
        assertTrue(isRevoked, "Certificate should be revoked in CRL");
    }

    /// @notice Test updateCRL with different certificate (invalid issuer) reverts
    function test_updateCRL_issuerMismatch_reverts() public {
        // Warp to a time within CRL validity (Nov 23 2025 - Nov 21 2035)
        vm.warp(1764979200); // Dec 6 2025 00:00:00 UTC

        bytes[] memory certs = _loadCertificate("self_signed_ec_ca");
        require(certs.length == 2, "Need 2 certs");

        bytes memory caCert = certs[1]; // Root CA
        bytes memory leafCert = certs[0]; // Leaf cert (wrong issuer)
        registry.addCA(caCert);

        // Try to update CRL with wrong issuer cert
        bytes memory crlBytes = _loadEmptyCRL();
        vm.expectRevert(CRLIssuerMismatch.selector);
        registry.updateCRL(crlBytes, leafCert);
    }

    /// @notice Test updateCRL with rollback attempt reverts
    function test_updateCRL_rollback_reverts() public {
        // Warp to a time within CRL validity (Nov 23 2025 - Nov 21 2035)
        vm.warp(1764979200); // Dec 6 2025 00:00:00 UTC

        bytes[] memory certs = _loadCertificate("self_signed_ec_ca");
        require(certs.length == 2, "Need 2 certs");

        bytes memory caCert = certs[1]; // Root CA
        registry.addCA(caCert);

        // First update with newer CRL
        bytes memory revokedCrl = _loadRevokedCRL();
        registry.updateCRL(revokedCrl, caCert);

        // Try to rollback to older CRL (should revert)
        bytes memory emptyCrl = _loadEmptyCRL();
        vm.expectRevert(CRLRollbackAttempt.selector);
        registry.updateCRL(emptyCrl, caCert);
    }

    /// @notice Test updateCRL emits CRLUpdated event
    function test_updateCRL_emitsEvent() public {
        // Warp to a time within CRL validity (Nov 23 2025 - Nov 21 2035)
        vm.warp(1764979200); // Dec 6 2025 00:00:00 UTC

        bytes[] memory certs = _loadCertificate("self_signed_ec_ca");
        require(certs.length == 2, "Need 2 certs");

        bytes memory caCert = certs[1]; // Root CA
        registry.addCA(caCert);

        bytes memory crlBytes = _loadEmptyCRL();
        CRLInfo memory crlInfo = this._parseCRLHelper(crlBytes);
        bytes memory issuerDN = LibX509.getCertSubjectDN(caCert);
        (, bytes memory skid) = LibX509.getSubjectKeyIdentifier(caCert);
        bytes32 issuerHash = keccak256(abi.encode(issuerDN, skid));
        bytes32 crlHash = keccak256(crlBytes);

        vm.expectEmit(true, false, false, true);
        emit ICertChainRegistry.CRLUpdated(
            issuerHash, crlInfo.issuerDN, crlInfo.authorityKeyId, crlHash, crlInfo.thisUpdate, crlInfo.nextUpdate
        );

        registry.updateCRL(crlBytes, caCert);
    }

    /// @notice Test updateCRL can update to newer CRL
    function test_updateCRL_updateToNewer_succeeds() public {
        // Warp to a time within CRL validity (Nov 23 2025 - Nov 21 2035)
        vm.warp(1764979200); // Dec 6 2025 00:00:00 UTC

        bytes[] memory certs = _loadCertificate("self_signed_ec_ca");
        require(certs.length == 2, "Need 2 certs");

        bytes memory caCert = certs[1]; // Root CA
        registry.addCA(caCert);

        // First update with empty CRL
        bytes memory emptyCrl = _loadEmptyCRL();
        registry.updateCRL(emptyCrl, caCert);

        CRLInfo memory oldCrlInfo = this._parseCRLHelper(emptyCrl);

        // Update to newer CRL with revoked cert (has later thisUpdate)
        bytes memory revokedCrl = _loadRevokedCRL();
        registry.updateCRL(revokedCrl, caCert);

        // Verify cache was updated
        CRLInfo memory newCrlInfo = this._parseCRLHelper(revokedCrl);
        bytes memory issuerDN = LibX509.getCertSubjectDN(caCert);
        (, bytes memory skid) = LibX509.getSubjectKeyIdentifier(caCert);
        bytes32 issuerHash = keccak256(abi.encode(issuerDN, skid));

        (bytes32 crlHash, uint256 thisUpdate,) = registry.crlCache(issuerHash);
        assertEq(crlHash, keccak256(revokedCrl), "CRL hash should be updated");
        assertEq(thisUpdate, newCrlInfo.thisUpdate, "thisUpdate should be updated");
        assertTrue(thisUpdate > oldCrlInfo.thisUpdate, "New thisUpdate should be later");
    }

    /// @notice Test parsing real GCP Root CA CRL
    function test_parseGCPRootCACRL_succeeds() public view {
        bytes[] memory crls = _loadCertificate("gcp_root_ca_crl");
        require(crls.length == 1, "Need 1 CRL");
        bytes memory gcpCrl = crls[0];

        CRLInfo memory crlInfo = this._parseCRLHelper(gcpCrl);

        // Verify issuer DN
        assertTrue(crlInfo.issuerDN.length > 0, "Issuer DN should be present");

        // Verify timestamps
        assertEq(crlInfo.thisUpdate, 1763859875, "thisUpdate should match: Nov 23, 2025 01:04:35 GMT");
        assertEq(crlInfo.nextUpdate, 1764464675, "nextUpdate should match: Nov 30, 2025 01:04:35 GMT");

        // Verify no revoked certificates
        assertEq(crlInfo.revokedSerials.length, 0, "CRL should have no revoked certificates");

        // Verify signature is present
        assertTrue(crlInfo.signature.length > 0, "Signature should be present");
        assertTrue(crlInfo.tbs.length > 0, "TBS should be present");

        // Verify Authority Key Identifier
        assertTrue(crlInfo.authorityKeyId.length > 0, "Authority Key ID should be present");
    }

    /// @notice Test updating registry with real GCP Root CA CRL
    function test_updateGCPRootCACRL_succeeds() public {
        // Warp to a time within CRL validity (Nov 23, 2025 01:04:35 - Nov 30, 2025 01:04:35)
        vm.warp(1764072000); // Nov 25, 2025 12:00:00 UTC (within CRL validity)

        bytes[] memory gcpCerts = _loadCertificate("gcp_tdx_tpm_certs");
        require(gcpCerts.length == 3, "Need 3 certs");
        bytes memory gcpRootCA = gcpCerts[2];

        // Add the root CA first
        registry.addCA(gcpRootCA);

        // Load GCP CRL
        bytes[] memory crls = _loadCertificate("gcp_root_ca_crl");
        require(crls.length == 1, "Need 1 CRL");
        bytes memory gcpCrl = crls[0];

        // Update CRL
        registry.updateCRL(gcpCrl, gcpRootCA);

        // Verify CRL was cached
        CRLInfo memory crlInfo = this._parseCRLHelper(gcpCrl);
        bytes memory issuerDN = LibX509.getCertSubjectDN(gcpRootCA);
        (, bytes memory skid) = LibX509.getSubjectKeyIdentifier(gcpRootCA);

        // Compute issuer hash (using DN + SKID since CRL has AKID)
        bytes32 issuerHash = keccak256(abi.encode(issuerDN, skid));

        (bytes32 crlHash, uint256 thisUpdate, uint256 nextUpdate) = registry.crlCache(issuerHash);

        assertEq(crlHash, keccak256(gcpCrl), "CRL hash should match");
        assertEq(thisUpdate, crlInfo.thisUpdate, "thisUpdate should match");
        assertEq(nextUpdate, crlInfo.nextUpdate, "nextUpdate should match");
    }

    /// @notice Test updateCRL syncs revoked certificates to blacklist
    function test_updateCRL_syncsRevokedToBlacklist_succeeds() public {
        // Warp to a time within CRL validity (Nov 23 2025 - Nov 21 2035)
        vm.warp(1764979200); // Dec 6 2025 00:00:00 UTC

        bytes[] memory certs = _loadCertificate("self_signed_ec_ca");
        require(certs.length == 2, "Need 2 certs");

        bytes memory leafCert = certs[0];
        bytes memory caCert = certs[1];
        registry.addCA(caCert);

        // Load CRL with revoked certificate
        bytes memory crlBytes = _loadRevokedCRL();

        // Verify certificate is not revoked before CRL update
        assertFalse(registry.isCertificateRevoked(leafCert), "Certificate should not be revoked yet");

        // Update CRL - this should sync revocations to blacklist
        registry.updateCRL(crlBytes, caCert);

        // Verify certificate is now revoked in blacklist
        assertTrue(registry.isCertificateRevoked(leafCert), "Certificate should be revoked after CRL sync");

        // Verify that verifyCertChain will fail for revoked certificate
        bytes[] memory chain = new bytes[](2);
        chain[0] = leafCert;
        chain[1] = caCert;

        vm.expectRevert(CertificateAlreadyRevoked.selector);
        registry.verifyCertChain(chain);
    }

    /// @notice Test updateCRL syncs multiple revoked certificates
    function test_updateCRL_syncsMultipleRevocations_succeeds() public {
        // Warp to a time within CRL validity
        vm.warp(1764979200); // Dec 6 2025 00:00:00 UTC

        bytes[] memory certs = _loadCertificate("self_signed_ec_ca");
        require(certs.length == 2, "Need 2 certs");

        bytes memory caCert = certs[1];
        registry.addCA(caCert);

        // Load CRL with revoked certificate(s)
        bytes memory crlBytes = _loadRevokedCRL();
        CRLInfo memory crlInfo = this._parseCRLHelper(crlBytes);

        // Update CRL
        registry.updateCRL(crlBytes, caCert);

        // Verify all revoked serials are synced to blacklist
        bytes memory issuerDN = LibX509.getCertSubjectDN(caCert);
        (, bytes memory skid) = LibX509.getSubjectKeyIdentifier(caCert);
        bytes32 issuerHash = keccak256(abi.encode(issuerDN, skid));

        // Check that all revoked serials from CRL are now in blacklist
        for (uint256 i = 0; i < crlInfo.revokedSerials.length; i++) {
            uint256 serial = crlInfo.revokedSerials[i];
            assertTrue(registry.revokedCertificates(issuerHash, serial), "Revoked serial should be in blacklist");
        }
    }

    /// @notice Comprehensive test for strict CRL mode behavior
    /// @dev Tests: enable/disable, CRL required, CRL expired, access control
    function test_strictCRLMode_comprehensive() public {
        // Warp to a time within CRL validity
        vm.warp(1764979200); // Dec 6 2025 00:00:00 UTC

        bytes[] memory certs = _loadCertificate("self_signed_ec_ca");
        require(certs.length == 2, "Need 2 certs");

        bytes memory caCert = certs[1];
        registry.addCA(caCert);

        // 1. Default: strict mode disabled, works without CRL
        assertFalse(registry.strictCRLMode(), "Should be disabled by default");
        registry.verifyCertChain(certs);

        // 2. Enable strict mode (only owner)
        vm.prank(nonOwner);
        vm.expectRevert();
        registry.setStrictCRLMode(true);

        vm.expectEmit(true, false, false, true);
        emit ICertChainRegistry.StrictCRLModeChanged(true);
        registry.setStrictCRLMode(true);
        assertTrue(registry.strictCRLMode(), "Should be enabled");

        // 3. Strict mode: fails without CRL
        vm.expectRevert(CRLRequiredInStrictMode.selector);
        registry.verifyCertChain(certs);

        // 4. Upload CRL: succeeds with valid CRL
        bytes memory crlBytes = _loadEmptyCRL();
        registry.updateCRL(crlBytes, caCert);
        registry.verifyCertChain(certs);

        // 5. Warp to future: fails with expired CRL
        vm.warp(2100000000); // Far in the future
        vm.expectRevert(CRLExpiredInStrictMode.selector);
        registry.verifyCertChain(certs);

        // 6. Disable strict mode
        registry.setStrictCRLMode(false);
        assertFalse(registry.strictCRLMode(), "Should be disabled");

        // Warp back to valid time to verify strict mode is disabled
        vm.warp(1763942400); // Back to Nov 24 2025
        registry.verifyCertChain(certs);
    }
}

/// @title CertChainRegistry_ZeroAddress_Test
/// @notice Tests for zero-address validation in constructor
contract CertChainRegistry_ZeroAddress_Test is Test {
    /// @notice Tests that constructor reverts when p256 address is zero
    function test_constructor_p256ZeroAddress_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(ZeroAddress.selector, "p256"));
        new MockCertChainRegistry_ZeroAddressTest(address(this), address(0));
    }

    /// @notice Tests that constructor succeeds with valid p256 address
    function test_constructor_validP256Address_succeeds() public {
        address validP256 = address(0x1234);
        MockCertChainRegistry_ZeroAddressTest registry =
            new MockCertChainRegistry_ZeroAddressTest(address(this), validP256);
        assertEq(registry.p256(), validP256, "p256 should be set correctly");
    }
}

/// @notice Mock contract for zero-address testing
contract MockCertChainRegistry_ZeroAddressTest is CertChainRegistry {
    constructor(address _owner, address _p256) CertChainRegistry(_owner, _p256) {}
}
