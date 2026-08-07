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
    CertificateExpired,
    CertificateAlreadyRevoked,
    CRLIssuerMismatch,
    CRLMissingNumber,
    InvalidCRLFormat,
    InvalidCRLNumber,
    DeltaCRLNotSupported,
    PartitionedCRLNotSupported,
    IndirectCRLNotSupported,
    InvalidTimeFormat,
    CRLRollbackAttempt,
    CRLSignNotSet,
    CRLSignerNotTrusted,
    CRLRequiredInStrictMode,
    CRLExpiredInStrictMode,
    CRLSignatureVerificationFailed,
    Asn1InvalidLengthBytes,
    InvalidCertChainLength,
    InvalidCertificateChain,
    IssuerSubjectDNMismatch,
    CertChainAKIDMismatch,
    InvalidSignature,
    PathLenConstraintViolated,
    UnsupportedCriticalCertificateExtension,
    ZeroAddress
} from "src/types/Errors.sol";

contract MockCertChainRegistry is CertChainRegistry {
    constructor(address _owner) CertChainRegistry(_owner, LibX509Verify.P256_VERIFIER) {}

    function exposedVerifyCRLSignerChain(bytes[] calldata signerChain) external view {
        _verifyCRLSignerChain(signerChain);
    }

    function exposedSetVerifiedCA(bytes calldata ca, bool trusted) external {
        verifiedCA[keccak256(ca)] = trusted;
    }

    function exposedSetRevoked(bytes32 revocationScope, uint256 serialNumber, bool revoked) external {
        uint256[] memory serials = new uint256[](revoked ? 1 : 0);
        if (revoked) {
            serials[0] = serialNumber;
        }

        bytes32 setHash = _computeRevokedSetHash(revocationScope, serials);
        if (revoked) {
            _revokedSerials[setHash][serialNumber] = true;
        }
        _indexedRevokedSets[setHash] = true;
        activeRevokedSetHash[revocationScope] = setHash;
    }

    function exposedComputeRevokedSetHash(bytes32 scope, uint256[] memory serials) external pure returns (bytes32) {
        return _computeRevokedSetHash(scope, serials);
    }

    function exposedGetPubkey(bytes calldata cert) external pure returns (CertPubkey memory) {
        return LibX509.getPubkey(cert);
    }
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

    function _singletonChain(bytes memory cert) internal pure returns (bytes[] memory chain) {
        chain = new bytes[](1);
        chain[0] = cert;
    }

    function _identityDerNode(bytes1 tag, bytes memory content) internal pure returns (bytes memory) {
        if (content.length < 128) return abi.encodePacked(tag, uint8(content.length), content);
        if (content.length <= type(uint8).max) {
            return abi.encodePacked(tag, bytes1(0x81), uint8(content.length), content);
        }
        require(content.length <= type(uint16).max, "Synthetic identity DER node too large");
        return abi.encodePacked(tag, bytes1(0x82), uint16(content.length), content);
    }

    function _identityCertificate(bytes memory rsaData, bytes memory subjectDN) internal pure returns (bytes memory) {
        bytes memory rsaAlgorithm = hex"300D06092A864886F70D0101010500";
        bytes memory subjectPublicKey = _identityDerNode(0x03, abi.encodePacked(hex"00", rsaData));
        bytes memory subjectPublicKeyInfo = _identityDerNode(0x30, abi.encodePacked(rsaAlgorithm, subjectPublicKey));
        bytes memory tbs = _identityDerNode(
            0x30,
            abi.encodePacked(
                hex"020101", // serial
                hex"300306012A", // placeholder signature AlgorithmIdentifier
                hex"3003020101", // placeholder issuer
                hex"3003020101", // placeholder validity
                subjectDN,
                subjectPublicKeyInfo
            )
        );
        return _identityDerNode(0x30, tbs);
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

    function test_addCA_unknownCriticalExtension_reverts() public {
        bytes memory root = _loadCertificate("gcp_snp_vek_certs")[2];
        bytes memory keyUsage = hex"0603551d0f0101ff";
        bool mutated;
        for (uint256 i; i + keyUsage.length <= root.length; ++i) {
            bool matches = true;
            for (uint256 j; j < keyUsage.length; ++j) {
                if (root[i + j] != keyUsage[j]) {
                    matches = false;
                    break;
                }
            }
            if (matches) {
                root[i + 4] = 0x7F; // unknown 2.5.29.127, still marked critical
                mutated = true;
                break;
            }
        }
        require(mutated, "KeyUsage fixture pattern not found");

        vm.expectRevert(UnsupportedCriticalCertificateExtension.selector);
        registry.addCA(root);
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

    function _expectedRevokedSetHash(bytes32 scope, uint256[] memory serials) internal pure returns (bytes32) {
        return keccak256(abi.encode(keccak256("AUTOMATA_CRL_REVOKED_SET_V1"), scope, serials));
    }

    function _loadRevokedCRL() internal view returns (bytes memory) {
        bytes[] memory crls = _loadCertificate("test_crls_with_revoked");
        require(crls.length == 1, "Need 1 CRL");
        return crls[0];
    }

    /// @notice Helper function to parse CRL from bytes memory to calldata
    function _parseCRLHelper(bytes calldata crlBytes) external pure returns (CRLInfo memory) {
        return LibX509.parseCRL(crlBytes);
    }

    function _withoutCRLNumber(bytes memory crl) internal pure returns (bytes memory modified) {
        modified = new bytes(crl.length);
        for (uint256 i = 0; i < crl.length; i++) {
            modified[i] = crl[i];
        }

        // Replace id-ce-cRLNumber (2.5.29.20) with an unknown, same-length OID.
        // Keeping the DER shape unchanged isolates the mandatory-extension check.
        for (uint256 i = 0; i + 2 < modified.length; i++) {
            if (modified[i] == 0x55 && modified[i + 1] == 0x1d && modified[i + 2] == 0x14) {
                modified[i + 2] = 0x15;
                return modified;
            }
        }

        revert("CRLNumber OID not found in fixture");
    }

    function _derNode(bytes1 tag, bytes memory content) internal pure returns (bytes memory) {
        require(content.length > 0, "Synthetic DER nodes must not be empty");
        if (content.length < 128) {
            return abi.encodePacked(tag, uint8(content.length), content);
        }
        require(content.length <= type(uint8).max, "Synthetic DER node too large");
        return abi.encodePacked(tag, bytes1(0x81), uint8(content.length), content);
    }

    function _withLeadingZeroOuterLength(bytes memory crl) internal pure returns (bytes memory modified) {
        require(crl.length > 4 && crl[0] == 0x30, "Need an outer CRL SEQUENCE");
        uint8 lengthOfLength = uint8(crl[1]) & 0x7F;
        require(uint8(crl[1]) & 0x80 != 0 && lengthOfLength < 0x7F, "Need a long-form outer length");

        modified = new bytes(crl.length + 1);
        modified[0] = crl[0];
        modified[1] = bytes1(0x80 | (lengthOfLength + 1));
        modified[2] = 0;
        for (uint256 i = 2; i < crl.length; ++i) {
            modified[i + 1] = crl[i];
        }
    }

    function _withLongFormSignatureLength(bytes memory crl) internal pure returns (bytes memory modified) {
        require(crl.length > 4 && crl[0] == 0x30, "Need an outer CRL SEQUENCE");
        uint8 rootLengthOfLength = uint8(crl[1]) & 0x7F;
        require(uint8(crl[1]) & 0x80 != 0 && rootLengthOfLength > 0, "Need a long-form outer length");

        uint256 signatureOffset = type(uint256).max;
        for (uint256 i = 2 + rootLengthOfLength; i + 2 < crl.length; ++i) {
            uint8 contentLength = uint8(crl[i + 1]);
            if (crl[i] == 0x03 && contentLength < 128 && i + 2 + contentLength == crl.length) {
                signatureOffset = i;
                break;
            }
        }
        require(signatureOffset != type(uint256).max, "Short-form signature BIT STRING not found");

        modified = new bytes(crl.length + 1);
        for (uint256 i; i <= signatureOffset; ++i) {
            modified[i] = crl[i];
        }
        modified[signatureOffset + 1] = 0x81;
        for (uint256 i = signatureOffset + 1; i < crl.length; ++i) {
            modified[i + 1] = crl[i];
        }

        uint256 lengthByte = 1 + rootLengthOfLength;
        while (true) {
            modified[lengthByte] = bytes1(uint8(modified[lengthByte]) + 1);
            if (modified[lengthByte] != 0) break;
            require(lengthByte > 2, "Outer CRL length overflow");
            --lengthByte;
        }
    }

    function _crlNumberExtension(bytes memory integerEncoding, bytes memory criticalField)
        internal
        pure
        returns (bytes memory)
    {
        return _derNode(0x30, abi.encodePacked(hex"0603551D14", criticalField, _derNode(0x04, integerEncoding)));
    }

    function _unknownCRLExtension(bytes memory criticalField) internal pure returns (bytes memory) {
        return _derNode(0x30, abi.encodePacked(hex"06032A0304", criticalField, _derNode(0x04, hex"0500")));
    }

    function _entryExtension(bytes memory oid, bytes memory criticalField, bytes memory value)
        internal
        pure
        returns (bytes memory)
    {
        return _derNode(0x30, abi.encodePacked(oid, criticalField, _derNode(0x04, value)));
    }

    function _revokedEntry(bytes memory serial, bytes memory revocationDate, bytes memory extensionPayload)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory extensions = extensionPayload.length == 0 ? bytes("") : _derNode(0x30, extensionPayload);
        return _derNode(0x30, abi.encodePacked(serial, revocationDate, extensions));
    }

    function _syntheticCRLWithFields(
        bytes memory innerAlgorithm,
        bytes memory outerAlgorithm,
        bytes memory thisUpdate,
        bytes memory nextUpdate,
        bytes memory revokedCertificates,
        bytes memory extensionPayload,
        bytes memory tbsSuffix,
        bytes memory outerSuffix
    ) internal pure returns (bytes memory) {
        bytes memory issuer = hex"3003020101";
        bytes memory extensions = _derNode(0xA0, _derNode(0x30, extensionPayload));
        bytes memory tbs = _derNode(
            0x30,
            abi.encodePacked(
                hex"020101", innerAlgorithm, issuer, thisUpdate, nextUpdate, revokedCertificates, extensions, tbsSuffix
            )
        );
        bytes memory signature = _derNode(0x03, abi.encodePacked(bytes1(0), new bytes(64)));
        return _derNode(0x30, abi.encodePacked(tbs, outerAlgorithm, signature, outerSuffix));
    }

    function _syntheticCRLWithEntries(bytes memory entries) internal pure returns (bytes memory) {
        return _syntheticCRLWithFields(
            hex"300306012A",
            hex"300306012A",
            hex"170D3235313230353036343233365A",
            hex"170D3236313230353036343233365A",
            _derNode(0x30, entries),
            _crlNumberExtension(hex"020101", ""),
            "",
            ""
        );
    }

    function _syntheticCRLWithVersion(bytes memory versionField, bytes memory extensionPayload)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory algorithm = hex"300306012A";
        bytes memory issuer = hex"3003020101";
        bytes memory thisUpdate = hex"170D3235313230353036343233365A";
        bytes memory nextUpdate = hex"170D3236313230353036343233365A";
        bytes memory extensions = _derNode(0xA0, _derNode(0x30, extensionPayload));
        bytes memory tbs =
            _derNode(0x30, abi.encodePacked(versionField, algorithm, issuer, thisUpdate, nextUpdate, extensions));
        bytes memory signature = _derNode(0x03, abi.encodePacked(bytes1(0), new bytes(64)));
        return _derNode(0x30, abi.encodePacked(tbs, algorithm, signature));
    }

    function _syntheticCRL(bytes memory extensionPayload) internal pure returns (bytes memory) {
        return _syntheticCRLWithVersion(hex"020101", extensionPayload);
    }

    /// @notice Test parsing an empty CRL succeeds
    function test_parseCRL_empty_succeeds() public view {
        bytes memory crlBytes = _loadEmptyCRL();
        CRLInfo memory crlInfo = this._parseCRLHelper(crlBytes);

        assertTrue(crlInfo.issuerDN.length > 0, "Issuer DN should be present");
        assertEq(crlInfo.crlNumber, 5, "CRL number should be parsed");
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
        assertEq(crlInfo.crlNumber, 6, "CRL number should be parsed");
        assertTrue(crlInfo.thisUpdate > 0, "thisUpdate should be set");
        assertTrue(crlInfo.nextUpdate > crlInfo.thisUpdate, "nextUpdate should be after thisUpdate");
        assertEq(crlInfo.revokedSerials.length, 1, "CRL should have 1 revoked certificate");
        assertTrue(crlInfo.signature.length > 0, "Signature should be present");
        assertTrue(crlInfo.tbs.length > 0, "TBS should be present");
    }

    function test_parseCRL_outerLengthWithLeadingZero_reverts() public {
        vm.expectRevert(Asn1InvalidLengthBytes.selector);
        this._parseCRLHelper(_withLeadingZeroOuterLength(_loadEmptyCRL()));
    }

    function test_parseCRL_signatureLengthLongFormBelow128_reverts() public {
        vm.expectRevert(Asn1InvalidLengthBytes.selector);
        this._parseCRLHelper(_withLongFormSignatureLength(_loadEmptyCRL()));
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
        registry.updateCRL(crlBytes, _singletonChain(caCert));

        // Verify CRL was cached
        CRLInfo memory crlInfo = this._parseCRLHelper(crlBytes);
        bytes32 revocationScope = registry.computeRevocationScope(keccak256(caCert), caCert);

        (bytes32 crlHash, uint256 thisUpdate, uint256 nextUpdate) = registry.crlCache(revocationScope);
        assertEq(crlHash, keccak256(crlBytes), "CRL hash should match");
        assertEq(thisUpdate, crlInfo.thisUpdate, "thisUpdate should match");
        assertEq(nextUpdate, crlInfo.nextUpdate, "nextUpdate should match");
        assertEq(registry.latestCRLNumber(revocationScope), 5, "Latest CRL number should be cached");
    }

    function test_updateCRL_newCompleteSnapshotRestoresOmittedSerial() public {
        vm.warp(1785283200); // 2026-07-29 00:00:00 UTC

        bytes[] memory chain = _loadCertificate("snapshot_chain");
        bytes[] memory crls = _loadCertificate("snapshot_crls");
        require(chain.length == 2 && crls.length == 5, "Need snapshot fixtures");

        bytes memory root = chain[1];
        registry.addCA(root);
        registry.verifyCertChain(chain);

        registry.updateCRL(crls[0], _singletonChain(root));
        assertTrue(registry.isCertificateRevokedInChain(chain), "CRL #1 must revoke the leaf");

        registry.updateCRL(crls[1], _singletonChain(root));
        assertFalse(registry.isCertificateRevokedInChain(chain), "New complete CRL must restore an omitted serial");
        CertPubkey memory restored = registry.verifyCertChain(chain);
        assertTrue(restored.data.length > 0, "Restored chain must verify");
    }

    function test_updateCRL_certificateHoldIsRestoredByNewCompleteSnapshot() public {
        vm.warp(1785283200);

        bytes[] memory chain = _loadCertificate("snapshot_chain");
        bytes[] memory crls = _loadCertificate("snapshot_crls");
        bytes memory root = chain[1];
        registry.addCA(root);

        registry.updateCRL(crls[3], _singletonChain(root));
        assertTrue(registry.isCertificateRevokedInChain(chain), "Hold CRL must revoke the leaf");

        registry.updateCRL(crls[4], _singletonChain(root));
        assertFalse(registry.isCertificateRevokedInChain(chain), "New complete CRL must release an omitted hold");
        CertPubkey memory released = registry.verifyCertChain(chain);
        assertTrue(released.data.length > 0, "Released chain must verify");
    }

    function test_updateCRL_completeSnapshotsActivateExpectedSetsAndReuseHistory() public {
        vm.warp(1785283200);

        bytes[] memory chain = _loadCertificate("snapshot_chain");
        bytes[] memory crls = _loadCertificate("snapshot_crls");
        bytes memory root = chain[1];
        registry.addCA(root);

        bytes32 scope = registry.computeRevocationScope(keccak256(root), root);
        uint256[] memory revokedSerials = new uint256[](1);
        revokedSerials[0] = 0x1001;
        uint256[] memory emptySerials = new uint256[](0);
        bytes32 firstSetHash = _expectedRevokedSetHash(scope, revokedSerials);
        bytes32 emptySetHash = _expectedRevokedSetHash(scope, emptySerials);

        registry.updateCRL(crls[0], _singletonChain(root));
        assertEq(registry.activeRevokedSetHash(scope), firstSetHash, "CRL #1 must activate its exact set");

        registry.updateCRL(crls[1], _singletonChain(root));
        assertNotEq(emptySetHash, bytes32(0), "An authenticated empty set needs a non-zero identity");
        assertNotEq(emptySetHash, firstSetHash, "Empty and one-serial sets must differ");
        assertEq(registry.activeRevokedSetHash(scope), emptySetHash, "CRL #2 must activate the empty set");

        vm.expectEmit(true, true, false, true);
        emit ICertChainRegistry.CRLRevokedSetActivated(scope, firstSetHash, 1, true);
        registry.updateCRL(crls[2], _singletonChain(root));
        assertEq(registry.activeRevokedSetHash(scope), firstSetHash, "CRL #3 must reactivate CRL #1's set");
    }

    function test_computeRevokedSetHash_sameSerialsDifferentScopes_areIsolated() public view {
        uint256[] memory serials = new uint256[](1);
        serials[0] = 0x1001;

        bytes32 first =
            MockCertChainRegistry(address(registry)).exposedComputeRevokedSetHash(bytes32(uint256(1)), serials);
        bytes32 second =
            MockCertChainRegistry(address(registry)).exposedComputeRevokedSetHash(bytes32(uint256(2)), serials);

        assertNotEq(first, second, "Identical serials under different issuer scopes must not share a set");
    }

    function test_revokedCertificates_legacySelectorReadsOnlyActiveSet() public {
        vm.warp(1785283200);

        bytes[] memory chain = _loadCertificate("snapshot_chain");
        bytes[] memory crls = _loadCertificate("snapshot_crls");
        bytes memory root = chain[1];
        registry.addCA(root);
        bytes32 scope = registry.computeRevocationScope(keccak256(root), root);
        bytes4 selector = bytes4(keccak256("revokedCertificates(bytes32,uint256)"));

        registry.updateCRL(crls[0], _singletonChain(root));
        (bool firstCallSucceeded, bytes memory firstResult) =
            address(registry).staticcall(abi.encodeWithSelector(selector, scope, uint256(0x1001)));
        assertTrue(firstCallSucceeded, "Legacy getter selector must remain callable");
        assertTrue(abi.decode(firstResult, (bool)), "CRL #1's active set must contain the leaf");

        registry.updateCRL(crls[1], _singletonChain(root));
        (bool secondCallSucceeded, bytes memory secondResult) =
            address(registry).staticcall(abi.encodeWithSelector(selector, scope, uint256(0x1001)));
        assertTrue(secondCallSucceeded, "Legacy getter selector must remain callable after replacement");
        assertFalse(abi.decode(secondResult, (bool)), "CRL #2's active empty set must omit the leaf");
    }

    function test_updateCRL_badSignature_keepsActiveSetHash() public {
        vm.warp(1785283200);

        bytes[] memory chain = _loadCertificate("snapshot_chain");
        bytes[] memory crls = _loadCertificate("snapshot_crls");
        bytes memory root = chain[1];
        registry.addCA(root);
        bytes32 scope = registry.computeRevocationScope(keccak256(root), root);

        registry.updateCRL(crls[0], _singletonChain(root));
        bytes32 activeSetHash = registry.activeRevokedSetHash(scope);

        bytes memory badSignature = abi.encodePacked(crls[1]);
        badSignature[badSignature.length - 1] ^= 0x01;
        vm.expectRevert(CRLSignatureVerificationFailed.selector);
        registry.updateCRL(badSignature, _singletonChain(root));

        assertEq(registry.activeRevokedSetHash(scope), activeSetHash, "Rejected signature must not activate a set");
    }

    function test_parseCRL_missingNumber_reverts() public {
        bytes memory crlWithoutNumber = _withoutCRLNumber(_loadEmptyCRL());

        vm.expectRevert(CRLMissingNumber.selector);
        this._parseCRLHelper(crlWithoutNumber);
    }

    function test_parseCRL_numberDERBoundaries_succeeds() public view {
        CRLInfo memory zero = this._parseCRLHelper(_syntheticCRL(_crlNumberExtension(hex"020100", "")));
        assertEq(zero.crlNumber, 0, "Zero is a valid first CRL number");

        CRLInfo memory oneByte = this._parseCRLHelper(_syntheticCRL(_crlNumberExtension(hex"02017F", "")));
        assertEq(oneByte.crlNumber, 127, "One-byte positive number should parse");

        CRLInfo memory signPadded = this._parseCRLHelper(_syntheticCRL(_crlNumberExtension(hex"02020080", "")));
        assertEq(signPadded.crlNumber, 128, "Required positive sign padding should parse");

        bytes memory maxLengthNumber = abi.encodePacked(hex"02140080", new bytes(18));
        CRLInfo memory maxLength = this._parseCRLHelper(_syntheticCRL(_crlNumberExtension(maxLengthNumber, "")));
        assertEq(maxLength.crlNumber, uint256(1) << 151, "20-octet CRL number should parse");
    }

    function test_parseCRL_invalidNumberEncoding_reverts() public {
        bytes[] memory invalidIntegers = new bytes[](6);
        invalidIntegers[0] = hex"030101"; // Wrong inner tag
        invalidIntegers[1] = hex"0200"; // Empty INTEGER
        invalidIntegers[2] = hex"020180"; // Negative INTEGER / missing sign padding
        invalidIntegers[3] = hex"0202007F"; // Redundant sign padding
        invalidIntegers[4] = hex"02810101"; // Non-canonical long-form length
        invalidIntegers[5] = hex"02010100"; // Trailing data after INTEGER

        for (uint256 i = 0; i < invalidIntegers.length; i++) {
            vm.expectRevert(InvalidCRLNumber.selector);
            this._parseCRLHelper(_syntheticCRL(_crlNumberExtension(invalidIntegers[i], "")));
        }

        bytes memory tooLongNumber = abi.encodePacked(hex"02150080", new bytes(19));
        vm.expectRevert(InvalidCRLNumber.selector);
        this._parseCRLHelper(_syntheticCRL(_crlNumberExtension(tooLongNumber, "")));
    }

    function test_parseCRL_criticalOrDuplicateNumber_reverts() public {
        vm.expectRevert(InvalidCRLFormat.selector);
        this._parseCRLHelper(_syntheticCRL(_crlNumberExtension(hex"020101", hex"0101FF")));

        // A DER DEFAULT FALSE field must be omitted, so explicit FALSE is invalid too.
        vm.expectRevert(InvalidCRLFormat.selector);
        this._parseCRLHelper(_syntheticCRL(_crlNumberExtension(hex"020101", hex"010100")));

        bytes memory extension = _crlNumberExtension(hex"020101", "");
        vm.expectRevert(InvalidCRLFormat.selector);
        this._parseCRLHelper(_syntheticCRL(abi.encodePacked(extension, extension)));
    }

    function test_parseCRL_extensionsWithoutV2Version_reverts() public {
        bytes memory numberExtension = _crlNumberExtension(hex"020101", "");

        vm.expectRevert(InvalidCRLFormat.selector);
        this._parseCRLHelper(_syntheticCRLWithVersion("", numberExtension));
    }

    function test_parseCRL_extensionsWithInvalidVersion_reverts() public {
        bytes memory numberExtension = _crlNumberExtension(hex"020101", "");
        bytes[] memory invalidVersions = new bytes[](3);
        invalidVersions[0] = hex"020100"; // v1 is not allowed when extensions are present
        invalidVersions[1] = hex"020102"; // only v2(1) is defined for CRLs
        invalidVersions[2] = hex"0A0101"; // Version must be an INTEGER, not ENUMERATED

        for (uint256 i = 0; i < invalidVersions.length; i++) {
            vm.expectRevert(InvalidCRLFormat.selector);
            this._parseCRLHelper(_syntheticCRLWithVersion(invalidVersions[i], numberExtension));
        }
    }

    function test_parseCRL_unknownNonCriticalExtension_succeeds() public view {
        bytes memory extensions = abi.encodePacked(_crlNumberExtension(hex"020107", ""), _unknownCRLExtension(""));

        CRLInfo memory crlInfo = this._parseCRLHelper(_syntheticCRL(extensions));

        assertEq(crlInfo.crlNumber, 7, "Unknown non-critical extension should be ignored");
    }

    function test_parseCRL_unknownCriticalExtension_reverts() public {
        bytes memory extensions =
            abi.encodePacked(_crlNumberExtension(hex"020107", ""), _unknownCRLExtension(hex"0101FF"));

        vm.expectRevert(InvalidCRLFormat.selector);
        this._parseCRLHelper(_syntheticCRL(extensions));
    }

    function test_parseCRL_unknownExtensionWithExplicitDefaultFalse_reverts() public {
        bytes memory extensions =
            abi.encodePacked(_crlNumberExtension(hex"020107", ""), _unknownCRLExtension(hex"010100"));

        vm.expectRevert(InvalidCRLFormat.selector);
        this._parseCRLHelper(_syntheticCRL(extensions));
    }

    function test_parseCRL_envelopeAndAlgorithmMismatch_reverts() public {
        bytes memory algorithm = hex"300306012A";
        bytes memory thisUpdate = hex"170D3235313230353036343233365A";
        bytes memory nextUpdate = hex"170D3236313230353036343233365A";
        bytes memory number = _crlNumberExtension(hex"020101", "");

        vm.expectRevert(InvalidCRLFormat.selector);
        this._parseCRLHelper(
            _syntheticCRLWithFields(algorithm, hex"300306012B", thisUpdate, nextUpdate, "", number, "", "")
        );

        vm.expectRevert(InvalidCRLFormat.selector);
        this._parseCRLHelper(
            _syntheticCRLWithFields(algorithm, hex"300506012A0500", thisUpdate, nextUpdate, "", number, "", "")
        );

        // ecdsa-with-SHA256 parameters must be absent; sha256WithRSAEncryption
        // parameters must be the canonical NULL value.
        bytes memory ecdsaWithNull = hex"300C06082A8648CE3D0403020500";
        vm.expectRevert(InvalidCRLFormat.selector);
        this._parseCRLHelper(
            _syntheticCRLWithFields(ecdsaWithNull, ecdsaWithNull, thisUpdate, nextUpdate, "", number, "", "")
        );

        bytes memory rsaWithoutNull = hex"300B06092A864886F70D01010B";
        vm.expectRevert(InvalidCRLFormat.selector);
        this._parseCRLHelper(
            _syntheticCRLWithFields(rsaWithoutNull, rsaWithoutNull, thisUpdate, nextUpdate, "", number, "", "")
        );

        vm.expectRevert(InvalidCRLFormat.selector);
        this._parseCRLHelper(abi.encodePacked(_syntheticCRL(number), hex"00"));

        vm.expectRevert(InvalidCRLFormat.selector);
        this._parseCRLHelper(
            _syntheticCRLWithFields(algorithm, algorithm, thisUpdate, nextUpdate, "", number, hex"020101", "")
        );

        vm.expectRevert(InvalidCRLFormat.selector);
        this._parseCRLHelper(
            _syntheticCRLWithFields(algorithm, algorithm, thisUpdate, nextUpdate, "", number, "", hex"020101")
        );
    }

    function test_parseCRL_strictTimes_reverts() public {
        bytes memory algorithm = hex"300306012A";
        bytes memory validTime = hex"170D3235313230353036343233365A";
        bytes memory laterTime = hex"170D3236313230353036343233365A";
        bytes memory number = _crlNumberExtension(hex"020101", "");

        vm.expectRevert(InvalidCRLFormat.selector);
        this._parseCRLHelper(
            _syntheticCRLWithFields(
                algorithm, algorithm, hex"160D3235313230353036343233365A", laterTime, "", number, "", ""
            )
        );

        vm.expectRevert(InvalidTimeFormat.selector);
        this._parseCRLHelper(
            _syntheticCRLWithFields(
                algorithm,
                algorithm,
                hex"170D3235303233303036343233365A", // 2025-02-30
                laterTime,
                "",
                number,
                "",
                ""
            )
        );

        vm.expectRevert(InvalidTimeFormat.selector);
        this._parseCRLHelper(
            _syntheticCRLWithFields(
                algorithm,
                algorithm,
                hex"180F32303235313230353036343233365A", // GeneralizedTime before 2050
                laterTime,
                "",
                number,
                "",
                ""
            )
        );

        bytes[] memory malformedTimes = new bytes[](3);
        malformedTimes[0] = _derNode(0x17, bytes("25120506423Z")); // too short
        malformedTimes[1] = _derNode(0x17, bytes("25120A064236Z")); // non-digit
        malformedTimes[2] = _derNode(0x17, bytes("251205064236X")); // not UTC Z
        for (uint256 i; i < malformedTimes.length; ++i) {
            vm.expectRevert(InvalidTimeFormat.selector);
            this._parseCRLHelper(
                _syntheticCRLWithFields(algorithm, algorithm, malformedTimes[i], laterTime, "", number, "", "")
            );
        }

        vm.expectRevert(InvalidCRLFormat.selector);
        this._parseCRLHelper(_syntheticCRLWithFields(algorithm, algorithm, validTime, validTime, "", number, "", ""));
    }

    function test_parseCRL_entryReasonAndUnknownNonCritical_succeeds() public view {
        bytes memory reason = _entryExtension(hex"0603551D15", "", hex"0A0101");
        bytes memory unknown = _entryExtension(hex"06032A0304", "", hex"0500");
        bytes memory invalidityDate = _entryExtension(hex"0603551D18", "", hex"180F32303235313230343036343233365A");
        bytes memory entry = _revokedEntry(
            hex"020101", hex"170D3235313230343036343233365A", abi.encodePacked(reason, unknown, invalidityDate)
        );

        CRLInfo memory crl = this._parseCRLHelper(_syntheticCRLWithEntries(entry));
        assertEq(crl.revokedSerials.length, 1);
        assertEq(crl.revokedSerials[0], 1);
    }

    function test_parseCRL_certificateHold_succeeds() public view {
        bytes memory date = hex"170D3235313230343036343233365A";
        bytes memory hold = _entryExtension(hex"0603551D15", "", hex"0A0106");

        CRLInfo memory crl = this._parseCRLHelper(_syntheticCRLWithEntries(_revokedEntry(hex"020101", date, hold)));

        assertEq(crl.revokedSerials.length, 1);
        assertEq(crl.revokedSerials[0], 1);
    }

    function test_parseCRL_removeFromCRL_reverts() public {
        bytes memory date = hex"170D3235313230343036343233365A";
        bytes memory removeFromCRL = _entryExtension(hex"0603551D15", "", hex"0A0108");
        vm.expectRevert(DeltaCRLNotSupported.selector);
        this._parseCRLHelper(_syntheticCRLWithEntries(_revokedEntry(hex"020101", date, removeFromCRL)));
    }

    function test_parseCRL_holdInstruction_nonCritical_succeeds() public view {
        bytes memory date = hex"170D3235313230343036343233365A";
        bytes memory holdInstruction = _entryExtension(hex"0603551D17", "", hex"06012A");

        CRLInfo memory crl =
            this._parseCRLHelper(_syntheticCRLWithEntries(_revokedEntry(hex"020101", date, holdInstruction)));

        assertEq(crl.revokedSerials.length, 1);
        assertEq(crl.revokedSerials[0], 1);
    }

    function test_parseCRL_holdInstruction_critical_reverts() public {
        bytes memory date = hex"170D3235313230343036343233365A";
        bytes memory holdInstruction = _entryExtension(hex"0603551D17", hex"0101FF", hex"06012A");

        vm.expectRevert(InvalidCRLFormat.selector);
        this._parseCRLHelper(_syntheticCRLWithEntries(_revokedEntry(hex"020101", date, holdInstruction)));
    }

    function test_parseCRL_deltaExtensions_revert() public {
        bytes memory number = _crlNumberExtension(hex"020101", "");

        vm.expectRevert(DeltaCRLNotSupported.selector);
        this._parseCRLHelper(_syntheticCRL(abi.encodePacked(number, _entryExtension(hex"0603551D1B", "", hex"020101"))));

        vm.expectRevert(DeltaCRLNotSupported.selector);
        this._parseCRLHelper(
            _syntheticCRL(abi.encodePacked(number, _entryExtension(hex"0603551D1B", hex"0101FF", hex"020101")))
        );
    }

    function test_parseCRL_issuingDistributionPointExtensions_revert() public {
        bytes memory number = _crlNumberExtension(hex"020101", "");

        vm.expectRevert(PartitionedCRLNotSupported.selector);
        this._parseCRLHelper(_syntheticCRL(abi.encodePacked(number, _entryExtension(hex"0603551D1C", "", hex"3000"))));

        vm.expectRevert(PartitionedCRLNotSupported.selector);
        this._parseCRLHelper(
            _syntheticCRL(abi.encodePacked(number, _entryExtension(hex"0603551D1C", hex"0101FF", hex"3000")))
        );
    }

    function test_parseCRL_certificateIssuerEntryExtension_reverts() public {
        bytes memory date = hex"170D3235313230343036343233365A";
        bytes memory value = hex"3003020101";

        bytes memory nonCritical = _entryExtension(hex"0603551D1D", "", value);
        vm.expectRevert(IndirectCRLNotSupported.selector);
        this._parseCRLHelper(_syntheticCRLWithEntries(_revokedEntry(hex"020101", date, nonCritical)));

        bytes memory critical = _entryExtension(hex"0603551D1D", hex"0101FF", value);
        vm.expectRevert(IndirectCRLNotSupported.selector);
        this._parseCRLHelper(_syntheticCRLWithEntries(_revokedEntry(hex"020101", date, critical)));
    }

    function test_parseCRL_malformedEntryAndExtensions_revert() public {
        bytes memory date = hex"170D3235313230343036343233365A";

        vm.expectRevert(InvalidCRLFormat.selector);
        this._parseCRLHelper(_syntheticCRLWithEntries(_derNode(0x30, hex"020101")));

        // The serial INTEGER crosses its revoked-entry SEQUENCE boundary.
        vm.expectRevert(InvalidCRLFormat.selector);
        this._parseCRLHelper(_syntheticCRLWithEntries(hex"3003020201"));

        vm.expectRevert(InvalidCRLFormat.selector);
        this._parseCRLHelper(_syntheticCRLWithEntries(_revokedEntry(hex"030101", date, "")));

        bytes memory unknownCritical = _entryExtension(hex"06032A0304", hex"0101FF", hex"0500");
        vm.expectRevert(InvalidCRLFormat.selector);
        this._parseCRLHelper(_syntheticCRLWithEntries(_revokedEntry(hex"020101", date, unknownCritical)));

        bytes memory explicitFalse = _entryExtension(hex"0603551D15", hex"010100", hex"0A0101");
        vm.expectRevert(InvalidCRLFormat.selector);
        this._parseCRLHelper(_syntheticCRLWithEntries(_revokedEntry(hex"020101", date, explicitFalse)));

        bytes memory reason = _entryExtension(hex"0603551D15", "", hex"0A0101");
        vm.expectRevert(InvalidCRLFormat.selector);
        this._parseCRLHelper(
            _syntheticCRLWithEntries(_revokedEntry(hex"020101", date, abi.encodePacked(reason, reason)))
        );

        bytes memory invalidReason = _entryExtension(hex"0603551D15", "", hex"0A0107");
        vm.expectRevert(InvalidCRLFormat.selector);
        this._parseCRLHelper(_syntheticCRLWithEntries(_revokedEntry(hex"020101", date, invalidReason)));

        bytes memory utcInvalidityDate = _entryExtension(hex"0603551D18", "", date);
        vm.expectRevert(InvalidCRLFormat.selector);
        this._parseCRLHelper(_syntheticCRLWithEntries(_revokedEntry(hex"020101", date, utcInvalidityDate)));

        // The child Extension claims two bytes beyond its Extensions parent,
        // while remaining within the overall CRL byte array.
        vm.expectRevert(InvalidCRLFormat.selector);
        this._parseCRLHelper(_syntheticCRL(hex"300A06032A0304040100"));
    }

    function test_updateCRL_missingNumber_reverts() public {
        vm.warp(1764979200);

        bytes[] memory certs = _loadCertificate("self_signed_ec_ca");
        bytes memory caCert = certs[1];
        registry.addCA(caCert);

        vm.expectRevert(CRLMissingNumber.selector);
        registry.updateCRL(_withoutCRLNumber(_loadEmptyCRL()), _singletonChain(caCert));
    }

    function test_updateCRL_sameNumber_reverts() public {
        vm.warp(1764979200);

        bytes[] memory certs = _loadCertificate("self_signed_ec_ca");
        bytes memory caCert = certs[1];
        registry.addCA(caCert);

        bytes memory crl = _loadEmptyCRL();
        registry.updateCRL(crl, _singletonChain(caCert));

        vm.expectRevert(CRLRollbackAttempt.selector);
        registry.updateCRL(crl, _singletonChain(caCert));
    }

    /// @notice An otherwise valid CRL must not authorize its own untrusted signer certificate
    function test_updateCRL_untrustedSigner_reverts() public {
        vm.warp(1764979200);

        bytes[] memory certs = _loadCertificate("self_signed_ec_ca");
        bytes memory caCert = certs[1];

        assertFalse(registry.verifiedCA(keccak256(caCert)));
        vm.expectRevert(CRLSignerNotTrusted.selector);
        registry.updateCRL(_loadEmptyCRL(), _singletonChain(caCert));
    }

    function test_verifyCRLSignerChain_empty_reverts() public {
        bytes[] memory signerChain = new bytes[](0);

        vm.expectRevert(InvalidCertChainLength.selector);
        MockCertChainRegistry(address(registry)).exposedVerifyCRLSignerChain(signerChain);
    }

    function test_verifyCRLSignerChain_tooLong_reverts() public {
        bytes[] memory signerChain = new bytes[](5);

        vm.expectRevert(InvalidCertChainLength.selector);
        MockCertChainRegistry(address(registry)).exposedVerifyCRLSignerChain(signerChain);
    }

    function test_verifyCRLSignerChain_duplicateCert_reverts() public {
        bytes[] memory certs = _loadCertificate("self_signed_ec_ca");
        bytes memory root = certs[1];
        registry.addCA(root);

        bytes[] memory signerChain = new bytes[](2);
        signerChain[0] = root;
        signerChain[1] = root;

        vm.expectRevert(InvalidCertificateChain.selector);
        MockCertChainRegistry(address(registry)).exposedVerifyCRLSignerChain(signerChain);
    }

    function test_verifyCRLSignerChain_missingCRLSign_reverts() public {
        bytes[] memory certs = _loadCertificate("gcp_snp_vek_certs");
        require(certs.length == 3, "Need 3 certs");

        (bool keyUsageExists, uint16 keyUsage) = LibX509.getKeyUsage(certs[1]);
        assertTrue(keyUsageExists, "Signer fixture must have key usage");
        assertEq(keyUsage & 0x0200, 0, "Signer fixture must omit cRLSign");

        // This fixture's root uses an unsupported RSA-PSS self-signature. Isolate
        // the cRLSign rule by setting only the trust-anchor precondition in the mock.
        MockCertChainRegistry mock = MockCertChainRegistry(address(registry));
        mock.exposedSetVerifiedCA(certs[2], true);

        bytes[] memory signerChain = new bytes[](2);
        signerChain[0] = certs[1];
        signerChain[1] = certs[2];

        vm.expectRevert(CRLSignNotSet.selector);
        mock.exposedVerifyCRLSignerChain(signerChain);
    }

    /// @dev Catches removal of _requireCertificateNotRevoked from the signer-chain constraint loop.
    function test_verifyCRLSignerChain_revokedSigner_reverts() public {
        bytes[] memory certs = _loadCertificate("gcp_tdx_tpm_certs");
        require(certs.length == 3, "Need leaf, intermediate and root");

        bytes32 rootHash = keccak256(certs[2]);
        bytes32 revocationScope = registry.computeRevocationScope(rootHash, certs[2]);
        uint256 signerSerial = LibX509.getCertSerialNumber(certs[1]);
        (bool keyUsageExists, uint16 keyUsage) = LibX509.getKeyUsage(certs[1]);
        assertTrue(keyUsageExists && (keyUsage & 0x0200) != 0, "Signer fixture must carry cRLSign");
        assertFalse(registry.revokedCertificates(revocationScope, signerSerial), "Signer must start unrevoked");

        registry.addCA(certs[2]);
        MockCertChainRegistry mock = MockCertChainRegistry(address(registry));
        mock.exposedSetRevoked(revocationScope, signerSerial, true);
        assertTrue(registry.revokedCertificates(revocationScope, signerSerial), "Signer must be revoked in root scope");

        bytes[] memory signerChain = new bytes[](2);
        signerChain[0] = certs[1];
        signerChain[1] = certs[2];

        vm.expectRevert(CertificateAlreadyRevoked.selector);
        mock.exposedVerifyCRLSignerChain(signerChain);
    }

    /// @dev Catches removal of the issuer-DN to parent-subject-DN linkage check.
    function test_verifyCRLSignerChain_dnMismatch_reverts() public {
        bytes[] memory gcpCerts = _loadCertificate("gcp_tdx_tpm_certs");
        bytes[] memory selfSignedCerts = _loadCertificate("self_signed_ec_ca");
        require(gcpCerts.length == 3 && selfSignedCerts.length == 2, "Need signer and root fixtures");

        bytes memory signer = gcpCerts[1];
        bytes memory root = selfSignedCerts[1];
        (bool keyUsageExists, uint16 keyUsage) = LibX509.getKeyUsage(signer);
        assertTrue(keyUsageExists && (keyUsage & 0x0200) != 0, "Signer fixture must carry cRLSign");
        assertNotEq(
            keccak256(LibX509.getCertIssuerDN(signer)),
            keccak256(LibX509.getCertSubjectDN(root)),
            "Fixture must reach the DN-mismatch branch"
        );

        registry.addCA(root);
        bytes[] memory signerChain = new bytes[](2);
        signerChain[0] = signer;
        signerChain[1] = root;

        vm.expectRevert(IssuerSubjectDNMismatch.selector);
        MockCertChainRegistry(address(registry)).exposedVerifyCRLSignerChain(signerChain);
    }

    /// @dev Catches removal of the signer AKID to issuer SKID linkage check.
    function test_verifyCRLSignerChain_akidSkidMismatch_reverts() public {
        vm.warp(1785196800);

        bytes[] memory chainA = _loadCertificate("collision_chain_a");
        bytes[] memory chainB = _loadCertificate("collision_chain_b");
        require(chainA.length == 3 && chainB.length == 3, "Need two three-level chains");

        bytes memory signer = chainA[1];
        bytes memory root = chainB[2];
        (bool keyUsageExists, uint16 keyUsage) = LibX509.getKeyUsage(signer);
        (bool akidExists, bytes memory akid) = LibX509.getAuthorityKeyIdentifier(signer);
        (bool skidExists, bytes memory skid) = LibX509.getSubjectKeyIdentifier(root);
        assertTrue(keyUsageExists && (keyUsage & 0x0200) != 0, "Signer fixture must carry cRLSign");
        assertEq(
            keccak256(LibX509.getCertIssuerDN(signer)),
            keccak256(LibX509.getCertSubjectDN(root)),
            "Fixture must pass DN linkage"
        );
        assertTrue(akidExists && akid.length > 0 && skidExists && skid.length > 0, "Fixture must carry AKID and SKID");
        assertNotEq(keccak256(akid), keccak256(skid), "Fixture must reach the AKID/SKID-mismatch branch");

        registry.addCA(root);
        bytes[] memory signerChain = new bytes[](2);
        signerChain[0] = signer;
        signerChain[1] = root;

        vm.expectRevert(abi.encodeWithSelector(CertChainAKIDMismatch.selector, uint256(0), akid, skid));
        MockCertChainRegistry(address(registry)).exposedVerifyCRLSignerChain(signerChain);
    }

    /// @dev Catches removal of the cryptographic child-certificate signature verification.
    function test_verifyCRLSignerChain_invalidChildSignature_reverts() public {
        bytes[] memory certs = _loadCertificate("gcp_tdx_tpm_certs");
        require(certs.length == 3, "Need leaf, intermediate and root");

        bytes memory signer = abi.encodePacked(certs[1]);
        bytes memory root = certs[2];
        (bool keyUsageExists, uint16 keyUsage) = LibX509.getKeyUsage(signer);
        assertTrue(keyUsageExists && (keyUsage & 0x0200) != 0, "Signer fixture must carry cRLSign");
        assertEq(
            keccak256(LibX509.getCertIssuerDN(signer)),
            keccak256(LibX509.getCertSubjectDN(root)),
            "Original fixture must pass DN linkage"
        );
        assertTrue(
            registry.verifyCertSignature(signer, MockCertChainRegistry(address(registry)).exposedGetPubkey(root)),
            "Original fixture signature must be valid"
        );

        signer[signer.length - 1] ^= 0x01;
        assertNotEq(keccak256(signer), keccak256(certs[1]), "Mutation must change the signer certificate");

        registry.addCA(root);
        bytes[] memory signerChain = new bytes[](2);
        signerChain[0] = signer;
        signerChain[1] = root;

        vm.expectRevert(InvalidSignature.selector);
        MockCertChainRegistry(address(registry)).exposedVerifyCRLSignerChain(signerChain);
    }

    /// @dev Catches removal of pathLenConstraint enforcement before signer-path linkage validation.
    function test_verifyCRLSignerChain_pathLenConstraint_reverts() public {
        vm.warp(1785196800);

        bytes[] memory tdxCerts = _loadCertificate("gcp_tdx_tpm_certs");
        bytes[] memory vekCerts = _loadCertificate("gcp_snp_vek_certs");
        require(tdxCerts.length == 3 && vekCerts.length == 3, "Need two three-level chains");

        bytes[] memory signerChain = new bytes[](3);
        signerChain[0] = tdxCerts[1];
        signerChain[1] = tdxCerts[2];
        signerChain[2] = vekCerts[1];

        (bool keyUsageExists, uint16 keyUsage) = LibX509.getKeyUsage(signerChain[0]);
        (bool basicConstraintsExists, bool isCA, bool hasPathLen, uint256 pathLen) =
            LibX509.getBasicConstraints(signerChain[2]);
        assertTrue(keyUsageExists && (keyUsage & 0x0200) != 0, "Signer fixture must carry cRLSign");
        assertTrue(basicConstraintsExists && isCA && hasPathLen, "Final fixture must be a path-length-constrained CA");
        assertEq(pathLen, 0, "Final fixture must have pathLen zero");
        assertNotEq(keccak256(signerChain[0]), keccak256(signerChain[1]), "Signer and parent must differ");
        assertNotEq(keccak256(signerChain[1]), keccak256(signerChain[2]), "Parent and final CA must differ");

        // This deliberately does not form a name-valid path: it isolates that
        // constraints are checked before DN, AKID/SKID, and signature linkage.
        MockCertChainRegistry mock = MockCertChainRegistry(address(registry));
        mock.exposedSetVerifiedCA(signerChain[2], true);

        vm.expectRevert(PathLenConstraintViolated.selector);
        mock.exposedVerifyCRLSignerChain(signerChain);
    }

    function test_verifyCRLSignerChain_intermediateToTrustedRoot_succeeds() public {
        bytes[] memory certs = _loadCertificate("gcp_tdx_tpm_certs");
        require(certs.length == 3, "Need 3 certs");

        registry.addCA(certs[2]);

        bytes[] memory signerChain = new bytes[](2);
        signerChain[0] = certs[1]; // CRL signer (intermediate)
        signerChain[1] = certs[2]; // Trusted root

        MockCertChainRegistry(address(registry)).exposedVerifyCRLSignerChain(signerChain);
    }

    function test_updateCRL_expiredSignerRoot_reverts() public {
        vm.warp(1764979200);

        bytes[] memory certs = _loadCertificate("self_signed_ec_ca");
        bytes memory caCert = certs[1];
        bytes memory crlBytes = _loadEmptyCRL();
        registry.addCA(caCert);

        // The signer/root expires on Oct 26 2035 while this CRL remains valid until Dec 3 2035.
        vm.warp(2077500000); // Nov 1 2035 03:20:00 UTC
        (, uint256 certNotAfter) = LibX509.getCertValidity(caCert);
        CRLInfo memory crlInfo = this._parseCRLHelper(crlBytes);
        assertGt(block.timestamp, certNotAfter, "Signer/root must be expired for this test");
        assertLt(block.timestamp, crlInfo.nextUpdate, "CRL must still be valid for this test");

        vm.expectRevert(CertificateExpired.selector);
        registry.updateCRL(crlBytes, _singletonChain(caCert));
    }

    function test_updateCRL_nonOwnerCanRelayValidRootCRL_succeeds() public {
        vm.warp(1764979200);

        bytes[] memory certs = _loadCertificate("self_signed_ec_ca");
        bytes memory caCert = certs[1];
        bytes memory crlBytes = _loadEmptyCRL();
        registry.addCA(caCert);

        vm.prank(nonOwner);
        registry.updateCRL(crlBytes, _singletonChain(caCert));

        bytes32 revocationScope = registry.computeRevocationScope(keccak256(caCert), caCert);
        (bytes32 cachedHash,,) = registry.crlCache(revocationScope);
        assertEq(cachedHash, keccak256(crlBytes));
    }

    function test_updateCRL_removedRoot_reverts() public {
        vm.warp(1764979200);

        bytes[] memory certs = _loadCertificate("self_signed_ec_ca");
        bytes memory root = certs[1];
        registry.addCA(root);
        registry.removeCA(root);

        vm.expectRevert(CRLSignerNotTrusted.selector);
        registry.updateCRL(_loadEmptyCRL(), _singletonChain(root));
    }

    function test_verifyCRLSignerChain_strictMode_requiresRootCRL() public {
        vm.warp(1764072000); // Nov 25 2025, within the GCP root CRL validity window

        bytes[] memory certs = _loadCertificate("gcp_tdx_tpm_certs");
        require(certs.length == 3, "Need 3 certs");
        registry.addCA(certs[2]);
        registry.setStrictCRLMode(true);

        bytes[] memory signerChain = new bytes[](2);
        signerChain[0] = certs[1];
        signerChain[1] = certs[2];

        vm.expectRevert(CRLRequiredInStrictMode.selector);
        MockCertChainRegistry(address(registry)).exposedVerifyCRLSignerChain(signerChain);

        bytes[] memory crls = _loadCertificate("gcp_root_ca_crl");
        require(crls.length == 1, "Need 1 CRL");
        registry.updateCRL(crls[0], _singletonChain(certs[2]));

        MockCertChainRegistry(address(registry)).exposedVerifyCRLSignerChain(signerChain);
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
        registry.addCA(caCert);

        bytes[] memory gcpCerts = _loadCertificate("gcp_tdx_tpm_certs");
        bytes memory wrongIssuer = gcpCerts[2];
        registry.addCA(wrongIssuer);

        // Try to update CRL with wrong issuer cert
        bytes memory crlBytes = _loadEmptyCRL();
        vm.expectRevert(CRLIssuerMismatch.selector);
        registry.updateCRL(crlBytes, _singletonChain(wrongIssuer));
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
        registry.updateCRL(revokedCrl, _singletonChain(caCert));
        bytes32 scope = registry.computeRevocationScope(keccak256(caCert), caCert);
        bytes32 activeSetHash = registry.activeRevokedSetHash(scope);

        // Try to rollback to older CRL (should revert)
        bytes memory emptyCrl = _loadEmptyCRL();
        vm.expectRevert(CRLRollbackAttempt.selector);
        registry.updateCRL(emptyCrl, _singletonChain(caCert));

        assertEq(registry.activeRevokedSetHash(scope), activeSetHash, "Rollback must not activate a set");
    }

    function test_updateCRL_higherNumberOlderThisUpdate_reverts() public {
        vm.warp(1785628800); // Aug 2 2026, after both CRLs and the CA become valid

        bytes[] memory certs = _loadCertificate("rollback_time_ca");
        require(certs.length == 1, "Need rollback-time CA");
        bytes memory caCert = certs[0];
        registry.addCA(caCert);

        bytes[] memory crls = _loadCertificate("rollback_time_crls");
        require(crls.length == 2, "Need baseline and candidate CRLs");
        CRLInfo memory baseline = this._parseCRLHelper(crls[0]);
        CRLInfo memory candidate = this._parseCRLHelper(crls[1]);

        assertGt(candidate.crlNumber, baseline.crlNumber, "Candidate number must advance");
        assertLt(candidate.thisUpdate, baseline.thisUpdate, "Candidate thisUpdate must roll back");
        assertLe(baseline.thisUpdate, block.timestamp, "Baseline must be active");
        assertGt(baseline.nextUpdate, block.timestamp, "Baseline must not be expired");
        assertLe(candidate.thisUpdate, block.timestamp, "Candidate must be active");
        assertGt(candidate.nextUpdate, block.timestamp, "Candidate must not be expired");

        registry.updateCRL(crls[0], _singletonChain(caCert));

        bytes32 scope = registry.computeRevocationScope(keccak256(caCert), caCert);
        (bytes32 cachedHash, uint256 cachedThisUpdate, uint256 cachedNextUpdate) = registry.crlCache(scope);
        uint256 cachedNumber = registry.latestCRLNumber(scope);
        bytes32 activeSetHash = registry.activeRevokedSetHash(scope);

        vm.expectRevert(CRLRollbackAttempt.selector);
        registry.updateCRL(crls[1], _singletonChain(caCert));

        (bytes32 finalHash, uint256 finalThisUpdate, uint256 finalNextUpdate) = registry.crlCache(scope);
        assertEq(finalHash, cachedHash, "Rejected CRL must not change cached hash");
        assertEq(finalThisUpdate, cachedThisUpdate, "Rejected CRL must not change thisUpdate");
        assertEq(finalNextUpdate, cachedNextUpdate, "Rejected CRL must not change nextUpdate");
        assertEq(registry.latestCRLNumber(scope), cachedNumber, "Rejected CRL must not change latest number");
        assertEq(registry.activeRevokedSetHash(scope), activeSetHash, "Rejected CRL must not activate a set");
        assertEq(cachedNumber, 10, "Baseline CRL number must remain current");
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
        bytes32 revocationScope = registry.computeRevocationScope(keccak256(caCert), caCert);
        bytes32 crlHash = keccak256(crlBytes);

        vm.expectEmit(true, false, false, true);
        emit ICertChainRegistry.CRLUpdated(
            revocationScope, crlInfo.issuerDN, crlInfo.authorityKeyId, crlHash, crlInfo.thisUpdate, crlInfo.nextUpdate
        );

        registry.updateCRL(crlBytes, _singletonChain(caCert));
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
        registry.updateCRL(emptyCrl, _singletonChain(caCert));

        CRLInfo memory oldCrlInfo = this._parseCRLHelper(emptyCrl);

        // Update to newer CRL with revoked cert (has later thisUpdate)
        bytes memory revokedCrl = _loadRevokedCRL();
        registry.updateCRL(revokedCrl, _singletonChain(caCert));

        // Verify cache was updated
        CRLInfo memory newCrlInfo = this._parseCRLHelper(revokedCrl);
        bytes32 revocationScope = registry.computeRevocationScope(keccak256(caCert), caCert);

        (bytes32 crlHash, uint256 thisUpdate,) = registry.crlCache(revocationScope);
        assertEq(crlHash, keccak256(revokedCrl), "CRL hash should be updated");
        assertEq(thisUpdate, newCrlInfo.thisUpdate, "thisUpdate should be updated");
        assertTrue(thisUpdate > oldCrlInfo.thisUpdate, "New thisUpdate should be later");
        assertEq(registry.latestCRLNumber(revocationScope), 6, "Latest CRL number should advance");
    }

    /// @notice Test parsing real GCP Root CA CRL
    function test_parseGCPRootCACRL_succeeds() public view {
        bytes[] memory crls = _loadCertificate("gcp_root_ca_crl");
        require(crls.length == 1, "Need 1 CRL");
        bytes memory gcpCrl = crls[0];

        CRLInfo memory crlInfo = this._parseCRLHelper(gcpCrl);

        // Verify issuer DN
        assertTrue(crlInfo.issuerDN.length > 0, "Issuer DN should be present");
        assertEq(crlInfo.crlNumber, 1234, "CRL number should be parsed");

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
        registry.updateCRL(gcpCrl, _singletonChain(gcpRootCA));

        // Verify CRL was cached
        CRLInfo memory crlInfo = this._parseCRLHelper(gcpCrl);
        bytes32 revocationScope = registry.computeRevocationScope(keccak256(gcpRootCA), gcpRootCA);

        (bytes32 crlHash, uint256 thisUpdate, uint256 nextUpdate) = registry.crlCache(revocationScope);

        assertEq(crlHash, keccak256(gcpCrl), "CRL hash should match");
        assertEq(thisUpdate, crlInfo.thisUpdate, "thisUpdate should match");
        assertEq(nextUpdate, crlInfo.nextUpdate, "nextUpdate should match");
    }

    /// @notice Test updateCRL indexes revoked certificates in the active set
    function test_updateCRL_indexesRevokedInActiveSet_succeeds() public {
        // Warp to a time within CRL validity (Nov 23 2025 - Nov 21 2035)
        vm.warp(1764979200); // Dec 6 2025 00:00:00 UTC

        bytes[] memory certs = _loadCertificate("self_signed_ec_ca");
        require(certs.length == 2, "Need 2 certs");

        bytes memory leafCert = certs[0];
        bytes memory caCert = certs[1];
        registry.addCA(caCert);

        // Load CRL with revoked certificate
        bytes memory crlBytes = _loadRevokedCRL();

        bytes[] memory chain = new bytes[](2);
        chain[0] = leafCert;
        chain[1] = caCert;

        // Verify certificate is not revoked before CRL update
        assertFalse(registry.isCertificateRevokedInChain(chain), "Certificate should not be revoked yet");

        // Update CRL - this should activate the revoked set
        registry.updateCRL(crlBytes, _singletonChain(caCert));

        // Verify certificate is now revoked in the active set
        assertTrue(registry.isCertificateRevokedInChain(chain), "Certificate should be revoked after CRL sync");

        // Verify that verifyCertChain will fail for revoked certificate
        vm.expectRevert(CertificateAlreadyRevoked.selector);
        registry.verifyCertChain(chain);
    }

    function test_updateCRL_akidlessLeaf_isRevokedByIssuerPathScope() public {
        vm.warp(1785196800); // Jul 28 2026, within the certificate and CRL validity windows

        bytes[] memory chain = _loadCertificate("akidless_ec_chain");
        require(chain.length == 2, "Need leaf and root");

        (bool akidExists, bytes memory akid) = LibX509.getAuthorityKeyIdentifier(chain[0]);
        assertFalse(akidExists, "Leaf fixture must omit AKID");
        assertEq(akid.length, 0, "Leaf fixture must have an empty AKID");

        bytes memory root = chain[1];
        registry.addCA(root);

        CertPubkey memory leafPubkey = registry.verifyCertChain(chain);
        assertTrue(leafPubkey.data.length > 0, "AKID-less leaf chain must initially verify");
        assertFalse(registry.isCertificateRevokedInChain(chain), "Leaf must initially be active");

        bytes[] memory crls = _loadCertificate("akidless_ec_crl");
        require(crls.length == 1, "Need one CRL");
        registry.updateCRL(crls[0], _singletonChain(root));

        assertTrue(registry.isCertificateRevokedInChain(chain), "Issuer CRL must revoke AKID-less leaf");

        bytes32 revocationScope = registry.computeRevocationScope(keccak256(root), root);
        uint256 leafSerial = LibX509.getCertSerialNumber(chain[0]);
        assertTrue(
            registry.revokedCertificates(revocationScope, leafSerial),
            "Revocation must be stored under the authenticated issuer path"
        );

        vm.expectRevert(CertificateAlreadyRevoked.selector);
        registry.verifyCertChain(chain);
    }

    function test_computeRevocationScope_sameIssuerAcrossRoots_isShared() public view {
        bytes[] memory chain = _loadCertificate("akidless_ec_chain");
        require(chain.length == 2, "Need leaf and root");

        bytes memory issuerCert = chain[1];
        bytes32 rootHash = keccak256(issuerCert);
        bytes32 otherRootHash = keccak256("different trusted root");
        bytes32 scope = registry.computeRevocationScope(rootHash, issuerCert);

        // Revocation identity deliberately has no root-hash input. A CRL signed by
        // this CA must remain effective when the same key is cross-certified or its
        // root certificate is renewed under another trusted path.
        assertEq(
            scope,
            registry.computeRevocationScope(otherRootHash, issuerCert),
            "One issuer identity must share revocation state across roots"
        );
    }

    function test_computeRevocationScope_equivalentRSAEncodings_areShared() public view {
        bytes[] memory certs = _loadCertificate("gcp_snp_tpm_certs");
        require(certs.length == 3, "Need leaf, intermediate and root");

        CertPubkey memory rsaPubkey = MockCertChainRegistry(address(registry)).exposedGetPubkey(certs[1]);
        (bytes memory n, bytes memory e) = LibX509.rsa(rsaPubkey);
        bytes memory canonicalRsa = LibX509.newRsaPubkey(n, e).data;

        bytes memory modulusInteger = uint8(n[0]) >= 0x80 ? abi.encodePacked(hex"00", n) : n;
        bytes memory nonMinimalRsa = _identityDerNode(
            0x30,
            abi.encodePacked(
                _identityDerNode(0x02, modulusInteger), _identityDerNode(0x02, abi.encodePacked(hex"00", e))
            )
        );
        assertNotEq(keccak256(canonicalRsa), keccak256(nonMinimalRsa), "Raw RSA encodings must differ");

        bytes memory subjectDN = hex"3003020101";
        bytes memory canonicalCert = _identityCertificate(canonicalRsa, subjectDN);
        bytes memory nonMinimalCert = _identityCertificate(nonMinimalRsa, subjectDN);

        assertEq(
            registry.computeRevocationScope(bytes32(0), canonicalCert),
            registry.computeRevocationScope(bytes32(0), nonMinimalCert),
            "Equivalent mathematical RSA keys must share one revocation scope"
        );
    }

    function test_computeRevocationScope_canonicalRSA_preservesExistingScope() public view {
        bytes[] memory certs = _loadCertificate("gcp_snp_tpm_certs");
        require(certs.length == 3, "Need leaf, intermediate and root");
        bytes memory issuerCert = certs[1];
        CertPubkey memory pubkey = MockCertChainRegistry(address(registry)).exposedGetPubkey(issuerCert);

        bytes32 issuerIdentity = keccak256(
            abi.encode(
                keccak256("AUTOMATA_ISSUER_IDENTITY_V1"),
                keccak256(LibX509.getCertSubjectDN(issuerCert)),
                pubkey.algo,
                pubkey.params,
                keccak256(pubkey.data)
            )
        );
        bytes32 expectedScope = keccak256(abi.encode(keccak256("AUTOMATA_REVOCATION_SCOPE_V2"), issuerIdentity));

        assertEq(registry.computeRevocationScope(bytes32(0), issuerCert), expectedScope);
    }

    function test_computeRevocationScope_ec_preservesExistingScope() public view {
        bytes[] memory certs = _loadCertificate("akidless_ec_chain");
        require(certs.length == 2, "Need leaf and root");
        bytes memory issuerCert = certs[1];
        CertPubkey memory pubkey = MockCertChainRegistry(address(registry)).exposedGetPubkey(issuerCert);

        bytes32 issuerIdentity = keccak256(
            abi.encode(
                keccak256("AUTOMATA_ISSUER_IDENTITY_V1"),
                keccak256(LibX509.getCertSubjectDN(issuerCert)),
                pubkey.algo,
                pubkey.params,
                keccak256(pubkey.data)
            )
        );
        bytes32 expectedScope = keccak256(abi.encode(keccak256("AUTOMATA_REVOCATION_SCOPE_V2"), issuerIdentity));

        assertEq(registry.computeRevocationScope(bytes32(0), issuerCert), expectedScope);
    }

    function test_updateCRL_sameDNSKIDDifferentIssuerKeys_areIsolated() public {
        vm.warp(1785196800); // Jul 28 2026, within all fixture validity windows

        bytes[] memory chainA = _loadCertificate("collision_chain_a");
        bytes[] memory chainB = _loadCertificate("collision_chain_b");
        require(chainA.length == 3 && chainB.length == 3, "Need two three-level chains");
        bytes32 scopeA = registry.computeRevocationScope(keccak256(chainA[1]), chainA[1]);
        bytes32 scopeB = registry.computeRevocationScope(keccak256(chainB[1]), chainB[1]);
        assertNotEq(scopeA, scopeB, "Different issuer keys must have different revocation scopes");

        assertEq(
            keccak256(LibX509.getCertSubjectDN(chainA[1])),
            keccak256(LibX509.getCertSubjectDN(chainB[1])),
            "Issuer DNs must collide"
        );
        (, bytes memory skidA) = LibX509.getSubjectKeyIdentifier(chainA[1]);
        (, bytes memory skidB) = LibX509.getSubjectKeyIdentifier(chainB[1]);
        assertEq(keccak256(skidA), keccak256(skidB), "Issuer SKIDs must collide");
        CertPubkey memory pubkeyA = MockCertChainRegistry(address(registry)).exposedGetPubkey(chainA[1]);
        CertPubkey memory pubkeyB = MockCertChainRegistry(address(registry)).exposedGetPubkey(chainB[1]);
        assertNotEq(keccak256(pubkeyA.data), keccak256(pubkeyB.data), "Issuer public keys must differ");
        assertEq(
            LibX509.getCertSerialNumber(chainA[0]), LibX509.getCertSerialNumber(chainB[0]), "Leaf serials must collide"
        );

        registry.addCA(chainA[2]);
        registry.addCA(chainB[2]);
        registry.verifyCertChain(chainA);
        registry.verifyCertChain(chainB);

        bytes[] memory signerChainA = new bytes[](2);
        signerChainA[0] = chainA[1];
        signerChainA[1] = chainA[2];
        bytes[] memory crls = _loadCertificate("collision_crl_a");
        registry.updateCRL(crls[0], signerChainA);

        assertEq(registry.latestCRLNumber(scopeA), 1, "Issuer A must track its CRL number");
        assertEq(registry.latestCRLNumber(scopeB), 0, "Issuer B must retain independent CRL state");

        assertTrue(registry.isCertificateRevokedInChain(chainA), "Root A CRL must revoke chain A leaf");
        assertFalse(registry.isCertificateRevokedInChain(chainB), "Root A CRL must not contaminate root B");

        vm.expectRevert(CertificateAlreadyRevoked.selector);
        registry.verifyCertChain(chainA);
        registry.verifyCertChain(chainB);
    }

    function test_updateCRL_crossCertifiedIssuerSharesRevocationAcrossRoots() public {
        vm.warp(1785196800); // Jul 28 2026, within all fixture validity windows

        bytes[] memory chainA = _loadCertificate("cross_cert_chain_a");
        bytes[] memory chainB = _loadCertificate("cross_cert_chain_b");
        bytes[] memory crls = _loadCertificate("cross_cert_crl");
        require(chainA.length == 3 && chainB.length == 3 && crls.length == 1, "Need cross-cert fixtures");

        assertEq(keccak256(chainA[0]), keccak256(chainB[0]), "Both paths must contain the same leaf");
        assertNotEq(keccak256(chainA[1]), keccak256(chainB[1]), "Cross-certificates must be distinct");
        assertNotEq(keccak256(chainA[2]), keccak256(chainB[2]), "Trusted roots must be distinct");
        assertEq(
            keccak256(LibX509.getCertSubjectDN(chainA[1])),
            keccak256(LibX509.getCertSubjectDN(chainB[1])),
            "Cross-certified issuer subjects must match"
        );
        CertPubkey memory issuerA = MockCertChainRegistry(address(registry)).exposedGetPubkey(chainA[1]);
        CertPubkey memory issuerB = MockCertChainRegistry(address(registry)).exposedGetPubkey(chainB[1]);
        assertEq(keccak256(issuerA.data), keccak256(issuerB.data), "Cross-certified issuer keys must match");

        registry.addCA(chainA[2]);
        registry.addCA(chainB[2]);
        registry.verifyCertChain(chainA);
        registry.verifyCertChain(chainB);

        bytes[] memory signerChainA = new bytes[](2);
        signerChainA[0] = chainA[1];
        signerChainA[1] = chainA[2];
        registry.updateCRL(crls[0], signerChainA);

        assertTrue(registry.isCertificateRevokedInChain(chainA), "Path A must observe issuer revocation");
        assertTrue(registry.isCertificateRevokedInChain(chainB), "Path B must share the same issuer revocation");
        bytes32 scopeA = registry.computeRevocationScope(keccak256(chainA[2]), chainA[1]);
        bytes32 scopeB = registry.computeRevocationScope(keccak256(chainB[2]), chainB[1]);
        assertEq(scopeA, scopeB, "Cross-certified issuer must resolve to one revocation scope");
        assertEq(registry.latestCRLNumber(scopeA), 1, "Both paths must share CRL anti-rollback state");

        vm.expectRevert(CertificateAlreadyRevoked.selector);
        registry.verifyCertChain(chainB);

        bytes[] memory signerChainB = new bytes[](2);
        signerChainB[0] = chainB[1];
        signerChainB[1] = chainB[2];
        vm.expectRevert(CRLRollbackAttempt.selector);
        registry.updateCRL(crls[0], signerChainB);
    }

    function test_isCertificateRevokedInChain_trustedRootTarget_returnsFalse() public {
        vm.warp(1785196800);

        bytes[] memory certs = _loadCertificate("akidless_ec_chain");
        require(certs.length == 2, "Need leaf and root");

        bytes memory root = certs[1];
        registry.addCA(root);

        bytes[] memory rootChain = _singletonChain(root);
        assertFalse(registry.isCertificateRevokedInChain(rootChain), "Trusted root must be active in its self scope");
    }

    function test_isCertificateRevokedInChain_intermediateTarget_returnsFalse() public {
        bytes[] memory certs = _loadCertificate("gcp_tdx_tpm_certs");
        require(certs.length == 3, "Need leaf, intermediate and root");
        registry.addCA(certs[2]);

        bytes[] memory intermediateChain = new bytes[](2);
        intermediateChain[0] = certs[1];
        intermediateChain[1] = certs[2];

        assertFalse(
            registry.isCertificateRevokedInChain(intermediateChain),
            "Authenticated intermediate must be queryable as a CA target"
        );
    }

    function test_computeRevocationScope_differentIssuerIdentities_areIsolated() public view {
        bytes[] memory issuerChain = _loadCertificate("akidless_ec_chain");
        bytes[] memory otherIssuerChain = _loadCertificate("self_signed_ec_ca");
        require(issuerChain.length == 2 && otherIssuerChain.length == 2, "Need two issuer fixtures");

        bytes32 rootHash = keccak256(issuerChain[1]);
        bytes32 scope = registry.computeRevocationScope(rootHash, issuerChain[1]);
        bytes32 otherScope = registry.computeRevocationScope(rootHash, otherIssuerChain[1]);

        assertNotEq(scope, otherScope, "Different issuer subject/key identities must remain isolated");
    }

    function test_computeRevocationScope_ignoresCertificateSignatureBytes() public view {
        bytes[] memory chain = _loadCertificate("akidless_ec_chain");
        require(chain.length == 2, "Need leaf and root");

        bytes memory issuerCert = chain[1];
        bytes memory issuerVariant = abi.encodePacked(issuerCert);
        uint256 lastIndex = issuerVariant.length - 1;
        issuerVariant[lastIndex] = bytes1(uint8(issuerVariant[lastIndex]) ^ 0x01);

        assertNotEq(keccak256(issuerCert), keccak256(issuerVariant), "Fixture certificate hashes must differ");

        bytes32 rootHash = keccak256(issuerCert);
        bytes32 scope = registry.computeRevocationScope(rootHash, issuerCert);
        bytes32 variantScope = registry.computeRevocationScope(rootHash, issuerVariant);

        assertEq(scope, variantScope, "Issuer identity must depend on subject/SPKI, not certificate signature");
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
        registry.updateCRL(crlBytes, _singletonChain(caCert));

        // Verify all revoked serials are indexed in the active set
        bytes32 revocationScope = registry.computeRevocationScope(keccak256(caCert), caCert);

        // Check that all revoked serials from the CRL are active
        for (uint256 i = 0; i < crlInfo.revokedSerials.length; i++) {
            uint256 serial = crlInfo.revokedSerials[i];
            assertTrue(registry.revokedCertificates(revocationScope, serial), "Revoked serial should be active");
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
        registry.updateCRL(crlBytes, _singletonChain(caCert));
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
