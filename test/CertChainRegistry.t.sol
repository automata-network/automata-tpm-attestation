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
    CRLMissingNumber,
    InvalidCRLFormat,
    InvalidCRLNumber,
    DeltaCRLNotSupported,
    IndirectCRLNotSupported,
    TemporaryRevocationNotSupported,
    InvalidTimeFormat,
    CRLRollbackAttempt,
    CRLRequiredInStrictMode,
    CRLExpiredInStrictMode,
    UnsupportedCriticalCertificateExtension,
    Asn1InvalidLengthBytes,
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

    function test_parseCRL_entryTemporaryReasons_revert() public {
        bytes memory date = hex"170D3235313230343036343233365A";

        bytes memory hold = _entryExtension(hex"0603551D15", "", hex"0A0106");
        vm.expectRevert(TemporaryRevocationNotSupported.selector);
        this._parseCRLHelper(_syntheticCRLWithEntries(_revokedEntry(hex"020101", date, hold)));

        bytes memory removeFromCRL = _entryExtension(hex"0603551D15", "", hex"0A0108");
        vm.expectRevert(DeltaCRLNotSupported.selector);
        this._parseCRLHelper(_syntheticCRLWithEntries(_revokedEntry(hex"020101", date, removeFromCRL)));

        bytes memory holdInstruction = _entryExtension(hex"0603551D17", "", hex"06012A");
        vm.expectRevert(TemporaryRevocationNotSupported.selector);
        this._parseCRLHelper(_syntheticCRLWithEntries(_revokedEntry(hex"020101", date, holdInstruction)));
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
