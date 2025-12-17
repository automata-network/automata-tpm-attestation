// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.27;

// Testing utilities
import "forge-std/console.sol";
import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";

// Target contract
import {LibX509} from "src/lib/LibX509.sol";
import "src/types/Errors.sol";

/// @title LibX509_Test
/// @notice Test suite for the LibX509.getBasicConstraints function using real certificates
contract LibX509_Test is Test {
    using stdJson for string;

    string private certificatesJson;

    function setUp() public virtual {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/test/testdata/certificates.json");
        certificatesJson = vm.readFile(path);
    }

    /// @notice Helper function to load a certificate from JSON
    /// @param certType The type of certificate (e.g., "gcp_snp_vek_certs")
    function _loadCertificate(string memory certType) internal view returns (bytes[] memory) {
        return certificatesJson.readBytesArrayOr(string(abi.encodePacked(".", certType)), new bytes[](0));
    }

    /// @notice Helper function to wrap internal checkCAConstraints for testing with vm.expectRevert
    function _checkCAConstraints(bytes memory der, uint256 remainingCAs, bool isLeaf) public pure {
        LibX509.checkCAConstraints(der, remainingCAs, isLeaf);
    }

    /// @notice Helper to parse serial number bytes to uint256
    function _parseSerialNumber(bytes memory serialBytes) internal pure returns (uint256 serial) {
        return LibX509._parseSerialNumber(serialBytes);
    }
}

/// @title LibX509_CAConstraints_Test
/// @notice Integration tests to verify CA constraint validation (BasicConstraints + KeyUsage)
contract LibX509_basicConstraints_Test is LibX509_Test {
    /// @notice Tests that getBasicConstraints returns expected values for VEK certificate chains
    function test_getBasicConstraints_vekCert_succeeds() public view {
        bytes memory cert;
        bool exists;
        bool isCA;
        bool hasPathLen;
        uint256 pathLen;
        string[] memory certTypes = new string[](2);
        certTypes[0] = "gcp_snp_vek_certs";
        certTypes[1] = "azure_snp_vek_certs";

        for (uint256 i = 0; i < certTypes.length; i++) {
            string memory certType = certTypes[i];
            cert = _loadCertificate(certType)[2];
            (exists, isCA, hasPathLen, pathLen) = LibX509.getBasicConstraints(cert);
            assertTrue(exists, "BasicConstraints should exist for root CA");
            assertTrue(isCA, "Root CA should have isCA=true");
            assertFalse(hasPathLen, "this certificate should not have pathLen constraint");
            assertEq(pathLen, 0, "this certificate pathLen should be 0");
            cert = _loadCertificate(certType)[1];
            (exists, isCA, hasPathLen, pathLen) = LibX509.getBasicConstraints(cert);
            assertTrue(exists, "BasicConstraints should exist for intermediate CA");
            assertTrue(isCA, "Root CA should have isCA=true");
            assertTrue(hasPathLen, "this certificate should have pathLen constraint");
            assertEq(pathLen, 0, "this certificate pathLen should be 0");
            cert = _loadCertificate(certType)[0];
            (exists, isCA, hasPathLen, pathLen) = LibX509.getBasicConstraints(cert);
            assertFalse(exists, "BasicConstraints should not exist for leaf cert");
            assertFalse(isCA, "Root CA should have isCA=true");
            assertFalse(hasPathLen, "this certificate should not have pathLen constraint");
            assertEq(pathLen, 0, "this certificate pathLen should be 0");
        }
    }

    /// @notice Tests that getBasicConstraints returns expected values for TPM certificate chains
    function test_getBasicConstraints_TpmCert_succeeds() public view {
        bytes memory cert;
        bool exists;
        bool isCA;
        bool hasPathLen;
        uint256 pathLen;
        string[] memory certTypes = new string[](2);
        certTypes[0] = "gcp_tdx_tpm_certs";
        certTypes[1] = "gcp_snp_tpm_certs";

        for (uint256 i = 0; i < certTypes.length; i++) {
            string memory certType = certTypes[i];
            cert = _loadCertificate(certType)[2];
            (exists, isCA, hasPathLen, pathLen) = LibX509.getBasicConstraints(cert);
            assertTrue(exists, "BasicConstraints should exist for root CA");
            assertTrue(isCA, "Root CA should have isCA=true");
            assertFalse(hasPathLen, "this certificate should not have pathLen constraint");
            assertEq(pathLen, 0, "this certificate pathLen should be 0");
            cert = _loadCertificate(certType)[1];
            (exists, isCA, hasPathLen, pathLen) = LibX509.getBasicConstraints(cert);
            assertTrue(exists, "BasicConstraints should exist for intermediate CA");
            assertTrue(isCA, "Root CA should have isCA=true");
            assertFalse(hasPathLen, "TPM intermediate CA certificate should not have pathLen constraint");
            assertEq(pathLen, 0, "intermediate CA certificate pathLen should be 0");
            cert = _loadCertificate(certType)[0];
            (exists, isCA, hasPathLen, pathLen) = LibX509.getBasicConstraints(cert);
            assertFalse(exists, "BasicConstraints should not exist for leaf cert");
            assertFalse(isCA, "Root CA should have isCA=true");
            assertFalse(hasPathLen, "TPM leaf certificate should not have pathLen constraint");
            assertEq(pathLen, 0, "TPM leaf certificate pathLen should be 0");
        }
    }

    /// @notice Tests that getBasicConstraints correctly identifies an intermediate CA certificate
    ///         Intermediate CA certificates should have isCA=true and may have pathLen constraint
    function test_getBasicConstraints_intermediateCA_succeeds() public view {
        // Load SEV-VLEK (intermediate CA) certificate from the chain
        bytes memory cert = _loadCertificate("gcp_snp_vek_certs")[1];

        (bool exists, bool isCA, bool hasPathLen, uint256 pathLen) = LibX509.getBasicConstraints(cert);

        // Intermediate CA should have BasicConstraints extension
        assertTrue(exists, "BasicConstraints should exist for intermediate CA");
        // Intermediate CA should be a CA certificate
        assertTrue(isCA, "Intermediate CA should have isCA=true");
        // Verify pathLen if present
        if (hasPathLen) {
            // Intermediate CA pathLen is typically smaller than root
            assertLe(pathLen, 5, "Intermediate CA pathLen should be reasonable");
        }
    }
}

/// @title LibX509_KeyUsage_Test
/// @notice Tests for KeyUsage extension parsing and validation
contract LibX509_KeyUsage_Test is LibX509_Test {
    /// @notice KeyUsage bit flags (from RFC 5280 Section 4.2.1.3)
    uint16 constant KEY_USAGE_DIGITAL_SIGNATURE = 0x8000; // bit 0
    uint16 constant KEY_USAGE_NON_REPUDIATION = 0x4000; // bit 1
    uint16 constant KEY_USAGE_KEY_ENCIPHERMENT = 0x2000; // bit 2
    uint16 constant KEY_USAGE_DATA_ENCIPHERMENT = 0x1000; // bit 3
    uint16 constant KEY_USAGE_KEY_AGREEMENT = 0x0800; // bit 4
    uint16 constant KEY_USAGE_KEY_CERT_SIGN = 0x0400; // bit 5
    uint16 constant KEY_USAGE_CRL_SIGN = 0x0200; // bit 6

    /// @notice Tests that getKeyUsage correctly extracts KeyUsage from root CA certificates
    function test_getKeyUsage_rootCA_hasKeyCertSign() public view {
        string[] memory certTypes = new string[](4);
        certTypes[0] = "gcp_snp_vek_certs";
        certTypes[1] = "azure_snp_vek_certs";
        certTypes[2] = "gcp_tdx_tpm_certs";
        certTypes[3] = "gcp_snp_tpm_certs";

        for (uint256 i = 0; i < certTypes.length; i++) {
            bytes memory rootCert = _loadCertificate(certTypes[i])[2];
            (bool exists, uint16 keyUsage) = LibX509.getKeyUsage(rootCert);

            // Root CAs should have KeyUsage extension
            assertTrue(exists, "Root CA should have KeyUsage extension");
            // Root CAs must have keyCertSign bit set
            assertTrue((keyUsage & KEY_USAGE_KEY_CERT_SIGN) != 0, "Root CA must have keyCertSign bit");
            // Root CAs typically also have cRLSign
            assertTrue((keyUsage & KEY_USAGE_CRL_SIGN) != 0, "Root CA typically has cRLSign bit");
        }
    }

    /// @notice Tests that getKeyUsage correctly extracts KeyUsage from intermediate CA certificates
    function test_getKeyUsage_intermediateCA_hasKeyCertSign() public view {
        string[] memory certTypes = new string[](4);
        certTypes[0] = "gcp_snp_vek_certs";
        certTypes[1] = "azure_snp_vek_certs";
        certTypes[2] = "gcp_tdx_tpm_certs";
        certTypes[3] = "gcp_snp_tpm_certs";

        for (uint256 i = 0; i < certTypes.length; i++) {
            bytes memory intermediateCert = _loadCertificate(certTypes[i])[1];
            (bool exists, uint16 keyUsage) = LibX509.getKeyUsage(intermediateCert);

            // Intermediate CAs should have KeyUsage extension
            assertTrue(exists, "Intermediate CA should have KeyUsage extension");
            // Intermediate CAs must have keyCertSign bit set
            assertTrue((keyUsage & KEY_USAGE_KEY_CERT_SIGN) != 0, "Intermediate CA must have keyCertSign bit");
        }
    }

    /// @notice Tests that getKeyUsage handles leaf certificates correctly
    ///         Leaf certificates may not have KeyUsage or may have different bits set
    function test_getKeyUsage_leafCert() public view {
        string[] memory certTypes = new string[](4);
        certTypes[0] = "gcp_snp_vek_certs";
        certTypes[1] = "azure_snp_vek_certs";
        certTypes[2] = "gcp_tdx_tpm_certs";
        certTypes[3] = "gcp_snp_tpm_certs";

        for (uint256 i = 0; i < certTypes.length; i++) {
            bytes memory leafCert = _loadCertificate(certTypes[i])[0];
            (bool exists, uint16 keyUsage) = LibX509.getKeyUsage(leafCert);

            // If KeyUsage exists in leaf cert, it should NOT have keyCertSign
            if (exists) {
                assertFalse((keyUsage & KEY_USAGE_KEY_CERT_SIGN) != 0, "Leaf cert should not have keyCertSign bit");
            }
        }
    }

    /// @notice Tests that KeyUsage can have multiple bits set
    function test_getKeyUsage_multipleBits() public view {
        bytes memory rootCert = _loadCertificate("gcp_snp_vek_certs")[2];
        (bool exists, uint16 keyUsage) = LibX509.getKeyUsage(rootCert);

        assertTrue(exists, "Certificate should have KeyUsage");

        // Count how many bits are set
        uint256 bitCount = 0;
        for (uint256 i = 0; i < 16; i++) {
            if ((keyUsage & (1 << i)) != 0) {
                bitCount++;
            }
        }

        // CA certificates typically have multiple KeyUsage bits set
        assertGe(bitCount, 1, "CA should have at least one KeyUsage bit set");
    }
}

/// @title LibX509_CheckCAConstraints_Comprehensive_Test
/// @notice Comprehensive tests for checkCAConstraints that validates both BasicConstraints and KeyUsage
contract LibX509_CheckCAConstraints_Test is LibX509_Test {
    uint16 constant KEY_USAGE_KEY_CERT_SIGN = 0x0400;

    /// @notice Tests that checkCAConstraints succeeds for valid CA certificate chains
    function test_checkCAConstraints_validChain_succeeds() public view {
        string[] memory certTypes = new string[](4);
        certTypes[0] = "gcp_snp_vek_certs";
        certTypes[1] = "azure_snp_vek_certs";
        certTypes[2] = "gcp_tdx_tpm_certs";
        certTypes[3] = "gcp_snp_tpm_certs";

        for (uint256 i = 0; i < certTypes.length; i++) {
            bytes[] memory certs = _loadCertificate(certTypes[i]);

            // Root CA (index 2) - can have 1 CA below it (the intermediate)
            // Intermediate CA (index 1) - no more CAs below it (just leaf)
            for (uint256 n = 0; n < certs.length; n++) {
                uint256 pathLen = 0;
                if (n >= 1) {
                    pathLen = n - 1;
                }
                LibX509.checkCAConstraints(certs[n], pathLen, n == 0);
            }
        }
    }

    /// @notice Tests that checkCAConstraints enforces BasicConstraints CA=true for CA certificates
    function test_checkCAConstraints_requiresCAFlag() public {
        bytes memory leafCert = _loadCertificate("gcp_snp_vek_certs")[0];

        // Should revert when a leaf cert is incorrectly marked as CA (isLeaf=false)
        vm.expectRevert("IssuerCertMissingBasicConstraints()");
        this._checkCAConstraints(leafCert, 0, false);
    }

    /// @notice Tests that checkCAConstraints enforces pathLen constraints
    function test_checkCAConstraints_enforcesPathLen() public {
        // Get intermediate CA with pathLen=0
        bytes memory intermediateCert = _loadCertificate("gcp_snp_vek_certs")[1];

        // Verify it has pathLen=0
        (,, bool hasPathLen, uint256 pathLen) = LibX509.getBasicConstraints(intermediateCert);
        assertTrue(hasPathLen, "Test cert should have pathLen");
        assertEq(pathLen, 0, "Test cert should have pathLen=0");

        // Should succeed with remainingCAs=0
        LibX509.checkCAConstraints(intermediateCert, 0, false);

        // Should fail with remainingCAs=1 (exceeds pathLen)
        vm.expectRevert("PathLenConstraintViolated()");
        this._checkCAConstraints(intermediateCert, 1, false);
    }

    /// @notice Tests that checkCAConstraints validates KeyUsage keyCertSign bit
    ///         This test verifies the integration of KeyUsage checking into CA validation
    function test_checkCAConstraints_validatesKeyCertSign() public view {
        string[] memory certTypes = new string[](2);
        certTypes[0] = "gcp_snp_vek_certs";
        certTypes[1] = "azure_snp_vek_certs";

        for (uint256 i = 0; i < certTypes.length; i++) {
            bytes[] memory certs = _loadCertificate(certTypes[i]);

            // Verify root CA has keyCertSign
            (bool rootKuExists, uint16 rootKeyUsage) = LibX509.getKeyUsage(certs[2]);
            assertTrue(rootKuExists, "Root CA should have KeyUsage");
            assertTrue((rootKeyUsage & KEY_USAGE_KEY_CERT_SIGN) != 0, "Root CA should have keyCertSign");

            // Verify intermediate CA has keyCertSign
            (bool intKuExists, uint16 intKeyUsage) = LibX509.getKeyUsage(certs[1]);
            assertTrue(intKuExists, "Intermediate CA should have KeyUsage");
            assertTrue((intKeyUsage & KEY_USAGE_KEY_CERT_SIGN) != 0, "Intermediate CA should have keyCertSign");

            // checkCAConstraints should succeed for both
            LibX509.checkCAConstraints(certs[2], 1, false);
            LibX509.checkCAConstraints(certs[1], 0, false);
        }
    }

    /// @notice Tests pathLen validation with different chain depths
    function test_checkCAConstraints_pathLenBoundaries() public view {
        bytes memory rootCert = _loadCertificate("gcp_snp_vek_certs")[2];

        // Check if root has pathLen constraint
        (,, bool hasPathLen, uint256 pathLen) = LibX509.getBasicConstraints(rootCert);

        if (hasPathLen) {
            // Test boundary: remainingCAs == pathLen (should succeed)
            LibX509.checkCAConstraints(rootCert, pathLen, false);

            // Test boundary: remainingCAs < pathLen (should succeed)
            if (pathLen > 0) {
                LibX509.checkCAConstraints(rootCert, pathLen - 1, false);
            }
        } else {
            // If no pathLen constraint, any number should work
            LibX509.checkCAConstraints(rootCert, 0, false);
            LibX509.checkCAConstraints(rootCert, 1, false);
            LibX509.checkCAConstraints(rootCert, 10, false);
        }
    }
}

/// @title LibX509_Basic_Test
/// @notice basic tests
contract LibX509_Basic_Test is LibX509_Test {
    using stdJson for string;

    string private expectedValuesJson;

    function setUp() public override {
        super.setUp();
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/test/testdata/expected_cert_values.json");
        expectedValuesJson = vm.readFile(path);
    }

    /// @notice Tests that getCertSerialNumber correctly extracts serial numbers with known values
    function test_getCertSerialNumber_succeeds() public view {
        string[] memory certTypes = new string[](4);
        certTypes[0] = "gcp_snp_vek_certs";
        certTypes[1] = "azure_snp_vek_certs";
        certTypes[2] = "gcp_tdx_tpm_certs";
        certTypes[3] = "gcp_snp_tpm_certs";

        for (uint256 i = 0; i < certTypes.length; i++) {
            string memory certType = certTypes[i];
            bytes[] memory certs = _loadCertificate(certType);

            // Load expected serial numbers from JSON
            bytes[] memory expectedSerials = expectedValuesJson.readBytesArrayOr(
                string(abi.encodePacked(".", certType, ".serialNumbers")), new bytes[](0)
            );

            // Verify each certificate's serial number
            for (uint256 j = 0; j < certs.length; j++) {
                uint256 actualSerial = LibX509.getCertSerialNumber(certs[j]);
                assertEq(
                    actualSerial,
                    _parseSerialNumber(expectedSerials[j]),
                    string(abi.encodePacked(certType, "[", vm.toString(j), "] serial number mismatch"))
                );
            }
        }
    }

    /// @notice Tests that getCertIssuerDN correctly extracts issuer DN with exact values
    function test_getCertIssuerDN_succeeds() public view {
        string[] memory certTypes = new string[](4);
        certTypes[0] = "gcp_snp_vek_certs";
        certTypes[1] = "azure_snp_vek_certs";
        certTypes[2] = "gcp_tdx_tpm_certs";
        certTypes[3] = "gcp_snp_tpm_certs";

        for (uint256 i = 0; i < certTypes.length; i++) {
            string memory certType = certTypes[i];
            bytes[] memory certs = _loadCertificate(certType);

            // Load expected issuer DNs from JSON
            bytes[] memory expectedIssuerDNs = expectedValuesJson.readBytesArrayOr(
                string(abi.encodePacked(".", certType, ".issuerDNs")), new bytes[](0)
            );

            // Verify each certificate's issuer DN
            for (uint256 j = 0; j < certs.length; j++) {
                bytes memory actualIssuerDN = LibX509.getCertIssuerDN(certs[j]);
                assertEq(
                    keccak256(actualIssuerDN),
                    keccak256(expectedIssuerDNs[j]),
                    string(abi.encodePacked(certType, "[", vm.toString(j), "] issuerDN mismatch"))
                );
            }
        }
    }

    /// @notice Tests that getCertSubjectDN correctly extracts subject DN
    ///         and verifies the DN linkage property (issuer DN of cert[i] == subject DN of cert[i+1])
    function test_getCertSubjectDN_succeeds() public view {
        string[] memory certTypes = new string[](3);
        certTypes[0] = "gcp_tdx_tpm_certs";
        certTypes[1] = "gcp_snp_tpm_certs";
        certTypes[2] = "azure_snp_vek_certs";

        for (uint256 i = 0; i < certTypes.length; i++) {
            string memory certType = certTypes[i];
            bytes[] memory certs = _loadCertificate(certType);

            // Verify each certificate's subject DN is non-empty
            for (uint256 j = 0; j < certs.length; j++) {
                bytes memory subjectDN = LibX509.getCertSubjectDN(certs[j]);
                assertTrue(
                    subjectDN.length > 0,
                    string(abi.encodePacked(certType, "[", vm.toString(j), "] subjectDN should not be empty"))
                );
            }

            // Verify DN linkage: issuer DN of cert[i] should match subject DN of cert[i+1]
            // This is required by RFC 5280 Section 6.1.3
            for (uint256 j = 0; j < certs.length - 1; j++) {
                bytes memory issuerDN = LibX509.getCertIssuerDN(certs[j]);
                bytes memory subjectDN = LibX509.getCertSubjectDN(certs[j + 1]);
                assertEq(
                    keccak256(issuerDN),
                    keccak256(subjectDN),
                    string(
                        abi.encodePacked(
                            certType, " issuerDN[", vm.toString(j), "] != subjectDN[", vm.toString(j + 1), "]"
                        )
                    )
                );
            }

            // Verify root CA is self-signed (issuer DN == subject DN)
            bytes memory rootIssuerDN = LibX509.getCertIssuerDN(certs[certs.length - 1]);
            bytes memory rootSubjectDN = LibX509.getCertSubjectDN(certs[certs.length - 1]);
            assertEq(
                keccak256(rootIssuerDN),
                keccak256(rootSubjectDN),
                string(abi.encodePacked(certType, ": root CA should be self-signed"))
            );
        }
    }
}
