// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.15;

import "./SetupBase.sol";
import "../src/lib/LibX509.sol";
import {SignatureAlgorithm} from "../src/lib/LibX509.sol";
import {TpmSignatureVerificationFailed, CertifiedNameMismatch, ExtraDataMismatch} from "../src/types/Errors.sol";

contract TPMCertifyTest is SetupBase {
    // Test data loaded from files
    string constant TESTDATA_DIR = "./test/testdata/certify/gcp/";

    bytes certifyInfo;
    bytes akSignature;
    bytes tpmtPublic;
    bytes akPubkeyData;
    bytes expectedExtraData;

    function setUp() public override {
        super.setUp();

        // Load test data from binary files using vm.readFileBinary
        certifyInfo = vm.readFileBinary(string.concat(TESTDATA_DIR, "attestation_data_20260117_094825.bin"));
        akSignature = vm.readFileBinary(string.concat(TESTDATA_DIR, "attestation_signature_20260117_094825.bin"));
        tpmtPublic = vm.readFileBinary(string.concat(TESTDATA_DIR, "vm_identity_public_20260117_094825.bin"));
        akPubkeyData = vm.readFileBinary(string.concat(TESTDATA_DIR, "ak_public_key_20260117_094825.bin"));
        expectedExtraData = vm.readFileBinary(string.concat(TESTDATA_DIR, "qualifying_data_20260117_094825.bin"));
    }

    function _buildAkPub() internal view returns (CertPubkey memory) {
        return CertPubkey({
            algo: 0x0023, // TPM_ALG_ECC
            params: 0x0003, // TPM_ECC_NIST_P256
            data: akPubkeyData
        });
    }

    function test_verifyTpmKeyCertification_succeeds() public view {
        // Construct akPub CertPubkey struct
        CertPubkey memory akPub = _buildAkPub();

        // Required attributes: fixedTPM (bit 1), fixedParent (bit 4), sensitiveDataOrigin (bit 5), sign (bit 18)
        // Binary: 0b0100_0000_0000_0011_0010 = 0x40032
        uint32 requiredAttributes = 0x40032;

        // Call verifyTpmKeyCertification
        CertPubkey memory certifiedPubkey = tpmAttestation.verifyTpmKeyCertification(
            certifyInfo, akSignature, tpmtPublic, akPub, expectedExtraData, requiredAttributes
        );

        // Assertions - verify the certified key was extracted
        assertEq(certifiedPubkey.algo, 0x0023, "Certified key should be ECC");
        assertEq(certifiedPubkey.params, 0x0003, "Certified key should be P-256");
        assertTrue(certifiedPubkey.data.length > 0, "Certified key data should not be empty");
        assertEq(certifiedPubkey.data.length, 65, "Uncompressed P-256 public key should be 65 bytes");
    }

    function test_verifyTpmKeyCertification_invalidSignature_reverts() public {
        // Tamper with signature (flip a byte in middle of r component)
        bytes memory badSig = akSignature;
        badSig[10] ^= 0xff;

        vm.expectRevert(TpmSignatureVerificationFailed.selector);
        tpmAttestation.verifyTpmKeyCertification(certifyInfo, badSig, tpmtPublic, _buildAkPub(), expectedExtraData, 0);
    }

    function test_verifyTpmKeyCertification_wrongExtraData_reverts() public {
        // Provide mismatched extraData
        bytes memory wrongExtra = hex"deadbeef";

        vm.expectRevert(ExtraDataMismatch.selector);
        tpmAttestation.verifyTpmKeyCertification(certifyInfo, akSignature, tpmtPublic, _buildAkPub(), wrongExtra, 0);
    }

    function test_verifyTpmKeyCertification_tamperedCertifyInfo_reverts() public {
        // Tamper with certifyInfo (changes hash, breaks signature)
        bytes memory badCertifyInfo = certifyInfo;
        badCertifyInfo[50] ^= 0xff;

        vm.expectRevert(TpmSignatureVerificationFailed.selector);
        tpmAttestation.verifyTpmKeyCertification(
            badCertifyInfo, akSignature, tpmtPublic, _buildAkPub(), expectedExtraData, 0
        );
    }

    function test_verifyTpmKeyCertification_wrongTpmtPublic_reverts() public {
        // Modify tpmtPublic to create name mismatch
        bytes memory wrongPublic = tpmtPublic;
        wrongPublic[50] ^= 0xff; // Change a byte in the key data

        vm.expectRevert(CertifiedNameMismatch.selector);
        tpmAttestation.verifyTpmKeyCertification(
            certifyInfo, akSignature, wrongPublic, _buildAkPub(), expectedExtraData, 0
        );
    }

    function test_verifyTpmKeyCertification_emptyExtraData_skipsValidation() public view {
        // Empty extraData should skip validation (not revert)
        bytes memory emptyExtra = "";

        // Should succeed because extraData validation is optional
        CertPubkey memory certifiedPubkey = tpmAttestation.verifyTpmKeyCertification(
            certifyInfo, akSignature, tpmtPublic, _buildAkPub(), emptyExtra, 0
        );

        // Verify it still returns valid data
        assertEq(certifiedPubkey.algo, 0x0023, "Should still extract certified key");
        assertTrue(certifiedPubkey.data.length > 0, "Certified key data should not be empty");
    }
}
