// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;
import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {TpmAttestation} from "src/TpmAttestation.sol";
import {LibX509, CertPubkey} from "src/lib/LibX509.sol";
import {LibX509Verify} from "src/lib/LibX509Verify.sol";
import {
    RootCaNotAtEndOfChain,
    InvalidSignature,
    CertificateAlreadyRevoked,
    CertificateExpired,
    CRLSignNotSet,
    CRLSignatureVerificationFailed,
    CRLIssuerMismatch,
    CRLNotYetValid,
    CRLExpired,
    CRLRollbackAttempt,
    CRLRequiredInStrictMode,
    CRLExpiredInStrictMode,
    LeafCertIsCa,
    PathLenConstraintViolated,
    DeltaCRLNotSupported,
    PartitionedCRLNotSupported,
    InvalidCertChainLength
} from "src/types/Errors.sol";

contract CRLAuthenticationTest is Test {
    using stdJson for string;
    TpmAttestation internal registry;
    string internal fixtures;
    uint256 internal constant NOW = 1790251200; // 2026-09-24 12:00 UTC

    function setUp() public {
        fixtures = vm.readFile("test/testdata/crl-authentication.json");
        vm.warp(NOW);
        registry = new TpmAttestation(address(this), LibX509Verify.P256_VERIFIER);
        registry.addCA(fixture("root"));
    }

    function fixture(string memory name) internal view returns (bytes memory) {
        return fixtures.readBytes(string.concat(".", name));
    }

    function chain(string memory target, string memory issuer) internal view returns (bytes[] memory certs) {
        certs = new bytes[](2);
        certs[0] = fixture(target);
        certs[1] = fixture(issuer);
    }

    function rootChain(string memory name) internal view returns (bytes[] memory certs) {
        certs = new bytes[](1);
        certs[0] = fixture(name);
    }

    function leafChain() internal view returns (bytes[] memory certs) {
        certs = new bytes[](3);
        certs[0] = fixture("intermediate_leaf");
        certs[1] = fixture("intermediate");
        certs[2] = fixture("root");
    }

    function issuerHash(bytes calldata cert) external pure returns (bytes32) {
        CertPubkey memory key = LibX509.getPubkey(cert);
        return keccak256(
            abi.encode("automata.tpm.crl.issuer.v1", LibX509.getCertSubjectDN(cert), key.algo, key.params, key.data)
        );
    }

    function test_genericVerifierAcceptsEndEntityCAAndRootTargets() public {
        assertGt(registry.verifyCertChain(chain("leaf", "root")).data.length, 0);
        assertGt(registry.verifyCertChain(chain("intermediate", "root")).data.length, 0);
        assertGt(registry.verifyCertChain(rootChain("root")).data.length, 0);
        registry.verifyCertChain(leafChain());
    }

    function test_runtimeFitsDeploymentLimit() public view {
        assertLe(address(registry).code.length, 24576);
    }

    function test_emptyChainRejected() public {
        vm.expectRevert(InvalidCertChainLength.selector);
        registry.verifyCertChain(new bytes[](0));
    }

    function test_tpmQuoteRejectsCATarget() public {
        bytes[] memory certs = chain("intermediate", "root");
        vm.expectRevert(LeafCertIsCa.selector);
        registry.verifyTpmQuote(hex"", hex"", certs);
    }

    function testFuzz_untrustedCopiedMetadataCannotPoisonRevocations(bool strict) public {
        bytes[] memory certs = chain("leaf", "root");
        bytes[] memory forgedChain = rootChain("attacker");
        bytes memory forgedCRL = fixture("attacker_revoked");
        registry.updateCRL(fixture("root_empty"), rootChain("root"));
        registry.setStrictCRLMode(strict);
        bytes32 id = this.issuerHash(fixture("root"));
        (bytes32 beforeHash, uint256 beforeThis, uint256 beforeNext) = registry.crlCache(id);
        vm.recordLogs();
        vm.prank(address(0xBEEF));
        vm.expectRevert(RootCaNotAtEndOfChain.selector);
        registry.updateCRL(forgedCRL, forgedChain);
        assertEq(vm.getRecordedLogs().length, 0);
        (bytes32 afterHash, uint256 afterThis, uint256 afterNext) = registry.crlCache(id);
        assertEq(beforeHash, afterHash);
        assertEq(beforeThis, afterThis);
        assertEq(beforeNext, afterNext);
        assertFalse(registry.revokedCertificates(id, 100));
        assertFalse(registry.isCertificateRevoked(certs));
        registry.verifyCertChain(certs);
    }

    function test_trustedDifferentKeyWithSameMetadataCannotPoisonAnotherIssuer() public {
        registry.addCA(fixture("attacker"));
        registry.updateCRL(fixture("attacker_revoked"), rootChain("attacker"));
        bytes32 fakeId = this.issuerHash(fixture("attacker"));
        bytes32 realId = this.issuerHash(fixture("root"));
        assertNotEq(fakeId, realId);
        assertTrue(registry.revokedCertificates(fakeId, 100));
        bytes[] memory certs = chain("leaf", "root");
        assertFalse(registry.isCertificateRevoked(certs));
        registry.verifyCertChain(certs);
        registry.setStrictCRLMode(true);
        vm.expectRevert(CRLRequiredInStrictMode.selector);
        registry.verifyCertChain(certs);
    }

    function test_copiedMetadataCannotAuthenticateWrongIssuerKey() public {
        registry.addCA(fixture("attacker"));
        bytes[] memory certs = chain("intermediate", "attacker");
        bytes memory crl = fixture("intermediate_empty");
        vm.expectRevert(InvalidSignature.selector);
        registry.updateCRL(crl, certs);
        certs = chain("leaf", "attacker");
        vm.expectRevert(InvalidSignature.selector);
        registry.isCertificateRevoked(certs);
    }

    function test_nonOwnerCanRelayRootAndIntermediateCRLs() public {
        bytes memory crl = fixture("root_empty");
        bytes[] memory certs = rootChain("root");
        vm.prank(address(0xBEEF));
        registry.updateCRL(crl, certs);
        crl = fixture("intermediate_revoked");
        certs = chain("intermediate", "root");
        vm.prank(address(0xBEEF));
        registry.updateCRL(crl, certs);
        assertTrue(registry.isCertificateRevoked(leafChain()));
    }

    function test_rootWithoutCRLSignRejected() public {
        registry.addCA(fixture("root_no_crlsign"));
        bytes memory crl = fixture("root_empty");
        bytes[] memory certs = rootChain("root_no_crlsign");
        vm.expectRevert(CRLSignNotSet.selector);
        registry.updateCRL(crl, certs);
    }

    function test_intermediateWithoutCRLSignRejected() public {
        bytes memory crl = fixture("intermediate_empty");
        bytes[] memory certs = chain("intermediate_no_crlsign", "root");
        vm.expectRevert(CRLSignNotSet.selector);
        registry.updateCRL(crl, certs);
    }

    function test_badCRLSignatureRejected() public {
        bytes memory crl = fixture("root_empty");
        crl[crl.length - 1] ^= 0x01;
        bytes[] memory certs = rootChain("root");
        vm.expectRevert(CRLSignatureVerificationFailed.selector);
        registry.updateCRL(crl, certs);
    }

    function test_wrongCRLIssuerRejected() public {
        bytes memory crl = fixture("intermediate_empty");
        bytes[] memory certs = rootChain("root");
        vm.expectRevert(CRLIssuerMismatch.selector);
        registry.updateCRL(crl, certs);
    }

    function test_expiredSignerRejectedDespiteCachedPath() public {
        bytes[] memory certs = leafChain();
        certs[1] = fixture("intermediate_expired");
        vm.warp(NOW - 3 days);
        registry.verifyCertChain(certs);
        vm.warp(NOW);
        vm.expectRevert(CertificateExpired.selector);
        registry.verifyCertChain(certs);
        bytes memory crl = fixture("intermediate_empty");
        certs = chain("intermediate_expired", "root");
        vm.expectRevert(CertificateExpired.selector);
        registry.updateCRL(crl, certs);
    }

    function test_revokedIntermediateRejectedDespiteCachedPath() public {
        bytes[] memory certs = leafChain();
        registry.verifyCertChain(certs);
        registry.updateCRL(fixture("root_revoke_intermediate"), rootChain("root"));
        bytes memory crl = fixture("intermediate_empty");
        bytes[] memory issuers = chain("intermediate", "root");
        vm.expectRevert(CertificateAlreadyRevoked.selector);
        registry.updateCRL(crl, issuers);
        vm.expectRevert(CertificateAlreadyRevoked.selector);
        registry.verifyCertChain(certs);
        vm.expectRevert(CertificateAlreadyRevoked.selector);
        registry.isCertificateRevoked(certs);
    }

    function test_removedRootRejectedDespiteCachedPath() public {
        bytes[] memory certs = leafChain();
        registry.verifyCertChain(certs);
        registry.removeCA(fixture("root"));
        bytes memory crl = fixture("intermediate_empty");
        bytes[] memory issuers = chain("intermediate", "root");
        vm.expectRevert(RootCaNotAtEndOfChain.selector);
        registry.updateCRL(crl, issuers);
        vm.expectRevert(RootCaNotAtEndOfChain.selector);
        registry.verifyCertChain(certs);
    }

    function test_sameKeyCertificateReissueRetainsRevocations() public {
        registry.addCA(fixture("root_reissued"));
        registry.updateCRL(fixture("root_revoked"), rootChain("root"));
        assertEq(this.issuerHash(fixture("root")), this.issuerHash(fixture("root_reissued")));
        bytes[] memory certs = chain("leaf", "root_reissued");
        assertTrue(registry.isCertificateRevoked(certs));
        vm.expectRevert(CertificateAlreadyRevoked.selector);
        registry.verifyCertChain(certs);
    }

    function test_strictModeBootstrapsAndRefreshesAncestorsFirst() public {
        registry.setStrictCRLMode(true);
        bytes[] memory issuers = chain("intermediate", "root");
        bytes memory initial = fixture("intermediate_empty");
        vm.expectRevert(CRLRequiredInStrictMode.selector);
        registry.updateCRL(initial, issuers);
        registry.updateCRL(fixture("root_empty"), rootChain("root"));
        registry.updateCRL(initial, issuers);
        bytes[] memory certs = leafChain();
        registry.verifyCertChain(certs);
        vm.warp(NOW + 3 days);
        vm.expectRevert(CRLExpiredInStrictMode.selector);
        registry.verifyCertChain(certs);
        bytes memory refresh = fixture("intermediate_refresh");
        vm.expectRevert(CRLExpiredInStrictMode.selector);
        registry.updateCRL(refresh, issuers);
        registry.updateCRL(fixture("root_refresh"), rootChain("root"));
        registry.updateCRL(refresh, issuers);
        registry.verifyCertChain(certs);
    }

    function testFuzz_genuineRevocationEnforcedInBothModes(bool strict) public {
        registry.updateCRL(fixture("root_revoked"), rootChain("root"));
        registry.setStrictCRLMode(strict);
        bytes[] memory certs = chain("leaf", "root");
        assertTrue(registry.isCertificateRevoked(certs));
        vm.expectRevert(CertificateAlreadyRevoked.selector);
        registry.verifyCertChain(certs);
        vm.warp(NOW + 3 days);
        registry.updateCRL(fixture("root_refresh"), rootChain("root"));
        assertTrue(registry.isCertificateRevoked(certs), "later empty CRL must not erase revocations");
    }

    function test_crlTimeAndRollbackChecksRemainEnforced() public {
        bytes[] memory certs = rootChain("root");
        bytes memory future = fixture("root_future");
        vm.expectRevert(CRLNotYetValid.selector);
        registry.updateCRL(future, certs);
        registry.updateCRL(fixture("root_revoked"), certs);
        bytes memory old = fixture("root_empty");
        vm.expectRevert(CRLRollbackAttempt.selector);
        registry.updateCRL(old, certs);
        vm.warp(NOW + 3 days);
        vm.expectRevert(CRLExpired.selector);
        registry.updateCRL(old, certs);
    }

    function test_unsupportedCRLFormatsRemainRejected() public {
        bytes[] memory certs = rootChain("root");
        bytes memory delta = fixture("root_delta");
        vm.expectRevert(DeltaCRLNotSupported.selector);
        registry.updateCRL(delta, certs);
        bytes memory partitioned = fixture("root_partitioned");
        vm.expectRevert(PartitionedCRLNotSupported.selector);
        registry.updateCRL(partitioned, certs);
    }

    function test_CAPathLengthExcludesTargetButIncludesIntermediates() public {
        registry.addCA(fixture("root_short"));
        registry.verifyCertChain(chain("intermediate", "root_short"));
        bytes[] memory certs = leafChain();
        certs[2] = fixture("root_short");
        vm.expectRevert(PathLenConstraintViolated.selector);
        registry.verifyCertChain(certs);
        certs[0] = fixture("second_intermediate");
        vm.expectRevert(PathLenConstraintViolated.selector);
        registry.verifyCertChain(certs);
    }
}
