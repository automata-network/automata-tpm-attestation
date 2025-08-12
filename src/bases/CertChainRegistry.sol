// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {RSA} from "@openzeppelin/contracts/utils/cryptography/RSA.sol";

import {ICertChainRegistry} from "../interfaces/ICertChainRegistry.sol";
import {LibX509} from "../lib/LibX509.sol";
import {Pubkey} from "../types/Crypto.sol";
import {TPM_ALG_RSASSA, TPM_ALG_ECDSA} from "../types/Constants.sol";

abstract contract CertChainRegistry is ICertChainRegistry, Ownable {
    using LibX509 for bytes;

    enum CertType {
        None, // 0
        CA, // 1
        Intermediate // 2

    }

    address public immutable p256;

    // keccak256(cert) => type: 0) none, 1) CA; 2) leaf
    mapping(bytes32 => CertType) public verifiedCertIssuers;

    constructor(address _intialOwner, address _p256) Ownable(_intialOwner) {
        p256 = _p256;
    }

    function addCA(bytes calldata ca) public override onlyOwner {
        bytes32 key = keccak256(ca);
        (, uint256 validityNotAfter) = LibX509.getCertValidity(ca);
        if (block.timestamp > validityNotAfter) {
            revert("cert expired");
        }
        Pubkey memory issuer = LibX509.getPubkey(ca);
        address verifier = issuer.sigScheme == TPM_ALG_ECDSA ? p256 : address(0);
        bool result = issuer.verifySignature(ca.getCertTbs(), ca.getCertSignature(), verifier);
        require(result, "verify sig failed");
        verifiedCertIssuers[key] = CertType.CA;
        emit AddCA(ca);
    }

    function removeCA(bytes calldata ca) public override onlyOwner {
        bytes32 key = keccak256(ca);
        require(verifiedCertIssuers[key] == CertType.CA, "CA not found");
        delete verifiedCertIssuers[key];
        emit RemoveCA(ca);
    }

    // certs order: leaf, intermediate, root
    function verifyCertChain(bytes[] calldata certs) public override returns (Pubkey memory) {
        require(certs.length > 0, "CertChainRegistry: empty certs");
        Pubkey[] memory issuers = new Pubkey[](certs.length);
        bytes32[] memory certHashes = LibX509.getCertHashes(certs);
        require(certs.length < 5, "CertChainRegistry: too many certs");
        uint256 verified = type(uint256).max;
        uint256 certLen = certs.length;
        uint256 validityNotBefore;
        uint256 validityNotAfter;

        // check verified
        for (uint256 i = 0; i < certLen; i++) {
            issuers[i] = LibX509.getPubkey(certs[i]);
            CertType cachedCertType = verifiedCertIssuers[certHashes[i]];
            if (i == certLen - 1 && cachedCertType == CertType.CA) {
                verified = i;
                break;
            } else if (i < certLen - 1 && cachedCertType == CertType.Intermediate) {
                verified = i;
                break;
            }
        }

        if (verified == type(uint256).max) {
            revert("CertChainRegistry: no CA found");
        }

        // check validity of leaf cert
        (validityNotBefore, validityNotAfter) = LibX509.getCertValidity(certs[0]);
        if (validityNotBefore > block.timestamp || validityNotAfter < block.timestamp) {
            revert("cert not valid yet");
        }

        for (uint256 i = 0; i < verified; i++) {
            bytes memory sig = LibX509.getCertSignature(certs[i]);
            address verifier = issuers[i + 1].sigScheme == TPM_ALG_ECDSA ? p256 : address(0);
            bool result = issuers[i + 1].verifySignature(LibX509.getCertTbs(certs[i]), sig, verifier);
            require(result, "verify sig failed");
        }

        // cache result
        for (uint256 i = 0; i < verified; i++) {
            verifiedCertIssuers[certHashes[i]] = CertType.Intermediate;
        }
        return issuers[0];
    }
}
