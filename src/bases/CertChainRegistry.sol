// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {RSA} from "@openzeppelin/contracts/utils/cryptography/RSA.sol";

import {ICertChainRegistry} from "../interfaces/ICertChainRegistry.sol";
import {LibX509} from "../lib/LibX509.sol";
import {Pubkey} from "../types/Crypto.sol";
import {TPM_ALG_RSASSA, TPM_ALG_ECDSA} from "../types/Constants.sol";
import "../types/Errors.sol";

abstract contract CertChainRegistry is ICertChainRegistry, Ownable {
    using LibX509 for bytes;

    enum CertType {
        None, // 0
        CA, // 1
        Intermediate // 2
    }

    address public immutable override p256;

    // keccak256(cert) => type: 0) none, 1) CA; 2) Intermediate
    mapping(bytes32 => CertType) public verifiedCertIssuers;
    mapping(bytes32 => Pubkey) public verifiedLeafKeys;

    constructor(address _intialOwner, address _p256) Ownable(_intialOwner) {
        p256 = _p256;
    }

    function addCA(bytes calldata ca) public override onlyOwner {
        bytes32 key = keccak256(ca);
        (, uint256 validityNotAfter) = LibX509.getCertValidity(ca);
        if (block.timestamp > validityNotAfter) {
            revert CertificateExpired();
        }
        Pubkey memory issuer = LibX509.getPubkey(ca);
        address verifier = issuer.sigScheme == TPM_ALG_ECDSA ? p256 : address(0);
        bool result = issuer.verifySignature(ca.getCertTbs(), ca.getCertSignature(), verifier);
        if (!result) {
            revert InvalidSignature();
        }
        verifiedCertIssuers[key] = CertType.CA;
        emit AddCA(ca);
    }

    function removeCA(bytes calldata ca) public override onlyOwner {
        bytes32 key = keccak256(ca);
        if (verifiedCertIssuers[key] != CertType.CA) {
            revert CertNotCa();
        }
        delete verifiedCertIssuers[key];
        emit RemoveCA(ca);
    }

    // certs order: leaf, intermediate(s), root
    function verifyCertChain(bytes[] calldata certs) public override returns (Pubkey memory) {
        uint256 certLen = certs.length;
        if (certLen == 0 || certLen >= 5) {
            revert InvalidCertChainLength();
        }

        // iterate through intermediate to check whether it has been cached
        uint256 trustedIndex = 0;
        bytes32[] memory intermediateHashes = new bytes32[](certLen - 2);
        for (uint256 i = 1; i < certLen - 1; i++) {
            bytes32 certHash = keccak256(certs[i]);
            if (verifiedCertIssuers[certHash] == CertType.Intermediate && trustedIndex == 0) {
                trustedIndex = i;
                break;
            }
            intermediateHashes[i - 1] = certHash;
        }

        // check whether RootCA has been added by contract owner
        bytes32 rootCertHash = keccak256(certs[certLen - 1]);
        if (verifiedCertIssuers[rootCertHash] != CertType.CA) {
            revert RootCaNotVerified();
        }
        if (trustedIndex == 0) {
            trustedIndex = certLen - 1;
        }

        Pubkey[] memory issuers = new Pubkey[](certLen);
        for (uint256 i = 0; i < certLen; i++) {
            issuers[i] = LibX509.getPubkey(certs[i]);
        }

        for (uint256 i = 0; i < certLen; i++) {
            // Check validity for all certs
            (uint256 validityNotBefore, uint256 validityNotAfter) = LibX509.getCertValidity(certs[i]);
            if (block.timestamp < validityNotBefore) {
                revert CertificateNotYetValid();
            }
            if (block.timestamp > validityNotAfter) {
                revert CertificateExpired();
            }

            // Performs signature verification up until the trusted index
            if (i < trustedIndex) {
                bytes memory sig = LibX509.getCertSignature(certs[i]);
                address verifier = issuers[i + 1].sigScheme == TPM_ALG_ECDSA ? p256 : address(0);
                bool result = issuers[i + 1].verifySignature(LibX509.getCertTbs(certs[i]), sig, verifier);
                if (!result) {
                    revert InvalidSignature();
                }
            }
        }

        // cache the intermediate CAs
        for (uint256 i = 0; i < intermediateHashes.length; i++) {
            bytes32 hash = intermediateHashes[i];
            if (hash != bytes32(0)) {
                verifiedCertIssuers[hash] = CertType.Intermediate;
            }
        }

        // cache the leaf key
        verifiedLeafKeys[keccak256(certs[0])] = issuers[0];
        return issuers[0];
    }
}
