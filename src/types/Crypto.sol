// SPDX-License-Identifier: MIT
// Automata Contracts
pragma solidity ^0.8.15;

import "./Constants.sol";
import "./Errors.sol";
import {Asn1Decode} from "../lib/Asn1Decode.sol";
import {LibBytes} from "../lib/LibBytes.sol";

import {RSA} from "@openzeppelin/contracts/utils/cryptography/RSA.sol";

struct Pubkey {
    uint16 sigScheme;
    uint16 curve;
    uint16 hashAlgo;
    bytes data;
}

using Crypto for Pubkey global;
using RSALib for Pubkey global;
using P256Lib for Pubkey global;

library Crypto {
    function empty(Pubkey memory pubkey) internal pure returns (bool) {
        return pubkey.data.length == 0;
    }

    /// @dev pass the external verifier address if needed, otherwise the signature
    /// can be verified with the public key directly
    function verifySignature(Pubkey memory key, bytes memory message, bytes memory signature, address externalVerifier)
        internal
        view
        returns (bool)
    {
        // Define the digest
        bytes32 digest;
        if (key.hashAlgo == TPM_ALG_SHA256) {
            digest = sha256(message);
        } else {
            revert UnsupportedHashAlgorithm();
        }

        // Decode the public key based on the signature scheme
        if (key.sigScheme == TPM_ALG_RSASSA) {
            (bytes memory n, bytes memory e) = RSALib.parseRsaDer(key.data);
            return RSA.pkcs1Sha256(digest, signature, e, n);
        } else if (key.sigScheme == TPM_ALG_ECDSA) {
            if (key.curve == TPM_ECC_NIST_P256) {
                (bytes32 r, bytes32 s) = P256Lib.parseSignature(signature);
                (bytes32 x, bytes32 y) = key.ec();
                return P256Lib.ecdsaVerify(externalVerifier, digest, r, s, x, y);
            } else {
                revert UnknownPublicKeyAlgorithm();
            }
        } else {
            revert UnknownPublicKeyAlgorithm();
        }
    }
}

library RSALib {
    using Asn1Decode for bytes;
    using LibBytes for bytes;

    function newRsaPubkey(bytes memory e, bytes memory n) internal pure returns (Pubkey memory) {
        // RSAPublicKey ::= SEQ { n, e }
        uint256 nLength = n[0] < 0x80 ? n.length : n.length + 1;
        uint256 eLength = e[0] < 0x80 ? e.length : e.length + 1;
        require(nLength > 0x80 && nLength < 65565 && eLength < 0x80, "invalid e or n");

        bytes memory der = abi.encodePacked(uint8(0x30), uint8(0x82), uint16(4 + nLength + 2 + eLength));
        if (n[0] >= 0x80) {
            der = abi.encodePacked(der, uint16(0x0282), uint16(nLength), uint8(0x0), n);
        } else {
            der = abi.encodePacked(der, uint16(0x0282), uint16(nLength), n);
        }
        if (e[0] >= 0x80) {
            der = abi.encodePacked(der, uint8(0x02), uint8(eLength), uint8(0x0), e);
        } else {
            der = abi.encodePacked(der, uint8(0x02), uint8(eLength), e);
        }

        return Pubkey({sigScheme: TPM_ALG_RSASSA, curve: 0, hashAlgo: TPM_ALG_SHA256, data: der});
    }

    function parseRsaDer(bytes memory der) internal pure returns (bytes memory n, bytes memory e) {
        uint256 root = der.root();
        uint256 parentPtr = der.firstChildOf(root);
        uint256 next = der.nextSiblingOf(parentPtr);
        n = der.bytesAt(parentPtr);

        // trim prefix 0
        for (uint256 i = 0; i < n.length; i++) {
            if (n[i] != 0x00) {
                if (i > 0) {
                    n = n.slice(i, n.length - i);
                }
                break;
            }
        }
        e = der.bytesAt(next);
        if (n.length < 256) {
            revert RsaKeyModulusTooSmall();
        }
    }
}

library P256Lib {
    /// @dev pubkey data does not contain the 0x04 prefix
    /// @dev P256 Pubkey currently does not support compressed format
    function ec(Pubkey memory pubkey) internal pure returns (bytes32 x, bytes32 y) {
        if (pubkey.sigScheme == TPM_ALG_ECDSA && pubkey.curve == TPM_ECC_NIST_P256) {
            if (pubkey.data.length != 64) {
                revert InvalidP256PublicKeyLength();
            }
            bytes memory data = pubkey.data;
            assembly {
                x := mload(add(data, 0x20))
                y := mload(add(data, 0x40))
            }
        } else {
            revert NotAP256ECPublicKey();
        }
    }

    function parseSignature(bytes memory signature) internal pure returns (bytes32 r, bytes32 s) {
        if (signature.length != 64) {
            revert InvalidEcdsaSignature();
        }
        assembly {
            let offset := add(signature, 0x20) // length
            r := mload(offset)
            offset := add(offset, 0x20)
            s := mload(offset)
        }
    }

    function ecdsaVerify(address verifier, bytes32 digest, bytes32 r, bytes32 s, bytes32 x, bytes32 y)
        internal
        view
        returns (bool verified)
    {
        // Call the P256 library to verify the ECDSA signature
        bytes memory args = abi.encode(digest, r, s, x, y);
        (bool success, bytes memory ret) = verifier.staticcall(args);
        assert(success); // never reverts, always returns 0 or 1
        verified = abi.decode(ret, (uint256)) == 1;
    }
}
