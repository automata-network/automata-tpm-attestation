// SPDX-License-Identifier: MIT
// Automata Contracts
pragma solidity ^0.8.15;

import {Asn1Decode, NodePtr} from "./Asn1Decode.sol";
import {LibBytes} from "./LibBytes.sol";
import {DateTimeLib} from "@solady/utils/DateTimeLib.sol";

import {Pubkey} from "../types/Crypto.sol";
import "../types/Constants.sol";

library LibX509 {
    using Asn1Decode for bytes;
    using NodePtr for uint256;
    using LibBytes for bytes;

    function getCertTbs(bytes memory der) internal pure returns (bytes memory) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        return der.allBytesAt(tbsParentPtr);
    }

    function getCertSignature(bytes memory der) internal pure returns (bytes memory) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root); // tbs
        uint256 sigPtr = der.nextSiblingOf(tbsParentPtr); // sig algo
        sigPtr = der.nextSiblingOf(sigPtr); // sig
        return der.bitstringAt(sigPtr);
    }

    function getCertValidity(bytes memory der)
        internal
        pure
        returns (uint256 validityNotBefore, uint256 validityNotAfter)
    {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        uint256 tbsPtr = der.firstChildOf(tbsParentPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        (validityNotBefore, validityNotAfter) = _getValidity(der, tbsPtr);
    }

    function getPubkey(bytes calldata der) internal pure returns (Pubkey memory) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        uint256 tbsPtr = der.firstChildOf(tbsParentPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        Pubkey memory subjectPublicKey = _getSubjectPublicKey(der, der.firstChildOf(tbsPtr));
        return subjectPublicKey;
    }

    function getCertHashes(bytes[] memory certs) internal pure returns (bytes32[] memory certHashes) {
        uint256 certLen = certs.length;
        certHashes = new bytes32[](certLen);
        unchecked {
            for (uint256 i = certLen - 1; i >= 0; i--) {
                if (i == certLen - 1) {
                    certHashes[i] = keccak256(certs[i]);
                } else {
                    certHashes[i] = keccak256(abi.encodePacked(certHashes[i + 1], sha256(certs[i])));
                }

                if (i == 0) {
                    break; // Prevent underflow
                }
            }
        }
    }

    function fromDERToTimestamp(bytes memory x509Time) internal pure returns (uint256) {
        uint16 yrs;
        uint8 mnths;
        uint8 dys;
        uint8 hrs;
        uint8 mins;
        uint8 secs;
        uint8 offset;

        if (x509Time.length == 13) {
            if (uint8(x509Time[0]) - 48 < 5) yrs += 2000;
            else yrs += 1900;
        } else {
            yrs += (uint8(x509Time[0]) - 48) * 1000 + (uint8(x509Time[1]) - 48) * 100;
            offset = 2;
        }
        yrs += (uint8(x509Time[offset + 0]) - 48) * 10 + uint8(x509Time[offset + 1]) - 48;
        mnths = (uint8(x509Time[offset + 2]) - 48) * 10 + uint8(x509Time[offset + 3]) - 48;
        dys += (uint8(x509Time[offset + 4]) - 48) * 10 + uint8(x509Time[offset + 5]) - 48;
        hrs += (uint8(x509Time[offset + 6]) - 48) * 10 + uint8(x509Time[offset + 7]) - 48;
        mins += (uint8(x509Time[offset + 8]) - 48) * 10 + uint8(x509Time[offset + 9]) - 48;
        secs += (uint8(x509Time[offset + 10]) - 48) * 10 + uint8(x509Time[offset + 11]) - 48;

        return DateTimeLib.dateTimeToTimestamp(yrs, mnths, dys, hrs, mins, secs);
    }

    function _getSubjectPublicKey(bytes memory der, uint256 subjectPublicKeyInfoPtr)
        private
        pure
        returns (Pubkey memory pubkey)
    {
        bytes memory key = der.bytesAt(subjectPublicKeyInfoPtr);
        (bytes memory oid,) = _getOid(key);
        if (oid.equal(hex"2a864886f70d010101")) {
            pubkey.sigScheme = TPM_ALG_RSA;
            pubkey.curve = 0;
            pubkey.hashAlgo = TPM_ALG_SHA256;
        } else if (oid.equal(hex"2a8648ce3d0201")) {
            pubkey.sigScheme = TPM_ALG_ECDSA;
            pubkey.curve = TPM_ECC_NIST_P256;
            pubkey.hashAlgo = TPM_ALG_SHA256;
        } else {
            revert("unknown pubkey algo");
        }

        subjectPublicKeyInfoPtr = der.nextSiblingOf(subjectPublicKeyInfoPtr);
        pubkey.data = der.bitstringAt(subjectPublicKeyInfoPtr);
        if (pubkey.sigScheme == TPM_ALG_ECDSA && pubkey.curve == TPM_ECC_NIST_P256) {
            if (pubkey.data.length != 65 || pubkey.data[0] != 0x04) {
                revert("compressed public key not supported");
            }
        }
    }

    function _getValidity(bytes memory der, uint256 validityPtr)
        private
        pure
        returns (uint256 notBefore, uint256 notAfter)
    {
        uint256 notBeforePtr = der.firstChildOf(validityPtr);
        uint256 notAfterPtr = der.nextSiblingOf(notBeforePtr);
        notBefore = fromDERToTimestamp(der.bytesAt(notBeforePtr));
        notAfter = fromDERToTimestamp(der.bytesAt(notAfterPtr));
    }

    function _decodeSequence(bytes memory value) private pure returns (bytes memory) {
        require(value[0] == 0x30, "Not a sequence");
        if (value[1] == 0x80) {
            require(false, "Not supported");
        }
        return value.slice(2, uint256(uint8(value[1])));
    }

    function _getOid(bytes memory value) private pure returns (bytes memory, uint256) {
        require(value[0] == 0x06, "Not a OID");
        uint256 oidLen = uint256(uint8(value[1]));
        return (value.slice(2, oidLen), oidLen + 2);
    }
}
