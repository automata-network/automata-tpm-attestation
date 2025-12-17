// SPDX-License-Identifier: MIT
// Original source: https://github.com/JonahGroendal/asn1-decode
pragma solidity ^0.8.0;

// Inspired by PufferFinance/rave
// https://github.com/JonahGroendal/asn1-decode/blob/5c2d1469fc678513753786acb441e597969192ec/contracts/Asn1Decode.sol

import {BytesUtils} from "./BytesUtils.sol";
import {
    Asn1NotBitString,
    Asn1NotOctetString,
    Asn1NotConstructedType,
    Asn1NotInteger,
    Asn1NotPositiveInteger,
    Asn1BitStringNotZeroPadded,
    Asn1IndexOutOfBounds,
    Asn1LengthCannotBeZero,
    Asn1InvalidLengthBytes,
    Asn1ContentLengthOutOfBounds
} from "../types/Errors.sol";

/// @title NodePtr
/// @notice A library for encoding and decoding ASN.1 DER node pointers
/// @dev A node pointer is a uint256 that packs three uint80 values representing:
///      - ixs: Index of the first byte of the node (tag byte)
///      - ixf: Index of the first content byte (after tag and length bytes)
///      - ixl: Index of the last content byte
///
///      Memory layout (256 bits total):
///      [bits 0-79: ixs] [bits 80-159: ixf] [bits 160-239: ixl] [bits 240-255: unused]
///
///      This encoding allows efficient storage and manipulation of ASN.1 node boundaries
///      while traversing DER-encoded structures without repeated parsing.
library NodePtr {
    /// @notice Extracts the start index (first byte of node) from a packed node pointer
    /// @param self The packed node pointer
    /// @return The index of the first byte of the ASN.1 node (the tag byte)
    function ixs(uint256 self) internal pure returns (uint256) {
        return uint80(self);
    }

    /// @notice Extracts the first content byte index from a packed node pointer
    /// @param self The packed node pointer
    /// @return The index of the first content byte (immediately after the tag and length bytes)
    function ixf(uint256 self) internal pure returns (uint256) {
        return uint80(self >> 80);
    }

    /// @notice Extracts the last content byte index from a packed node pointer
    /// @param self The packed node pointer
    /// @return The index of the last content byte of the ASN.1 node
    function ixl(uint256 self) internal pure returns (uint256) {
        return uint80(self >> 160);
    }

    /// @notice Packs three indices into a single uint256 node pointer
    /// @param _ixs Index of the first byte of the node (tag byte)
    /// @param _ixf Index of the first content byte
    /// @param _ixl Index of the last content byte
    /// @return The packed node pointer containing all three indices
    function getPtr(uint256 _ixs, uint256 _ixf, uint256 _ixl) internal pure returns (uint256) {
        _ixs |= _ixf << 80;
        _ixs |= _ixl << 160;
        return _ixs;
    }
}

/// @title Asn1Decode
/// @notice A library for decoding ASN.1 DER-encoded data structures
/// @dev This library provides functions for traversing and extracting data from ASN.1 DER
///      (Distinguished Encoding Rules) encoded byte arrays, commonly used in X.509 certificates.
///
/// @dev TPM/TCG ATTESTATION PROFILE RESTRICTION:
///      This decoder rejects zero-length ASN.1 nodes (i.e., nodes where the length field is 0).
///      While standard X.509 allows zero-length fields such as NULL, empty SEQUENCE, or empty
///      OCTET STRING, TPM and TCG attestation certificate profiles never emit such fields.
///      Specifically:
///      - TPM Endorsement Key (EK) certificates always have populated fields
///      - Attestation Key (AK) certificates follow the same convention
///      - Platform certificates conform to TCG Infrastructure Working Group specifications
///
///      This restriction provides defense-in-depth against malformed certificates and simplifies
///      parsing logic, as zero-length nodes would indicate either:
///      1. A malformed certificate not conforming to TPM/TCG specifications
///      2. A potential attack attempting to exploit edge cases in parsing logic
///
///      If you need to parse general X.509 certificates that may contain zero-length fields,
///      you must modify the `readNodePtr` function to allow `length == 0`.
///
/// @custom:security-contact security@ata.network
library Asn1Decode {
    using NodePtr for uint256;
    using BytesUtils for bytes;

    /// @notice Gets the root node pointer for a DER-encoded ASN.1 structure
    /// @dev This is the first step when traversing an ASN.1 structure. The root node
    ///      represents the outermost element (typically a SEQUENCE for X.509 certificates).
    /// @param der The DER-encoded ASN.1 structure
    /// @return A node pointer to the outermost node
    function root(bytes memory der) internal pure returns (uint256) {
        return readNodePtr(der, 0);
    }

    /// @notice Gets the root node of an ASN.1 structure embedded within a BIT STRING value
    /// @dev BIT STRING in DER encoding has an initial byte indicating unused bits. This function
    ///      skips that byte to parse the embedded structure (e.g., public keys in X.509 certificates).
    /// @param der The DER-encoded ASN.1 structure
    /// @param ptr Node pointer to the BIT STRING node
    /// @return A node pointer to the root of the embedded ASN.1 structure
    function rootOfBitStringAt(bytes memory der, uint256 ptr) internal pure returns (uint256) {
        if (der[ptr.ixs()] != 0x03) revert Asn1NotBitString();
        return readNodePtr(der, ptr.ixf() + 1);
    }

    /// @notice Gets the root node of an ASN.1 structure embedded within an OCTET STRING value
    /// @dev OCTET STRING is often used to wrap other DER structures in X.509 extensions.
    /// @param der The DER-encoded ASN.1 structure
    /// @param ptr Node pointer to the OCTET STRING node
    /// @return A node pointer to the root of the embedded ASN.1 structure
    function rootOfOctetStringAt(bytes memory der, uint256 ptr) internal pure returns (uint256) {
        if (der[ptr.ixs()] != 0x04) revert Asn1NotOctetString();
        return readNodePtr(der, ptr.ixf());
    }

    /// @notice Gets the next sibling node at the same level in the ASN.1 structure
    /// @dev Moves to the node immediately following the current node's content.
    /// @param der The DER-encoded ASN.1 structure
    /// @param ptr Node pointer to the current node
    /// @return A node pointer to the next sibling node
    function nextSiblingOf(bytes memory der, uint256 ptr) internal pure returns (uint256) {
        return readNodePtr(der, ptr.ixl() + 1);
    }

    /// @notice Gets the first child node of a constructed ASN.1 type
    /// @dev Only works for constructed types (SEQUENCE, SET, or context-specific constructed tags).
    ///      Constructed types have bit 5 set in their tag byte (0x20).
    /// @param der The DER-encoded ASN.1 structure
    /// @param ptr Node pointer to the parent node (must be a constructed type)
    /// @return A node pointer to the first child node
    function firstChildOf(bytes memory der, uint256 ptr) internal pure returns (uint256) {
        if (der[ptr.ixs()] & 0x20 != 0x20) revert Asn1NotConstructedType();
        return readNodePtr(der, ptr.ixf());
    }

    /// @notice Checks if one node is contained within another node
    /// @dev Useful for validating that a node is within the expected parent structure.
    ///      Returns true if either i contains j, or j contains i.
    /// @param i Node pointer to the first ASN.1 node
    /// @param j Node pointer to the second ASN.1 node
    /// @return True if one node is a child of the other
    function isChildOf(uint256 i, uint256 j) internal pure returns (bool) {
        return (((i.ixf() <= j.ixs()) && (j.ixl() <= i.ixl())) || ((j.ixf() <= i.ixs()) && (i.ixl() <= j.ixl())));
    }

    /// @notice Extracts the content bytes of a node (excluding tag and length bytes)
    /// @param der The DER-encoded ASN.1 structure
    /// @param ptr Node pointer to the target node
    /// @return The content bytes of the node
    function bytesAt(bytes memory der, uint256 ptr) internal pure returns (bytes memory) {
        return der.substring(ptr.ixf(), ptr.ixl() + 1 - ptr.ixf());
    }

    /// @notice Extracts the entire node including tag and length bytes
    /// @param der The DER-encoded ASN.1 structure
    /// @param ptr Node pointer to the target node
    /// @return All bytes of the node (tag + length + content)
    function allBytesAt(bytes memory der, uint256 ptr) internal pure returns (bytes memory) {
        return der.substring(ptr.ixs(), ptr.ixl() + 1 - ptr.ixs());
    }

    /// @notice Extracts the content bytes of a node as a bytes32
    /// @dev Useful for extracting fixed-length values like OIDs or small integers.
    ///      Values shorter than 32 bytes are left-padded with zeros.
    /// @param der The DER-encoded ASN.1 structure
    /// @param ptr Node pointer to the target node
    /// @return The content bytes as a bytes32 value
    function bytes32At(bytes memory der, uint256 ptr) internal pure returns (bytes32) {
        return der.readBytesN(ptr.ixf(), ptr.ixl() + 1 - ptr.ixf());
    }

    /// @notice Extracts a positive integer value from an INTEGER node
    /// @dev Validates that the node is an INTEGER type and that the value is non-negative.
    ///      For values larger than uint256, use `uintBytesAt` instead.
    /// @param der The DER-encoded ASN.1 structure
    /// @param ptr Node pointer to an INTEGER node
    /// @return The integer value as uint256
    function uintAt(bytes memory der, uint256 ptr) internal pure returns (uint256) {
        if (der[ptr.ixs()] != 0x02) revert Asn1NotInteger();
        if (der[ptr.ixf()] & 0x80 != 0) revert Asn1NotPositiveInteger();
        uint256 len = ptr.ixl() + 1 - ptr.ixf();
        return uint256(der.readBytesN(ptr.ixf(), len) >> (32 - len) * 8);
    }

    /// @notice Extracts the bytes of a positive integer, stripping any leading zero padding
    /// @dev DER encoding adds a leading 0x00 byte to positive integers when the high bit is set.
    ///      This function removes that padding to return the minimal representation.
    /// @param der The DER-encoded ASN.1 structure
    /// @param ptr Node pointer to an INTEGER node
    /// @return The integer value as minimal bytes (leading zero padding removed)
    function uintBytesAt(bytes memory der, uint256 ptr) internal pure returns (bytes memory) {
        if (der[ptr.ixs()] != 0x02) revert Asn1NotInteger();
        if (der[ptr.ixf()] & 0x80 != 0) revert Asn1NotPositiveInteger();
        uint256 valueLength = ptr.ixl() + 1 - ptr.ixf();
        if (der[ptr.ixf()] == 0) {
            return der.substring(ptr.ixf() + 1, valueLength - 1);
        } else {
            return der.substring(ptr.ixf(), valueLength);
        }
    }

    /// @notice Computes the keccak256 hash of a node's content bytes
    /// @param der The DER-encoded ASN.1 structure
    /// @param ptr Node pointer to the target node
    /// @return The keccak256 hash of the node's content bytes
    function keccakOfBytesAt(bytes memory der, uint256 ptr) internal pure returns (bytes32) {
        return der.keccak(ptr.ixf(), ptr.ixl() + 1 - ptr.ixf());
    }

    /// @notice Computes the keccak256 hash of the entire node (including tag and length)
    /// @param der The DER-encoded ASN.1 structure
    /// @param ptr Node pointer to the target node
    /// @return The keccak256 hash of all node bytes
    function keccakOfAllBytesAt(bytes memory der, uint256 ptr) internal pure returns (bytes32) {
        return der.keccak(ptr.ixs(), ptr.ixl() + 1 - ptr.ixs());
    }

    /// @notice Extracts the content of a BIT STRING node as bytes
    /// @dev Only supports BIT STRINGs with zero unused bits (i.e., byte-aligned).
    ///      The first content byte indicates unused bits and must be 0x00.
    /// @param der The DER-encoded ASN.1 structure
    /// @param ptr Node pointer to a BIT STRING node
    /// @return The bit string content as bytes (excluding the unused bits indicator)
    function bitstringAt(bytes memory der, uint256 ptr) internal pure returns (bytes memory) {
        if (der[ptr.ixs()] != 0x03) revert Asn1NotBitString();
        // Only 00 padded bitstr can be converted to bytestr!
        if (der[ptr.ixf()] != 0x00) revert Asn1BitStringNotZeroPadded();
        uint256 valueLength = ptr.ixl() + 1 - ptr.ixf();
        return der.substring(ptr.ixf() + 1, valueLength - 1);
    }

    /// @notice Parses the tag and length bytes at a given position to create a node pointer
    /// @dev This is the core parsing function for DER encoding. It handles both short-form
    ///      (length < 128) and long-form (length >= 128) DER length encoding.
    ///
    /// @dev TPM-PROFILE RESTRICTION: This function enforces non-zero length for all nodes.
    ///      See the library-level documentation for details on why zero-length nodes are rejected.
    ///
    /// @param der The DER-encoded ASN.1 structure
    /// @param ix The byte index to start parsing from (should point to a tag byte)
    /// @return A packed node pointer containing start, first content, and last content indices
    function readNodePtr(bytes memory der, uint256 ix) private pure returns (uint256) {
        uint256 n = der.length;
        if (ix + 1 >= n) revert Asn1IndexOutOfBounds();
        uint256 length;
        uint80 ixFirstContentByte;
        uint80 ixLastContentByte;
        if ((der[ix + 1] & 0x80) == 0) {
            length = uint8(der[ix + 1]);
            if (length == 0) revert Asn1LengthCannotBeZero();
            ixFirstContentByte = uint80(ix + 2);
            ixLastContentByte = uint80(ixFirstContentByte + length - 1);
        } else {
            uint8 lengthbytesLength = uint8(der[ix + 1] & 0x7F);
            bool invalidLengthBytes = lengthbytesLength == 0 || ix + 2 + lengthbytesLength >= n;
            if (invalidLengthBytes) {
                revert Asn1InvalidLengthBytes();
            }
            if (lengthbytesLength == 1) {
                length = der.readUint8(ix + 2);
                if (length == 0) revert Asn1LengthCannotBeZero();
            } else if (lengthbytesLength == 2) {
                length = der.readUint16(ix + 2);
                if (length == 0) revert Asn1LengthCannotBeZero();
            } else {
                length = uint256(der.readBytesN(ix + 2, lengthbytesLength) >> (32 - lengthbytesLength) * 8);
                if (length == 0) revert Asn1LengthCannotBeZero();
            }
            ixFirstContentByte = uint80(ix + 2 + lengthbytesLength);
            ixLastContentByte = uint80(ixFirstContentByte + length - 1);
        }

        if (ixLastContentByte + 1 > n) {
            revert Asn1ContentLengthOutOfBounds();
        }

        return NodePtr.getPtr(ix, ixFirstContentByte, ixLastContentByte);
    }
}
