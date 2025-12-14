// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

// Portions of this code are derived from Solady (https://github.com/Vectorized/solady)
// Copyright (c) 2022 Vectorized (https://github.com/vectorized/solady)
// Licensed under the MIT License

import { InvalidLength } from "../types/Errors.sol";

using LibBytes for Bytes48 global;
using LibBytes for Bytes64 global;

struct Bytes64 {
    bytes32 first;
    bytes32 second;
}

struct Bytes48 {
    bytes32 first;
    bytes16 second;
}

/**
 * @custom:security-contact security@ata.network
 */
library LibBytes {
    bytes16 private constant _SYMBOLS = "0123456789abcdef";

    /// @notice Reads 48 bytes from the input starting at the specified offset.
    /// @dev This function is commonly used for reading TEE measurement data (e.g., TDX RTMR values,
    ///      SNP measurements) which are 48 bytes in length. The function performs bounds checking
    ///      to ensure sufficient data is available.
    /// @param input The byte array to read from.
    /// @param offset The byte offset to start reading from (0-indexed).
    /// @return output A Bytes48 struct containing the 48-byte value.
    /// @dev Reverts with InvalidLength if input.length < offset + 48.
    function readBytes48(bytes memory input, uint256 offset) internal pure returns (Bytes48 memory output) {
        if (input.length < offset + 48) {
            revert InvalidLength(input.length, offset + 48);
        }
        assembly ("memory-safe") {
            function store48(dest, src, off) {
                mstore(dest, mload(add(add(src, 0x20), off)))
                mstore(add(dest, 0x20), mload(add(add(src, 0x40), off)))
            }
            store48(output, input, offset)
        }
    }

    /// @notice Reads 64 bytes from the input starting at the specified offset.
    /// @dev This function is commonly used for reading TEE user report data which is 64 bytes
    ///      in length. The function performs bounds checking to ensure sufficient data is available.
    /// @param input The byte array to read from.
    /// @param offset The byte offset to start reading from (0-indexed).
    /// @return output A Bytes64 struct containing the 64-byte value.
    /// @dev Reverts with InvalidLength if input.length < offset + 64.
    function readBytes64(bytes memory input, uint256 offset) internal pure returns (Bytes64 memory output) {
        if (input.length < offset + 64) {
            revert InvalidLength(input.length, offset + 64);
        }
        assembly ("memory-safe") {
            function store64(dest, src, off) {
                mstore(dest, mload(add(add(src, 0x20), off)))
                mstore(add(dest, 0x20), mload(add(add(src, 0x40), off)))
            }
            store64(output, input, offset)
        }
    }

    /// @notice Reads 2 bytes from the input starting at the specified offset.
    /// @dev This function reads a 2-byte value (e.g., uint16) from the input array.
    /// @param input The byte array to read from.
    /// @param offset The byte offset to start reading from (0-indexed).
    /// @return output The 2-byte value at the specified offset.
    function readBytes2(bytes memory input, uint256 offset) internal pure returns (bytes2 output) {
        assembly ("memory-safe") {
            output := mload(add(add(input, 0x20), offset))
        }
    }

    /// @notice Reads 4 bytes from the input starting at the specified offset.
    /// @dev This function reads a 4-byte value (e.g., uint32, function selector) from the input array.
    ///      The function performs bounds checking to ensure sufficient data is available.
    /// @param input The byte array to read from.
    /// @param offset The byte offset to start reading from (0-indexed).
    /// @return output The 4-byte value at the specified offset.
    /// @dev Reverts with InvalidLength if input.length < offset + 4.
    function readBytes4(bytes memory input, uint256 offset) internal pure returns (bytes4 output) {
        if (input.length < offset + 4) {
            revert InvalidLength(input.length, offset + 4);
        }
        assembly ("memory-safe") {
            output := mload(add(add(input, 0x20), offset))
        }
    }

    /// @notice Reads 32 bytes from the input starting at the specified offset.
    /// @dev This function reads a 32-byte value (e.g., bytes32, hash) from the input array.
    ///      The function performs bounds checking to ensure sufficient data is available.
    /// @param input The byte array to read from.
    /// @param offset The byte offset to start reading from (0-indexed).
    /// @return output The 32-byte value at the specified offset.
    /// @dev Reverts with InvalidLength if input.length < offset + 32.
    function readBytes32(bytes memory input, uint256 offset) internal pure returns (bytes32 output) {
        if (input.length < offset + 32) {
            revert InvalidLength(input.length, offset + 32);
        }
        assembly ("memory-safe") {
            output := mload(add(add(input, 0x20), offset))
        }
    }

    /// @notice Converts a bytes array to a Bytes48 struct.
    /// @dev This function validates that the input is exactly 48 bytes and converts it to
    ///      a Bytes48 struct for easier manipulation.
    /// @param data The byte array to convert (must be exactly 48 bytes).
    /// @return A Bytes48 struct containing the data.
    /// @dev Reverts with InvalidLength if data.length != 48.
    function toBytes48(bytes memory data) internal pure returns (Bytes48 memory) {
        if (data.length != 48) {
            revert InvalidLength(data.length, 48);
        }
        return readBytes48(data, 0);
    }

    /// @notice Converts a bytes array to a Bytes64 struct.
    /// @dev This function validates that the input is exactly 64 bytes and converts it to
    ///      a Bytes64 struct for easier manipulation.
    /// @param data The byte array to convert (must be exactly 64 bytes).
    /// @return A Bytes64 struct containing the data.
    /// @dev Reverts with InvalidLength if data.length != 64.
    function toBytes64(bytes memory data) internal pure returns (Bytes64 memory) {
        if (data.length != 64) {
            revert InvalidLength(data.length, 64);
        }
        return readBytes64(data, 0);
    }

    /// @notice Checks if two Bytes48 values are equal.
    /// @dev This function compares both the first (bytes32) and second (bytes16) fields
    ///      of two Bytes48 structs to determine equality.
    /// @param a The first Bytes48 value to compare.
    /// @param b The second Bytes48 value to compare.
    /// @return True if both values are equal, false otherwise.
    function equal(Bytes48 memory a, Bytes48 memory b) internal pure returns (bool) {
        return a.first == b.first && a.second == b.second;
    }

    /// @dev Returns whether `a` equals `b`.
    /// @notice Derived from Solady: https://github.com/Vectorized/solady/blob/73f13dd/src/utils/LibBytes.sol#L661-L667
    function equal(bytes memory a, bytes memory b) internal pure returns (bool result) {
        assembly ("memory-safe") {
            result := eq(keccak256(add(a, 0x20), mload(a)), keccak256(add(b, 0x20), mload(b)))
        }
    }

    /// @notice Checks if a Bytes48 value is zero (all bytes are zero).
    /// @dev This function is commonly used to check if TEE measurements are uninitialized.
    /// @param data The Bytes48 value to check.
    /// @return True if both the first (bytes32) and second (bytes16) fields are zero, false otherwise.
    function isZero(Bytes48 memory data) internal pure returns (bool) {
        return data.first == bytes32(0) && data.second == bytes16(0);
    }

    /// @notice Converts a Bytes48 struct to a bytes array.
    /// @dev This function packs the first (bytes32) and second (bytes16) fields into a
    ///      contiguous bytes array using abi.encodePacked.
    /// @param data The Bytes48 struct to convert.
    /// @return A bytes array containing the concatenated 48-byte value.
    function toBytes(Bytes48 memory data) internal pure returns (bytes memory) {
        return abi.encodePacked(data.first, data.second);
    }

    /// @dev Returns a copy of `subject` sliced from `start` to `start+len` (exclusive).
    /// `start` and `end` are byte offsets.
    /// @notice Derived from Solady: https://github.com/Vectorized/solady/blob/73f13dd/src/utils/LibBytes.sol#L443-L472
    function slice(bytes memory subject, uint256 start, uint256 len) internal pure returns (bytes memory result) {
        uint256 end = start + len;
        assembly ("memory-safe") {
            let l := mload(subject) // Subject length.
            if iszero(gt(l, end)) { end := l }
            if iszero(gt(l, start)) { start := l }
            if lt(start, end) {
                result := mload(0x40)
                let n := sub(end, start)
                let i := add(subject, start)
                let w := not(0x1f)
                // Copy the `subject` one word at a time, backwards.
                for { let j := and(add(n, 0x1f), w) } 1 { } {
                    mstore(add(result, j), mload(add(i, j)))
                    j := add(j, w) // `sub(j, 0x20)`.
                    if iszero(j) { break }
                }
                let o := add(add(result, 0x20), n)
                mstore(o, 0) // Zeroize the slot after the bytes.
                mstore(0x40, add(o, 0x20)) // Allocate memory.
                mstore(result, n) // Store the length.
            }
        }
    }

    function toString(bytes memory data) internal pure returns (string memory) {
        uint256 len = data.length;
        bytes memory buffer = new bytes(2 + len * 2);
        buffer[0] = "0";
        buffer[1] = "x";

        for (uint256 i; i < len; ++i) {
            uint8 b = uint8(data[i]);
            buffer[2 + i * 2] = _SYMBOLS[b >> 4];
            buffer[3 + i * 2] = _SYMBOLS[b & 0x0f];
        }
        return string(buffer);
    }

    function toString(Bytes64 memory data) internal pure returns (string memory) {
        return toString(abi.encodePacked(data.first, data.second));
    }

    function toString(Bytes48 memory data) internal pure returns (string memory) {
        return toString(abi.encodePacked(data.first, data.second));
    }

    function toString(uint256 data) internal pure returns (string memory) {
        return toString(abi.encodePacked(data));
    }

    function toString(bytes32 data) internal pure returns (string memory) {
        return toString(abi.encodePacked(data));
    }
}
