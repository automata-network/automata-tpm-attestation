// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

/// @notice PCR value with event replay log (from TPM quote)
struct PcrValue {
    /// @dev PCR index (0-23)
    uint8 pcrIndex;
    /// @dev Final PCR value (cumulative hash)
    bytes32 value;
    /// @dev Event hashes that were extended into this PCR (for DYNAMIC verification modes)
    bytes32[] eventLogHashes;
}

/// @title TPMS_CLOCK_INFO structure from TPM quote
/// @notice Can be used by callers for their own replay detection logic
/// @dev To check if a new ClockInfo is fresher than a previous one, compare in this order:
///      1. resetCount: If current > lastSeen, TPM was reset (valid even if clock is smaller)
///      2. restartCount: If current > lastSeen (same resetCount), TPM was restarted (valid)
///      3. clock: If same reset/restart counts, clock must be strictly greater
///      If any counter is less than lastSeen, it indicates rollback (reject).
///      If all values are equal, it indicates replay (reject).
struct ClockInfo {
    uint64 clock; // TPM clock value in milliseconds
    uint32 resetCount; // TPM reset count since manufacture
    uint32 restartCount; // Restart count since last reset
    bool safe; // Whether the TPM clock is in a safe state
}
