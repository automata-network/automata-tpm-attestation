// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

/// @title Measureable PCR Object
/// @notice This object contains the PCR value, and a list of event traces that
/// can be extended to compute the PCR value.
/// @notice This object also contains a list of log indices to select a sub-set of (or all) events
/// to be included in the final measurement.
/// @notice Generally, when the event indices are provided, the final PCR value
/// to include for measurement should be zero.
/// @custom:security-contact security@ata.network
struct MeasureablePcr {
    // pcr index
    uint256 index;
    // pcr value
    bytes32 pcr;
    // if allEvents.length > 0; extend_sha256(events) = pcr
    bytes32[] allEvents;
    // the index of events wants to measure
    uint256[] measureEventsIdx;
    bool measurePcr;
}

/// @title PCR Object
/// @notice This object represents the intended measurement of a PCR.
/// @notice Applications often use this object to define its golden measurement.
struct Pcr {
    // pcr index
    uint256 index;
    // sanity check: require(pcr!=0 || measureEvents.length>0)
    // this value is zero if we don't intend to include PCR value as part of the golden measurement
    bytes32 pcr;
    // the subset of events to measure
    bytes32[] measureEvents;
    // the index of events to measure
    uint256[] measureEventsIdx;
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
