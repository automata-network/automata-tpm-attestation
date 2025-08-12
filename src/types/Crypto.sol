// SPDX-License-Identifier: MIT
// Automata Contracts
pragma solidity ^0.8.15;

struct Pubkey {
    uint16 sigScheme;
    uint16 curve;
    uint16 hashAlgo;
    bytes data;
}
