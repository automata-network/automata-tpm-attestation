// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.20;

import {ITpmAttestation, MeasureablePcr, Pcr} from "./interfaces/ITpmAttestation.sol";
import {LibX509, CertPubkey, CertChainRegistry} from "./bases/CertChainRegistry.sol";

// TPM Quote Layout:
// =====================================
// magic: [0..4]
// att_type: [4..6]
// qualified_signer_len: [6..8]
// qualified_signer: [8..8+qualified_signer_len]
// extra_data_len: [8+qualified_signer_len..10+qualified_signer_len]
// extra_data: [10+qualified_signer_len..10+qualified_signer_len+extra_data_len]
// clock_info: [10+qualified_signer_len+extra_data_len..10+qualified_signer_len+extra_data_len+17]
// firmware_version: [27+qualified_signer_len+extra_data_len..27+qualified_signer_len+extra_data_len+8]
// if att_type == 0x8018
//   parse TPMSQuoteInfo
//   count: [35+qualified_signer_len+extra_data_len..35+qualified_signer_len+extra_data_len+4]
//   assert count == 1:
//   pcr_selections: TPMSPCRSelection[0]:
//     hash: [39+qualified_signer_len+extra_data_len + ..39+qualified_signer_len+extra_data_len+2]
//     pcr_size: [41+qualified_signer_len+extra_data_len + ..41+qualified_signer_len+extra_data_len+1]
//     pcrs: [42+qualified_signer_len+extra_data_len + ..42+qualified_signer_len+extra_data_len+pcr_size]
//   pcr_digest_size:
// [42+qualified_signer_len+extra_data_len+pcr_size..42+qualified_signer_len+extra_data_len+pcr_size+2]
//   pcr_digest:
// [44+qualified_signer_len+extra_data_len+pcr_size..44+qualified_signer_len+extra_data_len+pcr_size+pcr_digest_size]
// END

contract TpmAttestation is CertChainRegistry, ITpmAttestation {
    uint16 internal constant HASH_SHA256 = 0x000B;
    uint16 internal constant SIG_RSA = 0x0014;
    uint16 internal constant SIG_ECDSA = 0x0018;

    constructor(address _intitialOwner, address _p256) CertChainRegistry(_intitialOwner, _p256) {}

    function verifyTpmQuote(bytes calldata tpmQuote, bytes calldata tpmSignature, bytes[] calldata akCertchain)
        external
        override
        returns (bool, string memory)
    {
        CertPubkey memory akPub = verifyCertChain(akCertchain);
        if (akPub.data.length == 0) {
            return (false, "Invalid AK certificate chain");
        }
        return _verifyTpmQuote(tpmQuote, tpmSignature, akPub);
    }

    function verifyTpmQuote(bytes calldata tpmQuote, bytes calldata tpmSignature, CertPubkey calldata akPub)
        external
        view
        override
        returns (bool, string memory)
    {
        return _verifyTpmQuote(tpmQuote, tpmSignature, akPub);
    }

    function extractExtraData(bytes calldata tpmQuote)
        external
        pure
        override
        returns (bool success, bytes memory extraData)
    {
        (success,,, extraData) = _readTpmHeaders(tpmQuote);
    }

    function checkPcrMeasurements(bytes calldata tpmQuote, MeasureablePcr[] calldata tpmPcrs)
        external
        pure
        override
        returns (bool success, bytes memory extraData)
    {
        uint256 offset;
        {
            uint16 qualifiedSignerLen;
            uint16 extraDataLen;
            (success, qualifiedSignerLen, extraDataLen, extraData) = _readTpmHeaders(tpmQuote);
            if (!success) {
                return (false, extraData);
            }
            offset = 35 + qualifiedSignerLen + extraDataLen;
        }

        uint32 tpmsPCRCount = uint32(bytes4(tpmQuote[offset:offset + 4]));
        if (tpmsPCRCount != 1) {
            return (false, bytes("tpmsPCRCount != 1"));
        }
        offset += 4;

        uint16 tpmPcrHash = uint16(bytes2(tpmQuote[offset:offset + 2]));
        if (tpmPcrHash != HASH_SHA256) {
            return (false, bytes("TPM PCR hash is not SHA256"));
        }
        offset += 2;

        uint8 pcrsSize = uint8(tpmQuote[offset]);
        bytes4 pcrSelection = bytes4(tpmQuote[offset + 1:offset + 1 + pcrsSize]);
        if (pcrSelection != _compactSelections(tpmPcrs)) {
            return (false, bytes("PCR selections do not match"));
        }
        offset += 1 + pcrsSize;

        uint16 pcrDigestSize = uint16(bytes2(tpmQuote[offset:offset + 2]));
        if (pcrDigestSize != 32) {
            return (false, bytes("Invalid PCR digest size"));
        }
        offset += 2;

        bytes32 pcrDigest = bytes32(tpmQuote[offset:offset + pcrDigestSize]);
        bytes32 expectedDigest = _digest(tpmPcrs);
        if (pcrDigest != expectedDigest) {
            return (false, bytes("PCR digest does not match expected digest"));
        }

        return (true, extraData);
    }

    function toGoldenMeasurement(MeasureablePcr[] calldata mpcrs) external pure override returns (Pcr[] memory) {
        // Cache array length to avoid multiple storage reads
        uint256 mpcrsLength = mpcrs.length;
        Pcr[] memory pcrs = new Pcr[](mpcrsLength);

        // Use unchecked to save gas on bounds checking where we know it's safe
        unchecked {
            for (uint256 i = 0; i < mpcrsLength; i++) {
                // Cache the current MeasureablePcr to avoid multiple calldata accesses
                MeasureablePcr calldata currentMpcr = mpcrs[i];

                // Verify events before allocating memory for arrays
                require(_verifyEvents(currentMpcr), "Invalid all events");

                // Cache the measureEventsIdx length
                uint256 eventsIdxLength = currentMpcr.measureEventsIdx.length;

                // Only allocate memory if there are events to process
                bytes32[] memory measureEvents = new bytes32[](eventsIdxLength);
                uint256[] memory measureEventsIdx = new uint256[](eventsIdxLength);

                // Process events only if there are any
                if (eventsIdxLength > 0) {
                    uint256 allEventsLength = currentMpcr.allEvents.length;

                    for (uint256 j = 0; j < eventsIdxLength; j++) {
                        uint256 eventIdx = currentMpcr.measureEventsIdx[j];
                        require(eventIdx < allEventsLength, "Invalid event index");
                        measureEvents[j] = currentMpcr.allEvents[eventIdx];
                        measureEventsIdx[j] = eventIdx;
                    }
                }

                // Create the PCR with the correct values
                pcrs[i] = Pcr({
                    index: currentMpcr.index,
                    pcr: currentMpcr.measurePcr ? currentMpcr.pcr : bytes32(0),
                    measureEvents: measureEvents,
                    measureEventsIdx: measureEventsIdx
                });
            }
        }

        return pcrs;
    }

    function _verifyTpmQuote(bytes calldata tpmQuote, bytes calldata tpmSignature, CertPubkey memory akPub)
        private
        view
        returns (bool success, string memory errMessage)
    {
        (success, errMessage) = _verifyTpmQuoteSignature(tpmQuote, tpmSignature, akPub);
        if (!success) {
            return (false, errMessage);
        }

        return (true, "");
    }

    function _verifyTpmQuoteSignature(bytes calldata tpmQuote, bytes calldata tpmSignature, CertPubkey memory akPub)
        private
        view
        returns (bool, string memory)
    {
        uint16 sigAlg = uint16(bytes2(tpmSignature[0:2]));
        uint16 hashAlg = uint16(bytes2(tpmSignature[2:4]));
        uint16 sigSize = uint16(bytes2(tpmSignature[4:6]));

        if (hashAlg != HASH_SHA256) {
            return (false, "hash is not SHA256");
        }

        bytes memory sig;
        if (sigAlg == SIG_RSA) {
            sig = tpmSignature[6:6 + sigSize];
        } else if (sigAlg == SIG_ECDSA) {
            if (sigSize != 32) {
                return (false, "Incorrect ECDSA r-value size");
            }
            uint16 sSize = uint16(bytes2(tpmSignature[6 + sigSize:8 + sigSize]));
            if (sSize != 32) {
                return (false, "Incorrect ECDSA s-value size");
            }
            sig = new bytes(sigSize + sSize);
            sig = abi.encodePacked(
                tpmSignature[6:6 + sigSize], // r-value
                tpmSignature[8 + sigSize:8 + sigSize + sSize] // s-value
            );
        } else {
            return (false, "Unknown sigAlg");
        }

        bytes32 message = sha256(tpmQuote);
        bool result = verifySignature(message, sig, akPub);

        if (!result) {
            return (false, "Failed to verify TPM signature");
        }

        return (true, "");
    }

    function _readTpmHeaders(bytes calldata tpmQuote)
        private
        pure
        returns (bool success, uint16 qualifiedSignerLen, uint16 extraDataLen, bytes memory retData)
    {
        uint16 attType = uint16(bytes2(tpmQuote[4:6]));
        if (attType != 0x8018) {
            return (false, qualifiedSignerLen, extraDataLen, bytes("attType != 0x8018"));
        }

        qualifiedSignerLen = uint16(bytes2(tpmQuote[6:8]));
        extraDataLen = uint16(bytes2(tpmQuote[8 + qualifiedSignerLen:10 + qualifiedSignerLen]));
        retData = tpmQuote[10 + qualifiedSignerLen:10 + qualifiedSignerLen + extraDataLen];
        success = true;
    }

    function _compactSelections(MeasureablePcr[] calldata tpmPcrs) private pure returns (bytes4) {
        // Use a single uint32 instead of an array to reduce memory operations
        uint32 bitmap;
        uint256 len = tpmPcrs.length;

        // Cache array length and use unchecked for loop operations to save gas
        unchecked {
            for (uint256 i = 0; i < len && i < 32; i++) {
                uint256 idx = tpmPcrs[i].index;
                // Set bit directly in the bitmap using a single operation
                bitmap |= uint32(1 << idx);
            }
        }

        // Convert to bytes4 in a single operation
        return bytes4(
            ((bitmap & 0xFF000000) >> 24) | ((bitmap & 0x00FF0000) >> 8) | ((bitmap & 0x0000FF00) << 8)
                | ((bitmap & 0x000000FF) << 24)
        );
    }

    function _digest(MeasureablePcr[] calldata tpmPcrs) private pure returns (bytes32) {
        bytes memory concatenated;

        for (uint256 i = 0; i < tpmPcrs.length; i++) {
            concatenated = abi.encodePacked(concatenated, tpmPcrs[i].pcr);
        }

        return sha256(concatenated);
    }

    function _verifyEvents(MeasureablePcr calldata mpcr) private pure returns (bool) {
        // Early return conditions
        if (mpcr.pcr == bytes32(0)) {
            return true;
        }

        uint256 allEventsLength = mpcr.allEvents.length;
        if (allEventsLength == 0) {
            return true;
        }

        bytes32 before = bytes32(0);
        // Use unchecked for loop operations to save gas
        unchecked {
            for (uint256 i = 0; i < allEventsLength; i++) {
                before = sha256(abi.encodePacked(before, mpcr.allEvents[i]));
            }
        }

        return before == mpcr.pcr;
    }
}
