// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.20;

import {ITpmAttestation, MeasureablePcr, Pcr} from "./interfaces/ITpmAttestation.sol";
import {Pubkey, Crypto} from "./types/Crypto.sol";
import {TPM_ALG_SHA256, TPM_ALG_RSASSA, TPM_ALG_ECDSA, TPM_ECC_NIST_P256} from "./types/Constants.sol";
import {LibX509, CertChainRegistry} from "./bases/CertChainRegistry.sol";
import "./types/Errors.sol";

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
    constructor(address _intitialOwner, address _p256) CertChainRegistry(_intitialOwner, _p256) {}

    function verifyTpmQuote(bytes calldata tpmQuote, bytes calldata tpmSignature, bytes[] calldata akCertchain)
        external
        override
        returns (bool, bytes memory)
    {
        if (akCertchain.length == 0) {
            revert InvalidCertChainLength();
        }
        bytes32 leafHash = keccak256(akCertchain[0]);
        Pubkey memory akPub = verifiedLeafKeys[leafHash];

        if (akPub.data.length == 0) {
            akPub = verifyCertChain(akCertchain);
            if (akPub.data.length == 0) {
                revert InvalidCertificateChain();
            }
        }

        _verifyTpmQuote(tpmQuote, tpmSignature, akPub);
        return (true, abi.encode(akPub));
    }

    function verifyTpmQuote(bytes calldata tpmQuote, bytes calldata tpmSignature, Pubkey calldata akPub)
        external
        override
        returns (bool, string memory)
    {
        _verifyTpmQuote(tpmQuote, tpmSignature, akPub);
        return (true, "");
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
        override
        returns (bool success, bytes memory extraData)
    {
        uint256 offset;
        {
            uint16 qualifiedSignerLen;
            uint16 extraDataLen;
            (success, qualifiedSignerLen, extraDataLen, extraData) = _readTpmHeaders(tpmQuote);
            if (!success) {
                revert InvalidTpmQuote("Failed to read headers");
            }
            offset = 35 + qualifiedSignerLen + extraDataLen;
        }

        uint32 tpmsPCRCount = uint32(bytes4(tpmQuote[offset:offset + 4]));
        if (tpmsPCRCount != 1) {
            revert InvalidTpmQuote("tpmsPCRCount != 1");
        }
        offset += 4;

        uint16 tpmPcrHash = uint16(bytes2(tpmQuote[offset:offset + 2]));
        if (tpmPcrHash != TPM_ALG_SHA256) {
            revert UnsupportedHashAlgorithm();
        }
        offset += 2;

        uint8 pcrsSize = uint8(tpmQuote[offset]);
        bytes4 pcrSelection = bytes4(tpmQuote[offset + 1:offset + 1 + pcrsSize]);
        if (pcrSelection != _compactSelections(tpmPcrs)) {
            revert PcrSelectionMismatch();
        }
        offset += 1 + pcrsSize;

        uint16 pcrDigestSize = uint16(bytes2(tpmQuote[offset:offset + 2]));
        if (pcrDigestSize != 32) {
            revert InvalidPcrDigestSize();
        }
        offset += 2;

        bytes32 pcrDigest = bytes32(tpmQuote[offset:offset + pcrDigestSize]);
        bytes32 expectedDigest = _digest(tpmPcrs);
        if (pcrDigest != expectedDigest) {
            revert PcrDigestMismatch();
        }

        emit TpmMeasurementChecked(keccak256(tpmQuote), pcrDigest, extraData);

        return (true, extraData);
    }

    function toFinalMeasurement(MeasureablePcr[] calldata mpcrs) external pure override returns (Pcr[] memory) {
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

    function _verifyTpmQuote(bytes calldata tpmQuote, bytes calldata tpmSignature, Pubkey memory akPub) private {
        _verifyTpmQuoteSignature(tpmQuote, tpmSignature, akPub);
        emit TpmSignatureVerified(keccak256(tpmQuote));
    }

    function _verifyTpmQuoteSignature(bytes calldata tpmQuote, bytes calldata tpmSignature, Pubkey memory akPub)
        private
        view
    {
        uint16 sigAlg = uint16(bytes2(tpmSignature[0:2]));
        uint16 hashAlg = uint16(bytes2(tpmSignature[2:4]));
        uint16 sigSize = uint16(bytes2(tpmSignature[4:6]));

        if (hashAlg != TPM_ALG_SHA256) {
            revert UnsupportedHashAlgorithm();
        }

        bytes memory sig;
        if (sigAlg == TPM_ALG_RSASSA) {
            sig = tpmSignature[6:6 + sigSize];
        } else if (sigAlg == TPM_ALG_ECDSA) {
            if (sigSize != 32) {
                revert InvalidEcdsaSignature();
            }
            uint16 sSize = uint16(bytes2(tpmSignature[6 + sigSize:8 + sigSize]));
            if (sSize != 32) {
                revert InvalidEcdsaSignature();
            }
            sig = new bytes(sigSize + sSize);
            sig = abi.encodePacked(
                tpmSignature[6:6 + sigSize], // r-value
                tpmSignature[8 + sigSize:8 + sigSize + sSize] // s-value
            );
        } else {
            revert InvalidSignature();
        }

        address verifier = sigAlg == TPM_ALG_ECDSA ? p256 : address(0);
        bool result = akPub.verifySignature(tpmQuote, sig, verifier);

        if (!result) {
            revert TpmSignatureVerificationFailed();
        }
    }

    function _readTpmHeaders(bytes calldata tpmQuote)
        private
        pure
        returns (bool success, uint16 qualifiedSignerLen, uint16 extraDataLen, bytes memory retData)
    {
        if (tpmQuote.length < 10) {
            revert InvalidTpmQuote("Quote too short");
        }
        uint16 attType = uint16(bytes2(tpmQuote[4:6]));
        if (attType != 0x8018) {
            revert InvalidTpmQuote("attType != 0x8018");
        }

        qualifiedSignerLen = uint16(bytes2(tpmQuote[6:8]));
        if (tpmQuote.length < 10 + qualifiedSignerLen) {
            revert InvalidTpmQuote("Quote too short for qualified signer");
        }
        extraDataLen = uint16(bytes2(tpmQuote[8 + qualifiedSignerLen:10 + qualifiedSignerLen]));
        if (tpmQuote.length < 10 + qualifiedSignerLen + extraDataLen) {
            revert InvalidTpmQuote("Quote too short for extra data");
        }
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
            bytes32 pcrValue = tpmPcrs[i].pcr;
            // A PCR value of zero is valid if events are provided to reconstruct it.
            // If no events are provided, the PCR value must not be zero.
            if (pcrValue == bytes32(0)) {
                require(!tpmPcrs[i].measurePcr || tpmPcrs[i].allEvents.length > 0, "TPMA: PCR is zero without events");
                pcrValue = _calculatePcrFromEvents(tpmPcrs[i].allEvents);
            }
            concatenated = abi.encodePacked(concatenated, pcrValue);
        }

        return sha256(concatenated);
    }

    function _calculatePcrFromEvents(bytes32[] calldata events) private pure returns (bytes32) {
        bytes32 pcr = bytes32(0);
        for (uint256 i = 0; i < events.length; i++) {
            pcr = sha256(abi.encodePacked(pcr, events[i]));
        }
        return pcr;
    }

    function _verifyEvents(MeasureablePcr calldata mpcr) private pure returns (bool) {
        // If a PCR value is provided, it must match the calculated value from its events.
        // If no PCR value is provided, this check is skipped (it's calculated in _digest).
        if (mpcr.pcr != bytes32(0) && mpcr.allEvents.length > 0) {
            return _calculatePcrFromEvents(mpcr.allEvents) == mpcr.pcr;
        }
        // If no events are provided, or no pcr is provided, there's nothing to verify here.
        return true;
    }
}
